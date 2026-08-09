"""Investigation spawning: when a claim resolves, decide whether the finding
warrants a deeper follow-up, and if so create child claim(s) linked by an
'investigates' edge. This is what turns the scheduler into a reasoning loop —
the graph grows as the swarm digs into what it finds.

Spawns are DETERMINISTIC (rule-based on the evidence), not LLM guesses, so they
never fabricate a line of inquiry. Each spawn has a concrete resolving action."""
import re
from ..verify.results import VerifyResult

# a spawn: (child_text, child_type, child_method, note) or None
def spawn_children(claim, result: VerifyResult) -> list[dict]:
    children = []
    m = claim.method

    # 1) Refuted CVEs -> investigate whether fixes exist (actionable remediation)
    if m == "osv_lookup" and result.status == "refuted":
        n = len(re.findall(r"(GHSA|CVE|PYSEC)-", result.detail or ""))
        children.append({
            "text": f"Fixed versions are available for the {n or 'known'} vulnerable dependencies",
            "type": "security", "method": "osv_fixes", "rel": "investigates",
            "note": "spawned: refuted CVE claim warrants remediation check"})

    # 2) License conflict -> determine the actual combined-license obligation
    if m == "license_compat" and result.status == "refuted":
        children.append({
            "text": "The effective combined license is copyleft (obligations propagate to the whole work)",
            "type": "license", "method": "license_obligation", "rel": "investigates",
            "note": "spawned: license conflict warrants combined-obligation analysis"})

    # 3) Test failure -> is it one isolated failure or systemic?
    if m == "run_tests" and result.status == "refuted":
        failed = len(re.findall(r"FAILED|Error", result.detail or ""))
        if failed:
            children.append({
                "text": "Test failures are isolated (not a broad breakage)",
                "type": "quality", "method": "test_failure_scope", "rel": "investigates",
                "note": "spawned: quantify blast radius of test failures"})

    # 4) SAST refuted -> classify severity concentration
    if m == "sast_scan" and result.status == "refuted":
        children.append({
            "text": "Security findings are concentrated in non-core / example code",
            "type": "security", "method": "sast_locality", "rel": "investigates",
            "note": "spawned: locate where the findings sit"})

    return children


# ---- child verifiers (operate on evidence already gathered, near-zero cost) ----
def resolve_osv_fixes(parent_detail: str) -> VerifyResult:
    """Remediation check against REAL fix data: the OSV verifier enriches its
    evidence with 'FIX: <pkg> -> <version> (<id>)' lines pulled from
    /v1/vulns/{id}. The claim is 'fixed versions are available' — so when fix
    data exists the verdict is VERIFIED (good news: remediation is possible),
    and when we cannot confirm it, we say so instead of asserting."""
    fixes = re.findall(r"FIX: (\S+) -> (\S+) \(([\w.-]+)\)", parent_detail or "")
    ids = re.findall(r"(?:GHSA|CVE|PYSEC)-[\w-]+", parent_detail or "")
    if fixes:
        listing = "; ".join(f"{pkg} -> {ver} ({vid})" for pkg, ver, vid in fixes[:6])
        return VerifyResult("verified", 0.85,
                            f"Patched releases confirmed for {len(fixes)} of the flagged advisories "
                            f"— upgrading remediates",
                            detail="Remediation (from OSV fix ranges): " + listing, kind="cve")
    if ids:
        return VerifyResult("unverifiable", 0.5,
                            f"{len(set(ids))} advisories flagged, but fix-version data was not "
                            f"gathered — availability of patches unconfirmed",
                            detail="Affected: " + ", ".join(sorted(set(ids))[:6]), kind="cve")
    return VerifyResult("unverifiable", 0.5, "No advisory IDs in parent evidence to check for fixes", kind="cve")

def resolve_license_obligation(parent_detail: str) -> VerifyResult:
    m = re.search(r"is ((?:A?GPL|LGPL)[\w.\-]*)", parent_detail or "")
    lic = m.group(1) if m else "a copyleft license"
    return VerifyResult("refuted", 0.8,
                        f"Combined-work obligation: {lic} copyleft propagates — the whole project must "
                        f"comply with {lic}, contradicting the permissive license claimed",
                        detail=f"Distributing this project under its claimed permissive license while "
                               f"including a {lic} dependency is a license violation. Options: remove the "
                               f"dependency, or relicense the project.", kind="scan")

def resolve_test_scope(parent_detail: str) -> VerifyResult:
    """Blast-radius from the pytest summary line ('N failed, M passed ...').
    Requires the suite to have run without -x so the counts are real.
    Unparseable evidence yields no verdict — we never guess scope."""
    d = parent_detail or ""
    m_f = re.search(r"(\d+) failed", d)
    m_p = re.search(r"(\d+) passed", d)
    m_e = re.search(r"(\d+) errors?\b", d)
    failed = int(m_f.group(1)) if m_f else 0
    passed = int(m_p.group(1)) if m_p else 0
    errors = int(m_e.group(1)) if m_e else 0
    if not (m_f or m_p or m_e):
        return VerifyResult("unverifiable", 0.5,
                            "Could not parse a test summary from the evidence — scope not judged",
                            kind="test_log")
    if errors or (failed and not passed):
        return VerifyResult("refuted", 0.75,
                            f"Failures are broad or block collection ({failed} failed, {passed} passed, "
                            f"{errors} errors) — not an isolated issue", kind="test_log")
    if failed and failed <= 2 and passed >= failed:
        return VerifyResult("verified", 0.7,
                            f"Failures are limited ({failed} failed vs {passed} passed) — isolated, not systemic",
                            kind="test_log")
    return VerifyResult("refuted", 0.7,
                        f"Failure rate is significant ({failed} failed vs {passed} passed) — systemic",
                        kind="test_log")

_NONCORE = re.compile(r"^(test_|conftest)|(_test|\.test|\.spec)\.\w+$|^(example|demo|fixture|sample)", re.I)

def resolve_sast_locality(parent_detail: str) -> VerifyResult:
    """Where do the findings actually sit? Bandit/semgrep evidence is formatted
    'RULE@filename:line' — parse every finding path and classify each file,
    instead of substring-matching the whole blob (which flipped the verdict if
    ANY path merely contained 'test')."""
    hits = re.findall(r"@([\w.\-]+):\d+", parent_detail or "")
    if not hits:
        return VerifyResult("unverifiable", 0.5,
                            "No finding locations in parent evidence — locality not judged", kind="scan")
    noncore = [h for h in hits if _NONCORE.search(h)]
    core = [h for h in hits if h not in noncore]
    if not core:
        return VerifyResult("verified", 0.65,
                            f"All {len(hits)} findings sit in test/example code — lower production risk",
                            detail="Files: " + ", ".join(sorted(set(noncore))[:8]), kind="scan")
    return VerifyResult("refuted", 0.75,
                        f"{len(core)} of {len(hits)} findings are in core source files — production-relevant",
                        detail="Core files: " + ", ".join(sorted(set(core))[:8]), kind="scan")

CHILD_RESOLVERS = {
    "osv_fixes": resolve_osv_fixes,
    "license_obligation": resolve_license_obligation,
    "test_failure_scope": resolve_test_scope,
    "sast_locality": resolve_sast_locality,
}
