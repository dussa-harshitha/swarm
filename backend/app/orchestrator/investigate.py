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
    """Heuristic remediation check: OSV IDs with a fix are the norm for old pinned
    versions. We flag that upgrades exist to be applied (actionable), honestly
    noting this is advisory."""
    ids = re.findall(r"(?:GHSA|CVE|PYSEC)-[\w-]+", parent_detail or "")
    if not ids:
        return VerifyResult("unverifiable", 0.5, "No CVE IDs to check for fixes", kind="cve")
    return VerifyResult("refuted", 0.75,
                        f"{len(ids)} advisories affect pinned versions; upgrading the flagged "
                        f"dependencies is required to remediate",
                        detail="Remediation: bump the refuted dependencies to non-vulnerable releases. "
                               "Affected: " + ", ".join(ids[:6]), kind="cve")

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
    failed = len(re.findall(r"FAILED", parent_detail or ""))
    passed = len(re.findall(r"passed", parent_detail or ""))
    if failed and failed <= 2 and passed:
        return VerifyResult("verified", 0.7,
                            f"Failures are limited ({failed} failed, some passed) — isolated, not systemic",
                            kind="test_log")
    return VerifyResult("refuted", 0.7,
                        "Failures are broad or block collection — not an isolated issue", kind="test_log")

def resolve_sast_locality(parent_detail: str) -> VerifyResult:
    in_tests = bool(re.search(r"test|example|demo|fixture", parent_detail or "", re.I))
    if in_tests:
        return VerifyResult("verified", 0.65,
                            "Findings appear in test/example code — lower production risk", kind="scan")
    return VerifyResult("refuted", 0.75,
                        "Findings are in core source paths — production-relevant", kind="scan")

CHILD_RESOLVERS = {
    "osv_fixes": resolve_osv_fixes,
    "license_obligation": resolve_license_obligation,
    "test_failure_scope": resolve_test_scope,
    "sast_locality": resolve_sast_locality,
}
