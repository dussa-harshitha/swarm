"""Path-based finding triage — separate likely-real findings from likely
false positives by WHERE they occur. A secret or SAST hit in test/example/
fixture/docs code is very likely intentional (test data), not a real leak;
one in core source is production-relevant.

This does NOT hide findings — it classifies and down-weights them, honestly,
so a human reviews the core-code hits first. SWARM surfaces candidates; this
ranks them."""
import re

NONCORE = re.compile(
    r"(^|/|\\)(tests?|test|examples?|example|fixtures?|fixture|docs?|doc|"
    r"samples?|sample|demo|demos|mock|mocks|\.github|benchmarks?|vendor|"
    r"node_modules|site-packages)(/|\\|$)", re.I)

def is_noncore(path: str) -> bool:
    """True if the file path is in a test/example/docs area (likely false positive)."""
    return bool(NONCORE.search(path or ""))

def classify_findings(findings: list[dict], path_key) -> dict:
    """Split findings into core vs non-core by file path.
    path_key: a function extracting the file path from one finding.
    Returns {'core': [...], 'noncore': [...], 'core_n': int, 'noncore_n': int}."""
    core, noncore = [], []
    for f in findings:
        (noncore if is_noncore(path_key(f)) else core).append(f)
    return {"core": core, "noncore": noncore, "core_n": len(core), "noncore_n": len(noncore)}
