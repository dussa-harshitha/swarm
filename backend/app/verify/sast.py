"""Static analysis via bandit (Python).
Integrity rule: empty or unparseable scanner output is NEVER "clean" —
a scan that didn't demonstrably run yields "unverifiable", not "verified".
"""
import json, subprocess, sys
from pathlib import Path
from .triage import classify_findings
from .results import VerifyResult

def bandit_scan(repo: Path) -> VerifyResult:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", str(repo), "-f", "json", "-q", "-x", "tests"],
            capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        return VerifyResult("unverifiable", 0.5, "Python interpreter unavailable for bandit", kind="scan")
    except subprocess.TimeoutExpired:
        return VerifyResult("unverifiable", 0.5, "bandit scan timed out", kind="scan")
    if "No module named" in (proc.stderr or ""):
        return VerifyResult("unverifiable", 0.5,
                            "Required tool missing: bandit not installed (pip install bandit)", kind="scan")
    if not (proc.stdout or "").strip():
        return VerifyResult("unverifiable", 0.5,
                            f"bandit produced no output (exit {proc.returncode}); scan not proven to have run",
                            detail=(proc.stderr or "")[:300], kind="scan")
    try:
        obj = json.loads(proc.stdout)
    except Exception:
        return VerifyResult("unverifiable", 0.5, "bandit produced unparseable output", kind="scan")
    if "results" not in obj:
        return VerifyResult("unverifiable", 0.5, "bandit output missing results section", kind="scan")
    results = obj["results"]
    high = [r for r in results if r.get("issue_severity") in ("HIGH", "MEDIUM")]
    if not results:
        return VerifyResult("verified", 0.85, "bandit: no findings", kind="scan")
    if not high:
        return VerifyResult("verified", 0.7, f"bandit: only low-severity findings ({len(results)})", kind="scan")
    top = "; ".join(f"{r['test_id']}@{Path(r['filename']).name}:{r['line_number']}" for r in high[:5])
    cls = classify_findings(high, lambda r: r.get("filename", ""))
    if cls["core_n"] == 0 and cls["noncore_n"] > 0:
        return VerifyResult("unverifiable", 0.55,
            f"bandit: {len(high)} finding(s), ALL in test/example paths (likely intentional test code)",
            detail=top, kind="scan")
    note = f" ({cls['core_n']} core, {cls['noncore_n']} test/example)" if cls["noncore_n"] else ""
    return VerifyResult("refuted", 0.8, f"bandit: {len(high)} medium/high finding(s){note}", detail=top, kind="scan")
