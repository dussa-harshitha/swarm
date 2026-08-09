"""Static analysis via bandit (Python)."""
import json, subprocess
from pathlib import Path
from .results import VerifyResult

def bandit_scan(repo: Path) -> VerifyResult:
    proc = subprocess.run(
        ["python3", "-m", "bandit", "-r", str(repo), "-f", "json", "-q", "-x", "tests"],
        capture_output=True, text=True, timeout=180)
    try:
        obj = json.loads(proc.stdout or "{}")
    except Exception:
        return VerifyResult("unverifiable", 0.5, "bandit produced unparseable output", kind="scan")
    high = [r for r in obj.get("results", []) if r.get("issue_severity") in ("HIGH", "MEDIUM")]
    if not obj.get("results"):
        return VerifyResult("verified", 0.85, "bandit: no findings", kind="scan")
    if not high:
        return VerifyResult("verified", 0.7, f"bandit: only low-severity findings ({len(obj['results'])})", kind="scan")
    top = "; ".join(f"{r['test_id']}@{Path(r['filename']).name}:{r['line_number']}" for r in high[:5])
    return VerifyResult("refuted", 0.8, f"bandit: {len(high)} medium/high finding(s)", detail=top, kind="scan")
