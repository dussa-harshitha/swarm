"""Verify 'actively maintained' claims via git commit history."""
import subprocess, time
from pathlib import Path
from .results import VerifyResult

def maintenance_stats(repo: Path) -> VerifyResult:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "log", "--format=%ct", "-n", "200"],
            capture_output=True, text=True, timeout=30)
    except Exception as e:
        return VerifyResult("unverifiable", 0.5, f"git history unavailable: {e}", kind="scan")
    if proc.returncode != 0 or not proc.stdout.strip():
        return VerifyResult("unverifiable", 0.5,
                            "No git history (shallow clone or not a git repo)", kind="scan")
    stamps = [int(x) for x in proc.stdout.split()]
    now = time.time()
    days_since_last = (now - max(stamps)) / 86400
    last_90d = sum(1 for s in stamps if now - s < 90 * 86400)
    detail = f"last commit {days_since_last:.0f}d ago; {last_90d} commits in 90d; {len(stamps)} sampled"
    if days_since_last <= 90 and last_90d >= 5:
        return VerifyResult("verified", 0.85, "Actively maintained", detail=detail, kind="scan")
    if days_since_last > 365:
        return VerifyResult("refuted", 0.85, f"Dormant: no commits for {days_since_last/365:.1f} years",
                            detail=detail, kind="scan")
    return VerifyResult("unverifiable", 0.55, "Maintenance activity is borderline", detail=detail, kind="scan")
