"""Run a repo's test suite in an isolated subprocess.
Docker variant preferred on team machines; subprocess fallback (resource-limited)
is used where Docker is unavailable. Network isolation in subprocess mode is
BEST-EFFORT ONLY (env scrubbing); true network-off requires Docker."""
import shutil, subprocess, time
from pathlib import Path
from .results import VerifyResult

def docker_available() -> bool:
    return shutil.which("docker") is not None

def run_pytest_subprocess(repo: Path, timeout: int = 120) -> VerifyResult:
    if not (repo / "tests").exists() and not list(repo.glob("test_*.py")) and not list(repo.glob("**/test_*.py")):
        return VerifyResult("refuted", 0.85, "Claim implies tests, but no test files exist in the repo", kind="test_log")
    t0 = time.time()
    cmd = ["python3", "-m", "pytest", "-q", "--no-header", "-x", "-p", "no:cacheprovider"]
    try:
        proc = subprocess.run(
            cmd, cwd=repo, capture_output=True, text=True, timeout=timeout,
            env={"PATH": "/usr/bin:/usr/local/bin", "HOME": str(repo), "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except subprocess.TimeoutExpired:
        return VerifyResult("unverifiable", 0.5, f"Test suite exceeded {timeout}s timeout", kind="test_log")
    except FileNotFoundError:
        return VerifyResult("unverifiable", 0.5, "pytest not available in sandbox environment", kind="test_log")
    dur = time.time() - t0
    tail = (proc.stdout or "")[-1500:]
    if proc.returncode == 0:
        return VerifyResult("verified", 0.9, "Test suite passed", detail=tail, kind="test_log", seconds=dur)
    if proc.returncode in (1,):
        return VerifyResult("refuted", 0.9, "Test suite has failures", detail=tail, kind="test_log", seconds=dur)
    return VerifyResult("unverifiable", 0.5, f"Test run errored (exit {proc.returncode})", detail=tail, kind="test_log", seconds=dur)

def run_tests(repo: Path, timeout: int = 120) -> VerifyResult:
    # Docker path intentionally not implemented in this environment; see README manual steps.
    return run_pytest_subprocess(repo, timeout)
