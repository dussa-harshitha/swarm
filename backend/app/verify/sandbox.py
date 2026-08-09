"""Run a repo's test suite in an isolated subprocess (cross-platform).
Docker variant preferred on team machines; subprocess fallback is used where
Docker is unavailable. Network isolation in subprocess mode is BEST-EFFORT
(env scrubbing); true network-off requires Docker."""
import os, sys, subprocess, time
from pathlib import Path
from .results import VerifyResult

def docker_available() -> bool:
    from shutil import which
    return which("docker") is not None

def _scrubbed_env(repo: Path) -> dict:
    env = {"PYTHONDONTWRITEBYTECODE": "1", "HOME": str(repo)}
    if os.name == "nt":  # Windows needs its real PATH/SystemRoot to run anything
        for k in ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "USERPROFILE",
                  "PATHEXT", "COMSPEC", "LOCALAPPDATA", "APPDATA"):
            if k in os.environ:
                env[k] = os.environ[k]
    else:
        env["PATH"] = "/usr/bin:/usr/local/bin"
    return env

def run_pytest_subprocess(repo: Path, timeout: int = 120) -> VerifyResult:
    has_tests = (repo / "tests").exists() or list(repo.glob("test_*.py")) or list(repo.glob("**/test_*.py"))
    if not has_tests:
        return VerifyResult("refuted", 0.85, "Claim implies tests, but no test files exist in the repo", kind="test_log")
    t0 = time.time()
    cmd = [sys.executable, "-m", "pytest", "-q", "--no-header", "-x", "-p", "no:cacheprovider"]
    try:
        proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True,
                              timeout=timeout, env=_scrubbed_env(repo))
    except subprocess.TimeoutExpired:
        return VerifyResult("unverifiable", 0.5, f"Test suite exceeded {timeout}s timeout", kind="test_log")
    except FileNotFoundError:
        return VerifyResult("unverifiable", 0.5, "Python/pytest not available for sandbox run", kind="test_log")
    dur = time.time() - t0
    tail = (proc.stdout or "")[-1500:]
    if proc.returncode == 0:
        return VerifyResult("verified", 0.9, "Test suite passed", detail=tail, kind="test_log", seconds=dur)
    if proc.returncode == 1:
        return VerifyResult("refuted", 0.9, "Test suite has failures", detail=tail, kind="test_log", seconds=dur)
    return VerifyResult("unverifiable", 0.5, f"Test run errored (exit {proc.returncode})", detail=tail, kind="test_log", seconds=dur)

def run_tests(repo: Path, timeout: int = 120) -> VerifyResult:
    # Docker runner lands next; subprocess is the tested default everywhere.
    return run_pytest_subprocess(repo, timeout)
