"""Run a repo's test suite in isolation (cross-platform).
Preferred: Docker two-phase sandbox — deps installed WITH network into a scratch
volume, then tests executed with --network none, read-only repo mount, mem/cpu caps.
Fallback: resource-scrubbed subprocess (best-effort isolation only, honestly labeled).
"""
import os, sys, subprocess, time, uuid
from pathlib import Path
from shutil import which
from .results import VerifyResult

IMAGE = "python:3.11-slim"

def docker_available() -> bool:
    if which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False

# ---------------- Docker path (true network-off during test execution) ----------------
def run_pytest_docker(repo: Path, timeout: int = 420) -> VerifyResult:
    repo = repo.resolve()
    vol = f"swarm_venv_{uuid.uuid4().hex[:8]}"
    setup_cmd = [
        "docker", "run", "--rm",
        "-v", f"{vol}:/venv", "-v", f"{repo}:/repo:ro", "-w", "/repo", IMAGE, "sh", "-c",
        "python -m venv /venv && /venv/bin/pip install -q pytest && "
        "([ -f requirements.txt ] && /venv/bin/pip install -q -r requirements.txt || true)",
    ]
    test_cmd = [
        "docker", "run", "--rm", "--network", "none", "--memory", "512m", "--cpus", "1",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{vol}:/venv", "-v", f"{repo}:/repo:ro", "-w", "/repo", IMAGE,
        "/venv/bin/python", "-m", "pytest", "-q", "--no-header", "-x", "-p", "no:cacheprovider",
    ]
    t0 = time.time()
    try:
        setup = subprocess.run(setup_cmd, capture_output=True, text=True, timeout=timeout)
        if setup.returncode != 0:
            return VerifyResult("unverifiable", 0.5,
                                "Sandbox setup failed (dependency install)", detail=(setup.stderr or "")[-800:],
                                kind="test_log")
        proc = subprocess.run(test_cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return VerifyResult("unverifiable", 0.5, f"Sandboxed test run exceeded {timeout}s", kind="test_log")
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True)
    dur = time.time() - t0
    tail = (proc.stdout or "")[-1500:]
    label = "(docker sandbox, network off)"
    if proc.returncode == 0:
        return VerifyResult("verified", 0.92, f"Test suite passed {label}", detail=tail, kind="test_log", seconds=dur)
    if proc.returncode == 1:
        return VerifyResult("refuted", 0.92, f"Test suite has failures {label}", detail=tail, kind="test_log", seconds=dur)
    if proc.returncode == 5:
        return VerifyResult("refuted", 0.8, "Claim implies tests, but pytest collected none", detail=tail, kind="test_log", seconds=dur)
    return VerifyResult("unverifiable", 0.5, f"Sandboxed run errored (exit {proc.returncode})", detail=tail, kind="test_log", seconds=dur)

# ---------------- Subprocess fallback (best-effort isolation) ----------------
def _scrubbed_env(repo: Path) -> dict:
    env = {"PYTHONDONTWRITEBYTECODE": "1", "HOME": str(repo)}
    if os.name == "nt":
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
    label = "(subprocess fallback — best-effort isolation)"
    if proc.returncode == 0:
        return VerifyResult("verified", 0.9, f"Test suite passed {label}", detail=tail, kind="test_log", seconds=dur)
    if proc.returncode == 1:
        return VerifyResult("refuted", 0.9, f"Test suite has failures {label}", detail=tail, kind="test_log", seconds=dur)
    return VerifyResult("unverifiable", 0.5, f"Test run errored (exit {proc.returncode})", detail=tail, kind="test_log", seconds=dur)

def run_tests(repo: Path, timeout: int = 420) -> VerifyResult:
    mode = os.getenv("SWARM_SANDBOX", "auto")
    if mode != "subprocess" and docker_available():
        return run_pytest_docker(repo, timeout)
    return run_pytest_subprocess(repo, min(timeout, 120))
