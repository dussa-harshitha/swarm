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
        "([ -f requirements.txt ] && /venv/bin/pip install -q -r requirements.txt || true) && "
        "([ -f pyproject.toml ] || [ -f setup.py ] && /venv/bin/pip install -q -e . || true)",
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

def detect_test_ecosystem(repo: Path) -> str:
    """Identify how this repo declares/install deps and tests, so the fallback can
    build a matching environment. Returns 'python', 'node', or 'unknown'."""
    if any((repo / f).exists() for f in ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg")):
        return "python"
    if (repo / "package.json").exists():
        return "node"
    if (repo / "tests").exists() or list(repo.glob("**/test_*.py")):
        return "python"
    return "unknown"

def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

def run_pytest_subprocess(repo: Path, timeout: int = 300) -> VerifyResult:
    """Fallback when Docker is absent: build a throwaway venv, install the repo's
    OWN dependencies into it, then run its tests. Crucially, an import/collection
    error (env we couldn't fully reproduce) yields 'unverifiable', NOT 'refuted' —
    we never claim a repo's tests fail when the truth is we couldn't set up its env."""
    eco = detect_test_ecosystem(repo)
    has_tests = (repo / "tests").exists() or list(repo.glob("test_*.py")) or list(repo.glob("**/test_*.py"))
    if not has_tests:
        return VerifyResult("refuted", 0.85, "Claim implies tests, but no test files exist in the repo", kind="test_log")
    if eco != "python":
        return VerifyResult("unverifiable", 0.5,
                            f"Test runner supports Python; this repo looks like '{eco}' — not run", kind="test_log")

    import tempfile, venv as venvmod
    t0 = time.time()
    tmp = Path(tempfile.mkdtemp(prefix="swarm_venv_"))
    try:
        venvmod.create(tmp, with_pip=True)
        vpy = _venv_python(tmp)
        # install pytest + the repo's own deps (best effort; failures don't fail the audit)
        subprocess.run([str(vpy), "-m", "pip", "install", "-q", "pytest"],
                       capture_output=True, text=True, timeout=timeout)
        if (repo / "requirements.txt").exists():
            subprocess.run([str(vpy), "-m", "pip", "install", "-q", "-r", "requirements.txt"],
                           cwd=repo, capture_output=True, text=True, timeout=timeout)
        if (repo / "pyproject.toml").exists() or (repo / "setup.py").exists():
            subprocess.run([str(vpy), "-m", "pip", "install", "-q", "-e", "."],
                           cwd=repo, capture_output=True, text=True, timeout=timeout)
        # run tests with the venv's python
        cmd = [str(vpy), "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
               "--tb=short"]
        proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True,
                              timeout=timeout, env=_scrubbed_env(repo))
    except subprocess.TimeoutExpired:
        return VerifyResult("unverifiable", 0.5, f"Test suite exceeded {timeout}s timeout", kind="test_log")
    except FileNotFoundError:
        return VerifyResult("unverifiable", 0.5, "Python/pytest not available for sandbox run", kind="test_log")
    finally:
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)

    dur = time.time() - t0
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    tail = out[-1500:]
    label = "(temp-venv fallback — deps installed, best-effort isolation)"

    # INTEGRITY: import/collection errors mean we couldn't reproduce the env — unverifiable, not refuted.
    import re as _re
    collected_error = bool(_re.search(r"ERROR collecting|ModuleNotFoundError|ImportError|"
                                      r"No module named|errors during collection", out))
    passed = _re.search(r"(\d+) passed", out)
    failed = _re.search(r"(\d+) failed", out)

    if proc.returncode == 0:
        return VerifyResult("verified", 0.9, f"Test suite passed {label}", detail=tail, kind="test_log", seconds=dur)
    if collected_error and not failed:
        return VerifyResult("unverifiable", 0.55,
            f"Could not fully reproduce the repo's test environment (import/collection error) {label}",
            detail=tail, kind="test_log", seconds=dur)
    if failed:
        n = failed.group(1); p = passed.group(1) if passed else "?"
        return VerifyResult("refuted", 0.9,
            f"Test suite has failures ({n} failed, {p} passed) {label}", detail=tail, kind="test_log", seconds=dur)
    if proc.returncode == 5:
        return VerifyResult("unverifiable", 0.5, "pytest collected no tests", detail=tail, kind="test_log", seconds=dur)
    return VerifyResult("unverifiable", 0.5, f"Test run inconclusive (exit {proc.returncode}) {label}",
                        detail=tail, kind="test_log", seconds=dur)

def run_tests(repo: Path, timeout: int = 420) -> VerifyResult:
    mode = os.getenv("SWARM_SANDBOX", "auto")
    if mode != "subprocess" and docker_available():
        return run_pytest_docker(repo, timeout)
    return run_pytest_subprocess(repo, min(timeout, 300))
