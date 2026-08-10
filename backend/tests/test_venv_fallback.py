"""Temp-venv test fallback: installs the repo's own deps, and — critically —
never refutes a 'tests pass' claim just because WE couldn't build the env."""
import pathlib, pytest
from unittest.mock import patch, MagicMock
from app.verify.sandbox import detect_test_ecosystem, run_pytest_subprocess

def test_detect_ecosystem(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")
    assert detect_test_ecosystem(tmp_path) == "python"
    p2 = tmp_path / "node"; p2.mkdir(); (p2 / "package.json").write_text("{}")
    assert detect_test_ecosystem(p2) == "node"

def test_no_tests_refutes(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")
    r = run_pytest_subprocess(tmp_path)
    assert r.status == "refuted" and "no test files" in r.summary

def _proc(stdout="", stderr="", rc=1):
    m = MagicMock(); m.stdout, m.stderr, m.returncode = stdout, stderr, rc
    return m

def test_import_error_is_unverifiable_not_refuted(tmp_path):
    """The integrity rule: a missing-dependency import error must NOT refute the claim."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("import nonexistent_pkg\ndef test_a(): pass")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'")
    import_err = "ERROR collecting tests/test_x.py\nModuleNotFoundError: No module named 'nonexistent_pkg'\nerrors during collection"
    with patch("app.verify.sandbox.subprocess.run", return_value=_proc(stdout=import_err, rc=2)), \
         patch("venv.create"):
        r = run_pytest_subprocess(tmp_path)
    assert r.status == "unverifiable"      # NOT refuted — we couldn't reproduce the env
    assert "environment" in r.summary.lower() or "import" in r.summary.lower()

def test_real_failure_still_refutes(tmp_path):
    """A genuine test failure (not an env issue) must still refute."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_a(): assert False")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'")
    fail_out = "F\n1 failed, 0 passed in 0.01s"
    with patch("app.verify.sandbox.subprocess.run", return_value=_proc(stdout=fail_out, rc=1)), \
         patch("venv.create"):
        r = run_pytest_subprocess(tmp_path)
    assert r.status == "refuted" and "failed" in r.summary
