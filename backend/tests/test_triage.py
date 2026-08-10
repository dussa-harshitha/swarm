from app.verify.triage import is_noncore, classify_findings

def test_noncore_paths():
    assert is_noncore("tests/test_x.py")
    assert is_noncore("examples/demo.py")
    assert is_noncore("app/fixtures/data.py")
    assert is_noncore("docs/conf.py")
    assert not is_noncore("app/config.py")
    assert not is_noncore("src/core/auth.py")

def test_classify_splits():
    fs = [{"File": "tests/a.py"}, {"File": "app/config.py"}, {"File": "examples/b.py"}]
    c = classify_findings(fs, lambda x: x["File"])
    assert c["core_n"] == 1 and c["noncore_n"] == 2

def test_all_noncore_secrets_downgrade(tmp_path, monkeypatch):
    import app.verify.secrets as sec
    from unittest.mock import MagicMock, patch
    import json
    findings = [{"RuleID": "aws", "File": "tests/conftest.py", "StartLine": 3},
                {"RuleID": "aws", "File": "examples/demo.py", "StartLine": 9}]
    m = MagicMock(); m.returncode = 7; m.stderr = ""
    with patch("app.verify.secrets.subprocess.run", return_value=m), \
         patch("app.verify.secrets.shutil.which", return_value="/usr/bin/gitleaks"), \
         patch("pathlib.Path.read_text", return_value=json.dumps(findings)):
        r = sec.scan_secrets(tmp_path)
    assert r.status == "unverifiable" and "fixtures" in r.summary
