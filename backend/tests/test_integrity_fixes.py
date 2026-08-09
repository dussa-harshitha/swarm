"""Regression tests for the final-review integrity fixes:
1. Non-Python repos with tests are never falsely refuted (ecosystem detection).
2. osv_fixes child verdict matches its claim and uses real FIX data.
3. sast_locality classifies actual finding paths, not blob substrings.
4. test_failure_scope parses real summary counts; unparseable -> no verdict.
5. license_check without a determinable SPDX -> unverifiable (no MIT default).
6. Synthesis nodes are verified findings, ratio excludes SWARM's own nodes.
7. Strict sandbox mode refuses host execution when Docker is unavailable.
"""
import json
import pytest
from pathlib import Path

from app.verify.sandbox import detect_test_ecosystem, run_tests
from app.verify.osv import _first_fixed_version
from app.orchestrator.investigate import (
    resolve_osv_fixes, resolve_sast_locality, resolve_test_scope)
from app.orchestrator.loop import _synthesize
from app.orchestrator.actions import execute, ActionContext
from app.graph.claim_graph import ClaimGraph


# ---------- 1. ecosystem detection: no false refutation of JS/Go repos ----------

def _mk(tmp_path, files: dict) -> Path:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path

def test_js_repo_with_tests_is_unverifiable_not_refuted(tmp_path):
    repo = _mk(tmp_path, {"package.json": json.dumps(
        {"name": "x", "scripts": {"test": "jest"}})})
    assert detect_test_ecosystem(repo) == "js"
    r = run_tests(repo)
    assert r.status == "unverifiable"          # the old code refuted this — cardinal sin
    assert "JS" in r.summary or "not yet supported" in r.summary

def test_npm_placeholder_test_script_is_not_a_test_suite(tmp_path):
    repo = _mk(tmp_path, {"package.json": json.dumps(
        {"scripts": {"test": "echo \"Error: no test specified\" && exit 1"}})})
    assert detect_test_ecosystem(repo) == "none"

def test_go_repo_is_unverifiable_not_refuted(tmp_path):
    repo = _mk(tmp_path, {"go.mod": "module example.com/x\n"})
    r = run_tests(repo)
    assert r.status == "unverifiable"

def test_truly_testless_repo_is_still_refuted(tmp_path):
    repo = _mk(tmp_path, {"README.md": "# hi"})
    r = run_tests(repo)
    assert r.status == "refuted"

def test_python_tests_detected(tmp_path):
    repo = _mk(tmp_path, {"tests/test_a.py": "def test_ok():\n    assert True\n"})
    assert detect_test_ecosystem(repo) == "python"


# ---------- 7. strict sandbox mode ----------

def test_strict_docker_mode_refuses_host_fallback(tmp_path, monkeypatch):
    repo = _mk(tmp_path, {"tests/test_a.py": "def test_ok():\n    assert True\n"})
    monkeypatch.setenv("SWARM_SANDBOX", "docker")
    monkeypatch.setattr("app.verify.sandbox.docker_available", lambda: False)
    r = run_tests(repo)
    assert r.status == "unverifiable"
    assert "refusing host execution" in r.summary


# ---------- 2. osv_fixes: verdict matches claim, real data required ----------

def test_osv_fixes_verified_when_fix_data_present():
    detail = ("requests==2.19.0: PYSEC-2018-28; flask==0.12: GHSA-xxxx\n"
              "FIX: requests -> 2.20.0 (PYSEC-2018-28)\n"
              "FIX: flask -> 0.12.3 (GHSA-xxxx)")
    r = resolve_osv_fixes(detail)
    assert r.status == "verified"              # claim: "fixed versions ARE available"
    assert "2.20.0" in r.detail and "0.12.3" in r.detail

def test_osv_fixes_unverifiable_without_fix_data():
    r = resolve_osv_fixes("requests==2.19.0: PYSEC-2018-28; flask==0.12: CVE-2019-1010083")
    assert r.status == "unverifiable"          # never assert what wasn't checked

def test_osv_fixes_unverifiable_on_empty_evidence():
    assert resolve_osv_fixes("").status == "unverifiable"

def test_first_fixed_version_parses_osv_schema():
    vuln = {"affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}
    assert _first_fixed_version(vuln, "requests") == "2.20.0"
    assert _first_fixed_version(vuln, "flask") is None


# ---------- 3. sast_locality: path classification, not substring theater ----------

def test_locality_core_findings_stay_refuted_despite_test_word_in_blob():
    # Old bug: the word 'test' ANYWHERE flipped the verdict to verified.
    detail = "bandit: B307@settings.py:12; B602@server.py:40 || semgrep: eval@latest_util.js:9"
    r = resolve_sast_locality(detail)
    assert r.status == "refuted"
    assert "settings.py" in r.detail

def test_locality_verified_only_when_all_findings_in_test_code():
    detail = "bandit: B307@test_helpers.py:3; B105@conftest.py:1"
    r = resolve_sast_locality(detail)
    assert r.status == "verified"

def test_locality_mixed_findings_refuted_with_counts():
    detail = "bandit: B307@test_helpers.py:3; B602@server.py:40"
    r = resolve_sast_locality(detail)
    assert r.status == "refuted"
    assert "1 of 2" in r.summary

def test_locality_no_paths_no_verdict():
    assert resolve_sast_locality("something without locations").status == "unverifiable"


# ---------- 4. test_failure_scope: real counts ----------

def test_scope_isolated():
    r = resolve_test_scope("....\n1 failed, 41 passed in 2.11s")
    assert r.status == "verified"

def test_scope_systemic():
    r = resolve_test_scope("9 failed, 2 passed in 3.02s")
    assert r.status == "refuted"

def test_scope_collection_error_refuted():
    r = resolve_test_scope("2 errors in 0.30s")
    assert r.status == "refuted"

def test_scope_unparseable_gives_no_verdict():
    assert resolve_test_scope("garbage output").status == "unverifiable"


# ---------- 5. license_check: no silent MIT default ----------

@pytest.mark.asyncio
async def test_license_check_without_spdx_is_unverifiable(tmp_path):
    (tmp_path / "LICENSE").write_text("MIT License\n\nPermission is hereby granted...")
    g = ClaimGraph()
    c = g.add_claim("This project is properly licensed", "license", "README", "license_check")
    ctx = ActionContext(tmp_path, llm=None, graph=g)
    r = await execute("license_check", c, ctx)
    assert r.status == "unverifiable"
    assert "never assuming a default" in r.summary


# ---------- 6. synthesis semantics + honest trust ratio ----------

def _resolved(g, text, ctype, source, status):
    c = g.add_claim(text, ctype, source, "llm_critique")
    c.status = status
    c.confidence = 0.9
    return c

def test_synthesis_nodes_are_verified_findings():
    g = ClaimGraph()
    _resolved(g, "no vulns", "security", "baseline-audit", "refuted")
    _resolved(g, "no secrets", "security", "baseline-audit", "refuted")
    _synthesize(g)
    synth = [c for c in g.claims() if c.source == "synthesis"]
    assert synth, "systemic security finding should have been emitted"
    assert all(c.status == "verified" for c in synth)   # a finding that HOLDS is true
    assert all("severity=" in c.note for c in synth)

def test_trust_ratio_excludes_swarm_generated_nodes():
    g = ClaimGraph()
    # Repo's own claims: 2 of 4 refuted -> exactly at the 50% threshold
    _resolved(g, "a", "quality", "README", "refuted")
    _resolved(g, "b", "quality", "README", "refuted")
    _resolved(g, "c", "quality", "README", "verified")
    _resolved(g, "d", "quality", "baseline-audit", "verified")
    # SWARM's own spawned children: refuted — must NOT tip the ratio
    _resolved(g, "child1", "quality", "investigation:c_x", "refuted")
    _resolved(g, "child2", "quality", "investigation:c_y", "refuted")
    _synthesize(g)
    trust = [c for c in g.claims() if c.source == "synthesis" and "Overall trust" in c.text]
    assert trust and "2 of 4" in trust[0].text          # not "4 of 6"

def test_trust_verdict_absent_when_repo_claims_mostly_hold():
    g = ClaimGraph()
    _resolved(g, "a", "quality", "README", "verified")
    _resolved(g, "b", "quality", "README", "verified")
    _resolved(g, "c", "quality", "README", "refuted")
    # even if SWARM's own children all refuted, no trust indictment
    _resolved(g, "child", "quality", "investigation:c_z", "refuted")
    _synthesize(g)
    trust = [c for c in g.claims() if c.source == "synthesis" and "Overall trust" in c.text]
    assert not trust
