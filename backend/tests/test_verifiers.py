import pathlib, pytest
from app.verify.license import verify_license_claim, detect_license
from app.verify.sandbox import run_tests
from app.verify.secrets import scan_secrets, gitleaks_available
from app.verify.osv import parse_requirements, check_vulnerabilities
import httpx

REPO = pathlib.Path("/tmp/swarm_sample_repo")

def test_license_refutes_mismatch():
    r = verify_license_claim(REPO, "MIT")
    assert r.status == "refuted" and "Apache" in r.summary

def test_license_detects_apache():
    assert detect_license(REPO) == "Apache-2.0"

def test_sandbox_runs_real_tests():
    r = run_tests(REPO)
    assert r.status == "verified", r.summary

@pytest.mark.skipif(not gitleaks_available(), reason="gitleaks not installed")
def test_secret_scan_clean_repo():
    r = scan_secrets(REPO)
    assert r.status == "verified"

def test_osv_parses_pinned_deps():
    deps = parse_requirements(REPO)
    assert deps == [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"}]

@pytest.mark.asyncio
async def test_osv_refutes_with_mocked_api():
    async def handler(request):
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-x-demo"}]}]})
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        r = await check_vulnerabilities(REPO, client)
    assert r.status == "refuted" and "GHSA-x-demo" in r.detail
