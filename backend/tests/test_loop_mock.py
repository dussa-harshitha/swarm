"""End-to-end engine test: mocked LLM, real mechanical verifiers, sample repo."""
import json, pathlib, pytest, httpx
from app.graph.claim_graph import ClaimGraph
from app.llm.router import Router, MockLLM
from app.agents.extractor import extract_claims
from app.orchestrator.loop import run_audit, Budget
from app.orchestrator.actions import ActionContext

REPO = pathlib.Path("/tmp/swarm_sample_repo")

EXTRACT = json.dumps({"claims": [
    {"text": "MIT licensed", "type": "license", "source": "README.md", "method": "license_check", "spdx": "MIT",
     "edges": [{"to_text": "Production-ready", "rel": "supports"}]},
    {"text": "Fully tested", "type": "quality", "source": "README.md", "method": "run_tests",
     "edges": [{"to_text": "Production-ready", "rel": "supports"}]},
    {"text": "No known vulnerabilities", "type": "security", "source": "README.md", "method": "osv_lookup",
     "edges": [{"to_text": "Production-ready", "rel": "supports"}]},
    {"text": "Production-ready", "type": "quality", "source": "README.md", "method": "llm_critique", "edges": []},
]})
CRITIC = json.dumps({"verdict": "unverifiable", "confidence": 0.4,
                     "reason": "No mechanical basis; dependent claims mixed"})

@pytest.mark.asyncio
async def test_full_audit_mock():
    llm = Router(MockLLM({"extractor": [EXTRACT], "critic": [CRITIC]}), rps=100)
    graph = ClaimGraph()
    await extract_claims(REPO, llm, graph)
    assert len(graph.claims()) == 4

    async def osv_handler(request):
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "CVE-2018-18074"}]}]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(osv_handler)) as client:
        ctx = ActionContext(REPO, llm, http_client=client)
        dossier = await run_audit(graph, ctx, Budget(max_seconds=120))

    by_text = {c["text"]: c for c in dossier["claims"]}
    assert by_text["MIT licensed"]["status"] == "refuted"          # LICENSE is Apache
    assert by_text["Fully tested"]["status"] == "verified"          # pytest actually ran
    assert by_text["No known vulnerabilities"]["status"] == "refuted"  # mocked CVE hit
    assert by_text["Production-ready"]["status"] == "unverifiable"
    assert all(c["evidence"] for c in dossier["claims"])
    # original claims refuted: MIT + No-known-vulnerabilities (synthesis may add more)
    orig_refuted = [c for c in dossier["claims"]
                    if c["status"] == "refuted" and "[synthesis]" not in (c.get("note") or "")]
    assert len(orig_refuted) >= 2

