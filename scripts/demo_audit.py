"""Offline demo: full SWARM audit of the sample repo with MockLLM + real verifiers.
Usage: python3 scripts/demo_audit.py [repo_path]"""
import asyncio, json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "backend"))
from app.graph.claim_graph import ClaimGraph
from app.llm.router import Router, MockLLM
from app.agents.extractor import extract_claims
from app.orchestrator.loop import run_audit, Budget
from app.orchestrator.actions import ActionContext

EXTRACT = json.dumps({"claims": [
    {"text": "MIT licensed", "type": "license", "source": "README.md", "method": "license_check", "spdx": "MIT",
     "edges": [{"to_text": "Production-ready", "rel": "supports"}]},
    {"text": "Fully tested", "type": "quality", "source": "README.md", "method": "run_tests",
     "edges": [{"to_text": "Production-ready", "rel": "supports"}]},
    {"text": "No secrets in code", "type": "security", "source": "README.md", "method": "secret_scan", "edges": []},
    {"text": "No known vulnerabilities", "type": "security", "source": "README.md", "method": "osv_lookup",
     "edges": [{"to_text": "Production-ready", "rel": "supports"}]},
    {"text": "Production-ready", "type": "quality", "source": "README.md", "method": "llm_critique", "edges": []},
]})
CRITIC = json.dumps({"verdict": "unverifiable", "confidence": 0.4,
                     "reason": "Marketing claim; dependent evidence is mixed (license refuted)"})
COLORS = {"verified": "\033[92m", "refuted": "\033[91m", "unverifiable": "\033[93m"}

async def main():
    repo = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/swarm_sample_repo")
    llm = Router(MockLLM({"extractor": [EXTRACT], "critic": [CRITIC]}), rps=100)
    graph = ClaimGraph()
    print(f"== SWARM audit: {repo}\n-- extracting claims (MockLLM standing in for Granite)")
    await extract_claims(repo, llm, graph)
    print(f"   {len(graph.claims())} claims -> graph")
    ctx = ActionContext(repo, llm)  # OSV will hit the real network; may fail in sandboxed envs
    dossier = await run_audit(graph, ctx, Budget(max_seconds=180))
    print("\n== TRUST DOSSIER")
    for c in dossier["claims"]:
        col = COLORS.get(c["status"], "")
        ev = c["evidence"][0]["summary"] if c["evidence"] else ""
        print(f"{col}{c['status']:>13}\033[0m  {c['text']:<28} conf={c['confidence']:.2f}  [{c['method']}]  {ev}")
    print(f"\nsummary={dossier['summary']}  tokens={dossier['total_tokens']}")
    print("\n-- event log (last 8)")
    for e in graph.events[-8:]:
        print("  ", {k: v for k, v in e.items() if k != 't'})

asyncio.run(main())
