"""SWARM real audit CLI.
Usage:
  py scripts/audit.py <repo_url_or_path> --llm ollama|watsonx|mock [--micro TAG] [--small TAG]
"""
import argparse, asyncio, json, pathlib, sys, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))
from app.graph.claim_graph import ClaimGraph
from app.llm.router import Router, MockLLM, OllamaLLM, WatsonxLLM
from app.agents.extractor import extract_claims, inject_baseline
from app.orchestrator.loop import run_audit, Budget
from app.orchestrator.actions import ActionContext
from app.ingest.repo import clone

MOCK = {"extractor": [json.dumps({"claims": [
    {"text": "MIT licensed", "type": "license", "source": "README.md", "method": "license_check", "spdx": "MIT", "edges": []},
    {"text": "Fully tested", "type": "quality", "source": "README.md", "method": "run_tests", "edges": []}]})],
    "critic": [json.dumps({"verdict": "unverifiable", "confidence": 0.4, "reason": "mock"})]}

COLORS = {"verified": "\033[92m", "refuted": "\033[91m", "unverifiable": "\033[93m", "checking": "\033[96m"}

def build_router(args) -> Router:
    if args.llm == "ollama":
        return Router(OllamaLLM(small=args.small, micro=args.micro), rps=10)
    if args.llm == "watsonx":
        primary = WatsonxLLM()
        try:
            return Router(primary, OllamaLLM(small=args.small, micro=args.micro), rps=2)
        except Exception:
            return Router(primary, rps=2)
    return Router(MockLLM(MOCK), rps=100)

async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--llm", default="ollama", choices=["ollama", "watsonx", "mock"])
    ap.add_argument("--micro", default="granite4:micro")
    ap.add_argument("--small", default="granite4:micro")
    args = ap.parse_args()

    t0 = time.time()
    print(f"== SWARM audit: {args.repo}  [llm={args.llm}]")
    repo = clone(args.repo)
    print(f"-- repo at {repo}")
    llm = build_router(args)
    graph = ClaimGraph()

    print("-- extracting claims with Granite...")
    await extract_claims(repo, llm, graph)
    inject_baseline(repo, graph)
    print(f"   {len(graph.claims())} claims (extracted + baseline):")
    for c in graph.claims():
        print(f"     - [{c.type}] {c.text}  -> {c.method}")
    if not graph.claims():
        print("!! extractor returned no claims - check model output / tag")
        return

    dossier = await run_audit(graph, ActionContext(repo, llm), Budget(max_seconds=600))

    print("\n== TRUST DOSSIER")
    for c in dossier["claims"]:
        col = COLORS.get(c["status"], "")
        ev = c["evidence"][0]["summary"] if c["evidence"] else ""
        print(f"{col}{c['status']:>13}\033[0m  {c['text'][:44]:<44} conf={c['confidence']:.2f} [{c['method']}] {ev[:70]}")
    print(f"\nsummary={dossier['summary']}  llm_tokens={llm.total_tokens}  wall={time.time()-t0:.0f}s")
    out = pathlib.Path("dossier.json")
    out.write_text(json.dumps(dossier, indent=2))
    print(f"dossier saved -> {out.resolve()}")

asyncio.run(main())
