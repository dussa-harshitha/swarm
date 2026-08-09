"""SWARM CI gate — run SWARM as a CI/CD plugin that fails the build on
untrustworthy code.

Exit codes:
  0  = pass (no refuted claims, within tolerance)
  1  = FAIL (a refuted claim exceeded the gate) — blocks the merge
  2  = error (audit could not run)

Usage in CI:
  python scripts/swarm_ci.py .                       # gate on any refuted claim
  python scripts/swarm_ci.py . --fail-on refuted     # (default)
  python scripts/swarm_ci.py . --allow-unverifiable  # unverifiable never fails (default)
  python scripts/swarm_ci.py . --max-refuted 0       # tolerance (default 0)
Writes swarm-dossier.json and prints a PR-style summary."""
import argparse, asyncio, json, pathlib, sys, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))
from app.graph.claim_graph import ClaimGraph
from app.llm.router import Router, MockLLM, OllamaLLM, WatsonxLLM
from app.agents.extractor import extract_claims, inject_baseline
from app.orchestrator.loop import run_audit, Budget
from app.orchestrator.actions import ActionContext
from app.ingest.repo import clone

def build_router(mode, micro, small):
    if mode == "ollama":
        return Router(OllamaLLM(small=small, micro=micro), rps=10)
    if mode == "watsonx":
        try:
            return Router(WatsonxLLM(small=small, micro=micro), OllamaLLM(small=small, micro=micro), rps=2)
        except Exception:
            return Router(WatsonxLLM(small=small, micro=micro), rps=2)
    return Router(MockLLM({}), rps=100)

async def main() -> int:
    ap = argparse.ArgumentParser(description="SWARM CI trust gate")
    ap.add_argument("repo")
    ap.add_argument("--llm", default="ollama", choices=["ollama", "watsonx", "mock"])
    ap.add_argument("--micro", default="granite4:micro")
    ap.add_argument("--small", default="granite4:micro")
    ap.add_argument("--max-refuted", type=int, default=0,
                    help="allowed number of refuted claims before failing (default 0)")
    ap.add_argument("--fail-on", default="refuted", choices=["refuted", "never"])
    args = ap.parse_args()

    t0 = time.time()
    try:
        repo = clone(args.repo)
        llm = build_router(args.llm, args.micro, args.small)
        graph = ClaimGraph()
        await extract_claims(repo, llm, graph)
        inject_baseline(repo, graph)
        dossier = await run_audit(graph, ActionContext(repo, llm, graph=graph), Budget())
    except Exception as e:
        print(f"::error::SWARM audit failed to run: {type(e).__name__}: {e}")
        return 2

    s = dossier["summary"]
    refuted = [c for c in dossier["claims"] if c["status"] == "refuted"]
    pathlib.Path("swarm-dossier.json").write_text(json.dumps(dossier, indent=2))

    # PR-style summary
    print("\n" + "=" * 60)
    print("  SWARM TRUST GATE")
    print("=" * 60)
    print(f"  verified: {s.get('verified',0)}   refuted: {s.get('refuted',0)}   "
          f"unverifiable: {s.get('unverifiable',0)}")
    print(f"  tokens: {dossier['total_tokens']}   time: {time.time()-t0:.0f}s")
    if refuted:
        print("\n  REFUTED CLAIMS (trust violations):")
        for c in refuted:
            ev = c["evidence"][0]["summary"] if c["evidence"] else ""
            print(f"    ✗ {c['text'][:60]}")
            print(f"      → {ev[:90]}")
    print("=" * 60)

    n_ref = len(refuted)
    if args.fail_on == "refuted" and n_ref > args.max_refuted:
        print(f"\n::error::SWARM gate FAILED — {n_ref} refuted claim(s) "
              f"exceed the allowed maximum of {args.max_refuted}. Merge blocked.")
        return 1
    print(f"\nSWARM gate PASSED — {n_ref} refuted claim(s), within tolerance ({args.max_refuted}).")
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
