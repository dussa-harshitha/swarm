"""SWARM orchestration server: start audits, stream events, fetch dossiers.
NOTE: fresh-built minimal server. The spec assumed porting the team's prior
FastAPI infra (JWT etc.) — that codebase was not provided; see BUILD_STATUS.md."""
import asyncio, os, uuid, json
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from .graph.claim_graph import ClaimGraph
from .graph.store import GraphStore
from .orchestrator.loop import run_audit, Budget
from .orchestrator.actions import ActionContext
from .agents.extractor import extract_claims, inject_baseline
from .ingest.repo import clone
from .llm.router import Router, MockLLM, OllamaLLM, WatsonxLLM, LLMError

app = FastAPI(title="SWARM")
RUNS: dict[str, ClaimGraph] = {}
store = GraphStore(os.getenv("SWARM_DB", "swarm.db"))

def build_llm():
    mode = os.getenv("SWARM_LLM", "mock")
    if mode == "watsonx":
        primary = WatsonxLLM()
        try:
            return Router(primary, OllamaLLM())
        except Exception:
            return Router(primary)
    if mode == "ollama":
        return Router(OllamaLLM())
    # mock default: refuses roles it has no script for — honest, not fake
    return Router(MockLLM(script=json.loads(os.getenv("SWARM_MOCK_SCRIPT", "{}"))))

class AuditRequest(BaseModel):
    repo: str

@app.post("/audit")
async def start_audit(req: AuditRequest):
    # Demo safety: with SWARM_LOCAL_ROOT set (e.g. C:\tmp), local-path audits are
    # confined under that root — nobody types C:\Users\you into the projector and
    # gets gitleaks run over your home directory. URLs are unaffected.
    local_root = os.getenv("SWARM_LOCAL_ROOT")
    if local_root:
        p = Path(req.repo)
        if p.exists():
            try:
                p.resolve().relative_to(Path(local_root).resolve())
            except ValueError:
                raise HTTPException(400, f"Local-path audits are restricted to {local_root} on this instance")
    run_id = uuid.uuid4().hex[:8]
    graph = ClaimGraph()
    RUNS[run_id] = graph
    async def job():
        try:
            repo = clone(req.repo)
            llm = build_llm()
            ctx = ActionContext(repo, llm, graph=graph)
            await extract_claims(repo, llm, graph)
            inject_baseline(repo, graph)
            await run_audit(graph, ctx, Budget())
            await store.save(run_id, req.repo, graph)
        except Exception as e:
            graph._event("job_error", "-", {"note": f"{type(e).__name__}: {str(e)[:300]}"})
        finally:
            # Explicit completion signal — SSE termination must not be inferred
            # from graph state (racy, and hangs forever on early errors).
            graph._event("audit_complete", "-", {})
    asyncio.create_task(job())
    return {"run_id": run_id}

@app.get("/runs/{run_id}/events")
async def events(run_id: str):
    if run_id not in RUNS:
        raise HTTPException(404)
    async def gen():
        seen = 0
        done = False
        graph = RUNS[run_id]
        while not done:
            while seen < len(graph.events):
                ev = graph.events[seen]
                yield f"data: {json.dumps(ev)}\n\n"
                seen += 1
                if ev.get("kind") == "audit_complete":
                    done = True
            if done:
                yield "data: {\"kind\": \"done\"}\n\n"
                break
            await asyncio.sleep(0.4)
    return StreamingResponse(gen(), media_type="text/event-stream")

@app.get("/runs/{run_id}/dossier")
async def dossier(run_id: str):
    if run_id not in RUNS:
        raise HTTPException(404)
    return RUNS[run_id].dossier()

@app.get("/")
async def index():
    return HTMLResponse((Path(__file__).parent / "static_index.html").read_text(encoding="utf-8"))
