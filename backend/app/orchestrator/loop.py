"""The engine: uncertainty-directed SELECT -> ACT -> OBSERVE -> UPDATE loop."""
import time, uuid
from dataclasses import dataclass
from ..graph.claim_graph import ClaimGraph, Evidence
from .actions import execute, ActionContext, COST_RANK

@dataclass
class Budget:
    max_tokens: int = 40_000
    max_seconds: float = 600.0
    started: float = 0.0
    spent_tokens: int = 0
    def alive(self) -> bool:
        return self.spent_tokens < self.max_tokens and (time.time() - self.started) < self.max_seconds

async def run_audit(graph: ClaimGraph, ctx: ActionContext, budget: Budget | None = None,
                    confidence_threshold: float = 0.75) -> dict:
    budget = budget or Budget()
    budget.started = time.time()
    while budget.alive():
        pending = graph.unresolved()
        if not pending:
            break
        # SELECT: highest impact x uncertainty; cheap methods break ties
        target = max(pending, key=lambda c: (graph.priority(c), -COST_RANK.get(c.method, 5)))
        graph._event("selected", target.id, {"priority": round(graph.priority(target), 3),
                                             "method": target.method})
        target.status = "checking"
        # ACT + OBSERVE
        t0 = time.time()
        result = await execute(target.method, target, ctx)
        seconds = time.time() - t0
        budget.spent_tokens += result.tokens
        # UPDATE
        ev = Evidence(id=f"ev_{uuid.uuid4().hex[:6]}", kind=result.kind,
                      summary=result.summary, detail=result.detail)
        graph.attach_evidence(target.id, ev)
        graph.update(target.id, result.status, result.confidence,
                     tokens=result.tokens, seconds=seconds)
    # anything still open when budget dies is honestly unresolved
    for c in graph.unresolved():
        graph.update(c.id, "unverifiable", c.confidence, note="budget exhausted before verification")
    return graph.dossier()
