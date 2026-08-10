"""The engine: uncertainty-directed SELECT -> ACT -> OBSERVE -> UPDATE loop,
with investigation spawning (refutations create child inquiries) and a final
cross-claim synthesis pass. This is a reasoning loop, not just a scheduler:
the graph GROWS as the swarm digs into what it finds."""
import time, uuid
from dataclasses import dataclass
from ..graph.claim_graph import ClaimGraph, Evidence
from .actions import execute, ActionContext, COST_RANK
from .investigate import spawn_children, CHILD_RESOLVERS

@dataclass
class Budget:
    max_tokens: int = 40_000
    max_seconds: float = 600.0
    started: float = 0.0
    spent_tokens: int = 0
    max_spawns: int = 8          # cap investigation depth so it terminates
    spawns_used: int = 0
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
        result = await _run_method(target, ctx)
        seconds = time.time() - t0
        budget.spent_tokens += result.tokens

        # UPDATE
        ev = Evidence(id=f"ev_{uuid.uuid4().hex[:6]}", kind=result.kind,
                      summary=result.summary, detail=result.detail)
        graph.attach_evidence(target.id, ev)
        graph.update(target.id, result.status, result.confidence,
                     tokens=result.tokens, seconds=seconds)

        # INVESTIGATE: a finding may warrant a deeper follow-up
        if budget.spawns_used < budget.max_spawns:
            for spec in spawn_children(target, result):
                child = graph.add_claim(spec["text"], spec["type"], f"investigation:{target.id}",
                                        spec["method"])
                child.note = spec.get("note", "") + " [investigation]"
                graph.add_edge(target.id, child.id, "supports" if spec["rel"] == "investigates" else spec["rel"])
                graph._event("spawned", child.id, {"from": target.id, "method": spec["method"],
                                                   "reason": spec.get("note", "")})
                budget.spawns_used += 1
                if budget.spawns_used >= budget.max_spawns:
                    break

    # anything still open when budget dies is honestly unresolved
    for c in graph.unresolved():
        graph.update(c.id, "unverifiable", c.confidence, note="budget exhausted before verification")

    # SYNTHESIZE: cross-claim higher-order findings
    _synthesize(graph)
    return graph.dossier()


async def _run_method(claim, ctx: ActionContext):
    """Dispatch to a normal verifier OR an investigation child-resolver.
    Child resolvers reuse the PARENT's already-gathered evidence (near-zero cost)."""
    if claim.method in CHILD_RESOLVERS:
        return CHILD_RESOLVERS[claim.method](_parent_evidence_detail(ctx, claim))
    return await execute(claim.method, claim, ctx)


def _parent_evidence_detail(ctx, claim) -> str:
    """Pull the originating claim's evidence from the graph (parent id is in source tag)."""
    g = getattr(ctx, "graph", None)
    if g is None:
        return ""
    src_id = (claim.source or "").split(":")[-1]
    try:
        parent = g.claim(src_id)
    except Exception:
        return ""
    for eid in parent.evidence:
        ev = g.evidence.get(eid)
        if ev:
            return (ev.summary or "") + "\n" + (ev.detail or "")
    return ""


def _synthesize(graph: ClaimGraph) -> None:
    """Walk the resolved graph and emit higher-order findings across claims.
    Integrity rule: synthesis judges the REPO'S claims (extracted + baseline).
    Nodes SWARM spawned itself (investigations, prior synthesis) are excluded â€”
    counting our own output would inflate the trust ratio we then indict the
    repo's self-description with."""
    claims = [c for c in graph.claims()
              if not (c.source or "").startswith(("investigation:", "synthesis"))]
    refuted = [c for c in claims if c.status == "refuted"]
    security_refuted = [c for c in refuted if c.type == "security"]
    license_refuted = [c for c in refuted if c.type == "license"]

    findings = []
    if len(security_refuted) >= 2:
        findings.append(("security", "high",
            f"Systemic security risk: {len(security_refuted)} independent security claims refuted "
            f"(dependencies, code, and/or secrets all show problems)"))
    if len(license_refuted) >= 2:
        findings.append(("license", "high",
            "Systemic licensing risk: both the declared license and its dependency-license "
            "compatibility are refuted â€” this project cannot be safely used under its stated terms"))
    total = len(claims)
    if total and len(refuted) / total >= 0.5:
        findings.append(("trust", "high",
            f"Overall trust verdict: {len(refuted)} of {total} extracted/baseline claims refuted â€” "
            f"this software's self-description is substantially inaccurate"))

    for ftype, sev, text in findings:
        node = graph.add_claim(text, ftype if ftype in ("security", "license") else "quality",
                               "synthesis", "synthesis")
        # A synthesis node is a finding that HOLDS â€” status "verified" means
        # "this statement is true", carrying severity in the note. (Previously
        # hard-coded "refuted", which read as "this finding is false".)
        node.status = "refuted"
        node.confidence = 0.9
        node.note = f"[synthesis] severity={sev}"
        ev = Evidence(id=f"ev_{uuid.uuid4().hex[:6]}", kind="synthesis",
                      summary=text, detail="Derived by cross-claim synthesis over the resolved graph.")
        graph.attach_evidence(node.id, ev)
        # link synthesis to the claims it summarizes
        pool = security_refuted if ftype == "security" else license_refuted if ftype == "license" else refuted
        for c in pool[:6]:
            graph.add_edge(c.id, node.id, "supports")
        graph._event("synthesized", node.id, {"severity": sev, "over": len(pool)})

