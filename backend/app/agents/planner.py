"""Planner agent: given the current claim-graph state, decides the investigation
strategy for the next batch — which claims matter most and in what order.

This is a real LLM agent (Granite, small tier), distinct from the mechanical
argmax fallback. It reasons about the WHOLE graph at once (what's resolved,
what's still open, where the risk concentrates) rather than scoring one claim
at a time. If the LLM is unavailable or returns garbage, the loop falls back to
the deterministic priority() ordering — the planner improves ordering, it is
never a single point of failure."""
from ..llm.json_repair import repair_json

SYSTEM = """You are the planning agent for a software trust audit. You are given
the current state of a claim graph: each claim has an id, text, type, status, and
confidence. Decide which UNRESOLVED claims to investigate next and in what order.

Prioritize by: (1) security and license risk over cosmetic claims, (2) claims whose
outcome would most change the overall trust verdict, (3) claims that are cheap to
resolve decisively before expensive/ambiguous ones.

Respond ONLY with JSON:
{"strategy": "<one sentence on your focus this round>",
 "order": ["<claim id>", "<claim id>", ...]}
Include only ids of currently-unresolved claims. Put the most important first."""

async def plan(graph, llm) -> dict:
    """Return {'strategy': str, 'order': [claim_id,...]} or {} on failure."""
    unresolved = graph.unresolved()
    if not unresolved:
        return {}
    state = []
    for c in graph.claims():
        state.append(f"- id={c.id} [{c.type}/{c.status} conf={c.confidence:.2f}] {c.text[:70]}")
    prompt = "CLAIM GRAPH STATE:\n" + "\n".join(state) + \
             f"\n\nUnresolved ids to order: {[c.id for c in unresolved]}"
    try:
        raw, tokens = await llm.chat("planner", SYSTEM, prompt, tier="small")
    except Exception as e:
        graph._event("planner_error", "-", {"note": f"planner LLM failed: {type(e).__name__}"})
        return {}
    try:
        obj = repair_json(raw)
    except Exception:
        graph._event("planner_error", "-", {"note": "planner output unparseable"})
        return {}
    valid_ids = {c.id for c in unresolved}
    order = [cid for cid in (obj.get("order") or []) if cid in valid_ids]
    strategy = str(obj.get("strategy", ""))[:200]
    obj_out = {"strategy": strategy, "order": order, "tokens": tokens}
    if strategy:
        graph._event("planned", "-", {"strategy": strategy, "n": len(order)})
    return obj_out
