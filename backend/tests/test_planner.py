import json, pytest
from app.graph.claim_graph import ClaimGraph
from app.llm.router import Router, MockLLM
from app.agents.planner import plan

@pytest.mark.asyncio
async def test_planner_orders_by_returned_ids():
    g = ClaimGraph()
    a = g.add_claim("secure code", "security", "README", "sast_scan", cid="a")
    b = g.add_claim("nice docs", "quality", "README", "llm_critique", cid="b")
    resp = json.dumps({"strategy": "security first", "order": ["a", "b"]})
    llm = Router(MockLLM({"planner": [resp]}), rps=100)
    out = await plan(g, llm)
    assert out["order"] == ["a", "b"]
    assert "security" in out["strategy"]

@pytest.mark.asyncio
async def test_planner_filters_invalid_ids():
    g = ClaimGraph()
    g.add_claim("x", "security", "README", "sast_scan", cid="real")
    resp = json.dumps({"strategy": "s", "order": ["ghost", "real"]})
    llm = Router(MockLLM({"planner": [resp]}), rps=100)
    out = await plan(g, llm)
    assert out["order"] == ["real"]   # hallucinated id dropped

@pytest.mark.asyncio
async def test_planner_survives_garbage():
    g = ClaimGraph()
    g.add_claim("x", "security", "README", "sast_scan", cid="a")
    llm = Router(MockLLM({"planner": ["not json"]}), rps=100)
    out = await plan(g, llm)
    assert out == {}   # loop will fall back to priority()
