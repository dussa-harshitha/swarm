from app.graph.claim_graph import ClaimGraph

def make_graph():
    g = ClaimGraph()
    a = g.add_claim("No known CVEs", "security", "README", "osv_lookup", cid="a")
    b = g.add_claim("Production-ready", "quality", "README", "llm_critique", cid="b")
    g.add_edge("a", "b", "contradicts")  # refuting a undermines b? see propagate semantics
    return g

def test_priority_prefers_uncertain_high_impact():
    g = ClaimGraph()
    sec = g.add_claim("no secrets", "security", "README", "secret_scan")
    prov = g.add_claim("by ACME corp", "provenance", "README", "llm_critique")
    assert g.priority(sec) > g.priority(prov)

def test_update_and_propagation():
    g = make_graph()
    g.update("a", "refuted", 0.94)
    b = g.claim("b")
    # a refuted -> signal=-0.94, contradicts edge -> delta=-0.25*(-0.94)>0 ... 
    assert b.status == "unverified"
    assert 0.0 < b.confidence < 1.0

def test_supports_propagation_direction():
    g = ClaimGraph()
    g.add_claim("tests pass", "quality", "README", "run_tests", cid="t")
    g.add_claim("well engineered", "quality", "README", "llm_critique", cid="w", )
    g.add_edge("t", "w", "supports")
    before = g.claim("w").confidence
    g.update("t", "verified", 0.9)
    assert g.claim("w").confidence > before
    g2 = ClaimGraph()
    g2.add_claim("tests pass", "quality", "README", "run_tests", cid="t")
    g2.add_claim("well engineered", "quality", "README", "llm_critique", cid="w")
    g2.add_edge("t", "w", "supports")
    before2 = g2.claim("w").confidence
    g2.update("t", "refuted", 0.9)
    assert g2.claim("w").confidence < before2

def test_settled_nodes_not_overridden():
    g = make_graph()
    g.update("b", "verified", 0.9)
    g.update("a", "refuted", 0.95)
    assert g.claim("b").confidence == 0.9

def test_roundtrip_json():
    g = make_graph()
    g.update("a", "refuted", 0.94)
    g2 = ClaimGraph.from_json(g.to_json())
    assert g2.claim("a").status == "refuted"
    assert g2.g.has_edge("a", "b")
