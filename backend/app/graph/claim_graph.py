"""Claim Graph — the persistent world model SWARM reasons over."""
from __future__ import annotations
import json, time, uuid
from dataclasses import dataclass, field, asdict
from typing import Optional
import networkx as nx

VALID_STATUS = {"unverified", "checking", "verified", "refuted", "unverifiable"}
VALID_TYPES = {"security", "functional", "license", "quality", "provenance"}
TYPE_IMPACT = {"security": 1.0, "license": 0.8, "quality": 0.7, "functional": 0.6, "provenance": 0.5}

@dataclass
class Evidence:
    id: str
    kind: str            # test_log | cve | scan | file_match | llm_critique
    summary: str
    detail: str = ""
    created_at: float = field(default_factory=time.time)

@dataclass
class Claim:
    id: str
    text: str
    type: str
    source: str
    method: str                      # verification method name (action key)
    status: str = "unverified"
    confidence: float = 0.3
    evidence: list[str] = field(default_factory=list)
    cost_tokens: int = 0
    cost_seconds: float = 0.0
    note: str = ""

class ClaimGraph:
    """NetworkX DiGraph of Claims + Evidence store, persistable to SQLite."""

    def __init__(self) -> None:
        self.g = nx.DiGraph()
        self.evidence: dict[str, Evidence] = {}
        self.events: list[dict] = []          # audit trail for dashboard/SSE

    def add_claim(self, text: str, ctype: str, source: str, method: str,
                  confidence: float = 0.3, cid: Optional[str] = None) -> Claim:
        assert ctype in VALID_TYPES, f"bad type {ctype}"
        c = Claim(id=cid or f"c_{uuid.uuid4().hex[:6]}", text=text, type=ctype,
                  source=source, method=method, confidence=confidence)
        self.g.add_node(c.id, claim=c)
        self._event("claim_added", c.id, {"text": text, "type": ctype, "method": method})
        return c

    def add_edge(self, src: str, dst: str, rel: str) -> None:
        assert rel in {"supports", "contradicts", "derived_from", "cites"}
        self.g.add_edge(src, dst, rel=rel)

    def claim(self, cid: str) -> Claim:
        return self.g.nodes[cid]["claim"]

    def claims(self) -> list[Claim]:
        return [d["claim"] for _, d in self.g.nodes(data=True)]

    def unresolved(self) -> list[Claim]:
        return [c for c in self.claims() if c.status in ("unverified", "checking")]

    def uncertainty(self, c: Claim) -> float:
        return 1.0 - abs(2.0 * c.confidence - 1.0)

    def impact(self, c: Claim) -> float:
        degree = self.g.out_degree(c.id) + self.g.in_degree(c.id)
        return TYPE_IMPACT.get(c.type, 0.5) + 0.1 * degree

    def priority(self, c: Claim) -> float:
        return self.impact(c) * self.uncertainty(c)

    def attach_evidence(self, cid: str, ev: Evidence) -> None:
        self.evidence[ev.id] = ev
        self.claim(cid).evidence.append(ev.id)

    def update(self, cid: str, status: str, confidence: float,
               tokens: int = 0, seconds: float = 0.0, note: str = "") -> None:
        assert status in VALID_STATUS
        c = self.claim(cid)
        c.status = status
        c.confidence = max(0.0, min(1.0, confidence))
        c.cost_tokens += tokens
        c.cost_seconds += seconds
        if note:
            c.note = note
        self._event("claim_updated", cid, {"status": status, "confidence": round(c.confidence, 2)})
        self.propagate(cid)

    def propagate(self, cid: str) -> None:
        """Push the outcome of cid along its edges (one hop, damped)."""
        src = self.claim(cid)
        if src.status not in ("verified", "refuted"):
            return
        signal = src.confidence if src.status == "verified" else -src.confidence
        for _, dst, data in self.g.out_edges(cid, data=True):
            rel = data.get("rel")
            tgt = self.claim(dst)
            if tgt.status in ("verified", "refuted"):
                continue  # settled by direct evidence; do not override
            if rel == "supports":
                delta = 0.15 * signal
            elif rel == "contradicts":
                delta = -0.25 * signal
            else:
                continue
            old = tgt.confidence
            tgt.confidence = max(0.05, min(0.95, tgt.confidence + delta))
            self._event("propagated", dst, {"from": cid, "rel": rel,
                        "old": round(old, 2), "new": round(tgt.confidence, 2)})

    def dossier(self) -> dict:
        counts: dict[str, int] = {}
        for c in self.claims():
            counts[c.status] = counts.get(c.status, 0) + 1
        return {
            "generated_at": time.time(),
            "summary": counts,
            "total_tokens": sum(c.cost_tokens for c in self.claims()),
            "claims": [
                {**asdict(c), "evidence": [asdict(self.evidence[e]) for e in c.evidence if e in self.evidence]}
                for c in sorted(self.claims(), key=lambda c: (c.status != "refuted", -self.impact(c)))
            ],
        }

    def _event(self, kind: str, cid: str, data: dict) -> None:
        self.events.append({"t": time.time(), "kind": kind, "claim": cid, **data})

    def to_json(self) -> str:
        return json.dumps({
            "claims": [asdict(c) for c in self.claims()],
            "edges": [{"src": u, "dst": v, "rel": d["rel"]} for u, v, d in self.g.edges(data=True)],
            "evidence": {k: asdict(v) for k, v in self.evidence.items()},
        })

    @classmethod
    def from_json(cls, raw: str) -> "ClaimGraph":
        obj = json.loads(raw)
        cg = cls()
        for c in obj["claims"]:
            claim = Claim(**c)
            cg.g.add_node(claim.id, claim=claim)
        for e in obj["edges"]:
            cg.g.add_edge(e["src"], e["dst"], rel=e["rel"])
        for k, v in obj.get("evidence", {}).items():
            cg.evidence[k] = Evidence(**v)
        return cg
