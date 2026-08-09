"""Extractor agent: README/docs/manifests -> claims (Granite micro tier)."""
from pathlib import Path
from ..llm.json_repair import repair_json
from ..graph.claim_graph import ClaimGraph, VALID_TYPES

SYSTEM = """You extract verifiable claims a software project makes about itself.
Respond ONLY with JSON: {"claims":[{"text":str,"type":"security|functional|license|quality|provenance",
"source":str,"method":str,"spdx":str|null,"edges":[{"to_text":str,"rel":"supports|contradicts"}]}]}
Allowed method values: run_tests, osv_lookup, secret_scan, sast_scan, license_check, maintenance_stats, llm_critique.
Extract at most 12 claims. Do not invent claims that are not stated or strongly implied."""

def gather_docs(repo: Path, max_chars: int = 12000) -> str:
    parts = []
    for name in ("README.md", "README.rst", "README.txt", "package.json", "requirements.txt", "pyproject.toml"):
        p = repo / name
        if p.exists():
            parts.append(f"--- {name} ---\n" + p.read_text(errors="ignore")[:4000])
    return "\n".join(parts)[:max_chars]

async def extract_claims(repo: Path, llm, graph: ClaimGraph) -> None:
    docs = gather_docs(repo)
    raw, tokens = await llm.chat("extractor", SYSTEM, docs, tier="micro")
    obj = repair_json(raw)
    by_text = {}
    for c in obj.get("claims", []):
        if c.get("type") not in VALID_TYPES:
            continue
        claim = graph.add_claim(c["text"], c["type"], c.get("source", "README"), c.get("method", "llm_critique"))
        claim.cost_tokens += tokens // max(1, len(obj.get("claims", [])))
        if c.get("spdx"):
            claim.note = f"spdx={c['spdx']}"
        by_text[c["text"]] = claim
    for c in obj.get("claims", []):
        src = by_text.get(c["text"])
        if not src:
            continue
        for e in c.get("edges", []) or []:
            dst = by_text.get(e.get("to_text"))
            if dst and e.get("rel") in ("supports", "contradicts"):
                graph.add_edge(src.id, dst.id, e["rel"])
