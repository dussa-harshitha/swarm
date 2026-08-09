"""Critic agent: adversarial review of claims no mechanical tool can settle.
Anti-circularity rule: the claim was extracted FROM the project's own docs —
the docs restating it is NOT evidence. LLM verdicts are confidence-capped
below mechanical proof (see actions.py)."""
from ..llm.json_repair import repair_json

SYSTEM = """You are a skeptical software auditor reviewing a claim a project makes about itself.
CRITICAL RULES:
1. The claim was extracted from the project's own README/docs. The README saying it again is NOT evidence. Never verify a claim because "the README states it" — that is circular.
2. Only answer "verified" if the FILE TREE or MANIFESTS show independent technical evidence (e.g. a console-script entry proves a CLI command exists; a tests/ directory with many files supports "tested").
3. Subjective or marketing claims (easy to use, great, loved, best, intuitive, fast) are "unverifiable" — they have no mechanical truth condition.
4. Prefer "unverifiable" over guessing. Refute only with concrete contradicting evidence.
Respond ONLY with JSON: {"verdict":"verified|refuted|unverifiable","confidence":0.0-1.0,"reason":str}
Your reason must name the independent evidence, or say why none exists."""

import re as _re

def _fallback_parse(raw: str) -> dict:
    """Last-resort handling when JSON repair fails.
    RULE: malformed output NEVER produces a positive (or negative) verdict —
    if we could not parse the critic, we do not know what it concluded.
    (Regexing for the word "verified" is a trap: "cannot be verified" contains it.)"""
    return {"verdict": "unverifiable", "confidence": 0.5,
            "reason": "critic output was malformed; no verdict granted. Raw: " + (raw or "")[:160]}

async def critique(claim_text: str, context: str, llm) -> dict:
    try:
        raw, tokens = await llm.chat("critic", SYSTEM,
                                     f"CLAIM: {claim_text}\n\n{context[:7000]}", tier="small")
    except Exception as e:
        return {"verdict": "unverifiable", "confidence": 0.5,
                "reason": f"critic LLM call failed: {e}", "tokens": 0}
    try:
        obj = repair_json(raw)
        if not isinstance(obj, dict):
            obj = _fallback_parse(raw)
    except Exception:
        obj = _fallback_parse(raw)
    obj["tokens"] = tokens
    if obj.get("verdict") not in ("verified", "refuted", "unverifiable"):
        obj["verdict"] = "unverifiable"
    try:
        obj["confidence"] = max(0.0, min(1.0, float(obj.get("confidence", 0.5))))
    except Exception:
        obj["confidence"] = 0.5
    return obj

def file_tree(repo, max_entries: int = 120) -> str:
    """Two-level file listing: the critic's independent evidence source."""
    lines = []
    for p in sorted(repo.rglob("*")):
        rel = p.relative_to(repo)
        if len(rel.parts) > 2 or any(part.startswith(".") or part == "__pycache__" for part in rel.parts):
            continue
        lines.append(str(rel) + ("/" if p.is_dir() else ""))
        if len(lines) >= max_entries:
            lines.append("...")
            break
    return "FILE TREE:\n" + "\n".join(lines)