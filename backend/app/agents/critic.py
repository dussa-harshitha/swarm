"""Critic agent: adversarial review of claims no mechanical tool can settle."""
from ..llm.json_repair import repair_json

SYSTEM = """You are a skeptical software auditor. Given a claim and repo context, decide:
{"verdict":"verified|refuted|unverifiable","confidence":0.0-1.0,"reason":str}
Prefer "unverifiable" over guessing. Respond ONLY with JSON."""

async def critique(claim_text: str, context: str, llm) -> dict:
    raw, tokens = await llm.chat("critic", SYSTEM, f"CLAIM: {claim_text}\nCONTEXT:\n{context[:6000]}", tier="small")
    obj = repair_json(raw)
    obj["tokens"] = tokens
    if obj.get("verdict") not in ("verified", "refuted", "unverifiable"):
        obj["verdict"] = "unverifiable"
    obj["confidence"] = max(0.0, min(1.0, float(obj.get("confidence", 0.5))))
    return obj
