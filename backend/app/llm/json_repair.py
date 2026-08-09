"""Self-healing JSON: tolerate fences, prefixes, trailing commas."""
import json, re

def repair_json(raw: str):
    if raw is None:
        raise ValueError("empty LLM response")
    s = raw.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    start = min([i for i in (s.find("{"), s.find("[")) if i >= 0], default=-1)
    if start > 0:
        s = s[start:]
    for end in range(len(s), max(len(s) - 2000, 0), -1):
        try:
            return json.loads(s[:end])
        except Exception:
            continue
    s2 = re.sub(r",\s*([}\]])", r"\1", s)
    return json.loads(s2)
