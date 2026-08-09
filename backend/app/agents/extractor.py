"""Extractor agent: README/docs/manifests -> claims (Granite micro tier).
Design rule: the LLM PROPOSES claims and methods; deterministic rules VALIDATE.
Small models freelance on format and method choice - we normalize both."""
import re
from pathlib import Path
from ..llm.json_repair import repair_json
from ..graph.claim_graph import ClaimGraph, VALID_TYPES

SYSTEM = """You extract verifiable claims a software project makes about itself.
Respond ONLY with JSON of this exact shape:
{"claims":[{"text":str,"type":"security|functional|license|quality|provenance",
"source":str,"method":str,"spdx":str|null,"edges":[{"to_text":str,"rel":"supports|contradicts"}]}]}
Allowed method values: run_tests, osv_lookup, secret_scan, sast_scan, license_check, maintenance_stats, llm_critique.
Extract at most 12 claims. Do not invent claims that are not stated or strongly implied."""

VALID_METHODS = {"run_tests", "osv_lookup", "secret_scan", "sast_scan",
                 "license_check", "maintenance_stats", "llm_critique"}

# Deterministic method rules: (regex on claim text) -> method. First match wins.
METHOD_RULES = [
    (r"\btest(ed|s|ing)?\b|\bcoverage\b", "run_tests"),
    (r"vulnerab|\bcve\b|security advisor|no known (security )?issues", "osv_lookup"),
    (r"\bsecret|credential|api key|password", "secret_scan"),
    (r"\blicen[cs]e|\bmit\b|\bapache\b|\bgpl\b|\bbsd\b", "license_check"),
    (r"maintain|actively developed|active development|regular(ly)? updat", "maintenance_stats"),
    (r"secure cod|best practice|hardened", "sast_scan"),
]

SPDX_HINT = re.compile(r"\b(MIT|Apache-2\.0|Apache 2\.0|GPL-3\.0|GPLv3|BSD-3-Clause)\b", re.I)
SPDX_NORM = {"apache 2.0": "Apache-2.0", "gplv3": "GPL-3.0"}

# A mechanical method may only be used when the claim is actually ABOUT that thing.
# Prevents nonsense verdicts like "easy to learn: REFUTED because tests failed".
METHOD_FIT = {
    "run_tests": r"\btest(ed|s|ing)?\b|\bcoverage\b",
    "osv_lookup": r"vulnerab|\bcve\b|advisor|security issue",
    "secret_scan": r"secret|credential|api key|password",
    "license_check": r"licen[cs]e|\bmit\b|\bapache\b|\bgpl\b|\bbsd\b",
    "maintenance_stats": r"maintain|actively|active development|updat",
    "sast_scan": r"secure|security|best practice|hardened|safe",
}

def resolve_method(text: str, proposed: str | None) -> str:
    for pat, method in METHOD_RULES:
        if re.search(pat, text, re.I):
            return method
    if proposed in VALID_METHODS:
        if proposed == "llm_critique":
            return proposed
        fit = METHOD_FIT.get(proposed)
        if fit and re.search(fit, text, re.I):
            return proposed
        return "llm_critique"   # proposed method doesn't fit the claim semantics
    return "llm_critique"

def _normalize(obj) -> list[dict]:
    """Accept {'claims':[...]}, a bare list, or a single claim dict."""
    if isinstance(obj, dict):
        items = obj.get("claims", obj.get("Claims", []))
        if isinstance(items, dict):
            items = [items]
    elif isinstance(obj, list):
        items = obj
    else:
        items = []
    JUNK = __import__("re").compile(
        r"^(installation|documentation|source code|requirements|usage|features|getting started|license)\b[:\s]*$|"
        r"^(documentation|source code|homepage)\s*:\s*\S+$", __import__("re").I)
    def is_junk(text: str) -> bool:
        t = text.strip()
        if len(t) < 8:
            return True
        if JUNK.match(t):
            return True
        words = [w for w in t.split() if not w.startswith("http")]
        return len(words) < 1   # only pure-URL lines
    out = []
    for it in items:
        if isinstance(it, dict) and it.get("text") and not is_junk(str(it["text"])):
            out.append(it)
    return out[:8]

def gather_docs(repo: Path, max_chars: int = 12000) -> str:
    parts = []
    for name in ("README.md", "README.rst", "README.txt", "package.json", "requirements.txt", "pyproject.toml"):
        p = repo / name
        if p.exists():
            parts.append(f"## FILE: {name}\n" + p.read_text(errors="ignore")[:4000])
    return "\n".join(parts)[:max_chars]

async def extract_claims(repo: Path, llm, graph: ClaimGraph) -> None:
    docs = gather_docs(repo)
    tokens = 0
    obj = None
    for attempt, suffix in enumerate((
            "",
            "\n\nIMPORTANT: Your previous output was not JSON. Respond with ONLY a JSON object. "
            "The very first character of your reply must be {")):
        try:
            raw, t = await llm.chat("extractor", SYSTEM, docs + suffix, tier="micro")
            tokens += t
        except Exception as e:
            graph._event("extractor_error", "-", {"note": f"LLM call failed: {type(e).__name__}: {str(e)[:250]}"})
            return
        try:
            obj = repair_json(raw)
            break
        except Exception:
            graph._event("extractor_error", "-",
                         {"note": f"unparseable LLM output (attempt {attempt + 1})", "raw": (raw or "")[:200]})
            obj = None
    if obj is None:
        return
    items = _normalize(obj)
    per_claim = tokens // max(1, len(items))
    by_text = {}
    for c in items:
        ctype = c.get("type") if c.get("type") in VALID_TYPES else "quality"
        method = resolve_method(c["text"], c.get("method"))
        claim = graph.add_claim(c["text"], ctype, c.get("source", "README"), method)
        claim.cost_tokens += per_claim
        spdx = c.get("spdx")
        if not spdx and method == "license_check":
            m = SPDX_HINT.search(c["text"])
            if m:
                spdx = SPDX_NORM.get(m.group(1).lower(), m.group(1))
        if spdx:
            claim.note = f"spdx={spdx}"
        by_text[c["text"]] = claim
    for c in items:
        src = by_text.get(c.get("text"))
        if not src:
            continue
        for e in (c.get("edges") or []):
            if not isinstance(e, dict):
                continue
            dst = by_text.get(e.get("to_text"))
            if dst and e.get("rel") in ("supports", "contradicts") and dst.id != src.id:
                graph.add_edge(src.id, dst.id, e["rel"])


# ---------------- Baseline claims ----------------
# A trust audit always runs its mechanical checks - a silent README doesn't
# get to opt out of scrutiny. Injected AFTER extraction; any method the README
# already produced a claim for is skipped (no duplicates).
BASELINE = [
    ("No known-vulnerable dependencies", "security", "osv_lookup"),
    ("No secrets committed to the repository", "security", "secret_scan"),
    ("No medium/high-severity static-analysis findings", "security", "sast_scan"),
    ("Repository is actively maintained", "provenance", "maintenance_stats"),
]

def inject_baseline(repo: Path, graph: ClaimGraph) -> None:
    existing_methods = {c.method for c in graph.claims()}
    for text, ctype, method in BASELINE:
        if method in existing_methods:
            continue
        c = graph.add_claim(text, ctype, "baseline-audit", method)
        c.note = (c.note + " " if c.note else "") + "[baseline]"
    # test-suite baseline only when the repo actually has tests
    if "run_tests" not in existing_methods:
        has_tests = (repo / "tests").exists() or list(repo.glob("**/test_*.py"))
        if has_tests:
            c = graph.add_claim("Test suite passes", "quality", "baseline-audit", "run_tests")
            c.note = "[baseline]"
