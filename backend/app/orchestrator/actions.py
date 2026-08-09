"""Action registry: claim.method -> executable verification, with cost model."""
from pathlib import Path
from ..verify import license as lic, sandbox, secrets, sast, osv, maintenance, semgrep_scan as sgs, license_compat as lcompat
from ..verify.results import VerifyResult, ToolMissing
from ..agents.critic import critique

# lower = cheaper; the loop prefers cheap mechanical checks
COST_RANK = {"license_check": 0, "maintenance_stats": 1, "license_compat": 2, "secret_scan": 3, "sast_scan": 4, "osv_lookup": 5, "run_tests": 6, "llm_critique": 9}

REPO_GLOBAL = {"run_tests", "osv_lookup", "secret_scan", "sast_scan", "maintenance_stats", "license_compat"}

class ActionContext:
    def __init__(self, repo: Path, llm, http_client=None):
        self.repo, self.llm, self.http = repo, llm, http_client
        self.cache: dict[str, VerifyResult] = {}

def _combined_sast(repo):
    """Run bandit (Python) and semgrep (other languages); worst verdict wins,
    evidence merged. A refutation from either tool refutes the claim."""
    from ..verify.results import ToolMissing
    results = []
    b = sast.bandit_scan(repo)
    results.append(("bandit", b))
    try:
        s = sgs.semgrep_scan(repo)
        results.append(("semgrep", s))
    except ToolMissing:
        pass  # semgrep optional; bandit still covers Python
    refuted = [(n, r) for n, r in results if r.status == "refuted"]
    if refuted:
        summ = " | ".join(f"{n}: {r.summary}" for n, r in refuted)
        det = " || ".join(f"{n}: {r.detail}" for n, r in refuted if r.detail)
        conf = max(r.confidence for _, r in refuted)
        return VerifyResult("refuted", conf, summ, detail=det, kind="scan")
    verified = [(n, r) for n, r in results if r.status == "verified"]
    if verified:
        summ = " | ".join(f"{n}: {r.summary}" for n, r in verified)
        return VerifyResult("verified", min(r.confidence for _, r in verified), summ, kind="scan")
    return results[0][1] if results else VerifyResult("unverifiable", 0.5, "no SAST tool ran", kind="scan")

async def execute(method: str, claim, ctx: ActionContext) -> VerifyResult:
    if method in REPO_GLOBAL and method in ctx.cache:
        cached = ctx.cache[method]
        return VerifyResult(cached.status, cached.confidence, cached.summary + " (cached)",
                            cached.detail, cached.kind, 0, 0.0)
    result = await _execute(method, claim, ctx)
    if method in REPO_GLOBAL:
        ctx.cache[method] = result
    return result

async def _execute(method: str, claim, ctx: ActionContext) -> VerifyResult:
    try:
        if method == "license_check":
            spdx = (claim.note or "spdx=MIT").split("=", 1)[1] if "spdx=" in (claim.note or "") else "MIT"
            return lic.verify_license_claim(ctx.repo, spdx)
        if method == "run_tests":
            return sandbox.run_tests(ctx.repo)
        if method == "secret_scan":
            return secrets.scan_secrets(ctx.repo)
        if method == "sast_scan":
            return _combined_sast(ctx.repo)
        if method == "maintenance_stats":
            return maintenance.maintenance_stats(ctx.repo)
        if method == "license_compat":
            spdx = (claim.note or "").split("spdx=", 1)[1].split()[0] if "spdx=" in (claim.note or "") else None
            return lcompat.check_license_compat(ctx.repo, spdx)
        if method == "osv_lookup":
            return await osv.check_vulnerabilities(ctx.repo, ctx.http)
        if method == "llm_critique":
            from ..agents.extractor import gather_docs
            from ..agents.critic import file_tree
            context = file_tree(ctx.repo) + "\n\nPROJECT DOCS (the claim's own source - NOT evidence):\n" + gather_docs(ctx.repo, 4000)
            res = await critique(claim.text, context, ctx.llm)
            import re as _re
            CIRCULAR = _re.compile(
                r"readme[^.]{0,40}(explicitly )?(state|say|claim|mention|describe)|"
                r"(documentation|docs|project docs)[^.]{0,30}(state|say|claim)", _re.I)
            verdict = res["verdict"]
            reason = res.get("reason", "LLM critique")
            if verdict == "verified" and CIRCULAR.search(reason):
                verdict = "unverifiable"
                reason = "circular evidence rejected (claim's own docs cited as proof). " + reason
            LLM_CONF_CAP = 0.7
            conf = min(res["confidence"], LLM_CONF_CAP)
            return VerifyResult(verdict, conf, reason + " [LLM verdict, confidence capped]",
                                kind="llm_critique", tokens=res.get("tokens", 0))
        return VerifyResult("unverifiable", 0.5, f"No action registered for method '{method}'")
    except ToolMissing as e:
        return VerifyResult("unverifiable", 0.5, f"Required tool missing: {e}", kind="scan")
