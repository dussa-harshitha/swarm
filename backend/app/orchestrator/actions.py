"""Action registry: claim.method -> executable verification, with cost model."""
from pathlib import Path
from ..verify import license as lic, sandbox, secrets, sast, osv, maintenance
from ..verify.results import VerifyResult, ToolMissing
from ..agents.critic import critique

# lower = cheaper; the loop prefers cheap mechanical checks
COST_RANK = {"license_check": 0, "maintenance_stats": 1, "secret_scan": 2, "sast_scan": 3, "osv_lookup": 4, "run_tests": 5, "llm_critique": 9}

class ActionContext:
    def __init__(self, repo: Path, llm, http_client=None):
        self.repo, self.llm, self.http = repo, llm, http_client

async def execute(method: str, claim, ctx: ActionContext) -> VerifyResult:
    try:
        if method == "license_check":
            spdx = (claim.note or "spdx=MIT").split("=", 1)[1] if "spdx=" in (claim.note or "") else "MIT"
            return lic.verify_license_claim(ctx.repo, spdx)
        if method == "run_tests":
            return sandbox.run_tests(ctx.repo)
        if method == "secret_scan":
            return secrets.scan_secrets(ctx.repo)
        if method == "sast_scan":
            return sast.bandit_scan(ctx.repo)
        if method == "maintenance_stats":
            return maintenance.maintenance_stats(ctx.repo)
        if method == "osv_lookup":
            return await osv.check_vulnerabilities(ctx.repo, ctx.http)
        if method == "llm_critique":
            from ..agents.extractor import gather_docs
            res = await critique(claim.text, gather_docs(ctx.repo), ctx.llm)
            return VerifyResult(res["verdict"], res["confidence"], res.get("reason", "LLM critique"),
                                kind="llm_critique", tokens=res.get("tokens", 0))
        return VerifyResult("unverifiable", 0.5, f"No action registered for method '{method}'")
    except ToolMissing as e:
        return VerifyResult("unverifiable", 0.5, f"Required tool missing: {e}", kind="scan")
