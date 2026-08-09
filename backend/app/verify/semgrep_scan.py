"""Multi-language static analysis via semgrep (JS/TS/Go/Java/Ruby/PHP/C/... ).
Complements bandit (Python-only). Same integrity rule: a scan that cannot be
proven to have run yields 'unverifiable', never a clean verdict."""
import json, shutil, subprocess
from pathlib import Path
from .results import VerifyResult, ToolMissing

SCANNABLE = {".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php",
             ".c", ".cpp", ".cs", ".scala", ".kt"}

def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None

def has_scannable_code(repo: Path) -> bool:
    for p in repo.rglob("*"):
        if p.suffix.lower() in SCANNABLE and "node_modules" not in p.parts and ".git" not in p.parts:
            return True
    return False

def semgrep_scan(repo: Path) -> VerifyResult:
    if not semgrep_available():
        raise ToolMissing("semgrep not installed (pip install semgrep)")
    if not has_scannable_code(repo):
        return VerifyResult("unverifiable", 0.5,
                            "No non-Python source files for semgrep to scan (bandit covers Python)", kind="scan")
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", "--timeout", "60",
             "--exclude", "node_modules", "--exclude", "tests", str(repo)],
            capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return VerifyResult("unverifiable", 0.5, "semgrep scan timed out", kind="scan")
    if not (proc.stdout or "").strip():
        return VerifyResult("unverifiable", 0.5,
                            f"semgrep produced no output (exit {proc.returncode}); scan not proven to have run",
                            detail=(proc.stderr or "")[:300], kind="scan")
    try:
        obj = json.loads(proc.stdout)
    except Exception:
        return VerifyResult("unverifiable", 0.5, "semgrep produced unparseable output", kind="scan")
    findings = obj.get("results", [])
    if "results" not in obj:
        return VerifyResult("unverifiable", 0.5, "semgrep output missing results section", kind="scan")
    sev = lambda f: f.get("extra", {}).get("severity", "INFO").upper()
    high = [f for f in findings if sev(f) in ("ERROR", "WARNING")]
    if not findings:
        return VerifyResult("verified", 0.85, "semgrep: no findings across scanned languages", kind="scan")
    if not high:
        return VerifyResult("verified", 0.7, f"semgrep: only low-severity findings ({len(findings)})", kind="scan")
    top = "; ".join(f"{f.get('check_id','rule').split('.')[-1]}@{Path(f.get('path','')).name}:{f.get('start',{}).get('line','?')}" for f in high[:5])
    return VerifyResult("refuted", 0.8, f"semgrep: {len(high)} high/medium finding(s) across languages",
                        detail=top, kind="scan")
