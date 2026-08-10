"""Secret scanning via gitleaks. Hard requirement — no silent regex fallback."""
import json, shutil, subprocess, tempfile
from pathlib import Path
from .results import VerifyResult, ToolMissing
from .triage import classify_findings, is_noncore

def gitleaks_available() -> bool:
    return shutil.which("gitleaks") is not None

def scan_secrets(repo: Path) -> VerifyResult:
    if not gitleaks_available():
        raise ToolMissing("gitleaks binary not installed (https://github.com/gitleaks/gitleaks/releases)")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report = f.name
    proc = subprocess.run(
        ["gitleaks", "detect", "--source", str(repo), "--no-git",
         "--report-format", "json", "--report-path", report, "--exit-code", "7"],
        capture_output=True, text=True, timeout=120)
    findings = []
    try:
        findings = json.loads(Path(report).read_text() or "[]")
    except Exception:
        pass
    if proc.returncode == 0 and not findings:
        return VerifyResult("verified", 0.9, "gitleaks: no secrets detected", kind="scan")
    if findings:
        cls = classify_findings(findings, lambda x: x.get("File", ""))
        top = "; ".join(f"{x.get('RuleID')}@{x.get('File')}:{x.get('StartLine')}" for x in findings[:5])
        # If EVERY hit is in test/example/docs code, it's very likely fixtures — down-weight, don't refute hard.
        if cls["core_n"] == 0 and cls["noncore_n"] > 0:
            return VerifyResult("unverifiable", 0.55,
                f"gitleaks found {len(findings)} potential secret(s), ALL in test/example/docs paths "
                f"(likely fixtures — review advised, not confirmed leaks)", detail=top, kind="scan")
        # Otherwise refute, but say how many are core vs fixture so a human can triage.
        note = f" ({cls['core_n']} in core source, {cls['noncore_n']} in test/example)" if cls["noncore_n"] else ""
        return VerifyResult("refuted", 0.95,
            f"gitleaks found {len(findings)} potential secret(s){note}", detail=top, kind="scan")
    return VerifyResult("unverifiable", 0.5, f"gitleaks errored: {proc.stderr[:300]}", kind="scan")
