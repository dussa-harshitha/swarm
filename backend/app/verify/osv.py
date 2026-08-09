"""Live CVE lookup per dependency via OSV.dev querybatch API."""
import json, re
from pathlib import Path
import httpx
from .results import VerifyResult

OSV_URL = "https://api.osv.dev/v1/querybatch"

def parse_python_deps(repo: Path) -> list[dict]:
    req = repo / "requirements.txt"
    deps = []
    if req.exists():
        for line in req.read_text(errors="ignore").splitlines():
            line = line.split("#")[0].strip()
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
            if m:
                deps.append({"package": {"name": m.group(1), "ecosystem": "PyPI"}, "version": m.group(2)})
    return deps

def parse_npm_deps(repo: Path) -> list[dict]:
    pkg = repo / "package.json"
    deps = []
    if pkg.exists():
        try:
            obj = json.loads(pkg.read_text(errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                for name, ver in (obj.get(section) or {}).items():
                    clean = re.sub(r"^[^0-9]*", "", str(ver))
                    if clean:
                        deps.append({"package": {"name": name, "ecosystem": "npm"}, "version": clean})
        except Exception:
            pass
    return deps

async def check_vulnerabilities(repo: Path, client: httpx.AsyncClient | None = None) -> VerifyResult:
    deps = parse_python_deps(repo) + parse_npm_deps(repo)
    if not deps:
        return VerifyResult("unverifiable", 0.5, "No pinned dependencies found to check", kind="cve")
    own = client is None
    client = client or httpx.AsyncClient(timeout=20)
    try:
        resp = await client.post(OSV_URL, json={"queries": deps})
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except (httpx.HTTPError, httpx.HTTPStatusError) as e:
        return VerifyResult("unverifiable", 0.5,
                            f"OSV API unreachable from this environment ({type(e).__name__}); "
                            f"{len(deps)} deps parsed, re-run with network access", kind="cve")
    finally:
        if own:
            await client.aclose()
    vulns = []
    for dep, res in zip(deps, results):
        for v in (res.get("vulns") or []):
            vulns.append(f"{dep['package']['name']}=={dep['version']}: {v.get('id')}")
    if not vulns:
        return VerifyResult("verified", 0.92, f"OSV: 0 known vulnerabilities across {len(deps)} pinned deps", kind="cve")
    return VerifyResult("refuted", 0.95, f"OSV: {len(vulns)} known vulnerability match(es)",
                        detail="; ".join(vulns[:8]), kind="cve")
