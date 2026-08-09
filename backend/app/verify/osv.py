"""Live CVE lookup via OSV.dev, resolving the FULL dependency tree where a
lockfile is present (transitive deps), falling back to direct manifests.
Ecosystems: PyPI (requirements.txt, poetry.lock, Pipfile.lock) and npm
(package.json, package-lock.json)."""
import json, re
from pathlib import Path
import httpx
from .results import VerifyResult

OSV_URL = "https://api.osv.dev/v1/querybatch"

def parse_requirements(repo: Path) -> list[dict]:
    deps, req = [], repo / "requirements.txt"
    if req.exists():
        for line in req.read_text(errors="ignore").splitlines():
            line = line.split("#")[0].strip()
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
            if m:
                deps.append({"package": {"name": m.group(1), "ecosystem": "PyPI"}, "version": m.group(2)})
    return deps

def parse_poetry_lock(repo: Path) -> list[dict]:
    """Full transitive tree from poetry.lock (TOML, parsed without a TOML lib)."""
    deps, lock = [], repo / "poetry.lock"
    if not lock.exists():
        return deps
    name = ver = None
    for line in lock.read_text(errors="ignore").splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = ver = None
        elif s.startswith("name = "):
            name = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("version = "):
            ver = s.split("=", 1)[1].strip().strip('"')
            if name and ver:
                deps.append({"package": {"name": name, "ecosystem": "PyPI"}, "version": ver})
                name = ver = None
    return deps

def parse_pipfile_lock(repo: Path) -> list[dict]:
    deps, lock = [], repo / "Pipfile.lock"
    if lock.exists():
        try:
            obj = json.loads(lock.read_text(errors="ignore"))
            for section in ("default", "develop"):
                for pkg, meta in (obj.get(section) or {}).items():
                    v = str(meta.get("version", "")).lstrip("=")
                    if v:
                        deps.append({"package": {"name": pkg, "ecosystem": "PyPI"}, "version": v})
        except Exception:
            pass
    return deps

def parse_package_lock(repo: Path) -> list[dict]:
    """Full transitive tree from package-lock.json (npm)."""
    deps, lock = [], repo / "package-lock.json"
    if not lock.exists():
        return deps
    try:
        obj = json.loads(lock.read_text(errors="ignore"))
    except Exception:
        return deps
    for path, meta in (obj.get("packages") or {}).items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            deps.append({"package": {"name": name, "ecosystem": "npm"}, "version": ver})
    if not deps:
        def walk(d):
            for name, meta in (d or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    deps.append({"package": {"name": name, "ecosystem": "npm"}, "version": meta["version"]})
                    walk(meta.get("dependencies"))
        walk(obj.get("dependencies"))
    return deps

def parse_package_json(repo: Path) -> list[dict]:
    deps, pkg = [], repo / "package.json"
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

def resolve_dependencies(repo: Path) -> tuple[list[dict], str]:
    """Prefer lockfiles (transitive); fall back to direct manifests. Returns (deps, scope_label)."""
    for parser in (parse_poetry_lock, parse_pipfile_lock):
        d = parser(repo)
        if d:
            py = d
            break
    else:
        py = parse_requirements(repo)
    npm_lock = parse_package_lock(repo)
    npm = npm_lock if npm_lock else parse_package_json(repo)

    deps = _dedupe(py + npm)
    labels = []
    if py:
        labels.append("poetry.lock (transitive)" if (repo / "poetry.lock").exists()
                      else "Pipfile.lock (transitive)" if (repo / "Pipfile.lock").exists()
                      else "requirements.txt (direct)")
    if npm:
        labels.append("package-lock.json (transitive)" if npm_lock else "package.json (direct)")
    return deps, " + ".join(labels) if labels else "no manifest"

def _dedupe(deps: list[dict]) -> list[dict]:
    seen, out = set(), []
    for d in deps:
        key = (d["package"]["ecosystem"], d["package"]["name"], d["version"])
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out

async def check_vulnerabilities(repo: Path, client: httpx.AsyncClient | None = None) -> VerifyResult:
    deps, scope = resolve_dependencies(repo)
    if not deps:
        return VerifyResult("unverifiable", 0.5, "No dependencies found to check", kind="cve")
    own = client is None
    client = client or httpx.AsyncClient(timeout=30)
    try:
        results = []
        for i in range(0, len(deps), 500):
            resp = await client.post(OSV_URL, json={"queries": deps[i:i + 500]})
            resp.raise_for_status()
            results.extend(resp.json().get("results", []))
    except (httpx.HTTPError, httpx.HTTPStatusError) as e:
        return VerifyResult("unverifiable", 0.5,
                            f"OSV API unreachable ({type(e).__name__}); {len(deps)} deps parsed from {scope}",
                            kind="cve")
    finally:
        if own:
            await client.aclose()
    vulns = []
    for dep, res in zip(deps, results):
        for v in (res.get("vulns") or []):
            vulns.append(f"{dep['package']['name']}=={dep['version']}: {v.get('id')}")
    if not vulns:
        return VerifyResult("verified", 0.92,
                            f"OSV: 0 known vulnerabilities across {len(deps)} deps [{scope}]", kind="cve")
    return VerifyResult("refuted", 0.95,
                        f"OSV: {len(vulns)} known vulnerability match(es) across {len(deps)} deps [{scope}]",
                        detail="; ".join(vulns[:10]), kind="cve")
