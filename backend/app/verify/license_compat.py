"""License COMPATIBILITY: do the project's dependencies carry licenses that
conflict with the project's own declared license?

Classic failure: an MIT-declared project that depends on a GPL-3.0 package -
GPL's copyleft legally forces the combined work to be GPL, so 'MIT licensed'
is misleading. We check dependencies' licenses against the license the project
CLAIMS (from its README), using installed package metadata and/or an explicit
.license-manifest.json.

Honest scope: we check declared metadata, not the full transitive license tree,
and we render no legal judgment - we flag likely conflicts for human review."""
import json, re, subprocess, sys
from pathlib import Path
from .results import VerifyResult
from .license import detect_license

STRONG_COPYLEFT = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "AGPL-1.0"}
WEAK_COPYLEFT = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0"}
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Unlicense", "0BSD"}

def _normalize_license(text: str) -> str | None:
    if not text:
        return None
    t = text.strip()
    patterns = [
        (r"AGPL[- ]?3|affero.*(v\.?\s*)?3", "AGPL-3.0"),
        (r"LGPL[- ]?3|lesser.*(general public|gpl).*(v\.?\s*)?3", "LGPL-3.0"),
        (r"LGPL[- ]?2|lesser.*(general public|gpl).*(v\.?\s*)?2", "LGPL-2.1"),
        (r"GPL[- ]?3|general public license.*(v\.?\s*)?3", "GPL-3.0"),
        (r"GPL[- ]?2|general public license.*(v\.?\s*)?2", "GPL-2.0"),
        (r"Apache[- ]?2|apache software license.*2", "Apache-2.0"),
        (r"BSD[- ]?3|3[- ]clause bsd", "BSD-3-Clause"),
        (r"BSD[- ]?2|2[- ]clause bsd", "BSD-2-Clause"),
        (r"MPL[- ]?2|mozilla public license.*2", "MPL-2.0"),
        (r"\bISC\b", "ISC"), (r"\bMIT\b", "MIT"),
    ]
    for pat, spdx in patterns:
        if re.search(pat, t, re.I):
            return spdx
    return None

def _installed_pkg_licenses() -> dict[str, str]:
    out = {}
    try:
        proc = subprocess.run([sys.executable, "-m", "pip", "list", "--format=json"],
                              capture_output=True, text=True, timeout=30)
        pkgs = json.loads(proc.stdout or "[]")
    except Exception:
        return out
    import importlib.metadata as im
    for p in pkgs:
        name = p.get("name", "")
        try:
            meta = im.metadata(name)
            lic = meta.get("License") or ""
            for cls in meta.get_all("Classifier") or []:
                if cls.startswith("License ::"):
                    lic = cls.split("::")[-1].strip()
                    break
            norm = _normalize_license(lic)
            if norm:
                out[name.lower()] = norm
        except Exception:
            continue
    return out

def _declared_deps(repo: Path) -> list[str]:
    names, req = [], repo / "requirements.txt"
    if req.exists():
        for line in req.read_text(errors="ignore").splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-]+)", line.split("#")[0].strip())
            if m:
                names.append(m.group(1).lower())
    pkg = repo / "package.json"
    if pkg.exists():
        try:
            obj = json.loads(pkg.read_text(errors="ignore"))
            names += [n.lower() for n in (obj.get("dependencies") or {})]
        except Exception:
            pass
    return names

def check_license_compat(repo: Path, declared_spdx: str | None = None) -> VerifyResult:
    # Compare deps against the license the project CLAIMS (passed in from the
    # extracted claim); fall back to the LICENSE file only if nothing was claimed.
    project_license = declared_spdx or detect_license(repo)
    if not project_license or project_license == "UNKNOWN":
        return VerifyResult("unverifiable", 0.5,
                            "Cannot determine project's declared license to compare against", kind="scan")
    dep_names = _declared_deps(repo)
    if not dep_names:
        return VerifyResult("unverifiable", 0.5, "No declared dependencies to check licenses for", kind="scan")
    installed = _installed_pkg_licenses()
    manifest = {}
    mf = repo / ".license-manifest.json"
    if mf.exists():
        try:
            manifest = {k.lower(): v for k, v in json.loads(mf.read_text()).items()}
        except Exception:
            pass
    merged = {**installed, **{k: (_normalize_license(v) or v) for k, v in manifest.items()}}
    checked = {n: merged[n] for n in dep_names if n in merged and merged[n]}
    if not checked:
        return VerifyResult("unverifiable", 0.5,
                            f"Dependency licenses not resolvable in this environment "
                            f"({len(dep_names)} deps declared, 0 with readable metadata)", kind="scan")
    conflicts = []
    proj_permissive = project_license in PERMISSIVE
    for dep, lic in checked.items():
        if proj_permissive and lic in STRONG_COPYLEFT:
            conflicts.append(f"{dep} is {lic} (copyleft) but project claims {project_license}")
    if conflicts:
        return VerifyResult("refuted", 0.85,
                            f"License conflict: {len(conflicts)} copyleft dep(s) under a permissive project license",
                            detail="; ".join(conflicts[:5]), kind="scan")
    return VerifyResult("verified", 0.8,
                        f"No license conflicts among {len(checked)} resolvable deps (project claims: {project_license})",
                        kind="scan")
