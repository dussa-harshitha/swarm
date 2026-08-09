"""Clone / open target repositories."""
import subprocess, tempfile
from pathlib import Path

def clone(url_or_path: str) -> Path:
    p = Path(url_or_path)
    if p.exists():
        return p.resolve()
    dest = Path(tempfile.mkdtemp(prefix="swarm_repo_"))
    subprocess.run(["git", "clone", "--depth", "200", url_or_path, str(dest)],
                   check=True, capture_output=True, timeout=180)
    return dest