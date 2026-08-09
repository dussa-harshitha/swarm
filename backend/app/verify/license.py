"""Verify license claims: parse LICENSE files vs claimed license."""
import re
from pathlib import Path
from .results import VerifyResult

PATTERNS = {
    "MIT": r"MIT License|Permission is hereby granted, free of charge",
    "Apache-2.0": r"Apache License\s*,?\s*Version 2\.0",
    "GPL-3.0": r"GNU GENERAL PUBLIC LICENSE\s+Version 3",
    "BSD-3-Clause": r"Redistribution and use in source and binary forms",
}

def detect_license(repo: Path) -> str | None:
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"):
        p = repo / name
        if p.exists():
            text = p.read_text(errors="ignore")[:4000]
            for spdx, pat in PATTERNS.items():
                if re.search(pat, text, re.I):
                    return spdx
            return "UNKNOWN"
    return None

def verify_license_claim(repo: Path, claimed_spdx: str) -> VerifyResult:
    found = detect_license(repo)
    if found is None:
        return VerifyResult("refuted", 0.9, f"Claimed {claimed_spdx} but no LICENSE file exists", kind="file_match")
    if found == "UNKNOWN":
        return VerifyResult("unverifiable", 0.5, "LICENSE file present but not a recognized SPDX license", kind="file_match")
    if found.lower() == claimed_spdx.lower():
        return VerifyResult("verified", 0.95, f"LICENSE file matches claim: {found}", kind="file_match")
    return VerifyResult("refuted", 0.92, f"Claimed {claimed_spdx} but LICENSE is {found}", kind="file_match")
