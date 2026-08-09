# Final-review integrity patch — 2026-08-09
Extract this zip over C:\Users\asus\Downloads\swarm_build\swarm (it only touches the 7 files below + adds 1 test file). Then: `py -m pytest backend/tests -q` — expect 64 passed, 2 skipped (build the fixture first if needed: `py scripts/make_fixture.py`).

## Changed
1. **verify/sandbox.py** — `detect_test_ecosystem()`: JS/Go/Rust/Java repos with tests now return honest "unverifiable — execution not yet supported" instead of FALSE REFUTED ("no test files"). Only a repo with no recognizable test surface in ANY ecosystem gets refuted. Removed `-x` from pytest (it made blast-radius analysis structurally blind). Added strict mode: `SWARM_SANDBOX=docker` refuses host execution when Docker is down instead of silently falling back. **SET THIS FOR THE DEMO.**
2. **verify/osv.py** — after querybatch, fetches `/v1/vulns/{id}` for the top 5 advisories and embeds real `FIX: pkg -> version (ID)` lines in the evidence. Best-effort; failure never degrades the primary verdict.
3. **orchestrator/investigate.py** — `resolve_osv_fixes` now VERIFIES the "fixed versions available" claim from the real FIX data (verdict finally matches the claim text), unverifiable when fix data is absent. `resolve_test_scope` parses actual summary counts ("N failed, M passed"); unparseable → no verdict. `resolve_sast_locality` classifies each finding's file path (parsed from `RULE@file:line`) instead of substring-matching "test" against the whole blob.
4. **orchestrator/actions.py** — license_check with no determinable SPDX → unverifiable. No more silent assumed-MIT default.
5. **orchestrator/loop.py** — synthesis nodes are `verified` (a finding that HOLDS is true), severity in note (`severity=high`). Trust ratio + systemic counts computed over extracted+baseline claims ONLY — SWARM's own spawned nodes no longer inflate the "X of Y refuted" indictment.
6. **main.py** — explicit `audit_complete` SSE event emitted in job()'s finally; the stream terminates on it (no more inferring completion from graph state, no hang on early errors). Optional `SWARM_LOCAL_ROOT=C:\tmp` confines local-path audits under that root — set it for the demo so nobody types C:\Users\asus into the projector.
7. **agents/extractor.py** — prompt cap aligned to 8 (normalize truncated to 8 anyway). Compound-claim safety net: if docs declare an SPDX + a LICENSE file exists but no license_check claim was extracted (e.g. "MIT-licensed and well tested" routed to run_tests), a baseline license_check is injected.

## New
- **backend/tests/test_integrity_fixes.py** — 24 regression tests covering all of the above.

## Demo env (set both)
    $env:SWARM_SANDBOX = "docker"
    $env:SWARM_LOCAL_ROOT = "C:\tmp"

## Dashboard note (for the pending frontend work)
Synthesis nodes now arrive as status=verified with `severity=high` in `note`. When layering the investigation tree, color synthesis nodes by SEVERITY (red/amber), not by verdict color — otherwise "Systemic security risk" renders green.

## Expected PayLite delta
Node count shifts slightly (osv_fixes child is now VERIFIED with real fixed versions — a better demo beat: "and it tells you the exact upgrade that remediates"). Headline becomes "N of M extracted/baseline claims refuted" with honest denominators. Re-run once and update the deck numbers.
