# SWARM — Build Status

## ✅ Built and proven working (12/12 tests pass, offline demo runs)

| Module | Status | Proof |
|---|---|---|
| Claim graph (`app/graph/claim_graph.py`) | DONE | typed nodes, confidence, supports/contradicts propagation, settled-node protection, JSON round-trip — unit tested |
| SQLite persistence (`app/graph/store.py`) | DONE | save/load per run via aiosqlite |
| Orchestrator loop (`app/orchestrator/loop.py`) | DONE | SELECT (impact × uncertainty, cheap-method tiebreak) → ACT → OBSERVE → UPDATE, budget-aware, honest "budget exhausted" state |
| Action registry (`app/orchestrator/actions.py`) | DONE | method → verifier dispatch with cost ranking |
| License verifier | DONE | **real refutation demo works**: sample repo claims MIT, ships Apache → refuted 0.92 |
| Test-suite sandbox (subprocess) | DONE | actually runs pytest on the target repo; verified/refuted/timeout paths |
| Secret scan (gitleaks 8.24.3) | DONE | binary installed here, real scan passes; raises honest `ToolMissing` if absent — no silent fallback |
| SAST (bandit) | DONE | JSON parse, severity triage |
| OSV CVE lookup | CODE DONE, live call **not testable here** (see blockers) | parsing + verdict logic proven via mocked HTTP; graceful "unverifiable: network unreachable" |
| LLM router (`app/llm/router.py`) | DONE (mock path proven) | Mock / Ollama / watsonx providers, small-vs-micro tiering, 2-rps rate limiter, primary→fallback |
| JSON self-repair | DONE | fences, prefixes, trailing commas |
| Extractor + Critic agents | DONE (mock-tested) | prompts written; end-to-end with MockLLM |
| FastAPI server + SSE | DONE (smoke-tested) | POST /audit, GET /runs/{id}/events (SSE), /dossier, placeholder dashboard at / |
| Sample fixture + offline demo | DONE | `scripts/make_fixture.sh`, `scripts/demo_audit.py` |

Run everything:
```bash
cd backend && python3 -m pytest tests -q          # 12 passed
bash ../scripts/make_fixture.sh                   # build sample repo
python3 ../scripts/demo_audit.py                  # full offline audit
uvicorn app.main:app --port 8005                  # server + placeholder UI
```

## 🛑 STOPPED — need from you (in priority order)

1. **watsonx credentials.** The watsonx provider is written but cannot be tested without:
   - `WATSONX_APIKEY` (IBM Cloud API key)
   - `WATSONX_PROJECT_ID` (watsonx.ai project)
   - `WATSONX_URL` (region endpoint, default us-south)
   - Confirmation of the **exact Granite model IDs** your Lite plan/region exposes (I defaulted to `ibm/granite-4-h-small` / `ibm/granite-4-h-micro` — verify these strings against your watsonx model catalog; they may differ).
   → Manual steps for you in the section below.

2. **SupplyChainIQ codebase was never provided.** The spec assumed porting your prior FastAPI/JWT backend, React graph UI, JSON-repair and router. I did NOT have it, so I built minimal fresh equivalents where the build would otherwise stop (plain FastAPI server, simple JSON repair, HTML placeholder dashboard) and clearly marked them. If you want the real port (JWT auth, the Framer Motion graph view), **upload that repo** and I'll do the migration map. Before uploading: strip `vault.db`, `.env`, and any keys.

3. **OSV live validation.** This sandbox's network policy blocks `api.osv.dev` (403 from egress proxy). Code is proven against mocked responses. On any of your machines run:
   ```bash
   cd backend && python3 -c "
   import asyncio, pathlib
   from app.verify.osv import check_vulnerabilities
   print(asyncio.run(check_vulnerabilities(pathlib.Path('/tmp/swarm_sample_repo'))))"
   ```
   Expected: `refuted` with CVE IDs for requests==2.19.0 (it has known CVEs). If you see that, the live path works.

4. **Docker on your laptops** (manual). The current sandbox runner is a resource-limited subprocess with env scrubbing — **best-effort isolation only, not true network-off**. For the demo claim "network-disabled containers" to be true, install Docker Desktop / docker.io on the machine that runs audits. The Docker runner variant is the next thing I build once you confirm Docker is available (`docker --version`).

5. **Ollama + Granite locally** (manual, one laptop minimum — recommended: Nakshatra's):
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh     # or download the installer for your OS
   ollama pull granite4:micro                        # ~2–4 GB; verify exact tag with `ollama search granite`
   ollama run granite4:micro "say ok"                # timing check
   ```
   Then: `SWARM_LLM=ollama uvicorn app.main:app` runs the server against local Granite. Report the seconds-per-response so we can plan demo pacing.

6. **Coordinator email** (manual, 5 min, do today): ask the HackVerse organizers what watsonx.ai access/credits shortlisted teams get. This decides whether item 1 uses their credits or your free-tier account.

## ⚠️ Known deviations from spec (flagged, not hidden)
- **semgrep not installed** in this environment (bandit covers Python SAST). Install on your machines with `pip install semgrep` and I'll wire the wrapper next iteration.
- **Docling not integrated yet** — extractor currently reads raw README/manifest text directly (sufficient for the slice). Docling comes with the ingestion pass.
- **Embeddings / code_locate ("supports feature X" claims) not built** — requires a real embedding model (watsonx or Ollama), which is blocked on items 1/5.
- **React dashboard** is a placeholder HTML page. The real claim-graph view is Jahnavi's module; blocked on item 2 if porting, otherwise she builds fresh from `frontend/`.
- **Meta-memory / eval harness** not started (Phase 4 per plan).

## Next build steps (once unblocked)
1. You send watsonx creds → I validate the provider live + pin model IDs.
2. Docker confirmed → Docker sandbox runner (true network-off) replaces subprocess default.
3. Ollama timing reported → set demo pacing + wire embeddings for code_locate.
4. SupplyChainIQ repo (optional) → port JWT + React graph view.
5. Then Phase 3: critic-driven re-checks, meta-memory, eval harness.
