# SWARM — Software Trust Auditor
Point it at any repo. It extracts every claim the software makes about itself and
proves or breaks each one by execution. HackVerse 2.0 · Track 03 · Team SWARM.

Quick start:
  cd backend
  pip install networkx fastapi uvicorn httpx pytest pytest-asyncio gitpython bandit aiosqlite sse-starlette
  python3 -m pytest tests -q            # engine test suite
  bash ../scripts/make_fixture.sh       # sample target repo
  python3 ../scripts/demo_audit.py      # offline end-to-end audit (MockLLM + real verifiers)
  uvicorn app.main:app --port 8005      # server + placeholder dashboard

LLM modes (env SWARM_LLM): mock (default) | ollama | watsonx
watsonx needs: WATSONX_APIKEY, WATSONX_PROJECT_ID, WATSONX_URL, model IDs per region.

See BUILD_STATUS.md for exactly what is done, what is blocked, and the manual steps.
