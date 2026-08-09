"""watsonx.ai live validation: auth -> list Granite models -> one real chat.
Run after setting env vars:
  $env:WATSONX_APIKEY="..."         (IBM Cloud API key)
  $env:WATSONX_PROJECT_ID="..."     (watsonx project id)
  $env:WATSONX_URL="https://us-south.ml.cloud.ibm.com"   (match your region)
Then:  py scripts/watsonx_check.py
"""
import asyncio, os, sys, pathlib
import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

async def main():
    apikey = os.getenv("WATSONX_APIKEY")
    project = os.getenv("WATSONX_PROJECT_ID")
    url = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
    if not apikey or not project:
        print("!! Set WATSONX_APIKEY and WATSONX_PROJECT_ID first (see docstring).")
        return

    async with httpx.AsyncClient(timeout=60) as c:
        # 1) IAM token
        print("1) Authenticating with IBM Cloud IAM...")
        r = await c.post("https://iam.cloud.ibm.com/identity/token",
                         data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": apikey},
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        r.raise_for_status()
        tok = r.json()["access_token"]
        print("   auth OK")

        # 2) list available foundation models, filter granite
        print("2) Fetching model catalog...")
        r = await c.get(f"{url}/ml/v1/foundation_model_specs?version=2024-05-31&limit=200",
                        headers={"Authorization": f"Bearer {tok}"})
        r.raise_for_status()
        models = [m.get("model_id", "") for m in r.json().get("resources", [])]
        granites = [m for m in models if "granite" in m.lower()]
        print(f"   {len(models)} models total; Granite models available to this account:")
        for m in sorted(granites):
            print(f"     · {m}")
        if not granites:
            print("   !! no granite models visible — check region/plan")
            return

        # 3) pick IDs: prefer granite-4 small + smallest granite for micro tier
        small = next((m for m in granites if "granite-4" in m and "small" in m), granites[0])
        micro = next((m for m in granites if any(k in m for k in ("micro", "tiny", "3-3-8b", "3-8b", "2b"))), small)
        print(f"3) Using  SMALL={small}  MICRO={micro}")

        # 4) one real chat through our router
        from app.llm.router import WatsonxLLM, Router
        os.environ["WATSONX_MODEL_SMALL"] = small
        os.environ["WATSONX_MODEL_MICRO"] = micro
        llm = Router(WatsonxLLM(small=small, micro=micro), rps=2)
        text, tokens = await llm.chat("check", "You are a helpful assistant.",
                                      "Reply with exactly: SWARM-WATSONX-OK", tier="small")
        print(f"4) Model replied: {text.strip()[:80]}   (tokens={tokens})")
        print("\n== SUCCESS. Pin these in your shell before demo runs:")
        print(f'   $env:WATSONX_MODEL_SMALL="{small}"')
        print(f'   $env:WATSONX_MODEL_MICRO="{micro}"')

asyncio.run(main())