import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="PECWE Calculator Frontend")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

API_URL = os.getenv("API_URL", "http://localhost:8000")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"api_url": API_URL})
if __name__ == "__main__":
    import sys
    import asyncio

    if "--test" in sys.argv:
        async def run_test():
            # Hardcoded test CWE
            test_cwe = "CWE-79"

            # Fake/simple PECWE calculation for now
            # (you'll improve this later)
            result = 1.0

            print(f"PECWE_RESULT={result}")

        asyncio.run(run_test())

