from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx  # NEW: used to call external APIs

app = FastAPI(title="PECWE Calculator")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"request": request}
    )


@app.get("/api/health")
async def health():
    return {"status": "ok"}


# 🔥 UPDATED ENDPOINT
@app.post("/api/calculate")
async def calculate(request: Request):
    data = await request.json()
    cwe_id = data.get("cwe")  # Expecting a certain CWE ID from the frontend

    # --- VALIDATION ---
    if not cwe_id:
        return {"error": "Missing CWE"}

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"

    async with httpx.AsyncClient() as client:
        # --- STEP 1: GET CVEs FROM NVD ---
        params = {
            "cweId": cwe_id,
            "resultsPerPage": 50  # keep small for rate limits to limit many requests
        }

        nvd_response = await client.get(NVD_API_URL, params=params)
        nvd_json = nvd_response.json()

        # Extract CVE IDs
        cve_list = []
        for item in nvd_json.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            cve_list.append(cve_id)

        # --- STEP 2: GET EPSS DATA ---
        if cve_list:
            epss_response = await client.get(
                EPSS_API_URL,
                params={"cve": ",".join(cve_list)}
            )
            epss_data = epss_response.json().get("data", [])
        else:
            epss_data = []

    # --- FINAL OUTPUT ---
    return {
        "cwe": cwe_id,
        "cve_count": len(cve_list),
        "cves": cve_list,
        "epss": epss_data
    }