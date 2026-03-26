from fastapi import APIRouter, Request

from services import fetch_cves, fetch_epss

router = APIRouter(prefix="/api")


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.post("/calculate")
async def calculate(request: Request):
    data = await request.json()
    cwe_id = data.get("cwe")

    if not cwe_id:
        return {"error": "Missing CWE"}

    cve_list = await fetch_cves(cwe_id)
    epss_data = await fetch_epss(cve_list)

    return {
        "cwe": cwe_id,
        "cve_count": len(cve_list),
        "cves": cve_list,
        "epss": epss_data,
    }
