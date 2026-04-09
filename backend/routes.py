from fastapi import APIRouter, Request

from datetime import date as _date

from services import compute_pecwe, fetch_cves, fetch_epss, resolve_cve_epss, calculate_trend

router = APIRouter(prefix="/api")


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.post("/calculate")
async def calculate(request: Request):
    data = await request.json()
    cwe_id = data.get("cwe")
    date_str = data.get("date") or _date.today().isoformat()

    if not cwe_id:
        return {"error": "Missing CWE"}

    cve_list = await fetch_cves(cwe_id)
    epss_data = await fetch_epss(cve_list, date=date_str)
    pecwe = compute_pecwe(cve_list, epss_data)

    resolved = resolve_cve_epss(cve_list, epss_data)

    trend = calculate_trend(resolved)

    return {
        "cwe": cwe_id,
        "date": date_str,
        "cve_count": len(cve_list),
        "cves": cve_list,
        "epss": epss_data,
        "pecwe": pecwe,
        "resolved": resolved,
        "trend": trend,

    }
