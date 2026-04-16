import asyncio
from datetime import date as _date

from fastapi import APIRouter, Request

from services import (
    fetch_cves,
    fetch_epss,
    get_children,
    get_cwe_name,
    is_parent,
)

router = APIRouter(prefix="/api")

AGGREGATE_CVE_LIMIT = 200
SINGLE_CVE_LIMIT = 50


@router.get("/health")
async def health():
    return {"status": "ok"}


async def _fetch_one(cwe_id: str, date_str: str, limit: int):
    cves = await fetch_cves(cwe_id, limit=limit)
    epss = await fetch_epss(cves, date=date_str) if cves else []
    return cwe_id, {
        "name": get_cwe_name(cwe_id),
        "cves": cves,
        "epss": epss,
    }


@router.post("/calculate")
async def calculate(request: Request):
    data = await request.json()
    cwe_id = data.get("cwe")
    date_str = data.get("date") or _date.today().isoformat()

    if not cwe_id:
        return {"error": "Missing CWE"}

    parent = is_parent(cwe_id)
    if parent:
        cwes = [cwe_id] + get_children(cwe_id)
        limit = AGGREGATE_CVE_LIMIT
    else:
        cwes = [cwe_id]
        limit = SINGLE_CVE_LIMIT

    results = await asyncio.gather(*[_fetch_one(c, date_str, limit) for c in cwes])
    per_cwe = {cwe: payload for cwe, payload in results}

    return {
        "cwe": cwe_id,
        "is_parent": parent,
        "date": date_str,
        "per_cwe": per_cwe,
    }
