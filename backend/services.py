import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


async def fetch_cves(cwe_id: str, limit: int = 50) -> list[str]:
    async with httpx.AsyncClient() as client:
        response = await client.get(
            NVD_API_URL,
            params={"cweId": cwe_id, "resultsPerPage": limit},
        )
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        return [item["cve"]["id"] for item in vulnerabilities]


async def fetch_epss(cve_ids: list[str], date: str | None = None) -> list[dict]:
    if not cve_ids:
        return []
    params = {"cve": ",".join(cve_ids)}
    if date:
        params["date"] = date
    async with httpx.AsyncClient() as client:
        response = await client.get(EPSS_API_URL, params=params)
        response.raise_for_status()
        return response.json().get("data", [])


def compute_pecwe(cve_ids: list[str], epss_data: list[dict]) -> float:
    """PECWE(x, d) = 1 - prod(1 - EPSS(y, d)) for all y in S_x.

    CVEs missing from epss_data (e.g. not yet published on date d) are
    treated as having EPSS = 0, contributing a factor of 1.
    """
    epss_map = {entry["cve"]: float(entry.get("epss", 0) or 0) for entry in epss_data}
    product = 1.0
    for cve in cve_ids:
        product *= 1.0 - epss_map.get(cve, 0.0)
    return 1.0 - product

def resolve_cve_epss(cve_list, epss_data):
    epss_map = {item["cve"]: float(item["epss"]) for item in epss_data}

    resolved = []
    for cve in cve_list:
        resolved.append({
            "cve": cve,
            "epss": epss_map.get(cve, 0.0)
        })

    return resolved

def calculate_trend(resolved_data):
    recent = []
    old = []

    for item in resolved_data:
        cve = item["cve"]
        epss = item["epss"]

        year = int(cve.split("-")[1])

        if year >= 2022:
            recent.append(epss)
        else:
            old.append(epss)

    if not recent or not old:
        return "STABLE"

    avg_recent = sum(recent) / len(recent)
    avg_old = sum(old) / len(old)

    if avg_recent > avg_old + 0.1:
        return "UP"
    elif avg_recent < avg_old - 0.1:
        return "DOWN"
    else:
        return "STABLE"
