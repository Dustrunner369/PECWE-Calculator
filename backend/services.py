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


async def fetch_epss(cve_ids: list[str]) -> list[dict]:
    if not cve_ids:
        return []
    async with httpx.AsyncClient() as client:
        response = await client.get(
            EPSS_API_URL,
            params={"cve": ",".join(cve_ids)},
        )
        response.raise_for_status()
        return response.json().get("data", [])
