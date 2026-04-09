from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from services import resolve_cve_epss

from routes import router

app = FastAPI(title="PECWE Calculator API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


if __name__ == "__main__":
    import sys
    import asyncio

    if "--test" in sys.argv:
        from services import fetch_cves, fetch_epss

        async def run_test():
            test_cwe = "CWE-79"
            expected_pecwe = 0.05

            print(f"TEST_CWE={test_cwe}")
            print(f"EXPECTED_PECWE={expected_pecwe}")

            cve_list = await fetch_cves(test_cwe)
            print(f"CVE_COUNT={len(cve_list)}")

            epss_data = await fetch_epss(cve_list)
            print(f"EPSS_COUNT={len(epss_data)}")


            resolved = resolve_cve_epss(cve_list, epss_data)

            if resolved:
                scores = [item["epss"] for item in resolved]
                pecwe = sum(scores) / len(scores)
            else:
                pecwe = 0.0

            print(f"PECWE_RESULT={pecwe:.6f}")

            delta = abs(pecwe - expected_pecwe)
            print(f"DELTA={delta:.6f}")

            if delta > 0.1:
                print("STATUS=FAIL")
            else:
                print("STATUS=PASS")

        asyncio.run(run_test())
