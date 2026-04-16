# PECWE-Calculator

PECWE Calculator based off the following research papers:

Mell, P., Bojanova, I., & Galhardo, C. (2024). Measuring the Exploitation of Weaknesses in the Wild. arXiv:2405.01289
##

![](https://github.com/Dustrunner369/PECWE-Calculator/blob/main/CWE-79.gif)

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)

## Build & Run

### Full stack (backend + frontend)

```bash
docker compose up --build
```
- Backend API: http://localhost:8000
- Frontend: http://localhost:3000

### Backend only

```bash
docker build -t pecwe-backend ./backend
docker run -p 8000:8000 pecwe-backend
```

The API will be available at http://localhost:8000

## API Usage

**Health check:**

```bash
curl http://localhost:8000/api/health
```

**Query CVEs for a CWE:**

```bash
curl -X POST http://localhost:8000/api/calculate \
  -H "Content-Type: application/json" \
  -d '{"cwe": "CWE-79"}'
```

The response contains:

- `cwe` — the CWE queried
- `is_parent` — whether the CWE is a parent in CWE View-1003
- `date` — the date used for EPSS lookup
- `per_cwe` — map of each CWE (parent + children, if any) to its `name`, `cves`, and `epss` records

## Calculation

For a set of CVEs *S* mapped to a CWE *x* on date *d*, PECWE is:

> PECWE(x, d) = 1 − ∏<sub>y ∈ S</sub> (1 − EPSS(y, d))

EPSS is the per-CVE exploit probability from [FIRST EPSS](https://www.first.org/epss/). CVEs with no EPSS record on *d* are treated as 0, contributing a factor of 1.

## Parent / Child Aggregation (View-1003)

[CWE View-1003](https://cwe.mitre.org/data/definitions/1003.html) organizes weaknesses into a two-level tree of parents and children. When the queried CWE is a parent, the backend fetches CVEs for the parent and every child in parallel and returns them in `per_cwe`.

The frontend renders a chip for each CWE; toggling chips recomputes the aggregate client-side by taking the **union of unique CVEs** across the selected CWEs and applying the same PECWE formula. A CVE mapped to multiple CWEs is counted once.
