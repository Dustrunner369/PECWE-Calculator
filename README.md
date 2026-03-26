# PECWE-Calculator
PECWE Calculator based off the following research papers:

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

This returns a JSON response with:
- `cve_count` — number of CVEs found
- `cves` — list of CVE IDs
- `epss` — EPSS exploit probability scores for each CVE

> **Note:** NVD results are capped at 50 per request to respect API rate limits. This will be changed in future versions.
