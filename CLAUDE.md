# PECWE Calculator

## Project Overview
A web-based PECWE (Performance-based Energy and Carbon Weighted Estimate) Calculator built for a Topics in CS course (SP26). The app lets users input data, run calculations via a Python backend, and visualize results with interactive charts.

## Tech Stack
- **Backend**: FastAPI (Python) — API-only service querying NVD/EPSS APIs
- **Frontend**: Vanilla HTML/JS — served by a separate FastAPI instance, no build step
- **Charts**: ApexCharts via CDN — time-series and gauge visualizations
- **Styling**: TailwindCSS via CDN — utility-first CSS, no build tooling
- **Containerization**: Docker + Docker Compose

## Project Structure
```
├── backend/
│   ├── main.py          # FastAPI app entry point
│   ├── routes.py        # API route handlers (/api/health, /api/calculate)
│   ├── services.py      # NVD and EPSS API client functions
│   ├── requirements.txt # Backend Python dependencies
│   └── Dockerfile       # Backend container
├── frontend/
│   ├── main.py          # FastAPI app serving the HTML frontend
│   ├── requirements.txt # Frontend Python dependencies
│   ├── Dockerfile       # Frontend container
│   ├── static/
│   │   ├── js/
│   │   │   └── app.js   # Frontend application logic
│   │   └── css/
│   │       └── styles.css
│   └── templates/
│       └── index.html   # Main HTML page (Jinja2 template)
├── docker-compose.yml   # Runs backend (port 8000) + frontend (port 3000)
├── .dockerignore
├── README.md
└── CLAUDE.md            # This file
```

## Running the Project

### With Docker Compose (recommended)
```bash
docker compose up --build
```
- Backend API: http://localhost:8000
- Frontend: http://localhost:3000

### Backend only (Docker)
```bash
docker build -t pecwe-backend ./backend
docker run -p 8000:8000 pecwe-backend
```

### Backend only (local)
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

## Development Notes
- No build step required — all frontend deps loaded via CDN
- Backend and frontend are separate FastAPI services
- Backend has CORS enabled for cross-origin requests from the frontend
- Templates use Jinja2 (included with FastAPI via `jinja2`)
- NVD API results capped at 50 per request to respect rate limits
