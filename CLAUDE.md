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

## Design Context

### Users

General technical users — developers, IT staff, and students who occasionally need to assess vulnerability risk using CVE and EPSS data. They are technically literate but not necessarily cybersecurity specialists. The tool should feel accessible without dumbing down the data.

### Brand Personality

**3 words:** Innovative, Trustworthy, Precise

The interface should inspire confidence in the data it presents — users need to trust the numbers. At the same time, it should feel modern and forward-thinking, not like a legacy enterprise tool. The emotional goal is: "This tool knows what it's doing, and so do I when I use it."

### Aesthetic Direction

- **Visual tone:** Technical dashboard with a cybersecurity edge — data-dense where it matters, with clear visual hierarchy
- **Theme:** Dark mode — dark backgrounds with high-contrast data elements
- **Color direction:** Dark neutrals (slate/gray-900+) as base, with precise accent colors for data visualization (blues, teals, or cyans for a security/tech feel). Use color sparingly and purposefully — primarily for status, severity, and chart data
- **Typography:** Clean, monospace or semi-monospace for data; sans-serif for UI chrome. Prioritize legibility on dark backgrounds
- **References:** SOC dashboards, security tooling UIs (Shodan, GreyNoise, Wiz)
- **Anti-references:** Playful SaaS landing pages, overly decorative UIs, anything that undermines data credibility

### Design Principles

1. **Data first** — Every design decision should make the data easier to read, compare, and act on. Decoration that doesn't serve comprehension gets cut.
2. **Earned trust** — Use precise typography, consistent spacing, and restrained color to signal reliability. The UI should feel engineered, not decorated.
3. **Dark with purpose** — Dark mode isn't just aesthetic — it reduces eye strain for data analysis and makes charts/visualizations pop. Use contrast strategically.
4. **Progressive disclosure** — Show the essential inputs and key metrics upfront. Let users drill into detail (full CVE lists, EPSS breakdowns) on demand.
5. **Modern restraint** — Feel innovative through clean execution and smart interaction patterns, not through gratuitous animation or trendy effects.
