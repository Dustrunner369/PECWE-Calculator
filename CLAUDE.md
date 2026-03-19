# PECWE Calculator

## Project Overview
A web-based PECWE (Performance-based Energy and Carbon Weighted Estimate) Calculator built for a Topics in CS course (SP26). The app lets users input data, run calculations via a Python backend, and visualize results with interactive charts.

## Tech Stack
- **Backend**: FastAPI (Python) — serves the API and the frontend HTML
- **Frontend**: Vanilla HTML/JS — single page served by FastAPI, no build step
- **Charts**: ApexCharts via CDN — time-series and gauge visualizations
- **Styling**: TailwindCSS via CDN — utility-first CSS, no build tooling

## Project Structure
```
├── main.py              # FastAPI application entry point
├── requirements.txt     # Python dependencies
├── static/              # Static assets served by FastAPI
│   ├── js/
│   │   └── app.js       # Frontend application logic
│   └── css/
│       └── styles.css   # Custom styles (beyond Tailwind)
├── templates/
│   └── index.html       # Main HTML page (Jinja2 template)
└── CLAUDE.md            # This file
```

## Running the Project
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
The app runs at http://localhost:8000

## Development Notes
- No build step required — all frontend deps loaded via CDN
- FastAPI serves both the API (`/api/...`) and the frontend
- Templates use Jinja2 (included with FastAPI via `jinja2` + `python-multipart`)
