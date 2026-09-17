from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from resource_shield_ai import __version__
from resource_shield_ai.analyst import analyze_incident
from resource_shield_ai.schema import Incident
from resource_shield_ai.telemetry import get_default_incident


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env", override=True)

app = FastAPI(title="CWP7 Resource Shield AI", version=__version__)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")


def model_label() -> str:
    override = os.getenv("NEBIUS_MODEL", "").strip()
    if override:
        return override
    return "Nano triage • Super standard • Ultra deep"


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    incident = get_default_incident()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "incident": incident.model_dump(),
            "version": __version__,
            "live_ai": bool(os.getenv("NEBIUS_API_KEY", "").strip()),
            "model": model_label(),
        },
    )


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "version": __version__,
        "nebius_configured": bool(os.getenv("NEBIUS_API_KEY", "").strip()),
        "model_strategy": model_label(),
        "configured_models": {
            "triage": os.getenv("NEBIUS_MODEL_TRIAGE", "auto: Nemotron Nano"),
            "standard": os.getenv("NEBIUS_MODEL_STANDARD", "auto: Nemotron Super"),
            "deep": os.getenv("NEBIUS_MODEL_DEEP", "auto: Nemotron Ultra"),
        },
    }


@app.get("/api/demo-incident")
def demo_incident():
    return get_default_incident().model_dump()


@app.post("/api/analyze")
def analyze(
    incident: Incident,
    mode: Literal["triage", "standard", "deep"] = Query(default="standard"),
):
    try:
        return analyze_incident(incident, mode=mode).model_dump()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
