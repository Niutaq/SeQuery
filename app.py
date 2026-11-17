#!/usr/bin/env python3
"""
SeQuery Web UI - FastAPI (100% local FOSS).
Run: task ui -> http://127.0.0.1:8000
"""

from __future__ import annotations

import json
import queue
import threading
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from agent_swarm import (
    DEMO_SCENARIOS,
    get_system_context,
    list_ollama_models,
    list_users,
    run_swarm,
)

BASE = Path(__file__).resolve().parent

app = FastAPI(title="SeQuery", description="Prompt Injection vs Defense-in-Depth (local FOSS)")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
app.mount("/assets", StaticFiles(directory=str(BASE / "assets")), name="assets")
templates = Jinja2Templates(directory=str(BASE / "templates"))


class RunRequest(BaseModel):
    mode: Literal["vulnerable", "secure", "compare"] = "secure"
    username: str = "jan_sales_alpha"
    model: Optional[str] = None
    query: str = Field(..., min_length=1)
    use_red_team: bool = False


@app.get("/")
async def index(request: Request) -> HTMLResponse:
    ctx = get_system_context()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "presets": DEMO_SCENARIOS,
            "context": ctx,
        },
    )


@app.get("/api/context")
def api_context() -> dict[str, Any]:
    return get_system_context()


@app.get("/api/ollama")
def api_ollama() -> dict[str, Any]:
    return list_ollama_models()


@app.get("/api/users")
def api_users() -> list[dict[str, Any]]:
    try:
        return list_users()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}") from e


@app.get("/api/presets")
def api_presets() -> list[dict[str, Any]]:
    return DEMO_SCENARIOS


@app.post("/api/run")
def api_run(body: RunRequest) -> dict[str, Any]:
    try:
        if body.mode == "compare":
            vuln = run_swarm(
                mode="vulnerable",
                username=body.username,
                query=body.query,
                model=body.model,
                use_red_team=body.use_red_team,
                verbose=False,
            )
            # Run Red Team once so secure mode evaluates the exact same prompt
            secure = run_swarm(
                mode="secure",
                username=body.username,
                query=vuln.get("query") or body.query,
                model=body.model,
                use_red_team=False,
                verbose=False,
            )
            return {"mode": "compare", "vulnerable": vuln, "secure": secure}
        return run_swarm(
            mode=body.mode,
            username=body.username,
            query=body.query,
            model=body.model,
            use_red_team=body.use_red_team,
            verbose=False,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/run-stream")
def api_run_stream(body: RunRequest) -> StreamingResponse:
    q: queue.Queue[dict[str, Any] | None] = queue.Queue()

    def worker() -> None:
        try:
            q.put({"event": "run_start", "mode": body.mode})
            if body.mode == "compare":
                vuln = run_swarm(
                    mode="vulnerable",
                    username=body.username,
                    query=body.query,
                    model=body.model,
                    use_red_team=body.use_red_team,
                    verbose=False,
                    on_event=lambda ev: q.put({**ev, "branch": "vulnerable"}),
                )
                secure = run_swarm(
                    mode="secure",
                    username=body.username,
                    query=vuln.get("query") or body.query,
                    model=body.model,
                    use_red_team=False,
                    verbose=False,
                    on_event=lambda ev: q.put({**ev, "branch": "secure"}),
                )
                q.put(
                    {
                        "event": "final",
                        "payload": {"mode": "compare", "vulnerable": vuln, "secure": secure},
                    }
                )
            else:
                res = run_swarm(
                    mode=body.mode,
                    username=body.username,
                    query=body.query,
                    model=body.model,
                    use_red_team=body.use_red_team,
                    verbose=False,
                    on_event=lambda ev: q.put({**ev, "branch": body.mode}),
                )
                q.put({"event": "final", "payload": res})
        except Exception as e:  # noqa: BLE001
            q.put({"event": "error", "detail": str(e)})
        finally:
            q.put(None)

    threading.Thread(target=worker, daemon=True).start()

    def event_gen():
        while True:
            item = q.get()
            if item is None:
                break
            yield f"data: {json.dumps(item, ensure_ascii=False, default=str)}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
