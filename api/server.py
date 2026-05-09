from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import analyze, cases, stream

_cors_origins_str = os.environ.get("MORDOR_CORS_ORIGINS", "")
if _cors_origins_str:
    _cors_origins = [o.strip() for o in _cors_origins_str.split(",") if o.strip()]
else:
    _cors_origins = ["http://localhost:8765"]

app = FastAPI(
    title="MORDOR API",
    description="Malware Orchestration & Reverse engineering Detection Operations Runtime",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT = int(os.environ.get("MORDOR_RATE_LIMIT", "30"))
_RATE_WINDOW = int(os.environ.get("MORDOR_RATE_WINDOW", "60"))


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - _RATE_WINDOW
    timestamps = _rate_limit_store[client_ip]
    timestamps[:] = [t for t in timestamps if t > window_start]
    if len(timestamps) >= _RATE_LIMIT:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
    timestamps.append(now)
    return await call_next(request)


app.include_router(analyze.router)
app.include_router(cases.router)
app.include_router(stream.router)


@app.get("/")
async def root():
    return {
        "service": "MORDOR",
        "version": "1.0.0",
        "docs": "/docs",
        "openapi": "/openapi.json",
    }
