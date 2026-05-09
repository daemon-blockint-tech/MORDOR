from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import analyze, cases, stream

app = FastAPI(
    title="MORDOR API",
    description="Malware Orchestration & Reverse engineering Detection Operations Runtime",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
