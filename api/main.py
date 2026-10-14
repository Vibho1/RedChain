from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.database import init_db
from api.routers import attacks, reports

app = FastAPI(
    title = "RedChain API",
    description = "🔴 Autonomous Multi-Turn Red-Teaming Engine for AI Agents",
    version = "0.1.0",
    docs_url = "/docs",
    redoc_url = "/redoc",
)

# CORS — allows the Phase 7 Next.js dashboard to call this API from localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)

app.include_router(attacks.router)
app.include_router(reports.router)

@app.on_event("startup")
def on_startup():
    """ Create DB tables on first launch. """
    init_db()

@app.get("/health")
def health():
    return {"status": "ok", "service": "redchain-api"}