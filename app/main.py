"""Mini ZAP – FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.database import init_db
from app.routers import logs, scan, vulnerabilities


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB on startup."""
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="🛡️ A minimal security testing tool inspired by OWASP ZAP",
    lifespan=lifespan,
)

# Register routers
app.include_router(logs.router)
app.include_router(scan.router)
app.include_router(vulnerabilities.router)


@app.get("/", tags=["Health"])
def root():
    """Health check endpoint."""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }
