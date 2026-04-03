"""Mini ZAP – FastAPI application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
from app.routers import logs, scan, vulnerabilities

STATIC_DIR = Path(__file__).parent / "static"


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

# Serve static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", tags=["Dashboard"])
def dashboard():
    """Serve the Mini ZAP dashboard UI."""
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health", tags=["Health"])
def health():
    """Health check endpoint."""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }
