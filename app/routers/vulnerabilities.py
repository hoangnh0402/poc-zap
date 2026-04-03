"""Vulnerability API endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityResponse

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("/", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    skip: int = 0, limit: int = 100, db: Session = Depends(get_db)
):
    """List all detected vulnerabilities."""
    return db.query(Vulnerability).offset(skip).limit(limit).all()


@router.get("/by-log/{log_id}", response_model=list[VulnerabilityResponse])
def get_vulnerabilities_by_log(log_id: int, db: Session = Depends(get_db)):
    """Get vulnerabilities associated with a specific request log."""
    return (
        db.query(Vulnerability)
        .filter(Vulnerability.request_log_id == log_id)
        .all()
    )
