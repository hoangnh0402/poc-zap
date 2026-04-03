"""Scan API endpoints — trigger active scans and view results."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.request_log import RequestLog
from app.scanner.active import run_active_scan
from app.schemas.vulnerability import VulnerabilityResponse

router = APIRouter(prefix="/scan", tags=["Scanner"])


@router.post(
    "/active/{request_id}",
    response_model=list[VulnerabilityResponse],
    summary="Run active scan on a logged request",
)
def active_scan(request_id: int, db: Session = Depends(get_db)):
    """Replay a logged request with SQLi and XSS payloads.

    Injects attack payloads into URL query parameters and request body fields,
    then analyzes the responses for vulnerability indicators.
    """
    log = db.query(RequestLog).filter(RequestLog.id == request_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Request log not found")

    findings = run_active_scan(db, log)

    return findings
