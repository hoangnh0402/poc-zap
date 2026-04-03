"""Scan API endpoints — quick scan + active scans."""

import json
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.request_log import RequestLog
from app.scanner.active import run_active_scan
from app.scanner.passive import run_passive_scan
from app.schemas.vulnerability import VulnerabilityResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["Scanner"])


class QuickScanRequest(BaseModel):
    """Request body for the quick scan endpoint."""
    url: str
    method: str = "GET"
    body: str | None = None


class QuickScanResponse(BaseModel):
    """Response for the quick scan endpoint."""
    log_id: int
    passive_count: int
    active_count: int
    passive_findings: list[VulnerabilityResponse]
    active_findings: list[VulnerabilityResponse]


@router.post(
    "/active/{request_id}",
    response_model=list[VulnerabilityResponse],
    summary="Run active scan on a logged request",
)
def active_scan(request_id: int, db: Session = Depends(get_db)):
    """Replay a logged request with SQLi and XSS payloads."""
    log = db.query(RequestLog).filter(RequestLog.id == request_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Request log not found")
    findings = run_active_scan(db, log)
    return findings


@router.post(
    "/quick",
    response_model=QuickScanResponse,
    summary="Quick scan: fetch URL, log, passive scan, and active scan",
)
def quick_scan(req: QuickScanRequest, db: Session = Depends(get_db)):
    """All-in-one scan: fetches the target, logs it, and runs both passive + active scans."""
    # Step 1: Fetch the target URL
    try:
        client = httpx.Client(timeout=15.0, verify=False, follow_redirects=True)
        if req.method.upper() == "GET":
            resp = client.get(req.url)
        else:
            body_data = None
            if req.body:
                try:
                    body_data = json.loads(req.body)
                except json.JSONDecodeError:
                    body_data = None
            resp = client.request(req.method.upper(), req.url, json=body_data)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Cannot reach target: {str(e)}")

    # Step 2: Log to DB
    db_log = RequestLog(
        method=req.method.upper(),
        url=req.url,
        request_headers=json.dumps(dict(resp.request.headers)),
        request_body=req.body,
        status_code=resp.status_code,
        response_headers=json.dumps(dict(resp.headers)),
        response_body=resp.text[:10000],
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    # Step 3: Passive scan
    passive_findings = run_passive_scan(db, db_log)

    # Step 4: Active scan
    active_findings = run_active_scan(db, db_log)

    return QuickScanResponse(
        log_id=db_log.id,
        passive_count=len(passive_findings),
        active_count=len(active_findings),
        passive_findings=passive_findings,
        active_findings=active_findings,
    )
