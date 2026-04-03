"""Request log API endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.request_log import RequestLog
from app.scanner.passive import run_passive_scan
from app.schemas.request_log import RequestLogCreate, RequestLogResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.post("/", response_model=RequestLogResponse, status_code=201)
def create_log(log: RequestLogCreate, db: Session = Depends(get_db)):
    """Create a new request/response log entry and trigger passive scan."""
    db_log = RequestLog(**log.model_dump())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    # Automatically run passive scan on the new log
    try:
        findings = run_passive_scan(db, db_log)
        if findings:
            logger.info(
                "Passive scan found %d issue(s) for log #%d",
                len(findings),
                db_log.id,
            )
    except Exception as e:
        logger.error("Passive scan failed for log #%d: %s", db_log.id, e)

    return db_log


@router.get("/", response_model=list[RequestLogResponse])
def list_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """List all request logs with pagination."""
    return db.query(RequestLog).offset(skip).limit(limit).all()


@router.get("/{log_id}", response_model=RequestLogResponse)
def get_log(log_id: int, db: Session = Depends(get_db)):
    """Get a specific request log by ID."""
    log = db.query(RequestLog).filter(RequestLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log
