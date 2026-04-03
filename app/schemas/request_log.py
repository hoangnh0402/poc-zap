"""Pydantic schemas for request logs."""

from datetime import datetime

from pydantic import BaseModel


class RequestLogCreate(BaseModel):
    """Schema for creating a new request log."""

    method: str
    url: str
    request_headers: str | None = None
    request_body: str | None = None
    status_code: int | None = None
    response_headers: str | None = None
    response_body: str | None = None


class RequestLogResponse(BaseModel):
    """Schema for returning a request log."""

    id: int
    method: str
    url: str
    request_headers: str | None = None
    request_body: str | None = None
    status_code: int | None = None
    response_headers: str | None = None
    response_body: str | None = None
    timestamp: datetime

    model_config = {"from_attributes": True}
