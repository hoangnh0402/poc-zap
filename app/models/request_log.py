"""Request and response log model."""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.database import Base


class RequestLog(Base):
    """Stores intercepted HTTP request and response data."""

    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    method = Column(String(10), nullable=False)
    url = Column(Text, nullable=False)
    request_headers = Column(Text, nullable=True)
    request_body = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    response_headers = Column(Text, nullable=True)
    response_body = Column(Text, nullable=True)
    timestamp = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
