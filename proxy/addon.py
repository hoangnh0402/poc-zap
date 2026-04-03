"""mitmproxy addon — intercepts HTTP traffic and sends it to the Mini ZAP API."""

import json
import logging

import httpx
from mitmproxy import http

logger = logging.getLogger(__name__)

# Backend API URL — adjust if running on a different host/port
API_BASE_URL = "http://127.0.0.1:8000"


class MiniZapAddon:
    """mitmproxy addon that logs all intercepted HTTP traffic to the backend."""

    def __init__(self):
        self.client = httpx.Client(base_url=API_BASE_URL, timeout=5.0)
        logger.info("Mini ZAP addon initialized — sending logs to %s", API_BASE_URL)

    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a complete HTTP response has been received."""
        try:
            # Extract request data
            request = flow.request
            response = flow.response

            # Build headers as JSON strings
            request_headers = dict(request.headers)
            response_headers = dict(response.headers) if response else {}

            # Build request body
            request_body = None
            if request.content:
                try:
                    request_body = request.content.decode("utf-8", errors="replace")
                except Exception:
                    request_body = "<binary data>"

            # Build response body
            response_body = None
            if response and response.content:
                try:
                    response_body = response.content.decode("utf-8", errors="replace")
                except Exception:
                    response_body = "<binary data>"

            # Send to backend API
            log_data = {
                "method": request.method,
                "url": request.pretty_url,
                "request_headers": json.dumps(request_headers),
                "request_body": request_body,
                "status_code": response.status_code if response else None,
                "response_headers": json.dumps(response_headers),
                "response_body": response_body,
            }

            resp = self.client.post("/logs/", json=log_data)

            if resp.status_code == 201:
                log_id = resp.json().get("id")
                logger.info(
                    "Logged: %s %s → %s (log #%s)",
                    request.method,
                    request.pretty_url,
                    response.status_code if response else "?",
                    log_id,
                )
            else:
                logger.warning(
                    "Failed to log request: %s %s — API returned %s",
                    request.method,
                    request.pretty_url,
                    resp.status_code,
                )

        except Exception as e:
            logger.error("Error in Mini ZAP addon: %s", e)


# Register the addon with mitmproxy
addons = [MiniZapAddon()]
