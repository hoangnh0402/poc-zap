"""Active scanner — injects payloads and detects SQLi & XSS vulnerabilities."""

import json
import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from sqlalchemy.orm import Session

from app.models.request_log import RequestLog
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

# ─── Payloads ─────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
]

# ─── Detection patterns ──────────────────────────────────────────────

SQLI_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "sqlite3.operationalerror",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "you have an error in your sql",
    "warning: mysql",
    "postgresql",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "sqlstate",
    "syntax error",
    "unterminated string",
]


def _inject_into_params(url: str, payload: str) -> list[str]:
    """Generate URLs with payload injected into each query parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []

    injected_urls = []
    for key in params:
        modified = params.copy()
        modified[key] = [payload]
        new_query = urlencode(modified, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        injected_urls.append(new_url)

    return injected_urls


def _inject_into_body(body: str | None, payload: str) -> list[dict]:
    """Generate request bodies with payload injected into each field."""
    if not body:
        return []

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []

    if not isinstance(data, dict):
        return []

    injected_bodies = []
    for key in data:
        modified = data.copy()
        modified[key] = payload
        injected_bodies.append(modified)

    return injected_bodies


def _detect_sqli(response_text: str) -> str | None:
    """Check response text for SQL error message indicators."""
    text_lower = response_text.lower()
    for pattern in SQLI_ERROR_PATTERNS:
        if pattern in text_lower:
            return pattern
    return None


def _detect_xss(response_text: str, payload: str) -> bool:
    """Check if XSS payload is reflected in the response."""
    return payload in response_text


def run_active_scan(db: Session, log: RequestLog) -> list[Vulnerability]:
    """Run active SQL injection and XSS scans against a logged request.

    Replays the original request with injected payloads and analyzes responses.
    Returns a list of newly created Vulnerability records.
    """
    findings: list[Vulnerability] = []

    # Parse original request headers
    try:
        original_headers = json.loads(log.request_headers) if log.request_headers else {}
    except (json.JSONDecodeError, TypeError):
        original_headers = {}

    # Remove hop-by-hop headers that shouldn't be forwarded
    skip_headers = {"host", "content-length", "transfer-encoding", "connection"}
    clean_headers = {k: v for k, v in original_headers.items() if k.lower() not in skip_headers}

    with httpx.Client(timeout=10.0, verify=False, follow_redirects=True) as client:
        # ──── SQL Injection Scan ──────────────────────────────────────
        for payload in SQLI_PAYLOADS:
            # Inject into URL query parameters
            for injected_url in _inject_into_params(log.url, payload):
                try:
                    resp = client.request(log.method, injected_url, headers=clean_headers)
                    matched_pattern = _detect_sqli(resp.text)
                    if matched_pattern:
                        findings.append(
                            Vulnerability(
                                request_log_id=log.id,
                                scan_type="active",
                                rule_name="SQL Injection",
                                severity="high",
                                description=(
                                    f"Possible SQL injection detected. "
                                    f"Payload '{payload}' triggered SQL error pattern."
                                ),
                                evidence=(
                                    f"URL: {injected_url}\n"
                                    f"Pattern: {matched_pattern}\n"
                                    f"Status: {resp.status_code}"
                                ),
                            )
                        )
                except httpx.RequestError as e:
                    logger.debug("Request failed for SQLi scan: %s", e)

            # Inject into request body (for POST/PUT/PATCH)
            if log.method.upper() in ("POST", "PUT", "PATCH"):
                for injected_body in _inject_into_body(log.request_body, payload):
                    try:
                        resp = client.request(
                            log.method, log.url,
                            headers=clean_headers,
                            json=injected_body,
                        )
                        matched_pattern = _detect_sqli(resp.text)
                        if matched_pattern:
                            findings.append(
                                Vulnerability(
                                    request_log_id=log.id,
                                    scan_type="active",
                                    rule_name="SQL Injection",
                                    severity="high",
                                    description=(
                                        f"Possible SQL injection in request body. "
                                        f"Payload '{payload}' triggered SQL error pattern."
                                    ),
                                    evidence=(
                                        f"URL: {log.url}\n"
                                        f"Body: {json.dumps(injected_body)}\n"
                                        f"Pattern: {matched_pattern}\n"
                                        f"Status: {resp.status_code}"
                                    ),
                                )
                            )
                    except httpx.RequestError as e:
                        logger.debug("Request failed for SQLi body scan: %s", e)

        # ──── XSS Scan ────────────────────────────────────────────────
        for payload in XSS_PAYLOADS:
            # Inject into URL query parameters
            for injected_url in _inject_into_params(log.url, payload):
                try:
                    resp = client.request(log.method, injected_url, headers=clean_headers)
                    if _detect_xss(resp.text, payload):
                        findings.append(
                            Vulnerability(
                                request_log_id=log.id,
                                scan_type="active",
                                rule_name="Cross-Site Scripting (XSS)",
                                severity="high",
                                description=(
                                    f"Reflected XSS detected. "
                                    f"Payload '{payload}' was reflected in the response."
                                ),
                                evidence=(
                                    f"URL: {injected_url}\n"
                                    f"Status: {resp.status_code}"
                                ),
                            )
                        )
                except httpx.RequestError as e:
                    logger.debug("Request failed for XSS scan: %s", e)

            # Inject into request body
            if log.method.upper() in ("POST", "PUT", "PATCH"):
                for injected_body in _inject_into_body(log.request_body, payload):
                    try:
                        resp = client.request(
                            log.method, log.url,
                            headers=clean_headers,
                            json=injected_body,
                        )
                        if _detect_xss(resp.text, payload):
                            findings.append(
                                Vulnerability(
                                    request_log_id=log.id,
                                    scan_type="active",
                                    rule_name="Cross-Site Scripting (XSS)",
                                    severity="high",
                                    description=(
                                        f"Reflected XSS in response body. "
                                        f"Payload '{payload}' was reflected back."
                                    ),
                                    evidence=(
                                        f"URL: {log.url}\n"
                                        f"Body: {json.dumps(injected_body)}\n"
                                        f"Status: {resp.status_code}"
                                    ),
                                )
                            )
                    except httpx.RequestError as e:
                        logger.debug("Request failed for XSS body scan: %s", e)

    # Persist findings
    if findings:
        db.add_all(findings)
        db.commit()
        for f in findings:
            db.refresh(f)
        logger.info("Active scan found %d issues for log #%d", len(findings), log.id)

    return findings
