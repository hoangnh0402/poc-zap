"""Passive scanner — analyzes logged responses for security header issues."""

import json
import logging

from sqlalchemy.orm import Session

from app.models.request_log import RequestLog
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def run_passive_scan(db: Session, log: RequestLog) -> list[Vulnerability]:
    """Run all passive scan rules against a request log entry.

    Returns a list of newly created Vulnerability records.
    """
    findings: list[Vulnerability] = []

    # Only scan if we have response headers
    if not log.response_headers:
        return findings

    try:
        headers = json.loads(log.response_headers)
    except (json.JSONDecodeError, TypeError):
        return findings

    # Normalize header keys to lowercase for comparison
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # --- Rule 1: Missing Content-Security-Policy ---
    if "content-security-policy" not in headers_lower:
        findings.append(
            Vulnerability(
                request_log_id=log.id,
                scan_type="passive",
                rule_name="Missing Content-Security-Policy",
                severity="medium",
                description=(
                    "The response does not include a Content-Security-Policy header. "
                    "CSP helps prevent XSS, clickjacking, and other code injection attacks."
                ),
                evidence=f"URL: {log.url}",
            )
        )

    # --- Rule 2: Missing X-Frame-Options ---
    if "x-frame-options" not in headers_lower:
        findings.append(
            Vulnerability(
                request_log_id=log.id,
                scan_type="passive",
                rule_name="Missing X-Frame-Options",
                severity="medium",
                description=(
                    "The response does not include an X-Frame-Options header. "
                    "This makes the application vulnerable to clickjacking attacks."
                ),
                evidence=f"URL: {log.url}",
            )
        )

    # --- Rule 3: Missing X-Content-Type-Options ---
    if "x-content-type-options" not in headers_lower:
        findings.append(
            Vulnerability(
                request_log_id=log.id,
                scan_type="passive",
                rule_name="Missing X-Content-Type-Options",
                severity="low",
                description=(
                    "The response does not include X-Content-Type-Options: nosniff. "
                    "Browsers may MIME-sniff the content, leading to security issues."
                ),
                evidence=f"URL: {log.url}",
            )
        )

    # --- Rule 4: Missing Strict-Transport-Security ---
    if log.url.startswith("https") and "strict-transport-security" not in headers_lower:
        findings.append(
            Vulnerability(
                request_log_id=log.id,
                scan_type="passive",
                rule_name="Missing Strict-Transport-Security",
                severity="medium",
                description=(
                    "The HTTPS response does not include a Strict-Transport-Security header. "
                    "Users may be vulnerable to downgrade attacks."
                ),
                evidence=f"URL: {log.url}",
            )
        )

    # --- Rule 5: Cookie missing HttpOnly or Secure flags ---
    set_cookie = headers_lower.get("set-cookie", "")
    if set_cookie:
        cookies = set_cookie if isinstance(set_cookie, list) else [set_cookie]
        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            if "httponly" not in cookie_lower:
                findings.append(
                    Vulnerability(
                        request_log_id=log.id,
                        scan_type="passive",
                        rule_name="Cookie Missing HttpOnly Flag",
                        severity="medium",
                        description=(
                            f"Cookie '{cookie_name}' does not have the HttpOnly flag set. "
                            "This allows client-side scripts to access the cookie."
                        ),
                        evidence=f"Set-Cookie: {cookie}",
                    )
                )

            if "secure" not in cookie_lower:
                findings.append(
                    Vulnerability(
                        request_log_id=log.id,
                        scan_type="passive",
                        rule_name="Cookie Missing Secure Flag",
                        severity="medium",
                        description=(
                            f"Cookie '{cookie_name}' does not have the Secure flag set. "
                            "The cookie may be sent over unencrypted connections."
                        ),
                        evidence=f"Set-Cookie: {cookie}",
                    )
                )

    # Persist all findings
    if findings:
        db.add_all(findings)
        db.commit()
        for f in findings:
            db.refresh(f)
        logger.info("Passive scan found %d issues for log #%d", len(findings), log.id)

    return findings
