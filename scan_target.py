"""Direct scanner — fetches a target URL, logs it, and runs both passive + active scans."""

import json
import sys

import httpx

API_BASE = "http://127.0.0.1:8000"


def scan_url(target_url: str, method: str = "GET", body: dict | None = None):
    """Fetch a target URL and send it through the Mini ZAP pipeline."""
    api = httpx.Client(base_url=API_BASE, timeout=10.0)

    print(f"\n{'='*60}")
    print(f"🎯 Target: {method} {target_url}")
    print(f"{'='*60}")

    # ── Step 1: Fetch the target ──────────────────────────────
    print("\n[1/4] Fetching target...")
    try:
        target_client = httpx.Client(timeout=10.0, verify=False, follow_redirects=True)
        if method.upper() == "GET":
            resp = target_client.get(target_url)
        else:
            resp = target_client.post(target_url, json=body)
        print(f"      Status: {resp.status_code}")
    except httpx.RequestError as e:
        print(f"      ❌ Cannot reach target: {e}")
        return

    # ── Step 2: Log to Mini ZAP ───────────────────────────────
    print("[2/4] Logging to Mini ZAP...")
    log_data = {
        "method": method.upper(),
        "url": target_url,
        "request_headers": json.dumps(dict(resp.request.headers)),
        "request_body": json.dumps(body) if body else None,
        "status_code": resp.status_code,
        "response_headers": json.dumps(dict(resp.headers)),
        "response_body": resp.text[:5000],  # Limit response size
    }
    r = api.post("/logs/", json=log_data)
    if r.status_code != 201:
        print(f"      ❌ Failed to log: {r.status_code}")
        return

    log_id = r.json()["id"]
    print(f"      ✅ Logged as #{log_id}")

    # ── Step 3: Passive scan results (auto-triggered) ─────────
    print("[3/4] Passive scan results...")
    r = api.get(f"/vulnerabilities/by-log/{log_id}")
    passive_vulns = r.json()
    if passive_vulns:
        for v in passive_vulns:
            icon = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "💀"}.get(v["severity"], "⚪")
            print(f"      {icon} [{v['severity'].upper()}] {v['rule_name']}")
    else:
        print("      ✅ No passive issues found")

    # ── Step 4: Active scan ───────────────────────────────────
    print("[4/4] Running active scan (SQLi + XSS)...")
    r = api.post(f"/scan/active/{log_id}")
    active_vulns = r.json()
    if active_vulns:
        for v in active_vulns:
            icon = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "💀"}.get(v["severity"], "⚪")
            print(f"      {icon} [{v['severity'].upper()}] {v['rule_name']}")
            print(f"         {v['description']}")
    else:
        print("      ✅ No active vulnerabilities found")

    # ── Summary ───────────────────────────────────────────────
    total = len(passive_vulns) + len(active_vulns)
    print(f"\n{'='*60}")
    print(f"📊 Summary: {len(passive_vulns)} passive + {len(active_vulns)} active = {total} total findings")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_target.py <URL> [POST] ['{\"key\":\"value\"}']")
        print("Examples:")
        print("  python scan_target.py http://localhost:3000/login/")
        print('  python scan_target.py http://localhost:3000/login/ POST \'{"username":"admin","password":"123"}\'')
        sys.exit(1)

    url = sys.argv[1]
    method = sys.argv[2] if len(sys.argv) > 2 else "GET"
    body = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None

    scan_url(url, method, body)
