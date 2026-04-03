"""Quick end-to-end test for all Mini ZAP APIs."""

import json

import httpx

base = "http://127.0.0.1:8000"
c = httpx.Client(base_url=base)

# 1. Health check
print("=== Health Check ===")
r = c.get("/")
print(r.status_code, r.json())
assert r.status_code == 200

# 2. Create a log WITH response headers missing security headers
print("\n=== Create Log (missing security headers) ===")
log_data = {
    "method": "GET",
    "url": "http://vulnerable-site.com/page?q=test",
    "request_headers": json.dumps(
        {"host": "vulnerable-site.com", "user-agent": "Mozilla/5.0"}
    ),
    "request_body": None,
    "status_code": 200,
    "response_headers": json.dumps(
        {"content-type": "text/html", "set-cookie": "session=abc123; Path=/"}
    ),
    "response_body": "<html><body>Hello</body></html>",
}
r = c.post("/logs/", json=log_data)
print(f"Status: {r.status_code}, Log ID: {r.json()['id']}")
assert r.status_code == 201
log_id = r.json()["id"]

# 3. Check vulnerabilities found by passive scan
print("\n=== Passive Scan Results ===")
r = c.get(f"/vulnerabilities/by-log/{log_id}")
vulns = r.json()
print(f"Found {len(vulns)} vulnerabilities:")
for v in vulns:
    sev = v["severity"]
    name = v["rule_name"]
    print(f"  [{sev}] {name}")
assert len(vulns) > 0, "Passive scan should have found issues!"

# 4. List all logs
print("\n=== All Logs ===")
r = c.get("/logs/")
print(f"Total logs: {len(r.json())}")
assert r.status_code == 200

# 5. Get single log
print(f"\n=== Get Log #{log_id} ===")
r = c.get(f"/logs/{log_id}")
print(f"Status: {r.status_code}, Method: {r.json()['method']}, URL: {r.json()['url']}")
assert r.status_code == 200

# 6. Get all vulnerabilities
print("\n=== All Vulnerabilities ===")
r = c.get("/vulnerabilities/")
print(f"Total vulnerabilities: {len(r.json())}")
assert r.status_code == 200

# 7. 404 test
print("\n=== 404 Test ===")
r = c.get("/logs/99999")
print(f"Status: {r.status_code} (expected 404)")
assert r.status_code == 404

print("\n✅ ALL TESTS PASSED")
