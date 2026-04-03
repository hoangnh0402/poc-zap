# 📋 Task Breakdown – Mini ZAP POC

## Phase 1: Project Setup

* Create project structure
* Setup FastAPI
* Setup SQLite + SQLAlchemy
* Create base config

---

## Phase 2: Logging System

### Backend

* Create models:

  * request_logs
  * response_logs
* Create API:

  * POST /logs
  * GET /logs
  * GET /logs/{id}

---

## Phase 3: Proxy (mitmproxy)

* Create addon.py
* Intercept:

  * request
  * response
* Extract:

  * URL
  * method
  * headers
  * body
* Send to backend API

---

## Phase 4: Passive Scanner

* Implement rules:

  * Missing CSP header
  * Missing X-Frame-Options
  * Cookie missing HttpOnly/Secure
* Save vulnerabilities to DB

---

## Phase 5: Active Scanner

* Endpoint:

  * POST /scan/active/{request_id}

* Logic:

  * Load request
  * Inject payloads
  * Send via httpx
  * Analyze response

---

## Phase 6: Scanner Rules

### SQLi

* Payload:

  * ' OR 1=1--
* Detect:

  * SQL error message

### XSS

* Payload:

  * <script>alert(1)</script>
* Detect:

  * Reflected payload

---

## Phase 7: Final Integration

* Ensure:

  * Proxy → Backend works
  * Logs saved correctly
  * Scan results stored
