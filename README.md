# 🛡️ Mini ZAP — Security Testing Tool (POC)

A minimal security testing tool inspired by OWASP ZAP, built with Python.

## Architecture

```
Browser → mitmproxy (Proxy) → FastAPI (Backend) → SQLite (DB)
                                    ↓
                            Passive Scanner (auto)
                            Active Scanner (on-demand)
```

## Tech Stack

- **Python 3.10+**
- **FastAPI** — REST API + Swagger UI
- **SQLAlchemy** — ORM + SQLite
- **mitmproxy** — HTTP/HTTPS proxy
- **httpx** — HTTP client for active scanning

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
python -m venv venv

# Windows
.\venv\Scripts\pip install -r requirements.txt

# Linux/Mac
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Start the Backend API

```bash
# Windows
.\venv\Scripts\python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Linux/Mac
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- Swagger UI: **http://127.0.0.1:8000/docs**
- Health check: **http://127.0.0.1:8000/**

### 3. Start the Proxy (mitmproxy)

> ⚠️ Start the backend API **first**, then the proxy.

```bash
# Windows
.\venv\Scripts\mitmdump -s proxy/addon.py -p 8080

# Linux/Mac
mitmdump -s proxy/addon.py -p 8080
```

### 4. Configure Browser

Set your browser's HTTP proxy to `127.0.0.1:8080`.

For HTTPS, install the mitmproxy CA certificate:
1. With proxy running, visit **http://mitm.it**
2. Download and install the certificate for your OS

### 5. Browse & Scan

1. **Browse websites** through the proxy — traffic is automatically logged
2. **Passive scan** runs automatically on each request (checks security headers & cookies)
3. **Active scan** — pick a logged request and scan it:
   ```bash
   curl -X POST http://127.0.0.1:8000/scan/active/1
   ```
4. **View results**:
   ```bash
   # All vulnerabilities
   curl http://127.0.0.1:8000/vulnerabilities/

   # Vulnerabilities for a specific request
   curl http://127.0.0.1:8000/vulnerabilities/by-log/1
   ```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `POST` | `/logs/` | Create log (+ auto passive scan) |
| `GET` | `/logs/` | List all logs |
| `GET` | `/logs/{id}` | Get log by ID |
| `POST` | `/scan/active/{id}` | Run active scan on a logged request |
| `GET` | `/vulnerabilities/` | List all vulnerabilities |
| `GET` | `/vulnerabilities/by-log/{id}` | Get vulnerabilities by log ID |

---

## 🔍 Scanner Rules

### Passive Scanner (automatic)
| Rule | Severity |
|------|----------|
| Missing Content-Security-Policy | Medium |
| Missing X-Frame-Options | Medium |
| Missing X-Content-Type-Options | Low |
| Missing Strict-Transport-Security (HTTPS) | Medium |
| Cookie missing HttpOnly flag | Medium |
| Cookie missing Secure flag | Medium |

### Active Scanner (on-demand)
| Type | Payloads | Detection |
|------|----------|-----------|
| SQL Injection | `' OR 1=1--`, `' UNION SELECT NULL--`, etc. | SQL error patterns in response |
| XSS | `<script>alert(1)</script>`, `<svg/onload=alert(1)>`, etc. | Payload reflected in response |

---

## 🧪 Run Tests

```bash
# Start the server first, then:
.\venv\Scripts\python test_api.py
```

---

## Project Structure

```
poc-zap/
├── app/
│   ├── config.py           # Settings (env vars)
│   ├── database.py         # SQLAlchemy engine + session
│   ├── main.py             # FastAPI app entry point
│   ├── models/
│   │   ├── request_log.py  # RequestLog table
│   │   └── vulnerability.py # Vulnerability table
│   ├── schemas/
│   │   ├── request_log.py  # Pydantic validation
│   │   └── vulnerability.py
│   ├── routers/
│   │   ├── logs.py         # Log CRUD + passive scan trigger
│   │   ├── scan.py         # Active scan endpoint
│   │   └── vulnerabilities.py
│   └── scanner/
│       ├── passive.py      # Security header & cookie checks
│       └── active.py       # SQLi & XSS injection engine
├── proxy/
│   └── addon.py            # mitmproxy traffic interceptor
├── requirements.txt
├── test_api.py             # E2E test script
└── .env                    # Environment config
```