# 🧠 Prompt Chain for Claude Opus

## 🔥 RULES

* Always write working code
* Do not skip implementation
* Keep code modular and clean
* Explain briefly after each step

---

## 🧩 STEP 1 – Setup Project

Prompt:
Read AI_SPEC.md and TASKS.md.

Create full project structure and initialize FastAPI backend with SQLite and SQLAlchemy.

---

## 🧩 STEP 2 – Database + Models

Prompt:
Implement database connection and models:

* request_logs
* response_logs
* vulnerabilities

Include migrations or auto-create tables.

---

## 🧩 STEP 3 – Logging API

Prompt:
Implement REST APIs:

* POST /logs
* GET /logs
* GET /logs/{id}

Ensure request and response are stored correctly.

---

## 🧩 STEP 4 – Proxy Integration

Prompt:
Create mitmproxy addon (proxy/addon.py).

Intercept HTTP/HTTPS traffic and send logs to backend API.

---

## 🧩 STEP 5 – Passive Scanner

Prompt:
Implement passive scanning rules:

* Missing security headers
* Cookie issues

Trigger scan when logs are created.

---

## 🧩 STEP 6 – Active Scanner

Prompt:
Implement active scanning endpoint.

Inject payloads and detect:

* SQL Injection
* XSS

---

## 🧩 STEP 7 – Final Fix & Run

Prompt:
Ensure full system works end-to-end:

* Proxy → Backend → DB → Scanner

Provide instructions to run the system.
