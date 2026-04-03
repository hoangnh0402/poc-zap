# 🛡️ AI Spec – Mini ZAP (POC)

## 🎯 Goal

Build a minimal security testing tool inspired by OWASP ZAP.

## Core Capabilities

* HTTP/HTTPS Proxy (mitmproxy)
* Traffic logging
* Passive scanning
* Active scanning (SQLi, XSS)
* REST API (FastAPI)

## Tech Stack

* Python
* mitmproxy
* FastAPI
* SQLite
* SQLAlchemy
* httpx

## Architecture

Browser → Proxy → Analyzer → Scanner → DB → API

## Constraints

* No authentication
* No UI required (Swagger only)
* Keep it simple (POC level)

## Definition of Done

* Proxy intercepts traffic
* Logs saved to DB
* Passive scan works
* Active scan detects SQLi & XSS
