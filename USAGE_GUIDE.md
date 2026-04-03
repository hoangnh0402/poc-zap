# 📖 Hướng dẫn sử dụng Mini ZAP — Quét bảo mật dự án Localhost

## 📋 Yêu cầu

- Python 3.10+
- Dự án web đang chạy trên localhost (ví dụ: `http://localhost:3000`)

---

## 🚀 Khởi động hệ thống

### Bước 1: Cài đặt (chỉ lần đầu)

```bash
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

### Bước 2: Chạy Backend API

```bash
.\venv\Scripts\python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Sau khi chạy:
- API: http://127.0.0.1:8000
- Swagger UI: http://127.0.0.1:8000/docs

### Bước 3 (Tùy chọn): Chạy Proxy

```bash
.\venv\Scripts\mitmdump -s proxy/addon.py -p 8080
```

---

## 🔍 Cách quét dự án Localhost

### Cách 1: Dùng script `scan_target.py` (Khuyến nghị ✅)

Chỉ cần 1 lệnh — tool tự động: fetch trang → ghi log → passive scan → active scan.

#### Quét trang GET (hiển thị trang)

```bash
.\venv\Scripts\python scan_target.py http://localhost:3000/
.\venv\Scripts\python scan_target.py http://localhost:3000/login/
.\venv\Scripts\python scan_target.py http://localhost:3000/about
```

#### Quét URL có query parameters (dễ phát hiện SQLi/XSS nhất)

```bash
.\venv\Scripts\python scan_target.py "http://localhost:3000/api/users?id=1"
.\venv\Scripts\python scan_target.py "http://localhost:3000/api/search?q=test"
.\venv\Scripts\python scan_target.py "http://localhost:3000/products?category=1&sort=name"
```

#### Quét form POST (đăng nhập, đăng ký, tìm kiếm)

```bash
.\venv\Scripts\python scan_target.py http://localhost:3000/api/login POST "{\"username\":\"admin\",\"password\":\"123\"}"
.\venv\Scripts\python scan_target.py http://localhost:3000/api/register POST "{\"email\":\"test@test.com\",\"password\":\"abc\"}"
.\venv\Scripts\python scan_target.py http://localhost:3000/api/search POST "{\"keyword\":\"hello\"}"
```

#### Kết quả mẫu

```
============================================================
🎯 Target: GET http://localhost:3000/api/users?id=1
============================================================

[1/4] Fetching target...
      Status: 200
[2/4] Logging to Mini ZAP...
      ✅ Logged as #5
[3/4] Passive scan results...
      🟠 [MEDIUM] Missing Content-Security-Policy
      🟠 [MEDIUM] Missing X-Frame-Options
[4/4] Running active scan (SQLi + XSS)...
      🔴 [HIGH] SQL Injection
         Possible SQL injection detected. Payload '' OR 1=1--' triggered SQL error pattern.

============================================================
📊 Summary: 2 passive + 1 active = 3 total findings
============================================================
```

---

### Cách 2: Dùng Proxy (Quét tự động khi duyệt web)

#### Bước 1: Đảm bảo Backend API + Proxy đang chạy (xem phần Khởi động)

#### Bước 2: Mở Chrome qua Proxy

```bash
chrome.exe --proxy-server="http://127.0.0.1:8080" --ignore-certificate-errors
```

> ⚠️ Đối với localhost, cần thêm flag để Chrome gửi traffic qua proxy:
> ```bash
> chrome.exe --proxy-server="http://127.0.0.1:8080" --proxy-bypass-list="" --ignore-certificate-errors
> ```

#### Bước 3: Duyệt web bình thường

Truy cập `http://localhost:3000` và sử dụng ứng dụng — mọi request sẽ tự động được:
- ✅ Ghi log vào database
- ✅ Chạy passive scan (kiểm tra security headers + cookies)

#### Bước 4: Xem kết quả + Chạy Active Scan

1. Mở Swagger UI: http://127.0.0.1:8000/docs
2. `GET /logs/` → Xem tất cả request đã bắt được
3. Chọn request có query params hoặc POST body
4. `POST /scan/active/{log_id}` → Chạy active scan (SQLi + XSS)
5. `GET /vulnerabilities/` → Xem tất cả lỗ hổng phát hiện

---

### Cách 3: Dùng Swagger UI (Thủ công)

1. Mở http://127.0.0.1:8000/docs
2. Dùng `POST /logs/` để tạo log thủ công:
```json
{
  "method": "GET",
  "url": "http://localhost:3000/api/users?id=1",
  "request_headers": "{\"host\": \"localhost:3000\"}",
  "status_code": 200,
  "response_headers": "{\"content-type\": \"text/html\"}",
  "response_body": "<html>...</html>"
}
```
3. Dùng `POST /scan/active/{log_id}` để quét

---

## 🎯 Nên quét gì?

| Loại endpoint              | Ví dụ                                | Passive | Active (SQLi/XSS) |
|---------------------------|--------------------------------------|---------|-------------------|
| Trang tĩnh                | `/`, `/about`, `/login`              | ✅      | ⚪ Ít hiệu quả    |
| **URL có query params**   | `/api/users?id=1`, `/search?q=abc`   | ✅      | 🔴 **Hiệu quả cao** |
| **Form POST**             | `/api/login`, `/api/register`        | ✅      | 🔴 **Hiệu quả cao** |
| API REST có params        | `/api/products?category=1`           | ✅      | 🔴 **Hiệu quả cao** |
| API trả JSON không params | `/api/status`                        | ✅      | ⚪ Ít hiệu quả    |

> 💡 **Mẹo:** Tập trung quét các endpoint có **input từ người dùng** (query params, form fields, URL path params) — đó là nơi dễ có lỗ hổng nhất.

---

## 📡 Danh sách API

| Method | Endpoint                          | Mô tả                               |
|--------|-----------------------------------|--------------------------------------|
| GET    | `/`                               | Health check                         |
| POST   | `/logs/`                          | Tạo log + tự động passive scan      |
| GET    | `/logs/`                          | Xem tất cả logs                     |
| GET    | `/logs/{id}`                      | Xem log theo ID                     |
| POST   | `/scan/active/{id}`               | Chạy active scan (SQLi + XSS)       |
| GET    | `/vulnerabilities/`               | Xem tất cả lỗ hổng                  |
| GET    | `/vulnerabilities/by-log/{id}`    | Xem lỗ hổng theo log ID             |

---

## 🔍 Các loại lỗ hổng phát hiện được

### Passive Scanner (Tự động khi log request)

| Rule                              | Severity | Mô tả                                    |
|-----------------------------------|----------|-------------------------------------------|
| Missing Content-Security-Policy   | Medium   | Thiếu header CSP chống XSS               |
| Missing X-Frame-Options           | Medium   | Dễ bị clickjacking                        |
| Missing X-Content-Type-Options    | Low      | Browser có thể MIME-sniff nội dung        |
| Missing Strict-Transport-Security | Medium   | HTTPS có thể bị downgrade (chỉ HTTPS)    |
| Cookie Missing HttpOnly           | Medium   | Cookie bị truy cập từ JavaScript          |
| Cookie Missing Secure             | Medium   | Cookie gửi qua kết nối không mã hóa      |

### Active Scanner (Chạy thủ công)

| Loại          | Payload mẫu                       | Cách phát hiện                    |
|---------------|------------------------------------|------------------------------------|
| SQL Injection | `' OR 1=1--`                       | Tìm SQL error trong response       |
| SQL Injection | `' UNION SELECT NULL--`            | Tìm SQL error trong response       |
| XSS           | `<script>alert(1)</script>`        | Payload xuất hiện trong response   |
| XSS           | `<svg/onload=alert(1)>`            | Payload xuất hiện trong response   |

---

## ⚠️ Lưu ý quan trọng

1. **Chỉ quét dự án của bạn** — Không quét website của người khác khi chưa được phép
2. **Dự án target phải đang chạy** — Đảm bảo `localhost:3000` (hoặc port khác) đang hoạt động trước khi quét
3. **Active scan gửi request thật** — Nó sẽ gửi payload độc hại tới target, nên chỉ dùng trên môi trường dev/test
4. **Đây là công cụ POC** — Phát hiện các lỗ hổng cơ bản, không thay thế được các tool chuyên nghiệp như OWASP ZAP, Burp Suite
