# CloudVuln - Technical System Architecture & Documentation

## 1. Executive Architecture Summary

**CloudVuln** is an enterprise-grade cloud security engine engineered for continuous security assessment, static code analysis, cloud misconfiguration detection, and compliance auditing.

The platform follows a decoupled modern web application architecture:
- **Frontend Layer**: Single Page Application (SPA) built with React 18, Vite, Tailwind CSS, Lucide Icons, and Recharts. Deployed on **Vercel** edge infrastructure.
- **Backend Service Layer**: RESTful API engine powered by **FastAPI** (Python 3.10+), executed via **Gunicorn** process supervisor with **Uvicorn** worker processes. Deployed on **Render** cloud compute.
- **Database Engine**: **Supabase PostgreSQL** — cloud-hosted PostgreSQL as the single source of truth for all application data (users, scans, vulnerabilities, reports). Accessed via SQLAlchemy with psycopg3, connection pooling (pgBouncer), SSL enforcement, and pre-ping health checks.

---

## 2. System Architecture & Data Flow

```text
┌─────────────────────────────────────────────────────────────┐
│                      Client Browser                         │
│       React 18 SPA + Recharts + Tailwind CSS (Vercel)       │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTPS / JSON
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Vercel Edge Proxy                         │
│         Rewrites /api/* ──► Render Backend Service          │
└──────────────────────────────┬──────────────────────────────┘
                               │ TLS
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  Render Cloud Web Service                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │                  Gunicorn Supervisor                    │ │
│ │  ┌───────────────────┐        ┌───────────────────┐    │ │
│ │  │ Uvicorn Worker 1  │        │ Uvicorn Worker 2  │    │ │
│ │  └─────────┬─────────┘        └─────────┬─────────┘    │ │
│ └────────────┼────────────────────────────┼──────────────┘ │
│              │                            │                │
│              ▼                            ▼                │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │                    FastAPI Engine                       │ │
│ │ ┌───────────────┐ ┌───────────────┐ ┌─────────────────┐ │ │
│ │ │ Auth & JWT    │ │ Vulnerability │ │ Report Generator│ │ │
│ │ │ Security      │ │ Analyzer      │ │ (ReportLab PDF) │ │ │
│ │ └───────────────┘ └───────────────┘ └─────────────────┘ │ │
│ └────────────────────────────┬────────────────────────────┘ │
└──────────────────────────────┼──────────────────────────────┘
                               │ SQLAlchemy ORM
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              Supabase PostgreSQL (Primary DB)              │
│    Cloud-hosted | SSL | Connection Pooling | PITR Backups   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Security Architecture & Threat Model

### 3.1 Authentication & Token Lifecycle
- **Password Hashing**: Passlib with `bcrypt` (work factor 12) for secure password hashing and storage.
- **Access Tokens**: Short-lived JSON Web Tokens (`HS256`, 60-minute expiration) containing user identity (`sub`) and role scope.
- **Refresh Tokens**: Long-lived tokens (`HS256`, 7-day expiration) supporting sliding session refresh.

### 3.2 Network & Middleware Security
- **Rate Limiting**: Sliding-window in-memory rate limiter enforcing a limit of **100 requests / minute per IP address**.
- **CORS Protection**: Explicit origin whitelist (`ALLOWED_ORIGINS`) restricting unauthorized cross-site requests.
- **Security Headers**: Standard HTTP security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`, `Content-Security-Policy`).

### 3.3 Production Error Obscuration
In production mode (`APP_ENV=production`), global exception handling intercepts uncaught 500 errors, logging detailed stack traces to internal loggers while serving sanitized, generic error responses to clients to prevent information disclosure.

---

## 4. Vulnerability Detection Engine (Analyzer)

The scanner engine (`backend/analyzer.py`) processes three distinct scanning target vectors:

1. **Cloud Infrastructure Scan Vector**:
   - AWS S3 Public Read/Write ACLs
   - Open Security Group ingress (`0.0.0.0/0` on ports 22, 3389, 27017)
   - IAM Root Account Active API Keys
   - Unencrypted EBS & RDS Storage Volumes

2. **Container Security Vector**:
   - Root execution privilege in Dockerfiles (`USER root`)
   - Hardcoded Secrets / Tokens in Environment Variables
   - Outdated base image vulnerabilities
   - Unrestricted Container Resource Limits (CPU/RAM exhaustion)

3. **Infrastructure as Code (IaC) Vector**:
   - Broad IAM statement wildcard privileges (`Action: "*"`, `Resource: "*"`)
   - Unencrypted S3 Terraform State Backend Storage
   - Kubernetes Privileged Pod Security Contexts (`privileged: true`)

---

## 5. Database Schema & Persistence

Supabase PostgreSQL is the single source of truth for all persistent application data. All database access goes through SQLAlchemy ORM with psycopg3, using SSL-enforced connections and connection pooling via Supabase's pgBouncer.

### Primary Database Models (`backend/models.py`)

- **User**: ID, email, hashed_password, full_name, is_active, created_at, last_login.
- **Scan**: ID, scan_ref, target, provider, scan_type, status, risk_score, critical_count, high_count, medium_count, low_count, scan_data (JSON), created_at.
- **Vulnerability**: ID, scan_ref (FK→Scan), cve_id, title, severity, cvss_score, component, description, remediation, remediation_cmd, created_at.
- **Report**: ID, report_ref, scan_ref (FK→Scan), target, executive_summary, scan_type, html_generated, csv_generated, storage_path, file_name, file_type, created_at.
- **ActivityLog**: ID, text, type, time_ago, created_at.

---

## 6. Backup & Disaster Recovery

Supabase handles database backups at the infrastructure level:
- **Free Plan**: Daily automated backups retained for 7 days (accessible via Supabase Dashboard → Database → Backups).
- **Pro Plan**: Point-in-Time Recovery (PITR) with up to 30-day retention.

For supplementary local snapshots, run `backend/backup_db.py` to export all scan, report, user, and activity log data to a JSON file. This exports data without exposing password hashes.
