import time
import uuid
import logging
import logging.config
from collections import defaultdict
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

import models
import schemas
import security
import database
import analyzer
import scan_comparator
import report_generator
import report_storage
import config
from seed_data import seed_database

# ──────────────────────────────────────────────
# Structured Logging Setup
# ──────────────────────────────────────────────

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "structured": {
            "format": "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "structured",
            "level": "DEBUG",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "cloudvuln_api.log",
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 3,
            "formatter": "structured",
            "level": "INFO",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": config.settings.LOG_LEVEL,
    },
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("CloudVulnEngine")

# ──────────────────────────────────────────────
# App bootstrap
# ──────────────────────────────────────────────

database.init_db()
seed_database()

app = FastAPI(
    title=config.settings.PROJECT_NAME,
    description="FastAPI Authentication, Security Engine & Vulnerability Platform",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ──────────────────────────────────────────────
# CORS Middleware
# ──────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["X-Request-ID", "X-Process-Time"],
)

# ──────────────────────────────────────────────
# Rate Limiting Store (in-memory, per IP)
# ──────────────────────────────────────────────

ip_request_counts: dict = defaultdict(list)

# ──────────────────────────────────────────────
# Security + Logging Middleware
# ──────────────────────────────────────────────

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

    # ─── Rate Limiting ───
    current_time = time.time()
    window_start = current_time - config.settings.RATE_LIMIT_WINDOW_SECONDS
    ip_request_counts[client_ip] = [
        t for t in ip_request_counts[client_ip] if t > window_start
    ]

    if len(ip_request_counts[client_ip]) >= config.settings.RATE_LIMIT_REQUESTS:
        logger.warning(f"[{request_id}] Rate limit exceeded | IP={client_ip} | path={request.url.path}")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": True,
                "message": "Rate limit exceeded. Maximum 100 requests/minute. Please slow down.",
                "status_code": 429,
                "retry_after": config.settings.RATE_LIMIT_WINDOW_SECONDS,
            },
        )

    ip_request_counts[client_ip].append(current_time)

    # ─── Process Request ───
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)

    # ─── Security Headers ───
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' https://nvd.nist.gov https://api.first.org; "
        "frame-ancestors 'self';"
    )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{duration_ms}ms"

    # Remove server fingerprinting safely if present
    if "server" in response.headers:
        del response.headers["server"]
    if "x-powered-by" in response.headers:
        del response.headers["x-powered-by"]

    log_level = logging.WARNING if response.status_code >= 400 else logging.INFO
    logger.log(
        log_level,
        f"[{request_id}] {request.method} {request.url.path} "
        f"| status={response.status_code} | ip={client_ip} | {duration_ms}ms"
    )

    return response


# ──────────────────────────────────────────────
# Global Exception Handlers
# ──────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(
        f"HTTP {exc.status_code} on {request.method} {request.url.path}: {exc.detail}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": True, "message": str(exc.detail), "status_code": exc.status_code},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    # Build a human-readable message
    field_errors = []
    for e in errors:
        loc = " → ".join(str(l) for l in e.get("loc", []) if l != "body")
        field_errors.append(f"{loc}: {e['msg']}" if loc else e["msg"])
    message = "; ".join(field_errors) if field_errors else "Invalid request data"
    logger.warning(f"Validation error on {request.url.path}: {message}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": True,
            "message": message,
            "status_code": 422,
            "detail": errors,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "message": "An internal server error occurred. The incident has been logged.",
            "status_code": 500,
        },
    )


# ──────────────────────────────────────────────
# Health & Supabase Connectivity Check
# ──────────────────────────────────────────────

@app.get("/")
def health_check():
    db_connected = database.check_db_connection()
    return {
        "status": "online" if db_connected else "degraded",
        "engine": "CloudVuln Security Engine v2",
        "version": "2.0.0",
        "database": "Supabase PostgreSQL",
        "database_connected": db_connected,
        "features": ["jwt-auth", "supabase-postgresql", "supabase-storage", "rate-limiting", "security-headers"],
    }


@app.get("/api/health")
def api_health(db: Session = Depends(database.get_db)):
    is_healthy = database.check_db_connection()
    db_status = "ok" if is_healthy else "disconnected"
    return {
        "api": "ok",
        "database": db_status,
        "provider": "Supabase PostgreSQL",
        "version": "2.0.0"
    }


# ──────────────────────────────────────────────
# Auth Endpoints
# ──────────────────────────────────────────────

@app.post("/api/auth/register", response_model=schemas.Token, status_code=status.HTTP_201_CREATED)
def register(user_in: schemas.UserCreate, db: Session = Depends(database.get_db)):
    existing = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    hashed_pwd = security.get_password_hash(user_in.password)
    db_user = models.User(
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hashed_pwd,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    access_token = security.create_access_token(data={"sub": db_user.email})
    refresh_token = security.create_refresh_token(data={"sub": db_user.email})

    logger.info(f"New user registered: {db_user.email}")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": db_user,
    }


@app.post("/api/auth/login", response_model=schemas.Token)
def login(user_credentials: schemas.UserLogin, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == user_credentials.email).first()

    # Use constant-time comparison to prevent timing attacks
    if not user or not security.verify_password(user_credentials.password, user.hashed_password):
        logger.warning(f"Failed login attempt for email: {user_credentials.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email address or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Contact an administrator.",
        )

    # Update last_login
    import datetime
    user.last_login = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    access_token = security.create_access_token(data={"sub": user.email})
    refresh_token = security.create_refresh_token(data={"sub": user.email})

    logger.info(f"Successful login: {user.email}")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user,
    }


@app.post("/api/auth/refresh")
def refresh_token(req: schemas.RefreshTokenRequest, db: Session = Depends(database.get_db)):
    email = security.verify_refresh_token(req.refresh_token)
    user = db.query(models.User).filter(models.User.email == email).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account inactive or not found",
        )

    new_access_token = security.create_access_token(data={"sub": user.email})
    new_refresh_token = security.create_refresh_token(data={"sub": user.email})

    logger.info(f"Token refreshed for: {user.email}")
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "user": user,
    }


@app.get("/api/auth/me", response_model=schemas.UserResponse)
def get_me(current_user: models.User = Depends(security.get_current_user)):
    return current_user


@app.post("/api/auth/oauth-sync", response_model=schemas.Token)
def oauth_sync(req: schemas.OAuthSyncRequest, db: Session = Depends(database.get_db)):
    """
    Synchronizes a verified Google OAuth user into Supabase PostgreSQL.
    If the user does not exist, creates the account without requiring a password.
    If the user already exists, updates last_login and issues valid JWT tokens.
    """
    user = db.query(models.User).filter(models.User.email == req.email).first()
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)

    if not user:
        # Create user record in Supabase PostgreSQL
        user = models.User(
            email=req.email,
            full_name=req.full_name or req.email.split("@")[0],
            hashed_password=security.get_password_hash(security.secrets.token_urlsafe(32)),
            is_active=True,
            created_at=now,
            last_login=now,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"Google OAuth user created in Supabase PostgreSQL: {user.email}")
    else:
        user.last_login = now
        db.commit()
        logger.info(f"Google OAuth user logged in from Supabase PostgreSQL: {user.email}")

    access_token = security.create_access_token(data={"sub": user.email})
    refresh_token = security.create_refresh_token(data={"sub": user.email})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user,
    }


@app.post("/api/auth/logout")
def logout(current_user: models.User = Depends(security.get_current_user)):
    logger.info(f"User logged out: {current_user.email}")
    return {"message": "Logged out successfully. Please discard your tokens client-side."}


# ──────────────────────────────────────────────
# Dashboard Endpoints
# ──────────────────────────────────────────────

@app.get("/api/dashboard/summary", response_model=schemas.DashboardSummary)
def get_dashboard_summary(db: Session = Depends(database.get_db)):
    from sqlalchemy import func

    # Aggregate counts in a single query
    result = db.query(
        func.count(models.Scan.id).label("total_scans"),
        func.coalesce(func.sum(models.Scan.critical_count), 0).label("critical"),
        func.coalesce(func.sum(models.Scan.high_count), 0).label("high"),
        func.coalesce(func.sum(models.Scan.medium_count), 0).label("medium"),
        func.coalesce(func.sum(models.Scan.low_count), 0).label("low"),
        func.count(func.distinct(models.Scan.target)).label("monitored_assets"),
    ).first()

    total_scans = result.total_scans if result else 0
    monitored_assets = result.monitored_assets if (result and result.monitored_assets) else (1 if total_scans > 0 else 0)

    active_scans = db.query(models.Scan).filter(
        models.Scan.status == "running"
    ).count()

    # Calculate real posture score from latest completed scans
    avg_risk = db.query(func.avg(models.Scan.risk_score)).filter(models.Scan.status != "running").scalar()
    if avg_risk is not None:
        posture_score = max(0, min(100, int(100 - (avg_risk * 10))))
        compliance_score = round(max(0.0, min(100.0, 100.0 - (avg_risk * 5)), 1))
    else:
        posture_score = 100
        compliance_score = 100.0

    return {
        "total_scans": total_scans,
        "monitored_assets": monitored_assets,
        "critical_vulnerabilities": result.critical if result else 0,
        "high_vulnerabilities": result.high if result else 0,
        "medium_vulnerabilities": result.medium if result else 0,
        "low_vulnerabilities": result.low if result else 0,
        "info_vulnerabilities": 0,
        "active_scans": active_scans,
        "compliance_score": float(compliance_score),
        "posture_score": posture_score,
    }


@app.get("/api/dashboard/risk-statistics", response_model=schemas.RiskStatisticsResponse)
def get_risk_statistics(db: Session = Depends(database.get_db)):
    from sqlalchemy import func

    result = db.query(
        func.coalesce(func.sum(models.Scan.critical_count), 0).label("critical"),
        func.coalesce(func.sum(models.Scan.high_count), 0).label("high"),
        func.coalesce(func.sum(models.Scan.medium_count), 0).label("medium"),
        func.coalesce(func.sum(models.Scan.low_count), 0).label("low"),
    ).first()

    critical = int(result.critical) if result else 0
    high = int(result.high) if result else 0
    medium = int(result.medium) if result else 0
    low = int(result.low) if result else 0

    severity_breakdown = [
        {"name": "Critical", "value": critical, "color": "#ef4444"},
        {"name": "High",     "value": high,     "color": "#f97316"},
        {"name": "Medium",   "value": medium,   "color": "#f59e0b"},
        {"name": "Low",      "value": low,      "color": "#00f3ff"},
        {"name": "Info",     "value": 0,        "color": "#64748b"},
    ]

    # Calculate real chronological trend history from completed scans in DB
    completed_scans = (
        db.query(models.Scan)
        .filter(models.Scan.status != "running")
        .order_by(models.Scan.created_at.asc())
        .all()
    )

    trend_history = []
    if completed_scans:
        for s in completed_scans[-10:]:
            date_label = s.created_at.strftime("%b %d, %H:%M") if s.created_at else s.scan_ref
            trend_history.append({
                "date": date_label,
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
            })

    return {"severity_breakdown": severity_breakdown, "trend_history": trend_history}


@app.get("/api/dashboard/recent-scans", response_model=List[schemas.ScanResponse])
def get_recent_scans(db: Session = Depends(database.get_db)):
    return (
        db.query(models.Scan)
        .order_by(models.Scan.created_at.desc())
        .limit(10)
        .all()
    )


@app.get("/api/dashboard/activity", response_model=List[schemas.ActivityLogResponse])
def get_recent_activity(db: Session = Depends(database.get_db)):
    return (
        db.query(models.ActivityLog)
        .order_by(models.ActivityLog.created_at.desc())
        .limit(10)
        .all()
    )


# ──────────────────────────────────────────────
# Security Analysis & CVE
# ──────────────────────────────────────────────

@app.post("/api/analysis/target", response_model=schemas.SecurityAnalysisResponse)
def analyze_security_target(
    req: schemas.SecurityAnalysisRequest,
    db: Session = Depends(database.get_db),
):
    result = analyzer.perform_security_analysis(req.target_url)

    db.add(models.ActivityLog(
        text=f"Security analysis executed for {result['target']} (Score: {result['security_score']}/100)",
        type="info" if result["risk_level"] in ("Low", "Medium") else "warning",
        time_ago="Just now",
    ))
    db.commit()
    return result


@app.get("/api/cve/search", response_model=List[schemas.CVEResult])
def search_cve_database(query: str = "Tomcat"):
    if not query or len(query) > 200:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid CVE query")
    return analyzer.query_nvd_cve(query)


@app.get("/api/whois/lookup", response_model=schemas.WhoisSummary)
def lookup_whois(domain: str = "cloudvuln.io"):
    return analyzer.analyze_whois(domain)


@app.post("/api/analysis/owasp", response_model=schemas.OWASPSummary)
def analyze_owasp(req: schemas.SecurityAnalysisRequest):
    return analyzer.analyze_owasp_top10(req.target_url)


# ──────────────────────────────────────────────
# Scan History CRUD
# ──────────────────────────────────────────────

@app.post("/api/scans", response_model=schemas.ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan_record(
    scan_in: schemas.ScanCreate,
    db: Session = Depends(database.get_db),
):
    import random
    scan_ref = f"SCAN-2026-{random.randint(1000, 9999)}"

    new_scan = models.Scan(
        scan_ref=scan_ref,
        target=scan_in.target,
        provider=scan_in.provider or "AWS US-East-1",
        scan_type=scan_in.scan_type or "Cloud Misconfig",
        status=scan_in.status or "passed",
        critical_count=scan_in.critical_count or 0,
        high_count=scan_in.high_count or 0,
        medium_count=scan_in.medium_count or 0,
        low_count=scan_in.low_count or 0,
        risk_score=scan_in.risk_score or 0.0,
        duration=scan_in.duration or "2m 15s",
        scan_data=scan_in.scan_data,
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    new_report = models.Report(
        report_ref=f"REP-{scan_ref}",
        scan_ref=scan_ref,
        target=scan_in.target,
        executive_summary=f"Automated Security Posture Analysis for target {scan_in.target}.",
        scan_type=scan_in.scan_type or "Cloud Misconfig",
        duration=scan_in.duration or "2m 15s",
        html_generated=True,
        csv_generated=True,
    )
    db.add(new_report)

    # Persist real findings into vulnerabilities table in Supabase PostgreSQL
    if scan_in.scan_data:
        try:
            import json
            parsed = json.loads(scan_in.scan_data)
            # 1. OWASP findings that failed or generated warnings
            owasp_findings = (parsed.get("owasp_summary") or {}).get("findings") or []
            for f in owasp_findings:
                if f.get("status") in ("Failed", "Warning"):
                    db.add(models.Vulnerability(
                        cve_id=f.get("related_cve") or f.get("owasp_id") or "OWASP-FINDING",
                        title=f.get("title") or f.get("category") or "Security Finding",
                        severity=f.get("severity") or "Medium",
                        cvss_score=float(f.get("cvss_score") or 5.0),
                        component=f.get("affected_component") or "Web Application",
                        description=f.get("description") or "",
                        remediation=f.get("recommendation") or "",
                        remediation_cmd=f.get("remediation_cmd") or "",
                        scan_ref=scan_ref,
                    ))

            # 2. CVE findings from NVD
            cve_findings = parsed.get("cve_findings") or []
            for c in cve_findings:
                db.add(models.Vulnerability(
                    cve_id=c.get("cve_id") or "CVE-UNKNOWN",
                    title=c.get("description", "")[:280] or "Vulnerability Finding",
                    severity=c.get("severity") or "Medium",
                    cvss_score=float(c.get("cvss_score") or 5.0),
                    component=c.get("component") or "Web Server",
                    description=c.get("description") or "",
                    remediation=c.get("remediation") or "Update package to latest secure version",
                    remediation_cmd=c.get("remediation_cmd") or "",
                    scan_ref=scan_ref,
                ))
        except Exception as e:
            logger.warning(f"Could not parse and persist detailed findings for {scan_ref}: {e}")

    db.add(models.ActivityLog(
        text=f"New assessment recorded: {scan_ref} on {scan_in.target}",
        type="info" if scan_in.status == "passed" else "warning",
        time_ago="Just now",
    ))
    db.commit()
    
    logger.info(f"Scan created: {scan_ref} | target={scan_in.target}")
    return new_scan


@app.get("/api/scans", response_model=List[schemas.ScanResponse])
def get_scans_history(
    search: Optional[str] = None,
    status_filter: Optional[str] = None,
    sort_by: str = "date_desc",
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(database.get_db),
):
    # Validate pagination
    if limit < 1 or limit > 500:
        limit = 100
    if offset < 0:
        offset = 0

    query = db.query(models.Scan)

    if search:
        search = search[:100]  # cap length
        pattern = f"%{search}%"
        query = query.filter(
            models.Scan.target.ilike(pattern)
            | models.Scan.scan_ref.ilike(pattern)
            | models.Scan.provider.ilike(pattern)
        )

    if status_filter and status_filter.lower() != "all":
        query = query.filter(models.Scan.status.ilike(status_filter))

    order_map = {
        "risk_desc": models.Scan.risk_score.desc(),
        "risk_asc":  models.Scan.risk_score.asc(),
        "date_asc":  models.Scan.created_at.asc(),
        "date_desc": models.Scan.created_at.desc(),
    }
    query = query.order_by(order_map.get(sort_by, models.Scan.created_at.desc()))

    return query.offset(offset).limit(limit).all()


def _get_scan_by_any_ref(scan_ref: str, db: Session) -> models.Scan:
    scan = db.query(models.Scan).filter(models.Scan.scan_ref == scan_ref).first()
    if not scan:
        report = db.query(models.Report).filter(models.Report.report_ref == scan_ref).first()
        if report:
            scan = db.query(models.Scan).filter(models.Scan.scan_ref == report.scan_ref).first()
    if not scan and scan_ref.isdigit():
        scan = db.query(models.Scan).filter(models.Scan.id == int(scan_ref)).first()
    if not scan:
        scan = db.query(models.Scan).filter(models.Scan.target.ilike(f"%{scan_ref}%")).first()
    return scan


# ──────────────────────────────────────────────
# Scan Comparison & Trend Endpoints (Defined before parameterized {scan_ref})
# ──────────────────────────────────────────────

@app.get("/api/scans/comparison-options", response_model=List[schemas.ScanComparisonOption])
def get_comparison_options(db: Session = Depends(database.get_db)):
    """
    Returns only real completed scans stored in the database for comparison selection.
    """
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.status != "running")
        .order_by(models.Scan.created_at.desc())
        .all()
    )

    results = []
    for s in scans:
        parsed = scan_comparator.parse_scan_data(s)
        sec_score = parsed.get("security_score")
        if sec_score is None:
            sec_score = max(0, min(100, int(100 - (s.risk_score * 10))))

        tot = s.critical_count + s.high_count + s.medium_count + s.low_count
        results.append({
            "id": s.id,
            "scan_ref": s.scan_ref,
            "target": s.target,
            "provider": s.provider,
            "scan_type": s.scan_type,
            "status": s.status,
            "risk_score": s.risk_score,
            "security_score": sec_score,
            "risk_level": parsed.get("risk_level", s.status.capitalize()),
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "medium_count": s.medium_count,
            "low_count": s.low_count,
            "total_findings": tot,
            "duration": s.duration,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if s.created_at else "",
        })

    return results


@app.get("/api/scans/trend", response_model=schemas.ScanTrendResponse)
def get_scans_trend(
    target: Optional[str] = None,
    db: Session = Depends(database.get_db),
):
    """
    Fetch real historical score and severity trend data across all completed scans in database.
    """
    return scan_comparator.get_real_scan_trend(db, target)


@app.get("/api/scans/compare/{prev_scan_ref}/{latest_scan_ref}", response_model=schemas.ScanComparisonResponse)
def compare_scans(
    prev_scan_ref: str,
    latest_scan_ref: str,
    db: Session = Depends(database.get_db),
):
    """
    Compare two real completed scans.
    Validates scan existence, completed status, distinct scan refs, and returns structured comparison.
    """
    if prev_scan_ref == latest_scan_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot compare a scan with itself. Please select two distinct completed scans.",
        )

    prev_scan = _get_scan_by_any_ref(prev_scan_ref, db)
    if not prev_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Previous scan '{prev_scan_ref}' not found in database.",
        )

    latest_scan = _get_scan_by_any_ref(latest_scan_ref, db)
    if not latest_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Latest scan '{latest_scan_ref}' not found in database.",
        )

    if prev_scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Previous scan '{prev_scan.scan_ref}' is currently running and cannot be compared.",
        )

    if latest_scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Latest scan '{latest_scan.scan_ref}' is currently running and cannot be compared.",
        )

    comparison_result = scan_comparator.compare_scans_data(prev_scan, latest_scan)
    return comparison_result


@app.get("/api/scans/compare/{prev_scan_ref}/{latest_scan_ref}/download")
def download_comparison_report(
    prev_scan_ref: str,
    latest_scan_ref: str,
    format: str = "html",
    db: Session = Depends(database.get_db),
):
    """
    Download comparison report in HTML or CSV format based on real comparison results.
    """
    if prev_scan_ref == latest_scan_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot generate comparison report for identical scans.",
        )

    prev_scan = _get_scan_by_any_ref(prev_scan_ref, db)
    if not prev_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Previous scan '{prev_scan_ref}' not found in database.",
        )

    latest_scan = _get_scan_by_any_ref(latest_scan_ref, db)
    if not latest_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Latest scan '{latest_scan_ref}' not found in database.",
        )

    comparison_result = scan_comparator.compare_scans_data(prev_scan, latest_scan)

    if format.lower() == "csv":
        csv_str = report_generator.generate_comparison_csv_report(comparison_result)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=CLOUDVULN_Comparison_{prev_scan.scan_ref}_vs_{latest_scan.scan_ref}.csv"
            },
        )
    else:
        html_str = report_generator.generate_comparison_html_report(comparison_result)
        return Response(
            content=html_str,
            media_type="text/html",
            headers={
                "Content-Disposition": f"attachment; filename=CLOUDVULN_Comparison_{prev_scan.scan_ref}_vs_{latest_scan.scan_ref}.html"
            },
        )


@app.get("/api/scans/{scan_ref}", response_model=schemas.ScanDetailResponse)
def get_scan_by_ref(scan_ref: str, db: Session = Depends(database.get_db)):
    scan = _get_scan_by_any_ref(scan_ref, db)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_ref}' not found",
        )
    return scan


@app.delete("/api/scans/{scan_ref}")
def delete_scan_record(
    scan_ref: str,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    scan = _get_scan_by_any_ref(scan_ref, db)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_ref}' not found",
        )
    ref = scan.scan_ref
    db.delete(scan)
    db.commit()
    logger.info(f"Scan '{ref}' deleted by {current_user.email}")
    return {"message": f"Scan '{ref}' deleted successfully", "scan_ref": ref}


# ──────────────────────────────────────────────
# Report Endpoints
# ──────────────────────────────────────────────

@app.get("/api/reports")
def list_reports(db: Session = Depends(database.get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.created_at.desc()).all()
    return [{
        "id": s.id,
        "scan_ref": s.scan_ref,
        "target": s.target,
        "cloud_provider": s.provider,
        "status": s.status,
        "risk_score": s.risk_score,
        "critical_count": s.critical_count,
        "high_count": s.high_count,
        "medium_count": s.medium_count,
        "low_count": s.low_count,
        "executed_at": s.created_at.strftime("%Y-%m-%d %H:%M UTC") if s.created_at else "",
    } for s in scans]


@app.get("/api/reports/{scan_ref}")
def get_report_by_scan_ref(scan_ref: str, db: Session = Depends(database.get_db)):
    scan = _get_scan_by_any_ref(scan_ref, db)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for scan '{scan_ref}' not found",
        )

    import json
    parsed_data = {}
    if scan.scan_data:
        try:
            parsed_data = json.loads(scan.scan_data)
        except Exception:
            pass

    return {
        "id":             scan.id,
        "scan_ref":       scan.scan_ref,
        "target":         scan.target,
        "cloud_provider": scan.provider,
        "status":         scan.status,
        "risk_score":     scan.risk_score,
        "critical_count": scan.critical_count,
        "high_count":     scan.high_count,
        "medium_count":   scan.medium_count,
        "low_count":      scan.low_count,
        "executed_at":    scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "",
        "duration":       scan.duration,
        "scan_data":      parsed_data
    }


@app.get("/api/reports/{scan_ref}/html")
def get_report_html(scan_ref: str, db: Session = Depends(database.get_db)):
    import json

    scan = _get_scan_by_any_ref(scan_ref, db)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for scan '{scan_ref}' not found",
        )

    parsed_data = {}
    if scan.scan_data:
        try:
            parsed_data = json.loads(scan.scan_data)
        except Exception:
            pass

    scan_dict = {
        "scan_ref":       scan.scan_ref,
        "target":         scan.target,
        "provider":       scan.provider,
        "status":         scan.status,
        "risk_score":     scan.risk_score,
        "critical_count": scan.critical_count,
        "high_count":     scan.high_count,
        "medium_count":   scan.medium_count,
        "low_count":      scan.low_count,
        "created_at":     scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "",
        "scan_data":      parsed_data
    }

    html_str = report_generator.generate_html_report(scan_dict)
    return Response(
        content=html_str,
        media_type="text/html",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )


@app.get("/api/reports/{scan_ref}/download")
def download_report_file(
    scan_ref: str,
    format: str = "html",
    db: Session = Depends(database.get_db),
):
    import json

    scan = _get_scan_by_any_ref(scan_ref, db)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for scan '{scan_ref}' not found",
        )

    parsed_data = {}
    if scan.scan_data:
        try:
            parsed_data = json.loads(scan.scan_data)
        except Exception:
            pass

    scan_dict = {
        "scan_ref":       scan.scan_ref,
        "target":         scan.target,
        "provider":       scan.provider,
        "status":         scan.status,
        "risk_score":     scan.risk_score,
        "critical_count": scan.critical_count,
        "high_count":     scan.high_count,
        "medium_count":   scan.medium_count,
        "low_count":      scan.low_count,
        "created_at":     scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "",
        "scan_data":      parsed_data
    }

    filename = f"CLOUDVULN_Report_{scan.scan_ref}.{format.lower()}"
    report_record = db.query(models.Report).filter(models.Report.scan_ref == scan.scan_ref).first()

    if format.lower() == "csv":
        # Check if already stored in Supabase Storage
        file_bytes = None
        if report_record and report_record.storage_path and report_record.file_type == "csv":
            file_bytes = report_storage.download_report_file(report_record.storage_path)

        if not file_bytes:
            csv_str = report_generator.generate_csv_report(scan_dict)
            file_bytes = csv_str.encode("utf-8")
            storage_path = report_storage.upload_report_file(
                file_bytes=file_bytes,
                file_name=filename,
                content_type="text/csv",
            )
            if storage_path and report_record:
                report_record.storage_path = storage_path
                report_record.file_name = filename
                report_record.file_type = "csv"
                report_record.csv_generated = True
                db.commit()

        return Response(
            content=file_bytes,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    else:
        file_bytes = None
        if report_record and report_record.storage_path and report_record.file_type == "html":
            file_bytes = report_storage.download_report_file(report_record.storage_path)

        if not file_bytes:
            html_str = report_generator.generate_html_report(scan_dict)
            file_bytes = html_str.encode("utf-8")
            storage_path = report_storage.upload_report_file(
                file_bytes=file_bytes,
                file_name=filename,
                content_type="text/html",
            )
            if storage_path and report_record:
                report_record.storage_path = storage_path
                report_record.file_name = filename
                report_record.file_type = "html"
                report_record.html_generated = True
                db.commit()

        return Response(
            content=file_bytes,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )


