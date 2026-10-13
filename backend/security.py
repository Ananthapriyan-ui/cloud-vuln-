import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt, ExpiredSignatureError  # type: ignore[import-untyped]
from passlib.context import CryptContext  # type: ignore[import-untyped]
from fastapi import Depends, HTTPException, status, Request  # type: ignore[import-untyped]
from fastapi.security import OAuth2PasswordBearer  # type: ignore[import-untyped]
from sqlalchemy.orm import Session  # type: ignore[import-untyped]

import models  # type: ignore[import-untyped]
import database  # type: ignore[import-untyped]
import schemas  # type: ignore[import-untyped]
from config import settings  # type: ignore[import-untyped]

logger = logging.getLogger("CloudVulnSecurity")

# Bcrypt with 12 rounds (production strength)
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)

import httpx

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ──────────────────────────────────────────────
# Password hashing
# ──────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ──────────────────────────────────────────────
# JWT Token creation
# ──────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access", "iat": now})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode.update({"exp": expire, "type": "refresh", "iat": now})
    return jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)


# ──────────────────────────────────────────────
# Token verification
# ──────────────────────────────────────────────

def verify_refresh_token(token: str) -> str:
    """Verifies a refresh token and returns the user email (sub)."""
    try:
        payload = jwt.decode(token, settings.REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        token_type: str = payload.get("type")
        email: str = payload.get("sub")
        if not email or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return email
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def verify_oauth_provider_token(provider_token: str) -> dict:
    """
    Cryptographically / server-side verifies a Google or Supabase OAuth token.
    Extracts verified email and full name directly from the provider without trusting client claims.
    Raises HTTPException(401) if invalid or unverified.
    """
    token_str = (provider_token or "").strip()
    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing OAuth provider token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Attempt Google ID token verification via Google's tokeninfo API
    try:
        with httpx.Client(timeout=6.0) as client:
            resp = client.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={token_str}")
            if resp.status_code == 200:
                data = resp.json()
                email = data.get("email")
                email_verified = data.get("email_verified")
                if email and (email_verified is True or str(email_verified).lower() == "true"):
                    name = data.get("name") or data.get("given_name") or email.split("@")[0]
                    return {"email": email.lower(), "full_name": name, "provider": "google"}
    except Exception as e:
        logger.debug(f"Google tokeninfo check error: {e}")

    # 2. Attempt Supabase Auth user verification if Supabase URL is configured
    if settings.SUPABASE_URL:
        try:
            supabase_auth_url = f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/user"
            headers = {
                "Authorization": f"Bearer {token_str}",
                "apikey": settings.SUPABASE_SERVICE_ROLE_KEY or "",
            }
            with httpx.Client(timeout=6.0) as client:
                resp = client.get(supabase_auth_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    email = data.get("email")
                    if email:
                        meta = data.get("user_metadata") or {}
                        name = meta.get("full_name") or meta.get("name") or email.split("@")[0]
                        return {"email": email.lower(), "full_name": name, "provider": "supabase"}
        except Exception as e:
            logger.debug(f"Supabase auth check error: {e}")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Failed to verify OAuth identity with provider. Token is invalid or expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(database.get_db),
) -> models.User:
    """Decode access token and return the authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate security credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    actual_token = token
    if not actual_token:
        # Check query param for download links / new tab preview
        actual_token = request.query_params.get("token")
        if not actual_token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                actual_token = auth_header[7:]

    if not actual_token:
        raise credentials_exception

    try:
        payload = jwt.decode(actual_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type", "access")
        if not email or token_type != "access":
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired. Please refresh your session.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None or not user.is_active:
        logger.warning(f"Auth attempt for non-existent/inactive user: {email}")
        raise credentials_exception
    return user


# ──────────────────────────────────────────────
# Optional auth (does not raise 401 if missing)
# ──────────────────────────────────────────────

def get_optional_user(
    request: Request,
    db: Session = Depends(database.get_db),
) -> Optional[models.User]:
    """Returns the current user or None — never raises 401."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        token = request.query_params.get("token")

    if not token:
        return None

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        if not email:
            return None
        return db.query(models.User).filter(models.User.email == email).first()
    except JWTError:
        return None
