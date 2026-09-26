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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


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


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(database.get_db),
) -> models.User:
    """Decode access token and return the authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate security credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
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
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        if not email:
            return None
        return db.query(models.User).filter(models.User.email == email).first()
    except JWTError:
        return None
