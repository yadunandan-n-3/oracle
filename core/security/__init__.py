"""
Security Module
===============

JWT authentication, password hashing, and token management.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings
from core.exceptions import AuthenticationError

# Password hashing context
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password string
    """
    return _pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Stored hash to check against

    Returns:
        True if password matches
    """
    return _pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        subject: Token subject (usually user ID or email)
        expires_delta: Optional custom expiration time
        extra_claims: Additional claims to include in the token

    Returns:
        Encoded JWT string
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)

    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "iat": now,
        "exp": now + expires_delta,
        "type": "access",
        "iss": settings.service_name,
    }
    if extra_claims:
        claims.update(extra_claims)

    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a JWT refresh token.

    Args:
        subject: Token subject (usually user ID or email)
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT string
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_refresh_token_expire_minutes)

    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "iat": now,
        "exp": now + expires_delta,
        "type": "refresh",
        "iss": settings.service_name,
    }

    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token.

    Args:
        token: JWT token string

    Returns:
        Decoded claims dictionary

    Raises:
        AuthenticationError: If token is invalid or expired
    """
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.service_name,
        )
        return claims
    except JWTError as e:
        raise AuthenticationError(f"Invalid token: {str(e)}")


def validate_token_type(payload: Dict[str, Any], expected_type: str) -> None:
    """
    Validate that a token has the expected type.

    Args:
        payload: Decoded token claims
        expected_type: Expected token type (e.g., "access", "refresh")

    Raises:
        AuthenticationError: If token type doesn't match
    """
    token_type = payload.get("type")
    if token_type != expected_type:
        raise AuthenticationError(
            f"Invalid token type: expected '{expected_type}', got '{token_type}'"
        )


def get_token_expiration(payload: Dict[str, Any]) -> Optional[datetime]:
    """
    Get the expiration timestamp from a token payload.

    Args:
        payload: Decoded token claims

    Returns:
        Expiration datetime or None
    """
    exp = payload.get("exp")
    if exp:
        return datetime.fromtimestamp(exp, tz=timezone.utc)
    return None


def is_token_expired(payload: Dict[str, Any]) -> bool:
    """
    Check if a token is expired.

    Args:
        payload: Decoded token claims

    Returns:
        True if token is expired
    """
    exp = get_token_expiration(payload)
    if exp:
        return datetime.now(timezone.utc) > exp
    return True


__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "validate_token_type",
    "get_token_expiration",
    "is_token_expired",
]
