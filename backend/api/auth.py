"""
Authentication API Routes
=========================

User login, registration, and token management.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from core.exceptions import AuthenticationError
from core.logging import get_logger
from core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_token_type,
)

logger = get_logger(__name__)

router = APIRouter()


# Schemas

class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    name: str = ""
    password: str
    organization_name: str = ""


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str


# Routes


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest) -> Dict[str, Any]:
    """
    Authenticate user and return tokens.

    In production, this verifies against the database.
    For now, a simplified auth flow.
    """
    if not request.email or not request.password:
        raise AuthenticationError("Email and password required")

    # Create tokens
    access_token = create_access_token(
        subject=request.email,
        expires_delta=timedelta(hours=1),
    )
    refresh_token = create_refresh_token(subject=request.email)

    logger.info("auth.login", email=request.email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    ).model_dump()


@router.post("/register", response_model=TokenResponse)
async def register(request: RegisterRequest) -> Dict[str, Any]:
    """
    Register a new user.

    Creates user account and organization, returns tokens.
    """
    if not request.email or not request.password:
        raise AuthenticationError("Email and password required")

    if len(request.password) < 8:
        raise AuthenticationError("Password must be at least 8 characters")

    hashed = hash_password(request.password)

    logger.info("auth.register", email=request.email)

    # Create tokens
    access_token = create_access_token(
        subject=request.email,
        extra_claims={"name": request.name},
    )
    refresh_token = create_refresh_token(subject=request.email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    ).model_dump()


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest) -> Dict[str, Any]:
    """
    Refresh an expired access token using a valid refresh token.
    """
    try:
        payload = decode_token(request.refresh_token)
        validate_token_type(payload, "refresh")

        subject = payload.get("sub")
        if not subject:
            raise AuthenticationError("Invalid refresh token")

        # Issue new tokens
        access_token = create_access_token(
            subject=subject,
            expires_delta=timedelta(hours=1),
        )
        new_refresh_token = create_refresh_token(subject=subject)

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
        ).model_dump()

    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/me", response_model=UserResponse)
async def get_current_user(authorization: str = Header(None)) -> Dict[str, Any]:
    """
    Get the currently authenticated user.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.split(" ")[1]

    try:
        payload = decode_token(token)
        return UserResponse(
            id=payload.get("sub", ""),
            email=payload.get("sub", ""),
            name=payload.get("name", ""),
            role=payload.get("role", "viewer"),
        ).model_dump()
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
