"""
Common Utilities
================

Shared utility functions for ID generation, hashing, timing, and validation.
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID, uuid4


def generate_id() -> UUID:
    """Generate a new UUID v4 identifier."""
    return uuid4()


def generate_short_id(length: int = 8) -> str:
    """Generate a short, human-readable ID."""
    return uuid4().hex[:length]


def compute_hash(data: bytes) -> str:
    """
    Compute SHA-256 hash of binary data.

    Args:
        data: Binary data to hash

    Returns:
        Hex-encoded hash string
    """
    return hashlib.sha256(data).hexdigest()


def compute_string_hash(text: str) -> str:
    """
    Compute SHA-256 hash of a string.

    Args:
        text: String to hash

    Returns:
        Hex-encoded hash string
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def now_utc() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def timestamp() -> float:
    """Get current Unix timestamp."""
    return time.time()


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to a human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "2h 30m 15s")
    """
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)


def truncate(text: str, max_length: int = 100) -> str:
    """
    Truncate text to a maximum length with ellipsis.

    Args:
        text: Text to truncate
        max_length: Maximum length (including ellipsis)

    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def slugify(text: str) -> str:
    """
    Convert text to a URL-friendly slug.

    Args:
        text: Text to slugify

    Returns:
        Slug string
    """
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")


def merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.

    Args:
        base: Base dictionary
        override: Override dictionary (takes precedence)

    Returns:
        Merged dictionary
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def validate_ip_address(ip: str) -> bool:
    """
    Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address string

    Returns:
        True if valid
    """
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ipv4_pattern.match(ip):
        parts = [int(p) for p in ip.split(".")]
        return all(0 <= p <= 255 for p in parts)
    return False


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name.

    Args:
        domain: Domain name string

    Returns:
        True if valid
    """
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def validate_url(url: str) -> bool:
    """
    Validate a URL.

    Args:
        url: URL string

    Returns:
        True if valid
    """
    pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,})"  # domain
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    return bool(pattern.match(url))


def chunk_list(items: list, chunk_size: int) -> list:
    """
    Split a list into chunks of a given size.

    Args:
        items: List to split
        chunk_size: Maximum chunk size

    Returns:
        List of chunks
    """
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


__all__ = [
    "generate_id",
    "generate_short_id",
    "compute_hash",
    "compute_string_hash",
    "now_utc",
    "timestamp",
    "format_duration",
    "truncate",
    "slugify",
    "merge_dicts",
    "validate_ip_address",
    "validate_domain",
    "validate_url",
    "chunk_list",
]
