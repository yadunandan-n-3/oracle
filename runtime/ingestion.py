"""Pure normalization helpers for asset/evidence production."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from domain.asset import Asset, AssetCriticality, AssetType
from domain.evidence import Evidence, EvidenceType


_HOST_PORT = re.compile(r"^([^:/]+):(\d+)(?:/(?:tcp|udp))?$")


def canonical_asset_value(asset_type: AssetType, value: str) -> str:
    """Return a stable identity value for an observed asset."""
    value = value.strip()
    if asset_type == AssetType.WEB_APPLICATION:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        netloc = hostname if not port or default_port else f"{hostname}:{port}"
        path = parsed.path.rstrip("/")
        return urlunsplit((scheme, netloc, path, parsed.query, ""))

    raw_host = _host_from_observation(value)
    try:
        return str(ipaddress.ip_address(raw_host))
    except ValueError:
        return raw_host.lower().rstrip(".")


def normalize_asset(mission_id: UUID, asset: Asset) -> Asset:
    """Normalize identity and assign a deterministic mission-scoped UUID."""
    normalized = asset.model_copy(deep=True)
    normalized.value = canonical_asset_value(normalized.asset_type, normalized.value)
    normalized.id = uuid5(
        NAMESPACE_URL,
        f"oracle:{mission_id}:asset:{normalized.value}",
    )
    if not normalized.label:
        normalized.label = normalized.value
    normalized.ip_addresses = sorted(set(normalized.ip_addresses))
    normalized.hostnames = sorted({h.lower().rstrip(".") for h in normalized.hostnames})
    normalized.domains = sorted({d.lower().rstrip(".") for d in normalized.domains})
    normalized.open_ports = sorted(set(normalized.open_ports))
    normalized.services = sorted(set(normalized.services))
    normalized.tags = sorted(set(normalized.tags))
    return normalized


def merge_assets(existing: Asset, observed: Asset) -> Asset:
    """Merge a repeat observation without changing deterministic identity."""
    merged = existing.model_copy(deep=True)
    merged.label = observed.label or merged.label
    merged.description = observed.description or merged.description
    merged.ip_addresses = sorted(set(merged.ip_addresses + observed.ip_addresses))
    merged.hostnames = sorted(set(merged.hostnames + observed.hostnames))
    merged.domains = sorted(set(merged.domains + observed.domains))
    merged.open_ports = sorted(set(merged.open_ports + observed.open_ports))
    merged.services = sorted(set(merged.services + observed.services))
    merged.tags = sorted(set(merged.tags + observed.tags))
    merged.technologies.update(observed.technologies)
    merged.os = observed.os or merged.os
    merged.os_version = observed.os_version or merged.os_version
    merged.metadata.update(observed.metadata)
    merged.last_seen_at = max(merged.last_seen_at, observed.last_seen_at)
    return merged


def asset_from_evidence(mission_id: UUID, evidence: Evidence) -> Optional[Asset]:
    """Derive an asset only from values actually present in evidence."""
    value = evidence.asset_value.strip()
    if not value or value in {"system", "compilation", "vulnerability_scan"}:
        return None

    source_type = evidence.metadata.get("source_evidence_type", "")
    raw = evidence.raw_data or {}
    evidence_type = evidence.evidence_type

    if evidence_type in {
        EvidenceType.HTTP_ENDPOINT,
        EvidenceType.API_ENDPOINT,
        EvidenceType.VULNERABILITY,
        EvidenceType.MISCONFIGURATION,
        EvidenceType.EXPOSURE,
    } and "://" in value:
        asset_type = AssetType.WEB_APPLICATION
        asset_value = value
    elif source_type in {"host", "os", "port", "service"} or evidence_type in {
        EvidenceType.OPEN_PORT,
        EvidenceType.SERVICE,
        EvidenceType.BANNER,
    }:
        asset_type = AssetType.HOST
        asset_value = _host_from_observation(value)
    elif "://" in value:
        asset_type = AssetType.WEB_APPLICATION
        asset_value = value
    else:
        asset_value = _host_from_observation(value)
        try:
            ipaddress.ip_address(asset_value)
            asset_type = AssetType.HOST
        except ValueError:
            asset_type = AssetType.DOMAIN

    port = raw.get("port")
    if port is None:
        match = _HOST_PORT.match(value)
        port = int(match.group(2)) if match else None
    service = raw.get("service", "")
    hostnames = raw.get("hostnames", []) or []
    ip_addresses = [asset_value] if asset_type == AssetType.HOST and _is_ip(asset_value) else []

    asset = Asset(
        asset_type=asset_type,
        value=asset_value,
        label=(hostnames[0] if hostnames else asset_value),
        ip_addresses=ip_addresses,
        hostnames=list(hostnames),
        open_ports=[int(port)] if port is not None else [],
        services=[str(service)] if service else [],
        os=raw.get("os"),
        criticality=AssetCriticality.UNKNOWN,
        tags=["discovered"],
        metadata={"evidence_ids": [str(evidence.id)]},
    )
    return normalize_asset(mission_id, asset)


def coalesce_assets(mission_id: UUID, assets: Iterable[Asset]) -> list[Asset]:
    """Deduplicate a batch using canonical type/value identity."""
    coalesced: dict[str, Asset] = {}
    for asset in assets:
        normalized = normalize_asset(mission_id, asset)
        key = normalized.value
        coalesced[key] = (
            merge_assets(coalesced[key], normalized) if key in coalesced else normalized
        )
    return list(coalesced.values())


def _host_from_observation(value: str) -> str:
    if "://" in value:
        return urlsplit(value).hostname or value
    match = _HOST_PORT.match(value)
    return match.group(1) if match else value.split("/")[0]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


__all__ = [
    "asset_from_evidence",
    "canonical_asset_value",
    "coalesce_assets",
    "merge_assets",
    "normalize_asset",
]
