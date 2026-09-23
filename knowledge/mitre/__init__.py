"""
MITRE ATT&CK Mapping Engine
============================

Maps validated Findings to MITRE ATT&CK techniques.

Design goal, same as the Risk Engine: every mapping must be traceable
back to the specific evidence (a CVE, a CWE, a scanner tag, an evidence
type) that triggered it. No mapping is ever produced without at least
one named signal behind it — see `MitreMapping.matched_on`.

This is deliberately a curated subset of ATT&CK (~28 techniques relevant
to network/web penetration testing), not the full matrix. Extending
coverage means adding rows to the tables below — the mapping logic
itself doesn't change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class AttackTechnique:
    """A single MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactic: str
    tactic_id: str
    url: str


# ─── Curated ATT&CK Technique Database ──────────────────────────────────────
# Source: MITRE ATT&CK for Enterprise (attack.mitre.org). Only techniques
# that ORACLE can plausibly produce evidence for are included.
ATTACK_TECHNIQUES: Dict[str, AttackTechnique] = {
    t.technique_id: t
    for t in [
        AttackTechnique("T1595", "Active Scanning", "Reconnaissance", "TA0043",
                         "https://attack.mitre.org/techniques/T1595/"),
        AttackTechnique("T1592", "Gather Victim Host Information", "Reconnaissance", "TA0043",
                         "https://attack.mitre.org/techniques/T1592/"),
        AttackTechnique("T1590", "Gather Victim Network Information", "Reconnaissance", "TA0043",
                         "https://attack.mitre.org/techniques/T1590/"),
        AttackTechnique("T1046", "Network Service Discovery", "Discovery", "TA0007",
                         "https://attack.mitre.org/techniques/T1046/"),
        AttackTechnique("T1082", "System Information Discovery", "Discovery", "TA0007",
                         "https://attack.mitre.org/techniques/T1082/"),
        AttackTechnique("T1018", "Remote System Discovery", "Discovery", "TA0007",
                         "https://attack.mitre.org/techniques/T1018/"),
        AttackTechnique("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001",
                         "https://attack.mitre.org/techniques/T1190/"),
        AttackTechnique("T1133", "External Remote Services", "Initial Access", "TA0001",
                         "https://attack.mitre.org/techniques/T1133/"),
        AttackTechnique("T1189", "Drive-by Compromise", "Initial Access", "TA0001",
                         "https://attack.mitre.org/techniques/T1189/"),
        AttackTechnique("T1078", "Valid Accounts", "Initial Access", "TA0001",
                         "https://attack.mitre.org/techniques/T1078/"),
        AttackTechnique("T1110", "Brute Force", "Credential Access", "TA0006",
                         "https://attack.mitre.org/techniques/T1110/"),
        AttackTechnique("T1552", "Unsecured Credentials", "Credential Access", "TA0006",
                         "https://attack.mitre.org/techniques/T1552/"),
        AttackTechnique("T1040", "Network Sniffing", "Credential Access", "TA0006",
                         "https://attack.mitre.org/techniques/T1040/"),
        AttackTechnique("T1212", "Exploitation for Credential Access", "Credential Access", "TA0006",
                         "https://attack.mitre.org/techniques/T1212/"),
        AttackTechnique("T1059", "Command and Scripting Interpreter", "Execution", "TA0002",
                         "https://attack.mitre.org/techniques/T1059/"),
        AttackTechnique("T1210", "Exploitation of Remote Services", "Lateral Movement", "TA0008",
                         "https://attack.mitre.org/techniques/T1210/"),
        AttackTechnique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "TA0004",
                         "https://attack.mitre.org/techniques/T1068/"),
        AttackTechnique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "TA0004",
                         "https://attack.mitre.org/techniques/T1548/"),
        AttackTechnique("T1211", "Exploitation for Defense Evasion", "Defense Evasion", "TA0005",
                         "https://attack.mitre.org/techniques/T1211/"),
        AttackTechnique("T1600", "Weaken Encryption", "Defense Evasion", "TA0005",
                         "https://attack.mitre.org/techniques/T1600/"),
        AttackTechnique("T1005", "Data from Local System", "Collection", "TA0009",
                         "https://attack.mitre.org/techniques/T1005/"),
        AttackTechnique("T1213", "Data from Information Repositories", "Collection", "TA0009",
                         "https://attack.mitre.org/techniques/T1213/"),
        AttackTechnique("T1071", "Application Layer Protocol", "Command and Control", "TA0011",
                         "https://attack.mitre.org/techniques/T1071/"),
        AttackTechnique("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "TA0010",
                         "https://attack.mitre.org/techniques/T1041/"),
        AttackTechnique("T1499", "Endpoint Denial of Service", "Impact", "TA0040",
                         "https://attack.mitre.org/techniques/T1499/"),
        AttackTechnique("T1486", "Data Encrypted for Impact", "Impact", "TA0040",
                         "https://attack.mitre.org/techniques/T1486/"),
        AttackTechnique("T1584", "Compromise Infrastructure", "Resource Development", "TA0042",
                         "https://attack.mitre.org/techniques/T1584/"),
        AttackTechnique("T1136", "Create Account", "Persistence", "TA0003",
                         "https://attack.mitre.org/techniques/T1136/"),
        AttackTechnique("T1098", "Account Manipulation", "Persistence", "TA0003",
                         "https://attack.mitre.org/techniques/T1098/"),
    ]
}

# CWE -> candidate techniques. A CWE is a strong, specific signal, so these
# carry a higher base confidence than tag-based matches.
CWE_TO_TECHNIQUES: Dict[str, List[str]] = {
    "CWE-22": ["T1190", "T1005"],        # Path Traversal
    "CWE-78": ["T1190", "T1059"],        # OS Command Injection
    "CWE-89": ["T1190", "T1213"],        # SQL Injection
    "CWE-79": ["T1189", "T1059"],        # Cross-Site Scripting
    "CWE-94": ["T1190", "T1059"],        # Code Injection
    "CWE-287": ["T1078"],                # Improper Authentication
    "CWE-284": ["T1078"],                # Improper Access Control
    "CWE-798": ["T1552"],                # Hardcoded Credentials
    "CWE-521": ["T1110"],                # Weak Password Requirements
    "CWE-311": ["T1600"],                # Missing Encryption of Sensitive Data
    "CWE-326": ["T1600"],                # Inadequate Encryption Strength
    "CWE-330": ["T1600"],                # Use of Insufficiently Random Values
    "CWE-352": ["T1189"],                # CSRF
    "CWE-611": ["T1005", "T1213"],       # XXE
    "CWE-502": ["T1190", "T1059"],       # Insecure Deserialization
    "CWE-434": ["T1190"],                # Unrestricted File Upload
    "CWE-918": ["T1190"],                # SSRF
    "CWE-306": ["T1078", "T1133"],       # Missing Authentication for Critical Function
    "CWE-269": ["T1068", "T1548"],       # Improper Privilege Management
}

# Scanner/template tags -> candidate techniques. Lower confidence than CVE
# or CWE matches since tags are looser signals (a template family, not a
# specific classified weakness).
TAG_TO_TECHNIQUES: Dict[str, List[str]] = {
    "rce": ["T1190", "T1059"],
    "sqli": ["T1190", "T1213"],
    "lfi": ["T1190", "T1005"],
    "rfi": ["T1190"],
    "xxe": ["T1005", "T1213"],
    "ssrf": ["T1190"],
    "xss": ["T1189"],
    "cve": ["T1190"],
    "exposure": ["T1592", "T1005"],
    "config": ["T1552"],
    "default-login": ["T1078", "T1110"],
    "takeover": ["T1584"],
    "misconfig": ["T1552", "T1592"],
    "tech": ["T1592"],
    "panel": ["T1078", "T1133"],
    "dos": ["T1499"],
}

# core.interfaces / domain.evidence evidence_type -> candidate techniques.
# This is how raw reconnaissance evidence (which doesn't have a CVE/CWE)
# still contributes to the attack graph.
EVIDENCE_TYPE_TO_TECHNIQUES: Dict[str, List[str]] = {
    "port": ["T1046"],
    "open_port": ["T1046"],
    "host": ["T1018", "T1595"],
    "os": ["T1082"],
    "service": ["T1046"],
    "vulnerability": ["T1190"],
}


@dataclass
class MitreMapping:
    """A single technique mapping with full traceability."""

    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    confidence: float
    matched_on: List[str] = field(default_factory=list)
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "confidence": self.confidence,
            "matched_on": self.matched_on,
            "url": self.url,
        }


class MitreMapper:
    """
    Maps findings/evidence signals (CVE, CWE, tags, evidence type) to
    MITRE ATT&CK techniques.

    Each signal source has its own base confidence; when several signals
    independently point to the same technique, confidence is boosted
    (capped at 0.98) and every contributing signal is recorded in
    `matched_on` — the mapping is never a single opaque number.
    """

    CVE_CONFIDENCE = 0.75
    CWE_CONFIDENCE = 0.65
    TAG_CONFIDENCE = 0.5
    EVIDENCE_TYPE_CONFIDENCE = 0.4
    CONFIDENCE_BOOST_PER_EXTRA_SIGNAL = 0.12
    MAX_CONFIDENCE = 0.98

    def map(
        self,
        *,
        cve_ids: Optional[List[str]] = None,
        cwe_ids: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        evidence_type: Optional[str] = None,
    ) -> List[MitreMapping]:
        """
        Compute technique mappings from independent signals.

        Args:
            cve_ids: CVE identifiers associated with the finding
            cwe_ids: CWE identifiers associated with the finding
            tags: Scanner/template tags associated with the finding
            evidence_type: The evidence_type string (e.g. "port", "vulnerability")

        Returns:
            MitreMapping objects sorted by descending confidence.
        """
        # technique_id -> (confidence, matched_on list)
        candidates: Dict[str, Dict[str, Any]] = {}

        def _add(technique_id: str, base_confidence: float, reason: str) -> None:
            if technique_id not in ATTACK_TECHNIQUES:
                return
            entry = candidates.setdefault(technique_id, {"confidence": 0.0, "matched_on": []})
            if entry["confidence"] == 0.0:
                entry["confidence"] = base_confidence
            else:
                entry["confidence"] = min(
                    MitreMapper.MAX_CONFIDENCE,
                    entry["confidence"] + MitreMapper.CONFIDENCE_BOOST_PER_EXTRA_SIGNAL,
                )
            entry["matched_on"].append(reason)

        if cve_ids:
            for cve in cve_ids:
                # Any CVE presence implies exploitation of a public-facing
                # weakness at minimum; specific CWE mappings below refine this.
                _add("T1190", self.CVE_CONFIDENCE, f"CVE: {cve}")

        for cwe in (cwe_ids or []):
            cwe_normalized = cwe.upper().strip()
            for technique_id in CWE_TO_TECHNIQUES.get(cwe_normalized, []):
                _add(technique_id, self.CWE_CONFIDENCE, f"CWE: {cwe_normalized}")

        for tag in (tags or []):
            tag_normalized = tag.lower().strip()
            for technique_id in TAG_TO_TECHNIQUES.get(tag_normalized, []):
                _add(technique_id, self.TAG_CONFIDENCE, f"tag: {tag_normalized}")

        if evidence_type:
            for technique_id in EVIDENCE_TYPE_TO_TECHNIQUES.get(evidence_type.lower(), []):
                _add(technique_id, self.EVIDENCE_TYPE_CONFIDENCE, f"evidence_type: {evidence_type}")

        mappings = []
        for technique_id, data in candidates.items():
            technique = ATTACK_TECHNIQUES[technique_id]
            mappings.append(MitreMapping(
                technique_id=technique.technique_id,
                technique_name=technique.name,
                tactic=technique.tactic,
                tactic_id=technique.tactic_id,
                confidence=round(data["confidence"], 4),
                matched_on=data["matched_on"],
                url=technique.url,
            ))

        mappings.sort(key=lambda m: m.confidence, reverse=True)
        return mappings

    def map_finding(self, finding: Any) -> List[MitreMapping]:
        """
        Convenience wrapper: map a domain.finding.Finding (or any
        duck-typed object with cve_id/cwe_id/tags attributes).
        """
        cve_ids = [finding.cve_id] if getattr(finding, "cve_id", None) else []
        cwe_ids = [finding.cwe_id] if getattr(finding, "cwe_id", None) else []
        tags = list(getattr(finding, "tags", None) or [])
        return self.map(cve_ids=cve_ids, cwe_ids=cwe_ids, tags=tags)

    def apply_to_finding(self, finding: Any) -> Any:
        """
        Compute mappings for a finding and write them back onto it.

        The Finding model only has a single `mitre_technique_id` /
        `mitre_tactic` slot, so the highest-confidence mapping is written
        there; the full ranked list (with every contributing signal) is
        preserved in `finding.metadata["mitre_mappings"]` so nothing is
        lost for the report or attack graph.
        """
        mappings = self.map_finding(finding)
        if not mappings:
            return finding

        top = mappings[0]
        finding.mitre_technique_id = top.technique_id
        finding.mitre_tactic = top.tactic
        finding.metadata["mitre_mappings"] = [m.to_dict() for m in mappings]
        return finding


__all__ = [
    "AttackTechnique",
    "ATTACK_TECHNIQUES",
    "CWE_TO_TECHNIQUES",
    "TAG_TO_TECHNIQUES",
    "EVIDENCE_TYPE_TO_TECHNIQUES",
    "MitreMapping",
    "MitreMapper",
]
