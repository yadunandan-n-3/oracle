"""
CWE Service
===========

Threat intelligence provider for CWE (Common Weakness Enumeration)
data. Provides CWE descriptions, extended details, likelihood of
exploit, detection methods, and remediation phases.

CWE data is bundled locally since CWE identifiers change infrequently
and the CWE API is not always available during air-gapped operations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from domain.intelligence import CWEInfo
from knowledge.intelligence import ThreatIntelligenceProvider

# ─── Local CWE Database ────────────────────────────────────────────────────
# Curated CWE database covering the most common weakness types encountered
# during penetration testing. Extend this list as needed.

_BUILTIN_CWES: Dict[str, Dict[str, Any]] = {
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
        "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
        "extended_description": "Path traversal attacks allow an attacker to access files outside the intended directory structure. This can lead to disclosure of sensitive information, configuration files, or source code. In some cases, combined with file upload or write capabilities, it can lead to remote code execution.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Dynamic Analysis", "Penetration Testing"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
        "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
        "extended_description": "OS command injection allows an attacker to execute arbitrary commands on the host operating system. This is one of the most critical vulnerabilities as it typically leads to full server compromise.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing", "Automated Scanning"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "extended_description": "Cross-Site Scripting (XSS) allows an attacker to inject client-side scripts into web pages viewed by other users. This can lead to session hijacking, credential theft, and defacement.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing", "Automated Scanning"],
        "remediation_phases": ["Implementation", "Build and Compilation"],
    },
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
        "extended_description": "SQL injection allows an attacker to interfere with the queries that an application makes to its database. This can allow attackers to view data they are not normally able to retrieve, modify or delete data, and in some cases escalate to remote code execution on the database server.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing", "Automated Scanning"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        "extended_description": "Improper authentication allows attackers to bypass authentication mechanisms and gain access to protected resources or functionality. This can include missing authentication, weak authentication, or bypassable authentication.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Manual Code Review", "Penetration Testing", "Architecture Review"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        "extended_description": "Hard-coded credentials are a common security issue that allows attackers to bypass authentication by using the embedded credentials. They are often found in source code, configuration files, or binary blobs.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Binary Analysis"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The software deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        "extended_description": "Deserialization of untrusted data can allow an attacker to execute arbitrary code, perform denial of service attacks, or bypass authentication. This is a common vulnerability in Java, Python, PHP, and .NET applications.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "description": "The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
        "extended_description": "Missing authentication for critical functions allows attackers to access sensitive functionality without proving their identity. This is commonly found in API endpoints, administrative interfaces, and privileged operations.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Manual Code Review", "Penetration Testing", "Architecture Review", "Automated Scanning"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The software makes a request to a remote destination using a user-controlled URL, but does not properly validate or restrict the destination.",
        "extended_description": "SSRF allows an attacker to abuse server functionality to read or update internal resources. This can lead to access to internal services, cloud metadata endpoints, and remote code execution in some configurations.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Manual Code Review", "Penetration Testing", "Automated Scanning"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "description": "The software does not properly control the allocation and maintenance of a limited resource, enabling an actor to consume resources to the point of impacting the intended functionality of the software.",
        "extended_description": "Uncontrolled resource consumption can lead to denial of service, performance degradation, or unexpected behavior. This includes CPU exhaustion, memory exhaustion, disk space exhaustion, and network bandwidth exhaustion.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing", "Load Testing"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-94": {
        "name": "Improper Control of Generation of Code (Code Injection)",
        "description": "The software generates all or part of its own code using externally-influenced input, but it does not properly neutralize special elements that could modify the syntax or behavior of the generated code.",
        "extended_description": "Code injection allows an attacker to inject and execute arbitrary code. This is a critical vulnerability that can lead to full compromise of the application and server.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-521": {
        "name": "Weak Password Requirements",
        "description": "The software does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.",
        "extended_description": "Weak password policies allow users to set passwords that are easily guessable or crackable, making accounts vulnerable to brute force and dictionary attacks.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Manual Code Review", "Configuration Review", "Policy Review"],
        "remediation_phases": ["Architecture and Design", "Implementation", "Operations"],
    },
    "CWE-311": {
        "name": "Missing Encryption of Sensitive Data",
        "description": "The software does not encrypt sensitive data when it is transmitted or stored, which exposes it to unauthorized access.",
        "extended_description": "Missing encryption of sensitive data can expose confidential information to unauthorized parties. This includes data in transit (network communications) and data at rest (databases, files).",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Manual Code Review", "Architecture Review", "Penetration Testing"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows the upload of files with dangerous types without proper validation, which could allow an attacker to execute arbitrary code.",
        "extended_description": "Unrestricted file upload allows attackers to upload executable files (PHP, JSP, ASP, etc.) that can be executed on the server, leading to remote code execution and full server compromise.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Manual Code Review", "Penetration Testing", "Automated Scanning"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-269": {
        "name": "Improper Privilege Management",
        "description": "The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.",
        "extended_description": "Improper privilege management allows users to gain access to resources or functionality beyond their intended permissions. This is commonly found in role-based access control (RBAC) implementations.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Manual Code Review", "Architecture Review", "Penetration Testing"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        "extended_description": "CSRF forces an authenticated user to execute unwanted actions on a web application in which they are currently authenticated. This can lead to unauthorized state changes, data modification, and privilege escalation.",
        "likelihood_of_exploit": "medium",
        "detection_methods": ["Manual Code Review", "Penetration Testing", "Automated Scanning"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-611": {
        "name": "Improper Restriction of XML External Entity Reference (XXE)",
        "description": "The software processes XML data that contains external entity references, which may allow an attacker to disclose internal files, cause denial of service, or perform server-side request forgery.",
        "extended_description": "XXE allows attackers to interfere with an application's processing of XML data. It can be used to view files on the filesystem, interact with internal systems, and in some cases, execute remote code.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing", "Automated Scanning"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-912": {
        "name": "Backdoor",
        "description": "The software contains a mechanism that allows an attacker to bypass authentication or gain unauthorized access.",
        "extended_description": "Backdoors are intentionally or unintentionally inserted mechanisms that bypass normal security controls. Supply chain backdoors (like the XZ Utils CVE-2024-3094) are particularly dangerous as they are distributed through trusted channels.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Binary Analysis", "Supply Chain Verification", "Runtime Monitoring"],
        "remediation_phases": ["Architecture and Design", "Implementation", "Build and Compilation", "Supply Chain"],
    },
    "CWE-506": {
        "name": "Embedded Malicious Code",
        "description": "The software contains code that appears to be malicious in nature.",
        "extended_description": "Embedded malicious code is intentionally placed to achieve a malicious purpose. This includes trojans, backdoors, logic bombs, and time bombs found in software supply chains.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Binary Analysis", "Supply Chain Verification", "Behavioral Analysis"],
        "remediation_phases": ["Architecture and Design", "Implementation", "Build and Compilation", "Supply Chain"],
    },
    "CWE-917": {
        "name": "Improper Neutralization of Special Elements used in Expression Language Statement (EL Injection)",
        "description": "The software does not properly neutralize special elements in an expression language statement, allowing an attacker to modify the syntax or behavior of the statement.",
        "extended_description": "Expression Language (EL) injection allows attackers to execute arbitrary code through the evaluation of expression language statements. This is particularly dangerous in Java frameworks that use SpEL, OGNL, or similar EL evaluation engines.",
        "likelihood_of_exploit": "high",
        "detection_methods": ["Static Analysis", "Manual Code Review", "Penetration Testing"],
        "remediation_phases": ["Architecture and Design", "Implementation"],
    },
    "CWE-1133": {
        "name": "External Remote Services",
        "description": "The software uses external remote services without proper authentication or access controls.",
        "extended_description": "External remote services that are improperly secured can be used by attackers to gain initial access to a network. This includes VPNs, remote desktop services, and other remote access solutions.",
        "likelihood_of_exploit": "medium",
        "detection_methods": ["Network Scanning", "Penetration Testing", "Configuration Review"],
        "remediation_phases": ["Architecture and Design", "Implementation", "Operations"],
    },
}


class CWEService(ThreatIntelligenceProvider):
    """
    CWE threat intelligence provider.

    Looks up CWE data from the bundled local database.
    This is a local-only provider since CWE identifiers change
    infrequently and the canonical CWE API is not always available.
    """

    name = "cwe"
    description = "CWE lookup via local database"

    def __init__(self) -> None:
        self._database: Dict[str, CWEInfo] = {}
        self._populate_database()

    def _populate_database(self) -> None:
        """Populate the database from built-in CWE data."""
        for cwe_id, data in _BUILTIN_CWES.items():
            self._database[cwe_id.upper()] = CWEInfo(
                cwe_id=cwe_id.upper(),
                name=data.get("name", ""),
                description=data.get("description", ""),
                extended_description=data.get("extended_description", ""),
                likelihood_of_exploit=data.get("likelihood_of_exploit", "unknown"),
                detection_methods=data.get("detection_methods", []),
                remediation_phases=data.get("remediation_phases", []),
            )

    async def lookup(self, identifier: str, **kwargs: Any) -> Optional[CWEInfo]:
        """
        Look up a CWE by ID.

        Args:
            identifier: CWE ID (e.g., "CWE-22")
            **kwargs: Not used for CWE lookup

        Returns:
            CWEInfo if found, None otherwise
        """
        cwe_id = identifier.upper().strip()
        return self._database.get(cwe_id)

    async def health_check(self) -> Dict[str, Any]:
        """Check if the CWE service is available."""
        return {
            "healthy": True,
            "available": True,
            "database_size": len(self._database),
            "error": None,
        }

    @property
    def database(self) -> Dict[str, CWEInfo]:
        """Get the full CWE database."""
        return dict(self._database)


__all__ = ["CWEService", "_BUILTIN_CWES"]
