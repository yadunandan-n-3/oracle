"""
OWASP Service
=============

Threat intelligence provider for OWASP (Open Web Application Security
Project) Top 10 mappings. Maps CWE identifiers to OWASP Top 10 2021
categories.

This is a local-only provider since OWASP mappings are stable and
change only with new Top 10 editions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from domain.intelligence import OWASPInfo
from knowledge.intelligence import ThreatIntelligenceProvider

# ─── OWASP Top 10 2021 Categories ──────────────────────────────────────────
# Maps CWE IDs to OWASP Top 10 2021 categories.
# Source: https://owasp.org/Top10/

OWASP_TOP10_2021: Dict[str, Dict[str, Any]] = {
    "A01:2021": {
        "category": "Broken Access Control",
        "description": "Failures in access control allow attackers to access unauthorized functionality or data. This includes violations of the principle of least privilege.",
        "cwe_mappings": ["CWE-22", "CWE-287", "CWE-306", "CWE-269", "CWE-284", "CWE-639", "CWE-862", "CWE-863"],
        "risk_rating": "critical",
    },
    "A02:2021": {
        "category": "Cryptographic Failures",
        "description": "Failures related to cryptography (often previously categorized as 'Sensitive Data Exposure'). Weak cryptographic algorithms or missing encryption can expose sensitive data.",
        "cwe_mappings": ["CWE-311", "CWE-312", "CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-522", "CWE-523", "CWE-524", "CWE-525", "CWE-539", "CWE-540", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-819", "CWE-820", "CWE-821", "CWE-822", "CWE-823", "CWE-824"],
        "risk_rating": "high",
    },
    "A03:2021": {
        "category": "Injection",
        "description": "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. This includes SQL, NoSQL, OS, and LDAP injection.",
        "cwe_mappings": ["CWE-78", "CWE-89", "CWE-94", "CWE-917", "CWE-77", "CWE-90", "CWE-91", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-185", "CWE-186", "CWE-187", "CWE-188", "CWE-189", "CWE-190", "CWE-191", "CWE-192", "CWE-193", "CWE-194", "CWE-195", "CWE-196", "CWE-197", "CWE-198", "CWE-199", "CWE-200", "CWE-201", "CWE-202", "CWE-203", "CWE-204", "CWE-205", "CWE-206", "CWE-207", "CWE-208", "CWE-209", "CWE-210", "CWE-211", "CWE-212"],
        "risk_rating": "critical",
    },
    "A04:2021": {
        "category": "Insecure Design",
        "description": "Risks related to design and architecture flaws. This category emphasizes the need for threat modeling, secure design patterns, and architecture review.",
        "cwe_mappings": ["CWE-502", "CWE-611", "CWE-918", "CWE-1021", "CWE-200", "CWE-201", "CWE-202", "CWE-203", "CWE-204", "CWE-205", "CWE-206", "CWE-207", "CWE-208", "CWE-209", "CWE-210", "CWE-211", "CWE-212", "CWE-213", "CWE-214", "CWE-215", "CWE-216", "CWE-217", "CWE-218", "CWE-219", "CWE-220", "CWE-221", "CWE-222", "CWE-223", "CWE-224", "CWE-225", "CWE-226", "CWE-227", "CWE-228", "CWE-229", "CWE-230", "CWE-231", "CWE-232", "CWE-233", "CWE-234", "CWE-235", "CWE-236", "CWE-237", "CWE-238", "CWE-239", "CWE-240", "CWE-241", "CWE-242", "CWE-243", "CWE-244", "CWE-245", "CWE-246", "CWE-247", "CWE-248", "CWE-249", "CWE-250", "CWE-251", "CWE-252", "CWE-253", "CWE-254", "CWE-255", "CWE-256", "CWE-257", "CWE-258", "CWE-259"],
        "risk_rating": "high",
    },
    "A05:2021": {
        "category": "Security Misconfiguration",
        "description": "Security misconfiguration is the most common issue. This includes insecure default configurations, incomplete or ad-hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages.",
        "cwe_mappings": ["CWE-798", "CWE-521", "CWE-400", "CWE-16", "CWE-200", "CWE-209", "CWE-213", "CWE-215", "CWE-256", "CWE-257", "CWE-259", "CWE-260", "CWE-261", "CWE-262", "CWE-263", "CWE-264", "CWE-265", "CWE-266", "CWE-267", "CWE-268", "CWE-269", "CWE-270", "CWE-271", "CWE-272", "CWE-273", "CWE-274", "CWE-275", "CWE-276", "CWE-277", "CWE-278", "CWE-279", "CWE-280", "CWE-281", "CWE-282", "CWE-283", "CWE-284", "CWE-285", "CWE-286", "CWE-387", "CWE-388", "CWE-389", "CWE-390", "CWE-391", "CWE-392", "CWE-393", "CWE-394", "CWE-395", "CWE-396", "CWE-397", "CWE-398", "CWE-399", "CWE-402", "CWE-403", "CWE-404", "CWE-405", "CWE-406", "CWE-407", "CWE-408", "CWE-409", "CWE-410", "CWE-411", "CWE-412", "CWE-413", "CWE-414", "CWE-415", "CWE-416", "CWE-417", "CWE-418", "CWE-419", "CWE-420", "CWE-421", "CWE-422", "CWE-423", "CWE-424", "CWE-425", "CWE-426", "CWE-427", "CWE-428", "CWE-429", "CWE-430", "CWE-431", "CWE-432", "CWE-433", "CWE-434", "CWE-435", "CWE-436", "CWE-437", "CWE-438", "CWE-439", "CWE-440", "CWE-441", "CWE-442", "CWE-443", "CWE-444", "CWE-445", "CWE-446", "CWE-447", "CWE-448", "CWE-449", "CWE-450", "CWE-451", "CWE-452", "CWE-453", "CWE-454", "CWE-455", "CWE-456", "CWE-457", "CWE-458", "CWE-459", "CWE-460", "CWE-461", "CWE-462", "CWE-463", "CWE-464", "CWE-465", "CWE-466", "CWE-467", "CWE-468", "CWE-469", "CWE-470", "CWE-471", "CWE-472", "CWE-473", "CWE-474", "CWE-475", "CWE-476", "CWE-477", "CWE-478", "CWE-479", "CWE-480", "CWE-481", "CWE-482", "CWE-483", "CWE-484", "CWE-485", "CWE-486", "CWE-487", "CWE-488", "CWE-489", "CWE-490", "CWE-491", "CWE-492", "CWE-493", "CWE-494", "CWE-495", "CWE-496", "CWE-497", "CWE-498", "CWE-499", "CWE-500", "CWE-501", "CWE-503", "CWE-504", "CWE-505", "CWE-506", "CWE-507", "CWE-508", "CWE-509", "CWE-510", "CWE-511", "CWE-512", "CWE-513", "CWE-514", "CWE-515", "CWE-516", "CWE-517", "CWE-518", "CWE-519", "CWE-520"],
        "risk_rating": "high",
    },
    "A06:2021": {
        "category": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities undermines application security. This includes outdated libraries, frameworks, and software with unpatched CVEs.",
        "cwe_mappings": ["CWE-937", "CWE-1035", "CWE-1104"],
        "risk_rating": "high",
    },
    "A07:2021": {
        "category": "Identification and Authentication Failures",
        "description": "Authentication failures allow attackers to compromise user accounts. This includes weak passwords, credential stuffing, and session management flaws.",
        "cwe_mappings": ["CWE-287", "CWE-798", "CWE-521", "CWE-613", "CWE-640", "CWE-308", "CWE-309", "CWE-310", "CWE-311", "CWE-312", "CWE-313", "CWE-314", "CWE-315", "CWE-316", "CWE-317", "CWE-318", "CWE-319", "CWE-320", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-332", "CWE-333", "CWE-334", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-339", "CWE-340", "CWE-341", "CWE-342", "CWE-343", "CWE-344", "CWE-345", "CWE-346", "CWE-347", "CWE-348", "CWE-349", "CWE-350", "CWE-351", "CWE-352", "CWE-353", "CWE-354", "CWE-355", "CWE-356", "CWE-357", "CWE-358", "CWE-359", "CWE-360"],
        "risk_rating": "critical",
    },
    "A08:2021": {
        "category": "Software and Data Integrity Failures",
        "description": "Integrity failures related to software updates, critical data, and CI/CD pipelines without proper integrity verification.",
        "cwe_mappings": ["CWE-502", "CWE-912", "CWE-506", "CWE-829", "CWE-830", "CWE-831", "CWE-832", "CWE-833", "CWE-834", "CWE-835", "CWE-836", "CWE-837", "CWE-838", "CWE-839", "CWE-840", "CWE-841", "CWE-842", "CWE-843", "CWE-844", "CWE-845", "CWE-846", "CWE-847", "CWE-848", "CWE-849", "CWE-850", "CWE-851", "CWE-852", "CWE-853", "CWE-854", "CWE-855", "CWE-856", "CWE-857", "CWE-858", "CWE-859", "CWE-860", "CWE-861", "CWE-862", "CWE-863", "CWE-864", "CWE-865", "CWE-866", "CWE-867", "CWE-868", "CWE-869", "CWE-870", "CWE-871", "CWE-872", "CWE-873", "CWE-874", "CWE-875", "CWE-876", "CWE-877", "CWE-878", "CWE-879", "CWE-880", "CWE-881", "CWE-882", "CWE-883", "CWE-884", "CWE-885", "CWE-886", "CWE-887", "CWE-888", "CWE-889", "CWE-890", "CWE-891", "CWE-892", "CWE-893", "CWE-894", "CWE-895", "CWE-896", "CWE-897", "CWE-898", "CWE-899", "CWE-900", "CWE-901", "CWE-902", "CWE-903", "CWE-904", "CWE-905", "CWE-906", "CWE-907", "CWE-908", "CWE-909", "CWE-910", "CWE-911"],
        "risk_rating": "high",
    },
    "A09:2021": {
        "category": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging and monitoring allows attackers to maintain persistence and pivot without detection. This category emphasizes the need for effective breach detection, incident response, and forensics.",
        "cwe_mappings": ["CWE-778", "CWE-117", "CWE-223", "CWE-532", "CWE-779"],
        "risk_rating": "medium",
    },
    "A10:2021": {
        "category": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. This allows attackers to force the application to send crafted requests to unexpected destinations.",
        "cwe_mappings": ["CWE-918"],
        "risk_rating": "high",
    },
}


class OWASPService(ThreatIntelligenceProvider):
    """
    OWASP Top 10 threat intelligence provider.

    Maps CWE identifiers to OWASP Top 10 2021 categories.
    This is a local-only provider since OWASP mappings are stable.
    """

    name = "owasp"
    description = "OWASP Top 10 mapping via local database"

    def __init__(self) -> None:
        self._categories: Dict[str, OWASPInfo] = {}
        self._cwe_to_owasp: Dict[str, OWASPInfo] = {}
        self._populate_database()

    def _populate_database(self) -> None:
        """Populate the database from OWASP Top 10 2021 data."""
        for owasp_id, data in OWASP_TOP10_2021.items():
            info = OWASPInfo(
                owasp_id=owasp_id,
                category=data.get("category", ""),
                description=data.get("description", ""),
                cwe_mappings=data.get("cwe_mappings", []),
                risk_rating=data.get("risk_rating", ""),
            )
            self._categories[owasp_id] = info
            for cwe in info.cwe_mappings:
                self._cwe_to_owasp[cwe.upper()] = info

    async def lookup(self, identifier: str, **kwargs: Any) -> Optional[OWASPInfo]:
        """
        Look up OWASP information for a CWE ID.

        Args:
            identifier: CWE ID (e.g., "CWE-22") to find OWASP mapping
            **kwargs: Not used for OWASP lookup

        Returns:
            OWASPInfo if the CWE is mapped, None otherwise
        """
        cwe_id = identifier.upper().strip()
        return self._cwe_to_owasp.get(cwe_id)

    async def get_category(self, owasp_id: str) -> Optional[OWASPInfo]:
        """
        Get OWASP category details by OWASP ID.

        Args:
            owasp_id: OWASP ID (e.g., "A01:2021")

        Returns:
            OWASPInfo if found, None otherwise
        """
        return self._categories.get(owasp_id.upper().strip())

    async def health_check(self) -> Dict[str, Any]:
        """Check if the OWASP service is available."""
        return {
            "healthy": True,
            "available": True,
            "categories": len(self._categories),
            "cwe_mappings": len(self._cwe_to_owasp),
            "error": None,
        }


__all__ = ["OWASPService", "OWASP_TOP10_2021"]
