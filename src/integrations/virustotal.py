"""VirusTotal API integration for threat intelligence.

This module provides integration with VirusTotal's API for file, URL,
domain, and IP reputation checking.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from loguru import logger

try:
    import vt
    HAS_VT = True
except ImportError:
    HAS_VT = False
    logger.warning("vt-py not installed - VirusTotal integration disabled")


@dataclass
class VTFileReport:
    """VirusTotal file analysis report."""

    sha256: str
    md5: str
    sha1: str

    # Detection stats
    malicious: int
    suspicious: int
    undetected: int
    harmless: int
    total_engines: int

    # Metadata
    first_submission: Optional[datetime] = None
    last_analysis: Optional[datetime] = None
    file_size: int = 0
    file_type: str = ""
    file_name: str = ""

    # Detailed results
    scan_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    popular_threat_label: Optional[str] = None

    # Behavioral data
    sandbox_verdicts: Dict[str, str] = field(default_factory=dict)

    def is_malicious(self) -> bool:
        """Check if file is considered malicious."""
        return self.malicious > 0

    def detection_ratio(self) -> float:
        """Calculate detection ratio."""
        if self.total_engines == 0:
            return 0.0
        return self.malicious / self.total_engines


@dataclass
class VTDomainReport:
    """VirusTotal domain reputation report."""

    domain: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    total_engines: int

    categories: Dict[str, str] = field(default_factory=dict)
    last_analysis: Optional[datetime] = None
    reputation: int = 0

    def is_malicious(self) -> bool:
        """Check if domain is malicious."""
        return self.malicious > 0 or self.reputation < -50


@dataclass
class VTIPReport:
    """VirusTotal IP address reputation report."""

    ip: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    total_engines: int

    asn: str = ""
    country: str = ""
    last_analysis: Optional[datetime] = None
    reputation: int = 0

    def is_malicious(self) -> bool:
        """Check if IP is malicious."""
        return self.malicious > 0 or self.reputation < -50


class VirusTotalClient:
    """Client for VirusTotal API."""

    def __init__(self, api_key: str):
        """Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key

        Raises:
            ImportError: If vt-py is not installed
        """
        if not HAS_VT:
            raise ImportError(
                "vt-py library required for VirusTotal integration. "
                "Install with: pip install vt-py"
            )

        if not api_key:
            raise ValueError("VirusTotal API key is required")

        self.api_key = api_key
        self.client = vt.Client(api_key)
        logger.info("Initialized VirusTotal client")

    async def get_file_report(self, file_hash: str) -> Optional[VTFileReport]:
        """Get file analysis report from VirusTotal.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            VTFileReport if found, None otherwise
        """
        try:
            logger.debug(f"Querying VirusTotal for hash: {file_hash}")

            async with self.client:
                file_obj = await self.client.get_object_async(f"/files/{file_hash}")

            # Extract detection stats
            stats = file_obj.last_analysis_stats

            # Parse timestamps
            first_submission = None
            last_analysis = None

            if file_obj.first_submission_date:
                first_submission = datetime.fromtimestamp(file_obj.first_submission_date)

            if file_obj.last_analysis_date:
                last_analysis = datetime.fromtimestamp(file_obj.last_analysis_date)

            # Extract scan results
            scan_results = {}
            if hasattr(file_obj, 'last_analysis_results'):
                for engine, result in file_obj.last_analysis_results.items():
                    scan_results[engine] = {
                        'result': result.get('result', ''),
                        'category': result.get('category', ''),
                        'engine_version': result.get('engine_version', ''),
                    }

            # Extract tags
            tags = list(file_obj.tags) if hasattr(file_obj, 'tags') else []

            # Get popular threat label
            threat_label = None
            if hasattr(file_obj, 'popular_threat_classification'):
                threat_label = file_obj.popular_threat_classification.get('suggested_threat_label')

            report = VTFileReport(
                sha256=file_obj.sha256,
                md5=file_obj.md5,
                sha1=file_obj.sha1,
                malicious=stats.get('malicious', 0),
                suspicious=stats.get('suspicious', 0),
                undetected=stats.get('undetected', 0),
                harmless=stats.get('harmless', 0),
                total_engines=sum(stats.values()),
                first_submission=first_submission,
                last_analysis=last_analysis,
                file_size=file_obj.size if hasattr(file_obj, 'size') else 0,
                file_type=file_obj.type_description if hasattr(file_obj, 'type_description') else '',
                file_name=file_obj.meaningful_name if hasattr(file_obj, 'meaningful_name') else '',
                scan_results=scan_results,
                tags=tags,
                popular_threat_label=threat_label,
            )

            logger.info(
                f"VT report: {report.malicious}/{report.total_engines} detections "
                f"({report.detection_ratio():.1%})"
            )

            return report

        except vt.APIError as e:
            if e.code == "NotFoundError":
                logger.debug(f"Hash not found in VirusTotal: {file_hash}")
                return None
            else:
                logger.error(f"VirusTotal API error: {e}")
                raise

        except Exception as e:
            logger.error(f"Error querying VirusTotal: {e}")
            raise

    async def get_domain_report(self, domain: str) -> Optional[VTDomainReport]:
        """Get domain reputation report.

        Args:
            domain: Domain name

        Returns:
            VTDomainReport if found, None otherwise
        """
        try:
            logger.debug(f"Querying VirusTotal for domain: {domain}")

            async with self.client:
                domain_obj = await self.client.get_object_async(f"/domains/{domain}")

            stats = domain_obj.last_analysis_stats

            # Extract categories
            categories = {}
            if hasattr(domain_obj, 'categories'):
                categories = dict(domain_obj.categories)

            # Parse timestamp
            last_analysis = None
            if hasattr(domain_obj, 'last_analysis_date'):
                last_analysis = datetime.fromtimestamp(domain_obj.last_analysis_date)

            # Get reputation score
            reputation = domain_obj.reputation if hasattr(domain_obj, 'reputation') else 0

            report = VTDomainReport(
                domain=domain,
                malicious=stats.get('malicious', 0),
                suspicious=stats.get('suspicious', 0),
                harmless=stats.get('harmless', 0),
                undetected=stats.get('undetected', 0),
                total_engines=sum(stats.values()),
                categories=categories,
                last_analysis=last_analysis,
                reputation=reputation,
            )

            logger.info(
                f"Domain {domain}: {report.malicious} malicious engines, "
                f"reputation: {reputation}"
            )

            return report

        except vt.APIError as e:
            if e.code == "NotFoundError":
                logger.debug(f"Domain not found in VirusTotal: {domain}")
                return None
            else:
                logger.error(f"VirusTotal API error: {e}")
                raise

        except Exception as e:
            logger.error(f"Error querying VirusTotal for domain: {e}")
            raise

    async def get_ip_report(self, ip: str) -> Optional[VTIPReport]:
        """Get IP address reputation report.

        Args:
            ip: IP address

        Returns:
            VTIPReport if found, None otherwise
        """
        try:
            logger.debug(f"Querying VirusTotal for IP: {ip}")

            async with self.client:
                ip_obj = await self.client.get_object_async(f"/ip_addresses/{ip}")

            stats = ip_obj.last_analysis_stats

            # Parse timestamp
            last_analysis = None
            if hasattr(ip_obj, 'last_analysis_date'):
                last_analysis = datetime.fromtimestamp(ip_obj.last_analysis_date)

            # Get ASN and country
            asn = str(ip_obj.asn) if hasattr(ip_obj, 'asn') else ""
            country = ip_obj.country if hasattr(ip_obj, 'country') else ""

            # Get reputation
            reputation = ip_obj.reputation if hasattr(ip_obj, 'reputation') else 0

            report = VTIPReport(
                ip=ip,
                malicious=stats.get('malicious', 0),
                suspicious=stats.get('suspicious', 0),
                harmless=stats.get('harmless', 0),
                undetected=stats.get('undetected', 0),
                total_engines=sum(stats.values()),
                asn=asn,
                country=country,
                last_analysis=last_analysis,
                reputation=reputation,
            )

            logger.info(
                f"IP {ip}: {report.malicious} malicious engines, "
                f"ASN: {asn}, country: {country}"
            )

            return report

        except vt.APIError as e:
            if e.code == "NotFoundError":
                logger.debug(f"IP not found in VirusTotal: {ip}")
                return None
            else:
                logger.error(f"VirusTotal API error: {e}")
                raise

        except Exception as e:
            logger.error(f"Error querying VirusTotal for IP: {e}")
            raise

    def format_report_for_ai(
        self,
        report: Optional[VTFileReport | VTDomainReport | VTIPReport]
    ) -> str:
        """Format a VT report for AI consumption.

        Args:
            report: VirusTotal report

        Returns:
            Formatted string for AI context
        """
        if report is None:
            return "VirusTotal: No data available"

        if isinstance(report, VTFileReport):
            return self._format_file_report(report)
        elif isinstance(report, VTDomainReport):
            return self._format_domain_report(report)
        elif isinstance(report, VTIPReport):
            return self._format_ip_report(report)
        else:
            return f"VirusTotal: {report}"

    def _format_file_report(self, report: VTFileReport) -> str:
        """Format file report."""
        lines = [
            "VIRUSTOTAL FILE REPORT:",
            f"SHA256: {report.sha256}",
            f"Detections: {report.malicious}/{report.total_engines} ({report.detection_ratio():.1%})",
            f"  - Malicious: {report.malicious}",
            f"  - Suspicious: {report.suspicious}",
            f"  - Harmless: {report.harmless}",
            f"  - Undetected: {report.undetected}",
        ]

        if report.popular_threat_label:
            lines.append(f"Threat Label: {report.popular_threat_label}")

        if report.tags:
            lines.append(f"Tags: {', '.join(report.tags[:10])}")

        if report.last_analysis:
            lines.append(f"Last Analysis: {report.last_analysis.isoformat()}")

        # Include top detections
        if report.scan_results:
            lines.append("\nTop Detections:")
            malicious_results = [
                (engine, data) for engine, data in report.scan_results.items()
                if data['category'] in ['malicious', 'suspicious']
            ]
            for engine, data in list(malicious_results)[:5]:
                lines.append(f"  - {engine}: {data['result']}")

        return "\n".join(lines)

    def _format_domain_report(self, report: VTDomainReport) -> str:
        """Format domain report."""
        return f"""VIRUSTOTAL DOMAIN REPORT:
Domain: {report.domain}
Detections: {report.malicious}/{report.total_engines}
Reputation: {report.reputation}
Categories: {', '.join(f"{k}: {v}" for k, v in list(report.categories.items())[:3])}
"""

    def _format_ip_report(self, report: VTIPReport) -> str:
        """Format IP report."""
        return f"""VIRUSTOTAL IP REPORT:
IP: {report.ip}
Detections: {report.malicious}/{report.total_engines}
Reputation: {report.reputation}
ASN: {report.asn}
Country: {report.country}
"""

    async def close(self):
        """Close the VirusTotal client."""
        await self.client.close_async()
