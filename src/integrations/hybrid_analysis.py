"""Hybrid Analysis API integration.

This module provides integration with Hybrid Analysis (formerly Payload Security)
for automated malware analysis in a sandbox environment.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests
from loguru import logger


@dataclass
class HybridAnalysisReport:
    """Hybrid Analysis sandbox report."""

    sha256: str
    verdict: str  # 'malicious', 'suspicious', 'no specific threat', 'whitelisted'
    threat_score: int  # 0-100
    threat_level: int  # 0-2
    av_detect: int
    vx_family: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    ssdeep: Optional[str] = None
    submit_name: Optional[str] = None
    analysis_start_time: Optional[str] = None
    environment_description: Optional[str] = None
    classification_tags: List[str] = None
    compromised_hosts: List[str] = None
    domains: List[str] = None
    extracted_files: List[Dict[str, Any]] = None
    hosts: List[str] = None
    total_network_connections: int = 0
    total_processes: int = 0
    total_signatures: int = 0

    def __post_init__(self):
        """Initialize default values."""
        if self.classification_tags is None:
            self.classification_tags = []
        if self.compromised_hosts is None:
            self.compromised_hosts = []
        if self.domains is None:
            self.domains = []
        if self.extracted_files is None:
            self.extracted_files = []
        if self.hosts is None:
            self.hosts = []


class HybridAnalysisClient:
    """Client for Hybrid Analysis API.

    Hybrid Analysis provides automated malware analysis with detailed
    behavioral reports including network activity, file operations, and more.
    """

    API_BASE = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, api_key: str):
        """Initialize Hybrid Analysis client.

        Args:
            api_key: Hybrid Analysis API key
        """
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'api-key': api_key,
            'User-Agent': 'BlueGuardian AI',
        })

        logger.info("Initialized HybridAnalysisClient")

    async def submit_file(
        self,
        file_path: str,
        environment_id: int = 160,  # Windows 10 64-bit
    ) -> Optional[str]:
        """Submit a file for analysis.

        Args:
            file_path: Path to file
            environment_id: Sandbox environment ID

        Returns:
            Job ID or None if failed
        """
        url = f"{self.API_BASE}/submit/file"

        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                data = {
                    'environment_id': environment_id,
                }

                response = self.session.post(url, files=files, data=data, timeout=60)

            if response.status_code == 201:
                result = response.json()
                job_id = result.get('job_id')
                logger.info(f"File submitted to Hybrid Analysis: {job_id}")
                return job_id
            else:
                logger.error(f"Hybrid Analysis submission failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to submit file to Hybrid Analysis: {e}")
            return None

    async def get_report(self, sha256: str) -> Optional[HybridAnalysisReport]:
        """Get analysis report by SHA256.

        Args:
            sha256: SHA256 hash of file

        Returns:
            HybridAnalysisReport or None
        """
        url = f"{self.API_BASE}/search/hash"

        try:
            data = {'hash': sha256}
            response = self.session.post(url, data=data, timeout=30)

            if response.status_code == 200:
                results = response.json()

                if not results:
                    logger.debug(f"No reports found for {sha256}")
                    return None

                # Take most recent report
                report_data = results[0]

                report = HybridAnalysisReport(
                    sha256=report_data.get('sha256', sha256),
                    verdict=report_data.get('verdict', 'unknown'),
                    threat_score=report_data.get('threat_score', 0),
                    threat_level=report_data.get('threat_level', 0),
                    av_detect=report_data.get('av_detect', 0),
                    vx_family=report_data.get('vx_family'),
                    type=report_data.get('type'),
                    size=report_data.get('size'),
                    md5=report_data.get('md5'),
                    sha1=report_data.get('sha1'),
                    ssdeep=report_data.get('ssdeep'),
                    submit_name=report_data.get('submit_name'),
                    analysis_start_time=report_data.get('analysis_start_time'),
                    environment_description=report_data.get('environment_description'),
                    classification_tags=report_data.get('classification_tags', []),
                    compromised_hosts=report_data.get('compromised_hosts', []),
                    domains=report_data.get('domains', []),
                    extracted_files=report_data.get('extracted_files', []),
                    hosts=report_data.get('hosts', []),
                    total_network_connections=report_data.get('total_network_connections', 0),
                    total_processes=report_data.get('total_processes', 0),
                    total_signatures=report_data.get('total_signatures', 0),
                )

                logger.debug(f"Retrieved Hybrid Analysis report: {report.verdict}")
                return report

            else:
                logger.error(f"Hybrid Analysis query failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to get Hybrid Analysis report: {e}")
            return None

    def format_report_for_ai(self, report: HybridAnalysisReport) -> str:
        """Format report for AI context.

        Args:
            report: Hybrid Analysis report

        Returns:
            Formatted string
        """
        lines = [
            "HYBRID ANALYSIS SANDBOX REPORT:",
            f"Verdict: {report.verdict}",
            f"Threat Score: {report.threat_score}/100",
            f"AV Detections: {report.av_detect}",
        ]

        if report.vx_family:
            lines.append(f"Malware Family: {report.vx_family}")

        if report.classification_tags:
            lines.append(f"Tags: {', '.join(report.classification_tags)}")

        if report.domains:
            lines.append(f"Domains Contacted: {', '.join(report.domains[:10])}")

        if report.hosts:
            lines.append(f"IPs Contacted: {', '.join(report.hosts[:10])}")

        lines.append(f"Network Connections: {report.total_network_connections}")
        lines.append(f"Processes Created: {report.total_processes}")
        lines.append(f"Signatures Matched: {report.total_signatures}")

        return '\n'.join(lines)

    async def close(self):
        """Close the HTTP session."""
        self.session.close()
