"""Network analysis agent for IPs, domains, and URLs.

This agent specializes in analyzing network indicators for threat intelligence,
reputation analysis, and malicious infrastructure detection.
"""

import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from src.agents.base_agent import (
    AnalysisResult,
    AnalysisStatus,
    BaseAgent,
    IOC,
    Verdict,
)
from src.ai_providers.base import BaseAIProvider
from src.ai_providers.consensus import ConsensusEngine
from src.analyzers.network_analyzer import NetworkAnalyzer
from src.config.settings import Settings
from src.core.hallucination_guard import HallucinationGuard
from src.integrations.virustotal import VirusTotalClient
from src.prompts.network_prompts import (
    DOMAIN_ANALYSIS_PROMPT,
    IP_ANALYSIS_PROMPT,
    NETWORK_ANALYSIS_SYSTEM_PROMPT,
    URL_ANALYSIS_PROMPT,
    format_prompt,
)


class NetworkAgent(BaseAgent):
    """Agent specialized in network indicator analysis.

    This agent analyzes IP addresses, domain names, and URLs for threat intelligence,
    reputation analysis, and detection of malicious infrastructure.
    """

    def __init__(
        self,
        settings: Settings,
        ai_providers: List[BaseAIProvider],
        consensus_engine: Optional[ConsensusEngine] = None,
        vt_client: Optional[VirusTotalClient] = None,
        hallucination_guard: Optional[HallucinationGuard] = None,
    ):
        """Initialize network analysis agent.

        Args:
            settings: Application settings
            ai_providers: AI providers for analysis
            consensus_engine: Multi-model consensus engine
            vt_client: VirusTotal client for threat intel
            hallucination_guard: Hallucination detection system
        """
        super().__init__(settings, ai_providers, consensus_engine)

        self.vt_client = vt_client
        self.hallucination_guard = hallucination_guard or HallucinationGuard(
            min_confidence_threshold=settings.hallucination_guard.min_confidence_score
        )

        self.network_analyzer = NetworkAnalyzer()

        logger.info("Initialized NetworkAgent")

    def get_supported_file_types(self) -> List[str]:
        """Get supported file extensions.

        Returns:
            List of supported extensions (text files with network indicators)
        """
        return ['.txt', '.ioc', '.csv']

    def get_system_prompt(self) -> str:
        """Get network analysis system prompt.

        Returns:
            System prompt
        """
        return NETWORK_ANALYSIS_SYSTEM_PROMPT

    async def analyze(self, artifact_path: str, **kwargs: Any) -> AnalysisResult:
        """Analyze network indicators (IP, domain, or URL).

        This method can analyze:
        - A file containing network indicators (one per line)
        - A single indicator passed as string via artifact_path

        Args:
            artifact_path: Path to file or indicator string
            **kwargs: Additional parameters
                - indicator_type: 'ip', 'domain', or 'url' (auto-detect if not provided)

        Returns:
            AnalysisResult with comprehensive findings

        Raises:
            ValueError: If indicator is invalid
        """
        start_time = time.time()

        # Create result template
        result = AnalysisResult(
            artifact_name=Path(artifact_path).name if Path(artifact_path).exists() else artifact_path,
            agent_name=self.__class__.__name__,
            started_at=datetime.now(),
            status=AnalysisStatus.RUNNING,
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            summary="",
            details={},
            iocs=[],
            mitre_techniques=[],
            tags=[],
            warnings=[],
            errors=[],
            tool_outputs={},
        )

        logger.info(f"Starting network analysis: {artifact_path}")

        try:
            # Determine if this is a file or a direct indicator
            indicator = None
            if Path(artifact_path).exists():
                # Read indicators from file
                with open(artifact_path, 'r', encoding='utf-8', errors='ignore') as f:
                    indicators = [line.strip() for line in f if line.strip()]

                if not indicators:
                    raise ValueError("No indicators found in file")

                # For now, analyze first indicator (could batch in future)
                indicator = indicators[0]
                logger.info(f"Analyzing first indicator from file: {indicator}")
            else:
                # Treat as direct indicator
                indicator = artifact_path

            # Auto-detect indicator type
            indicator_type = kwargs.get('indicator_type') or self._detect_indicator_type(indicator)
            logger.debug(f"Detected indicator type: {indicator_type}")

            # Analyze based on type
            if indicator_type == 'ip':
                analysis_result = await self._analyze_ip(indicator, **kwargs)
            elif indicator_type == 'domain':
                analysis_result = await self._analyze_domain(indicator, **kwargs)
            elif indicator_type == 'url':
                analysis_result = await self._analyze_url(indicator, **kwargs)
            else:
                raise ValueError(f"Unknown indicator type: {indicator_type}")

            result.tool_outputs = analysis_result
            ai_response = analysis_result.get('ai_response')

            # Validate AI response
            if ai_response and self.hallucination_guard:
                logger.debug("Validating AI response")
                validation = self.hallucination_guard.validate(
                    consensus_result=ai_response,
                    tool_outputs=result.tool_outputs,
                    expected_evidence_types=[f'{indicator_type}_analysis'],
                )

                result.confidence = validation.confidence
                result.warnings.extend(validation.warnings)
            else:
                result.confidence = ai_response.confidence_score if ai_response else 0.5

            # Extract verdict and IOCs
            if ai_response:
                result.summary = ai_response.merged_response
                result.ai_responses = ai_response

                # Extract verdict
                result.verdict = self._extract_verdict(ai_response.merged_response)

                # Extract IOCs
                result.iocs = self._extract_all_iocs(
                    ai_response.merged_response,
                    analysis_result,
                    indicator_type
                )

                # Extract MITRE techniques
                result.mitre_techniques = self._extract_mitre_techniques(
                    ai_response.merged_response
                )

                # Extract tags
                result.tags = self._extract_tags(ai_response.merged_response, indicator_type)

            # Set completion time
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            result.status = AnalysisStatus.COMPLETED

            logger.info(
                f"Network analysis complete: {result.verdict.value} "
                f"(confidence: {result.confidence:.0%}, duration: {result.duration_seconds:.1f}s)"
            )

            return result

        except Exception as e:
            logger.error(f"Network analysis failed: {e}", exc_info=True)
            result.status = AnalysisStatus.FAILED
            result.errors.append(str(e))
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            raise

    def _detect_indicator_type(self, indicator: str) -> str:
        """Auto-detect the type of network indicator.

        Args:
            indicator: Network indicator string

        Returns:
            Type: 'ip', 'domain', or 'url'
        """
        import re

        # Check if URL (has scheme)
        if indicator.startswith(('http://', 'https://', 'ftp://')):
            return 'url'

        # Check if IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, indicator):
            return 'ip'

        # Otherwise assume domain
        return 'domain'

    async def _analyze_ip(self, ip_address: str, **kwargs) -> Dict[str, Any]:
        """Analyze an IP address.

        Args:
            ip_address: IP to analyze
            **kwargs: Additional options

        Returns:
            Analysis results dictionary
        """
        logger.debug(f"Performing IP analysis: {ip_address}")

        ip_result = self.network_analyzer.analyze_ip(ip_address)

        # Query VirusTotal if available
        vt_context = ""
        vt_data = None
        if self.vt_client and not kwargs.get('skip_vt', False):
            try:
                vt_report = await self.vt_client.get_ip_report(ip_address)
                if vt_report:
                    vt_context = self.vt_client.format_report_for_ai(vt_report)
                    vt_data = {
                        'malicious': vt_report.malicious,
                        'total': vt_report.total_engines,
                        'reputation': vt_report.reputation,
                    }
            except Exception as e:
                logger.warning(f"VirusTotal query failed: {e}")

        # Format context for AI
        context = {
            'ip_address': ip_address,
            'reverse_dns': ip_result.reverse_dns or "N/A",
            'is_private': str(ip_result.is_private),
            'is_cloud': str(ip_result.is_cloud),
            'cloud_provider': ip_result.cloud_provider or "N/A",
            'anomalies': '\n'.join([f"- {a}" for a in ip_result.anomalies]) if ip_result.anomalies else "None",
            'virustotal_data': vt_context,
        }

        # Query AI
        prompt = format_prompt(IP_ANALYSIS_PROMPT, **context)
        ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

        return {
            'ip_analysis': {
                'ip_address': ip_address,
                'is_private': ip_result.is_private,
                'reverse_dns': ip_result.reverse_dns,
                'is_cloud': ip_result.is_cloud,
                'cloud_provider': ip_result.cloud_provider,
                'anomalies': ip_result.anomalies,
            },
            'virustotal': vt_data,
            'ai_response': ai_response,
        }

    async def _analyze_domain(self, domain: str, **kwargs) -> Dict[str, Any]:
        """Analyze a domain name.

        Args:
            domain: Domain to analyze
            **kwargs: Additional options

        Returns:
            Analysis results dictionary
        """
        logger.debug(f"Performing domain analysis: {domain}")

        domain_result = self.network_analyzer.analyze_domain(domain)

        # Query VirusTotal if available
        vt_context = ""
        vt_data = None
        if self.vt_client and not kwargs.get('skip_vt', False):
            try:
                vt_report = await self.vt_client.get_domain_report(domain)
                if vt_report:
                    vt_context = self.vt_client.format_report_for_ai(vt_report)
                    vt_data = {
                        'malicious': vt_report.malicious,
                        'total': vt_report.total_engines,
                        'reputation': vt_report.reputation,
                    }
            except Exception as e:
                logger.warning(f"VirusTotal query failed: {e}")

        # Format context for AI
        context = {
            'domain': domain,
            'tld': domain_result.tld,
            'length': str(domain_result.length),
            'entropy': f"{domain_result.entropy:.2f}" if domain_result.entropy else "N/A",
            'is_dga': str(domain_result.is_dga),
            'subdomain_count': str(domain_result.subdomain_count),
            'resolved_ips': ', '.join(domain_result.resolved_ips) if domain_result.resolved_ips else "None",
            'anomalies': '\n'.join([f"- {a}" for a in domain_result.anomalies]) if domain_result.anomalies else "None",
            'virustotal_data': vt_context,
        }

        # Query AI
        prompt = format_prompt(DOMAIN_ANALYSIS_PROMPT, **context)
        ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

        return {
            'domain_analysis': {
                'domain': domain,
                'tld': domain_result.tld,
                'is_dga': domain_result.is_dga,
                'entropy': domain_result.entropy,
                'resolved_ips': domain_result.resolved_ips,
                'anomalies': domain_result.anomalies,
            },
            'virustotal': vt_data,
            'ai_response': ai_response,
        }

    async def _analyze_url(self, url: str, **kwargs) -> Dict[str, Any]:
        """Analyze a URL.

        Args:
            url: URL to analyze
            **kwargs: Additional options

        Returns:
            Analysis results dictionary
        """
        logger.debug(f"Performing URL analysis: {url}")

        url_result = self.network_analyzer.analyze_url(url)

        # Query VirusTotal if available
        vt_context = ""
        vt_data = None
        if self.vt_client and not kwargs.get('skip_vt', False):
            try:
                vt_report = await self.vt_client.get_url_report(url)
                if vt_report:
                    vt_context = self.vt_client.format_report_for_ai(vt_report)
                    vt_data = {
                        'malicious': vt_report.malicious,
                        'total': vt_report.total_engines,
                        'threat_label': vt_report.popular_threat_label,
                    }
            except Exception as e:
                logger.warning(f"VirusTotal query failed: {e}")

        # Format context for AI
        context = {
            'url': url,
            'scheme': url_result.scheme,
            'domain': url_result.domain,
            'path': url_result.path,
            'is_shortened': str(url_result.is_shortened),
            'uses_ip': str(url_result.uses_ip),
            'suspicious_tld': url_result.suspicious_tld or "N/A",
            'has_suspicious_path': str(url_result.has_suspicious_path),
            'has_suspicious_params': str(url_result.has_suspicious_params),
            'anomalies': '\n'.join([f"- {a}" for a in url_result.anomalies]) if url_result.anomalies else "None",
            'virustotal_data': vt_context,
        }

        # Query AI
        prompt = format_prompt(URL_ANALYSIS_PROMPT, **context)
        ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

        return {
            'url_analysis': {
                'url': url,
                'domain': url_result.domain,
                'is_shortened': url_result.is_shortened,
                'uses_ip': url_result.uses_ip,
                'has_suspicious_tld': url_result.has_suspicious_tld,
                'anomalies': url_result.anomalies,
            },
            'virustotal': vt_data,
            'ai_response': ai_response,
        }

    def _extract_verdict(self, ai_response: str) -> Verdict:
        """Extract verdict from AI response.

        Args:
            ai_response: AI response text

        Returns:
            Verdict
        """
        response_lower = ai_response.lower()

        if 'malicious' in response_lower:
            return Verdict.MALICIOUS
        elif 'suspicious' in response_lower:
            return Verdict.SUSPICIOUS
        elif 'clean' in response_lower or 'benign' in response_lower or 'legitimate' in response_lower:
            return Verdict.CLEAN
        else:
            return Verdict.UNKNOWN

    def _extract_all_iocs(
        self,
        ai_response: str,
        analysis_result: Dict[str, Any],
        indicator_type: str
    ) -> List[IOC]:
        """Extract IOCs from AI response and analysis.

        Args:
            ai_response: AI response text
            analysis_result: Analysis result dictionary
            indicator_type: Type of indicator analyzed

        Returns:
            List of IOCs
        """
        iocs = []

        # Extract from AI response
        ai_iocs = self.extract_iocs_from_text(ai_response)
        iocs.extend(ai_iocs)

        # Add the analyzed indicator itself
        if indicator_type == 'ip':
            ip_data = analysis_result.get('ip_analysis', {})
            iocs.append(IOC(
                type="ip",
                value=ip_data.get('ip_address', ''),
                confidence=0.95,
                description="Analyzed IP address"
            ))
        elif indicator_type == 'domain':
            domain_data = analysis_result.get('domain_analysis', {})
            iocs.append(IOC(
                type="domain",
                value=domain_data.get('domain', ''),
                confidence=0.95,
                description="Analyzed domain"
            ))
            # Add resolved IPs
            for ip in domain_data.get('resolved_ips', []):
                iocs.append(IOC(
                    type="ip",
                    value=ip,
                    confidence=0.9,
                    description=f"Resolved from domain {domain_data.get('domain')}"
                ))
        elif indicator_type == 'url':
            url_data = analysis_result.get('url_analysis', {})
            iocs.append(IOC(
                type="url",
                value=url_data.get('url', ''),
                confidence=0.95,
                description="Analyzed URL"
            ))

        # Remove duplicates
        unique_iocs = []
        seen = set()

        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def _extract_mitre_techniques(self, ai_response: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs.

        Args:
            ai_response: AI response text

        Returns:
            List of technique IDs
        """
        import re

        pattern = r'\bT\d{4}(?:\.\d{3})?\b'
        techniques = re.findall(pattern, ai_response)

        return list(set(techniques))

    def _extract_tags(self, ai_response: str, indicator_type: str) -> List[str]:
        """Extract relevant tags.

        Args:
            ai_response: AI response text
            indicator_type: Type of indicator

        Returns:
            List of tags
        """
        tags = ['network', indicator_type]
        response_lower = ai_response.lower()

        # Threat categories
        categories = [
            'c2', 'phishing', 'malware', 'botnet', 'ransomware',
            'exploit', 'spam', 'scanning', 'brute_force',
        ]

        for category in categories:
            if category in response_lower:
                tags.append(category)

        return list(set(tags))
