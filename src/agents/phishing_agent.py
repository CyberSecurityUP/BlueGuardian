"""Phishing analysis agent for email messages.

This agent specializes in detecting phishing emails, analyzing social
engineering tactics, and identifying malicious content in emails.
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
from src.analyzers.email_analyzer import EmailAnalyzer
from src.config.settings import Settings
from src.core.hallucination_guard import HallucinationGuard
from src.integrations.virustotal import VirusTotalClient
from src.prompts.phishing_prompts import (
    EMAIL_PHISHING_ANALYSIS_PROMPT,
    PHISHING_ANALYSIS_SYSTEM_PROMPT,
    format_prompt,
)


class PhishingAgent(BaseAgent):
    """Agent specialized in phishing email analysis.

    This agent analyzes emails for phishing indicators, social engineering
    tactics, malicious links, and dangerous attachments.
    """

    def __init__(
        self,
        settings: Settings,
        ai_providers: List[BaseAIProvider],
        consensus_engine: Optional[ConsensusEngine] = None,
        vt_client: Optional[VirusTotalClient] = None,
        hallucination_guard: Optional[HallucinationGuard] = None,
    ):
        """Initialize phishing agent.

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

        self.email_analyzer = EmailAnalyzer()

        logger.info("Initialized PhishingAgent")

    def get_supported_file_types(self) -> List[str]:
        """Get supported file extensions.

        Returns:
            List of supported extensions
        """
        return ['.eml', '.msg']

    def get_system_prompt(self) -> str:
        """Get phishing analysis system prompt.

        Returns:
            System prompt
        """
        return PHISHING_ANALYSIS_SYSTEM_PROMPT

    async def analyze(self, artifact_path: str, **kwargs: Any) -> AnalysisResult:
        """Analyze an email for phishing indicators.

        Args:
            artifact_path: Path to email file (.eml or .msg)
            **kwargs: Additional parameters

        Returns:
            AnalysisResult with comprehensive findings

        Raises:
            ValueError: If file is invalid or unsupported
        """
        start_time = time.time()

        # Validate artifact
        self.validate_artifact(artifact_path)

        # Create result template
        result = self.create_result_template(artifact_path)
        result.status = AnalysisStatus.RUNNING

        logger.info(f"Starting phishing analysis: {artifact_path}")

        try:
            # Step 1: Calculate file hash
            logger.debug("Calculating file hash")
            hashes = self.calculate_file_hash(artifact_path)
            result.details['hashes'] = hashes

            # Step 2: Analyze email
            logger.debug("Analyzing email")
            email_result = self.email_analyzer.analyze(artifact_path)

            # Step 3: Query VirusTotal for URLs and domains (if available)
            vt_context = ""
            if self.vt_client and not kwargs.get('skip_vt', False):
                vt_results = await self._query_vt_for_iocs(email_result)
                if vt_results:
                    vt_context = self._format_vt_results(vt_results)
                    result.details['virustotal'] = vt_results

            # Step 4: Format context for AI
            context = self._format_email_context(email_result, vt_context)

            # Step 5: Query AI
            prompt = format_prompt(EMAIL_PHISHING_ANALYSIS_PROMPT, **context)
            ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

            # Package tool outputs
            result.tool_outputs = {
                'email_analysis': {
                    'sender': email_result.sender,
                    'subject': email_result.subject,
                    'spf': email_result.spf_result,
                    'dkim': email_result.dkim_result,
                    'dmarc': email_result.dmarc_result,
                    'has_attachments': email_result.has_attachments,
                    'attachment_count': len(email_result.attachments),
                    'has_links': email_result.has_links,
                    'link_count': len(email_result.links),
                    'impersonates_brand': email_result.impersonates_brand,
                    'suspected_brand': email_result.suspected_brand,
                    'urgency_keywords': email_result.contains_urgency_keywords,
                    'financial_keywords': email_result.contains_financial_keywords,
                    'anomalies': email_result.anomalies,
                },
                'hashes': hashes,
                'ai_response': ai_response,
            }

            # Step 6: Validate AI response
            if ai_response and self.hallucination_guard:
                logger.debug("Validating AI response")
                validation = self.hallucination_guard.validate(
                    consensus_result=ai_response,
                    tool_outputs=result.tool_outputs,
                    expected_evidence_types=['email_analysis'],
                )

                result.confidence = validation.confidence
                result.warnings.extend(validation.warnings)
            else:
                result.confidence = ai_response.confidence_score if ai_response else 0.5

            # Step 7: Extract verdict and IOCs
            if ai_response:
                result.summary = ai_response.merged_response
                result.ai_responses = ai_response

                # Extract verdict
                result.verdict = self._extract_verdict(ai_response.merged_response)

                # Extract IOCs
                result.iocs = self._extract_all_iocs(ai_response.merged_response, email_result)

                # Extract MITRE techniques
                result.mitre_techniques = self._extract_mitre_techniques(
                    ai_response.merged_response
                )

                # Extract tags
                result.tags = self._extract_tags(ai_response.merged_response, email_result)

            # Set completion time
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            result.status = AnalysisStatus.COMPLETED

            logger.info(
                f"Phishing analysis complete: {result.verdict.value} "
                f"(confidence: {result.confidence:.0%}, duration: {result.duration_seconds:.1f}s)"
            )

            return result

        except Exception as e:
            logger.error(f"Phishing analysis failed: {e}", exc_info=True)
            result.status = AnalysisStatus.FAILED
            result.errors.append(str(e))
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            raise

    async def _query_vt_for_iocs(self, email_result) -> Dict[str, Any]:
        """Query VirusTotal for URLs and domains in email."""
        vt_results = {}

        # Query for URLs (limit to first 5 to avoid rate limits)
        for link in email_result.links[:5]:
            try:
                url_report = await self.vt_client.get_domain_report(link.url)
                if url_report:
                    vt_results[link.url] = {
                        'malicious': url_report.malicious,
                        'total': url_report.total_engines,
                        'reputation': url_report.reputation,
                    }
            except:
                pass

        return vt_results

    def _format_vt_results(self, vt_results: Dict[str, Any]) -> str:
        """Format VirusTotal results for AI context."""
        if not vt_results:
            return "VirusTotal: Not queried"

        lines = ["VIRUSTOTAL RESULTS:"]
        for url, data in vt_results.items():
            lines.append(
                f"  {url}: {data['malicious']}/{data['total']} engines, "
                f"reputation: {data['reputation']}"
            )

        return '\n'.join(lines)

    def _format_email_context(self, email_result, vt_context: str) -> Dict[str, str]:
        """Format email data for AI prompt."""
        # Format attachments
        attachment_list = []
        for att in email_result.attachments:
            att_str = f"- {att.filename} ({att.content_type}, {att.size} bytes)"
            if att.suspicious:
                att_str += f" [SUSPICIOUS: {', '.join(att.reasons)}]"
            attachment_list.append(att_str)

        # Format links
        link_list = []
        for link in email_result.links[:20]:  # Limit for context
            link_str = f"- {link.url}"
            if link.display_text != link.url:
                link_str += f" (displays as: {link.display_text})"
            if link.suspicious:
                link_str += f" [SUSPICIOUS: {', '.join(link.reasons)}]"
            link_list.append(link_str)

        # Format body (truncate if too long)
        body = email_result.body_text or email_result.body_html
        if len(body) > 2000:
            body = body[:2000] + "\n... [TRUNCATED]"

        return {
            'sender': email_result.sender or "N/A",
            'reply_to': email_result.reply_to or "N/A",
            'recipients': ', '.join(email_result.recipients[:5]) if email_result.recipients else "N/A",
            'subject': email_result.subject or "N/A",
            'date': email_result.date.isoformat() if email_result.date else "N/A",
            'spf': email_result.spf_result or "N/A",
            'dkim': email_result.dkim_result or "N/A",
            'dmarc': email_result.dmarc_result or "N/A",
            'body': body,
            'attachment_count': str(len(email_result.attachments)),
            'attachments': '\n'.join(attachment_list) if attachment_list else "No attachments",
            'link_count': str(len(email_result.links)),
            'links': '\n'.join(link_list) if link_list else "No links found",
            'header_anomalies': '\n'.join([f"- {a}" for a in email_result.header_anomalies]) if email_result.header_anomalies else "None detected",
            'suspicious_patterns': '\n'.join([f"- {p}" for p in email_result.suspicious_patterns]) if email_result.suspicious_patterns else "None detected",
            'virustotal_data': vt_context,
        }

    def _extract_verdict(self, ai_response: str) -> Verdict:
        """Extract verdict from AI response."""
        response_lower = ai_response.lower()

        # Phishing-specific checks
        if 'phishing' in response_lower or 'malicious' in response_lower:
            return Verdict.MALICIOUS
        elif 'suspicious' in response_lower:
            return Verdict.SUSPICIOUS
        elif 'legitimate' in response_lower or 'clean' in response_lower or 'benign' in response_lower:
            return Verdict.CLEAN
        else:
            return Verdict.UNKNOWN

    def _extract_all_iocs(self, ai_response: str, email_result) -> List[IOC]:
        """Extract IOCs from AI response and email data."""
        iocs = []

        # Extract from AI response
        ai_iocs = self.extract_iocs_from_text(ai_response)
        iocs.extend(ai_iocs)

        # Extract sender domain
        if email_result.sender:
            sender_match = self._extract_domain_from_email(email_result.sender)
            if sender_match:
                iocs.append(IOC(
                    type="email",
                    value=email_result.sender,
                    confidence=0.9,
                    description="Sender address"
                ))
                iocs.append(IOC(
                    type="domain",
                    value=sender_match,
                    confidence=0.9,
                    description="Sender domain"
                ))

        # Extract URLs from links
        for link in email_result.links:
            iocs.append(IOC(
                type="url",
                value=link.url,
                confidence=0.95 if link.suspicious else 0.7,
                description="Link in email body"
            ))

        # Extract from attachment hashes (if we had them)
        for attachment in email_result.attachments:
            if attachment.suspicious:
                iocs.append(IOC(
                    type="filename",
                    value=attachment.filename,
                    confidence=0.8,
                    description="Suspicious attachment"
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

    def _extract_domain_from_email(self, email_address: str) -> Optional[str]:
        """Extract domain from email address."""
        import re

        match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
        return match.group(1).lower() if match else None

    def _extract_mitre_techniques(self, ai_response: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs."""
        import re

        pattern = r'\bT\d{4}(?:\.\d{3})?\b'
        techniques = re.findall(pattern, ai_response)

        return list(set(techniques))

    def _extract_tags(self, ai_response: str, email_result) -> List[str]:
        """Extract relevant tags."""
        tags = ['email', 'phishing']
        response_lower = ai_response.lower()

        # Phishing types
        if 'spear' in response_lower or 'targeted' in response_lower:
            tags.append('spear_phishing')

        if 'bec' in response_lower or 'business email compromise' in response_lower:
            tags.append('bec')

        if email_result.impersonates_brand:
            tags.append('brand_impersonation')
            if email_result.suspected_brand:
                tags.append(f"{email_result.suspected_brand}_impersonation")

        if 'credential' in response_lower:
            tags.append('credential_harvesting')

        # Social engineering
        if email_result.contains_urgency_keywords:
            tags.append('urgency')

        if email_result.contains_financial_keywords:
            tags.append('financial_fraud')

        # Technical indicators
        if any(a.suspicious for a in email_result.attachments):
            tags.append('malicious_attachment')

        if any(l.suspicious for l in email_result.links):
            tags.append('malicious_link')

        # Authentication failures
        if email_result.spf_result == 'fail':
            tags.append('spf_fail')

        if email_result.dkim_result == 'fail':
            tags.append('dkim_fail')

        if email_result.dmarc_result == 'fail':
            tags.append('dmarc_fail')

        return list(set(tags))
