"""Document analysis agent for PDF, Office, and LNK files.

This agent specializes in analyzing potentially malicious documents including
PDFs, Microsoft Office files, and Windows shortcuts.
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
from src.analyzers.lnk_analyzer import LNKAnalyzer
from src.analyzers.office_analyzer import OfficeAnalyzer
from src.analyzers.pdf_analyzer import PDFAnalyzer
from src.config.settings import Settings
from src.core.hallucination_guard import HallucinationGuard
from src.integrations.virustotal import VirusTotalClient
from src.prompts.document_prompts import (
    DOCUMENT_ANALYSIS_SYSTEM_PROMPT,
    LNK_ANALYSIS_PROMPT,
    OFFICE_ANALYSIS_PROMPT,
    PDF_ANALYSIS_PROMPT,
    format_prompt,
)


class DocumentAgent(BaseAgent):
    """Agent specialized in document analysis.

    This agent analyzes potentially malicious documents including PDFs,
    Office files (DOCX, XLSX, DOC, XLS), and LNK shortcuts.
    """

    def __init__(
        self,
        settings: Settings,
        ai_providers: List[BaseAIProvider],
        consensus_engine: Optional[ConsensusEngine] = None,
        vt_client: Optional[VirusTotalClient] = None,
        hallucination_guard: Optional[HallucinationGuard] = None,
    ):
        """Initialize document agent.

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

        # Initialize analyzers
        self.pdf_analyzer = PDFAnalyzer()
        self.office_analyzer = OfficeAnalyzer()
        self.lnk_analyzer = LNKAnalyzer()

        logger.info("Initialized DocumentAgent")

    def get_supported_file_types(self) -> List[str]:
        """Get supported file extensions.

        Returns:
            List of supported extensions
        """
        return [
            '.pdf',
            '.doc', '.docx', '.docm',
            '.xls', '.xlsx', '.xlsm',
            '.ppt', '.pptx', '.pptm',
            '.rtf', '.lnk',
        ]

    def get_system_prompt(self) -> str:
        """Get document analysis system prompt.

        Returns:
            System prompt
        """
        return DOCUMENT_ANALYSIS_SYSTEM_PROMPT

    async def analyze(self, artifact_path: str, **kwargs: Any) -> AnalysisResult:
        """Analyze a document file.

        Args:
            artifact_path: Path to document to analyze
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

        logger.info(f"Starting document analysis: {artifact_path}")

        try:
            # Step 1: Calculate file hashes
            logger.debug("Calculating file hashes")
            hashes = self.calculate_file_hash(artifact_path)
            result.details['hashes'] = hashes

            # Step 2: Query VirusTotal (if available)
            vt_report = None
            vt_context = ""

            if self.vt_client and not kwargs.get('skip_vt', False):
                logger.debug("Querying VirusTotal")
                try:
                    vt_report = await self.vt_client.get_file_report(hashes['sha256'])
                    if vt_report:
                        vt_context = self.vt_client.format_report_for_ai(vt_report)
                        result.details['virustotal'] = {
                            'detections': f"{vt_report.malicious}/{vt_report.total_engines}",
                            'ratio': vt_report.detection_ratio(),
                            'threat_label': vt_report.popular_threat_label,
                        }
                except Exception as e:
                    logger.warning(f"VirusTotal query failed: {e}")
                    result.warnings.append(f"VirusTotal unavailable: {str(e)}")

            # Step 3: Analyze based on document type
            path = Path(artifact_path)
            suffix = path.suffix.lower()

            if suffix == '.pdf':
                doc_result = await self._analyze_pdf(artifact_path, hashes, vt_context)
            elif suffix in ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm']:
                doc_result = await self._analyze_office(artifact_path, hashes, vt_context)
            elif suffix == '.lnk':
                doc_result = await self._analyze_lnk(artifact_path, hashes, vt_context)
            else:
                raise ValueError(f"Unsupported document type: {suffix}")

            result.tool_outputs = doc_result
            ai_response = doc_result.get('ai_response')

            # Step 4: Validate AI response
            if ai_response and self.hallucination_guard:
                logger.debug("Validating AI response")
                validation = self.hallucination_guard.validate(
                    consensus_result=ai_response,
                    tool_outputs=result.tool_outputs,
                    expected_evidence_types=['hashes'],
                )

                result.confidence = validation.confidence
                result.warnings.extend(validation.warnings)

                if validation.contradictions:
                    result.errors.extend([
                        f"AI contradiction: {c['claim']}" for c in validation.contradictions
                    ])
            else:
                result.confidence = ai_response.confidence_score if ai_response else 0.5

            # Step 5: Extract verdict and IOCs
            if ai_response:
                result.summary = ai_response.merged_response
                result.ai_responses = ai_response

                # Extract verdict
                result.verdict = self._extract_verdict(ai_response.merged_response)

                # Extract IOCs
                result.iocs = self._extract_all_iocs(
                    ai_response.merged_response,
                    result.tool_outputs
                )

                # Extract MITRE techniques
                result.mitre_techniques = self._extract_mitre_techniques(
                    ai_response.merged_response
                )

                # Extract tags
                result.tags = self._extract_tags(ai_response.merged_response, suffix)

            # Set completion time
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            result.status = AnalysisStatus.COMPLETED

            logger.info(
                f"Document analysis complete: {result.verdict.value} "
                f"(confidence: {result.confidence:.0%}, duration: {result.duration_seconds:.1f}s)"
            )

            return result

        except Exception as e:
            logger.error(f"Document analysis failed: {e}", exc_info=True)
            result.status = AnalysisStatus.FAILED
            result.errors.append(str(e))
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            raise

    async def _analyze_pdf(
        self, file_path: str, hashes: Dict[str, str], vt_context: str
    ) -> Dict[str, Any]:
        """Analyze a PDF file."""
        logger.debug("Performing PDF analysis")

        pdf_result = self.pdf_analyzer.analyze(file_path)

        # Format data for AI
        context = {
            'file_info': f"Size: {pdf_result.file_size} bytes\n"
                        f"Version: {pdf_result.pdf_version}\n"
                        f"Pages: {pdf_result.page_count}\n"
                        f"MD5: {hashes['md5']}\n"
                        f"SHA256: {hashes['sha256']}",

            'pdf_structure': f"Objects: {pdf_result.total_objects}\n"
                            f"Encrypted: {pdf_result.is_encrypted}\n"
                            f"JavaScript: {pdf_result.has_javascript}\n"
                            f"Embedded Files: {pdf_result.has_embedded_files}\n"
                            f"Launch Actions: {pdf_result.has_launch_actions}\n"
                            f"Auto-Action: {pdf_result.has_auto_action}",

            'javascript': '\n'.join(pdf_result.javascript_code[:5]) if pdf_result.javascript_code else "None detected",

            'embedded_files': "Present" if pdf_result.has_embedded_files else "None",

            'suspicious_elements': '\n'.join([
                f"- {kw}" for kw in pdf_result.suspicious_keywords
            ]) if pdf_result.suspicious_keywords else "None",

            'urls': '\n'.join(pdf_result.urls[:20]) if pdf_result.urls else "None found",

            'virustotal_data': vt_context,
        }

        prompt = format_prompt(PDF_ANALYSIS_PROMPT, **context)
        ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

        return {
            'pdf_analysis': {
                'page_count': pdf_result.page_count,
                'has_javascript': pdf_result.has_javascript,
                'has_embedded_files': pdf_result.has_embedded_files,
                'has_launch_actions': pdf_result.has_launch_actions,
                'suspicious_keywords': pdf_result.suspicious_keywords,
                'urls': pdf_result.urls,
                'anomalies': pdf_result.anomalies,
            },
            'hashes': hashes,
            'ai_response': ai_response,
        }

    async def _analyze_office(
        self, file_path: str, hashes: Dict[str, str], vt_context: str
    ) -> Dict[str, Any]:
        """Analyze an Office document."""
        logger.debug("Performing Office analysis")

        office_result = self.office_analyzer.analyze(file_path)

        # Format macros
        macro_info = []
        for macro in office_result.macros[:5]:  # Limit for context
            macro_info.append(
                f"Stream: {macro.stream_name}\n"
                f"Auto-exec: {macro.auto_exec}\n"
                f"Obfuscated: {macro.obfuscated}\n"
                f"Suspicious keywords: {', '.join(macro.suspicious_keywords[:10])}\n"
                f"Code snippet:\n{macro.code[:500]}\n"
            )

        context = {
            'file_info': f"Size: {office_result.file_size} bytes\n"
                        f"Type: {office_result.file_type.upper()}\n"
                        f"MD5: {hashes['md5']}\n"
                        f"SHA256: {hashes['sha256']}",

            'doc_type': f"Format: {'OOXML (Modern)' if office_result.is_ooxml else 'OLE (Legacy)'}\n"
                       f"Has Macros: {office_result.has_macros}\n"
                       f"Has Embedded Objects: {office_result.has_embedded_objects}\n"
                       f"Has DDE: {office_result.has_dde}\n"
                       f"Has ActiveX: {office_result.has_activex}",

            'macros': '\n\n'.join(macro_info) if macro_info else "No macros detected",

            'embedded_objects': '\n'.join([
                f"- {obj.object_type} ({obj.size} bytes)" +
                (f" [SUSPICIOUS: {', '.join(obj.reasons)}]" if obj.suspicious else "")
                for obj in office_result.embedded_objects
            ]) if office_result.embedded_objects else "None",

            'external_links': '\n'.join(office_result.external_urls[:10]) if office_result.external_urls else "None",

            'dde_links': '\n'.join(office_result.dde_links) if office_result.dde_links else "None detected",

            'virustotal_data': vt_context,
        }

        prompt = format_prompt(OFFICE_ANALYSIS_PROMPT, **context)
        ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

        return {
            'office_analysis': {
                'file_type': office_result.file_type,
                'has_macros': office_result.has_macros,
                'macro_count': office_result.macro_count,
                'has_dde': office_result.has_dde,
                'has_embedded_objects': office_result.has_embedded_objects,
                'anomalies': office_result.anomalies,
            },
            'hashes': hashes,
            'ai_response': ai_response,
        }

    async def _analyze_lnk(
        self, file_path: str, hashes: Dict[str, str], vt_context: str
    ) -> Dict[str, Any]:
        """Analyze a LNK file."""
        logger.debug("Performing LNK analysis")

        lnk_result = self.lnk_analyzer.analyze(file_path)

        context = {
            'file_info': f"Size: {lnk_result.file_size} bytes\n"
                        f"MD5: {hashes['md5']}\n"
                        f"SHA256: {hashes['sha256']}",

            'target': lnk_result.target_path or "N/A",

            'arguments': lnk_result.arguments or "None",

            'working_directory': lnk_result.working_directory or "N/A",

            'suspicious_indicators': '\n'.join([
                f"Uses PowerShell: {lnk_result.uses_powershell}",
                f"Uses CMD: {lnk_result.uses_cmd}",
                f"Uses MSHTA: {lnk_result.uses_mshta}",
                f"Uses WScript/CScript: {lnk_result.uses_wscript or lnk_result.uses_cscript}",
                f"Runs Minimized: {lnk_result.runs_minimized}",
                f"Suspicious Target: {lnk_result.suspicious_target}",
                f"Suspicious Arguments: {lnk_result.suspicious_arguments}",
                '\nAnomalies:',
            ] + [f"- {a}" for a in lnk_result.anomalies]),

            'virustotal_data': vt_context,
        }

        prompt = format_prompt(LNK_ANALYSIS_PROMPT, **context)
        ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

        return {
            'lnk_analysis': {
                'target_path': lnk_result.target_path,
                'arguments': lnk_result.arguments,
                'uses_powershell': lnk_result.uses_powershell,
                'uses_cmd': lnk_result.uses_cmd,
                'suspicious_target': lnk_result.suspicious_target,
                'suspicious_arguments': lnk_result.suspicious_arguments,
                'anomalies': lnk_result.anomalies,
            },
            'hashes': hashes,
            'ai_response': ai_response,
        }

    def _extract_verdict(self, ai_response: str) -> Verdict:
        """Extract verdict from AI response."""
        response_lower = ai_response.lower()

        if 'malicious' in response_lower:
            return Verdict.MALICIOUS
        elif 'suspicious' in response_lower:
            return Verdict.SUSPICIOUS
        elif 'clean' in response_lower or 'legitimate' in response_lower or 'benign' in response_lower:
            return Verdict.CLEAN
        else:
            return Verdict.UNKNOWN

    def _extract_all_iocs(self, ai_response: str, tool_outputs: Dict[str, Any]) -> List[IOC]:
        """Extract IOCs from AI response and tool outputs."""
        iocs = []

        # Extract from AI response
        ai_iocs = self.extract_iocs_from_text(ai_response)
        iocs.extend(ai_iocs)

        # Extract from tool outputs based on document type
        if 'pdf_analysis' in tool_outputs:
            pdf_data = tool_outputs['pdf_analysis']
            for url in pdf_data.get('urls', []):
                iocs.append(IOC(type="url", value=url, confidence=0.9))

        elif 'office_analysis' in tool_outputs:
            # Office documents don't typically have direct IOCs in static analysis
            pass

        elif 'lnk_analysis' in tool_outputs:
            lnk_data = tool_outputs['lnk_analysis']

            # Extract from target and arguments
            target = lnk_data.get('target_path', '')
            args = lnk_data.get('arguments', '')

            combined = f"{target} {args}"
            lnk_iocs = self.extract_iocs_from_text(combined)
            iocs.extend(lnk_iocs)

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
        """Extract MITRE ATT&CK technique IDs."""
        import re

        pattern = r'\bT\d{4}(?:\.\d{3})?\b'
        techniques = re.findall(pattern, ai_response)

        return list(set(techniques))

    def _extract_tags(self, ai_response: str, file_ext: str) -> List[str]:
        """Extract relevant tags."""
        tags = []
        response_lower = ai_response.lower()

        # Document type tag
        tags.append(f"document_{file_ext[1:]}")

        # Threat categories
        categories = [
            'phishing', 'exploit', 'dropper', 'macro', 'javascript',
            'credential_theft', 'social_engineering', 'obfuscation',
        ]

        for category in categories:
            if category in response_lower:
                tags.append(category)

        return list(set(tags))
