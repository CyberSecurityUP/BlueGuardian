"""Memory forensics agent for analyzing memory dumps.

This agent specializes in memory forensics analysis using Volatility 3,
detecting malware in memory, process injection, rootkits, and persistence mechanisms.
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
from src.analyzers.memory_analyzer import MemoryAnalyzer
from src.config.settings import Settings
from src.core.hallucination_guard import HallucinationGuard
from src.integrations.virustotal import VirusTotalClient
from src.prompts.forensics_prompts import (
    MEMORY_ANALYSIS_PROMPT,
    MEMORY_ANALYSIS_SYSTEM_PROMPT,
    format_prompt,
)


class MemoryAgent(BaseAgent):
    """Agent specialized in memory forensics analysis.

    This agent analyzes memory dumps for malware artifacts, process injection,
    rootkits, persistence mechanisms, and suspicious network activity.
    """

    def __init__(
        self,
        settings: Settings,
        ai_providers: List[BaseAIProvider],
        consensus_engine: Optional[ConsensusEngine] = None,
        vt_client: Optional[VirusTotalClient] = None,
        hallucination_guard: Optional[HallucinationGuard] = None,
    ):
        """Initialize memory forensics agent.

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

        self.memory_analyzer = MemoryAnalyzer()

        logger.info("Initialized MemoryAgent")

    def get_supported_file_types(self) -> List[str]:
        """Get supported file extensions.

        Returns:
            List of supported extensions
        """
        return ['.dmp', '.raw', '.mem', '.vmem', '.lime']

    def get_system_prompt(self) -> str:
        """Get memory forensics system prompt.

        Returns:
            System prompt
        """
        return MEMORY_ANALYSIS_SYSTEM_PROMPT

    async def analyze(self, artifact_path: str, **kwargs: Any) -> AnalysisResult:
        """Analyze a memory dump for malware and suspicious activity.

        Args:
            artifact_path: Path to memory dump file
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

        logger.info(f"Starting memory forensics analysis: {artifact_path}")

        try:
            # Step 1: Calculate file hash
            logger.debug("Calculating file hash")
            hashes = self.calculate_file_hash(artifact_path)
            result.details['hashes'] = hashes

            # Step 2: Run Volatility analysis
            logger.debug("Running memory analysis with Volatility")
            mem_result = self.memory_analyzer.analyze(artifact_path)

            if not mem_result.volatility_available:
                result.warnings.append(
                    "Volatility 3 not available - install with: pip install volatility3"
                )

            # Step 3: Query VirusTotal for suspicious IPs (if available)
            vt_context = ""
            if self.vt_client and not kwargs.get('skip_vt', False):
                vt_results = await self._query_vt_for_network(mem_result)
                if vt_results:
                    vt_context = self._format_vt_results(vt_results)
                    result.details['virustotal'] = vt_results

            # Step 4: Format context for AI
            context = self._format_memory_context(mem_result, vt_context)

            # Step 5: Query AI
            prompt = format_prompt(MEMORY_ANALYSIS_PROMPT, **context)
            ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

            # Package tool outputs
            result.tool_outputs = {
                'memory_analysis': {
                    'os_profile': mem_result.os_profile,
                    'process_count': mem_result.process_count,
                    'suspicious_process_count': len(mem_result.suspicious_processes),
                    'network_connection_count': len(mem_result.network_connections),
                    'injection_count': len(mem_result.injected_code),
                    'hidden_process_count': len(mem_result.hidden_processes),
                    'malware_indicator_count': len(mem_result.malware_indicators),
                    'volatility_available': mem_result.volatility_available,
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
                    expected_evidence_types=['memory_analysis'],
                )

                result.confidence = validation.confidence
                result.warnings.extend(validation.warnings)

                if validation.contradictions:
                    result.errors.extend([
                        f"AI contradiction: {c['claim']}" for c in validation.contradictions
                    ])
            else:
                result.confidence = ai_response.confidence_score if ai_response else 0.5

            # Step 7: Extract verdict and IOCs
            if ai_response:
                result.summary = ai_response.merged_response
                result.ai_responses = ai_response

                # Extract verdict
                result.verdict = self._extract_verdict(ai_response.merged_response, mem_result)

                # Extract IOCs
                result.iocs = self._extract_all_iocs(
                    ai_response.merged_response,
                    mem_result
                )

                # Extract MITRE techniques
                result.mitre_techniques = self._extract_mitre_techniques(
                    ai_response.merged_response
                )

                # Extract tags
                result.tags = self._extract_tags(ai_response.merged_response, mem_result)

            # Set completion time
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            result.status = AnalysisStatus.COMPLETED

            logger.info(
                f"Memory analysis complete: {result.verdict.value} "
                f"(confidence: {result.confidence:.0%}, duration: {result.duration_seconds:.1f}s)"
            )

            return result

        except Exception as e:
            logger.error(f"Memory analysis failed: {e}", exc_info=True)
            result.status = AnalysisStatus.FAILED
            result.errors.append(str(e))
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            raise

    async def _query_vt_for_network(self, mem_result) -> Dict[str, Any]:
        """Query VirusTotal for IP addresses found in memory.

        Args:
            mem_result: Memory analysis result

        Returns:
            VirusTotal results dictionary
        """
        vt_results = {}

        # Query for unique remote IPs (limit to first 10)
        seen_ips = set()
        for conn in mem_result.network_connections[:10]:
            if conn.remote_addr and conn.remote_addr not in seen_ips:
                if not conn.remote_addr.startswith(('127.', '0.0.0.0', '::1')):
                    try:
                        ip_report = await self.vt_client.get_ip_report(conn.remote_addr)
                        if ip_report:
                            vt_results[conn.remote_addr] = {
                                'malicious': ip_report.malicious,
                                'total': ip_report.total_engines,
                                'reputation': ip_report.reputation,
                            }
                        seen_ips.add(conn.remote_addr)
                    except:
                        pass

        return vt_results

    def _format_vt_results(self, vt_results: Dict[str, Any]) -> str:
        """Format VirusTotal results for AI context.

        Args:
            vt_results: VT results dictionary

        Returns:
            Formatted string
        """
        if not vt_results:
            return "VirusTotal: Not queried"

        lines = ["VIRUSTOTAL IP REPUTATION:"]
        for ip, data in vt_results.items():
            lines.append(
                f"  {ip}: {data['malicious']}/{data['total']} engines, "
                f"reputation: {data['reputation']}"
            )

        return '\n'.join(lines)

    def _format_memory_context(self, mem_result, vt_context: str) -> Dict[str, str]:
        """Format memory analysis data for AI prompt.

        Args:
            mem_result: Memory analysis result
            vt_context: VirusTotal context string

        Returns:
            Context dictionary for prompt
        """
        # Format suspicious processes
        suspicious_procs = []
        for proc in mem_result.suspicious_processes[:10]:  # Limit to 10
            proc_str = f"- PID {proc.pid}: {proc.name} (PPID: {proc.ppid})"
            if proc.reasons:
                proc_str += f" [SUSPICIOUS: {', '.join(proc.reasons)}]"
            suspicious_procs.append(proc_str)

        # Format network connections
        network_conns = []
        for conn in mem_result.network_connections[:20]:  # Limit to 20
            conn_str = (
                f"- {conn.protocol}: {conn.local_addr}:{conn.local_port} -> "
                f"{conn.remote_addr}:{conn.remote_port} (PID {conn.pid}, {conn.process_name})"
            )
            if conn.suspicious:
                conn_str += f" [SUSPICIOUS: {', '.join(conn.reasons)}]"
            network_conns.append(conn_str)

        # Format malware indicators
        malware_indicators = []
        for indicator in mem_result.malware_indicators:
            malware_indicators.append(
                f"- [{indicator.severity.upper()}] {indicator.type}: {indicator.description}"
                f"\n  Evidence: {indicator.evidence}"
            )

        # Format injected code
        injections = []
        for inj in mem_result.injected_code[:10]:
            injections.append(
                f"- PID {inj.get('pid')}: {inj.get('process')} at {inj.get('address')}"
            )

        return {
            'file_info': f"Size: {mem_result.file_size} bytes\n"
                        f"OS: {mem_result.os_profile or 'Unknown'}\n"
                        f"Volatility Available: {mem_result.volatility_available}",

            'process_summary': f"Total Processes: {mem_result.process_count}\n"
                              f"Suspicious Processes: {len(mem_result.suspicious_processes)}\n"
                              f"Hidden Processes: {len(mem_result.hidden_processes)}",

            'suspicious_processes': '\n'.join(suspicious_procs) if suspicious_procs else "None detected",

            'network_connections': '\n'.join(network_conns) if network_conns else "No connections found",

            'malware_indicators': '\n'.join(malware_indicators) if malware_indicators else "None detected",

            'code_injection': '\n'.join(injections) if injections else "None detected",

            'hidden_processes': ', '.join(map(str, mem_result.hidden_processes)) if mem_result.hidden_processes else "None",

            'persistence_mechanisms': '\n'.join([f"- {p}" for p in mem_result.registry_persistence]) if mem_result.registry_persistence else "None detected",

            'anomalies': '\n'.join([f"- {a}" for a in mem_result.anomalies]) if mem_result.anomalies else "None detected",

            'virustotal_data': vt_context,
        }

    def _extract_verdict(self, ai_response: str, mem_result) -> Verdict:
        """Extract verdict from AI response and analysis.

        Args:
            ai_response: AI response text
            mem_result: Memory analysis result

        Returns:
            Verdict
        """
        response_lower = ai_response.lower()

        # Check for strong indicators from analysis
        if mem_result.malware_indicators:
            for indicator in mem_result.malware_indicators:
                if indicator.severity in ['critical', 'high']:
                    return Verdict.MALICIOUS

        # Check AI response
        if 'malicious' in response_lower or 'infected' in response_lower:
            return Verdict.MALICIOUS
        elif 'suspicious' in response_lower or 'anomalies' in response_lower:
            return Verdict.SUSPICIOUS
        elif 'clean' in response_lower or 'benign' in response_lower:
            return Verdict.CLEAN
        else:
            return Verdict.UNKNOWN

    def _extract_all_iocs(self, ai_response: str, mem_result) -> List[IOC]:
        """Extract IOCs from AI response and memory analysis.

        Args:
            ai_response: AI response text
            mem_result: Memory analysis result

        Returns:
            List of IOCs
        """
        iocs = []

        # Extract from AI response
        ai_iocs = self.extract_iocs_from_text(ai_response)
        iocs.extend(ai_iocs)

        # Extract network IOCs
        for conn in mem_result.network_connections:
            if conn.suspicious or conn.remote_addr not in ['0.0.0.0', '127.0.0.1']:
                if not conn.remote_addr.startswith(('127.', '0.0.0.0', '::1')):
                    iocs.append(IOC(
                        type="ip",
                        value=conn.remote_addr,
                        confidence=0.95 if conn.suspicious else 0.7,
                        description=f"Network connection from PID {conn.pid} ({conn.process_name})"
                    ))

        # Extract suspicious process names
        for proc in mem_result.suspicious_processes:
            iocs.append(IOC(
                type="process_name",
                value=proc.name,
                confidence=0.9,
                description=f"Suspicious process: {', '.join(proc.reasons)}"
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

    def _extract_tags(self, ai_response: str, mem_result) -> List[str]:
        """Extract relevant tags.

        Args:
            ai_response: AI response text
            mem_result: Memory analysis result

        Returns:
            List of tags
        """
        tags = ['memory_forensics', 'volatility']
        response_lower = ai_response.lower()

        # Malware types
        malware_types = ['rootkit', 'trojan', 'ransomware', 'backdoor', 'stealer']
        for malware_type in malware_types:
            if malware_type in response_lower:
                tags.append(malware_type)

        # Techniques
        if mem_result.injected_code:
            tags.append('code_injection')

        if mem_result.hidden_processes:
            tags.append('process_hiding')

        if mem_result.registry_persistence:
            tags.append('persistence')

        if mem_result.suspicious_processes:
            tags.append('suspicious_activity')

        # OS tag
        if mem_result.os_profile:
            tags.append('windows')

        return list(set(tags))
