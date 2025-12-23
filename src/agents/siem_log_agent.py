"""SIEM log analysis agent.

This agent specializes in analyzing logs from SIEM platforms to detect
threats, anomalies, and security incidents using AI-powered analysis.
"""

import json
import time
from datetime import datetime, timedelta
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
from src.config.settings import Settings
from src.core.hallucination_guard import HallucinationGuard
from src.integrations.siem_integration import SIEMManager
from src.prompts.siem_prompts import (
    SIEM_LOG_ANALYSIS_PROMPT,
    SIEM_LOG_ANALYSIS_SYSTEM_PROMPT,
    format_prompt,
)


class SIEMLogAgent(BaseAgent):
    """Agent specialized in SIEM log analysis.

    This agent analyzes logs from SIEM platforms to detect:
    - Security incidents and anomalies
    - Brute force attacks
    - Privilege escalation
    - Lateral movement
    - Data exfiltration
    - Malware infections
    - Suspicious user behavior
    """

    def __init__(
        self,
        settings: Settings,
        ai_providers: List[BaseAIProvider],
        consensus_engine: Optional[ConsensusEngine] = None,
        siem_manager: Optional[SIEMManager] = None,
        hallucination_guard: Optional[HallucinationGuard] = None,
    ):
        """Initialize SIEM log analysis agent.

        Args:
            settings: Application settings
            ai_providers: AI providers for analysis
            consensus_engine: Multi-model consensus engine
            siem_manager: SIEM integration manager
            hallucination_guard: Hallucination detection system
        """
        super().__init__(settings, ai_providers, consensus_engine)

        self.siem_manager = siem_manager
        self.hallucination_guard = hallucination_guard or HallucinationGuard(
            min_confidence_threshold=settings.hallucination_guard.min_confidence_score
        )

        logger.info("Initialized SIEMLogAgent")

    def get_supported_file_types(self) -> List[str]:
        """Get supported file extensions.

        Returns:
            List of supported extensions (log files)
        """
        return ['.log', '.json', '.txt', '.csv']

    def get_system_prompt(self) -> str:
        """Get SIEM log analysis system prompt.

        Returns:
            System prompt
        """
        return SIEM_LOG_ANALYSIS_SYSTEM_PROMPT

    async def analyze(self, artifact_path: str, **kwargs: Any) -> AnalysisResult:
        """Analyze SIEM logs for security incidents.

        Can analyze logs from:
        - A log file (JSON, CSV, or text)
        - Direct SIEM query (if siem_manager configured and query provided)

        Args:
            artifact_path: Path to log file or query identifier
            **kwargs: Additional parameters
                - siem_query: Query to fetch logs from SIEM
                - log_count: Number of logs to analyze (default: 100)
                - time_range_hours: Hours of logs to fetch (default: 24)

        Returns:
            AnalysisResult with comprehensive findings

        Raises:
            ValueError: If logs are invalid
        """
        start_time = time.time()

        # Create result template
        result = self.create_result_template(artifact_path)
        result.status = AnalysisStatus.RUNNING

        logger.info(f"Starting SIEM log analysis: {artifact_path}")

        try:
            # Determine if analyzing file or SIEM query
            logs = []
            log_source = "file"

            if kwargs.get('siem_query') and self.siem_manager:
                # Fetch logs from SIEM
                log_source = "siem_query"
                logs = await self._fetch_logs_from_siem(
                    kwargs['siem_query'],
                    kwargs.get('log_count', 100),
                    kwargs.get('time_range_hours', 24),
                )
            elif Path(artifact_path).exists():
                # Read logs from file
                logs = self._read_log_file(artifact_path)
            else:
                raise ValueError(f"Invalid artifact path or missing SIEM query: {artifact_path}")

            if not logs:
                raise ValueError("No logs found to analyze")

            logger.info(f"Loaded {len(logs)} log entries from {log_source}")

            # Analyze logs
            analysis = self._analyze_logs(logs)

            # Format context for AI
            context = self._format_log_context(logs, analysis)

            # Query AI
            prompt = format_prompt(SIEM_LOG_ANALYSIS_PROMPT, **context)
            ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

            # Package tool outputs
            result.tool_outputs = {
                'log_analysis': analysis,
                'log_count': len(logs),
                'log_source': log_source,
                'ai_response': ai_response,
            }

            # Validate AI response
            if ai_response and self.hallucination_guard:
                logger.debug("Validating AI response")
                validation = self.hallucination_guard.validate(
                    consensus_result=ai_response,
                    tool_outputs=result.tool_outputs,
                    expected_evidence_types=['log_analysis'],
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
                result.verdict = self._extract_verdict(ai_response.merged_response, analysis)

                # Extract IOCs
                result.iocs = self._extract_all_iocs(ai_response.merged_response, logs)

                # Extract MITRE techniques
                result.mitre_techniques = self._extract_mitre_techniques(
                    ai_response.merged_response
                )

                # Extract tags
                result.tags = self._extract_tags(ai_response.merged_response, analysis)

            # Set completion time
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            result.status = AnalysisStatus.COMPLETED

            logger.info(
                f"SIEM log analysis complete: {result.verdict.value} "
                f"(confidence: {result.confidence:.0%}, duration: {result.duration_seconds:.1f}s)"
            )

            return result

        except Exception as e:
            logger.error(f"SIEM log analysis failed: {e}", exc_info=True)
            result.status = AnalysisStatus.FAILED
            result.errors.append(str(e))
            result.completed_at = datetime.now()
            result.duration_seconds = time.time() - start_time
            raise

    async def _fetch_logs_from_siem(
        self, query: str, log_count: int, time_range_hours: int
    ) -> List[Dict[str, Any]]:
        """Fetch logs from SIEM.

        Args:
            query: SIEM query string
            log_count: Number of logs to fetch
            time_range_hours: Time range in hours

        Returns:
            List of log entries
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time_range_hours)

        logger.info(f"Querying SIEM: {query} (last {time_range_hours} hours)")

        results = self.siem_manager.query_all_siems(
            query=query,
            start_time=start_time,
            end_time=end_time,
            limit=log_count,
        )

        # Combine results from all SIEMs
        all_logs = []
        for siem_type, logs in results.items():
            logger.debug(f"Retrieved {len(logs)} logs from {siem_type}")
            all_logs.extend(logs)

        return all_logs[:log_count]  # Limit total logs

    def _read_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Read logs from a file.

        Args:
            file_path: Path to log file

        Returns:
            List of log entries
        """
        logs = []
        path = Path(file_path)

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                # Try JSON lines format first
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        log = json.loads(line)
                        logs.append(log)
                    except json.JSONDecodeError:
                        # Fall back to plain text
                        logs.append({'message': line, 'raw': True})

        except Exception as e:
            logger.error(f"Error reading log file: {e}")
            raise

        return logs

    def _analyze_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform statistical analysis on logs.

        Args:
            logs: List of log entries

        Returns:
            Analysis results dictionary
        """
        analysis = {
            'total_logs': len(logs),
            'unique_ips': set(),
            'unique_users': set(),
            'failed_logins': 0,
            'successful_logins': 0,
            'privilege_escalations': 0,
            'suspicious_commands': [],
            'unusual_ports': set(),
            'high_severity_count': 0,
            'error_count': 0,
            'top_sources': {},
            'top_destinations': {},
            'anomalies': [],
        }

        # Suspicious command patterns
        suspicious_patterns = [
            'whoami', 'net user', 'net localgroup', 'mimikatz',
            'powershell -enc', 'bash -i', 'nc -e', '/bin/sh',
            'wget', 'curl', 'certutil', 'bitsadmin',
        ]

        for log in logs:
            # Extract common fields (different SIEMs use different field names)
            message = log.get('message', log.get('Message', ''))
            source_ip = log.get('src_ip', log.get('source', log.get('SourceIP', '')))
            dest_ip = log.get('dst_ip', log.get('destination', log.get('DestinationIP', '')))
            user = log.get('user', log.get('User', log.get('username', '')))
            event_type = log.get('event_type', log.get('EventType', ''))
            severity = log.get('severity', log.get('Severity', '')).lower()
            port = log.get('port', log.get('Port', 0))

            # Track unique IPs
            if source_ip:
                analysis['unique_ips'].add(source_ip)
                analysis['top_sources'][source_ip] = analysis['top_sources'].get(source_ip, 0) + 1
            if dest_ip:
                analysis['unique_ips'].add(dest_ip)
                analysis['top_destinations'][dest_ip] = analysis['top_destinations'].get(dest_ip, 0) + 1

            # Track users
            if user:
                analysis['unique_users'].add(user)

            # Detect patterns
            message_lower = message.lower()

            # Failed logins
            if any(pattern in message_lower for pattern in ['failed', 'failure', 'invalid', 'denied']):
                if any(pattern in message_lower for pattern in ['login', 'authentication', 'logon']):
                    analysis['failed_logins'] += 1

            # Successful logins
            if any(pattern in message_lower for pattern in ['success', 'successful', 'accepted']):
                if any(pattern in message_lower for pattern in ['login', 'authentication', 'logon']):
                    analysis['successful_logins'] += 1

            # Privilege escalation
            if any(pattern in message_lower for pattern in ['sudo', 'su -', 'runas', 'administrator', 'root']):
                analysis['privilege_escalations'] += 1

            # Suspicious commands
            for pattern in suspicious_patterns:
                if pattern in message_lower:
                    analysis['suspicious_commands'].append({
                        'command': pattern,
                        'source': source_ip,
                        'user': user,
                    })

            # Unusual ports
            if port and (port < 1024 or port > 49151):
                if port not in [80, 443, 22, 21, 25, 53]:
                    analysis['unusual_ports'].add(port)

            # Severity tracking
            if severity in ['critical', 'high', 'error']:
                analysis['high_severity_count'] += 1
            if 'error' in severity:
                analysis['error_count'] += 1

        # Convert sets to counts/lists
        analysis['unique_ip_count'] = len(analysis['unique_ips'])
        analysis['unique_user_count'] = len(analysis['unique_users'])
        analysis['unique_ips'] = list(analysis['unique_ips'])[:20]  # Limit for context
        analysis['unique_users'] = list(analysis['unique_users'])[:20]

        # Detect anomalies
        if analysis['failed_logins'] > 50:
            analysis['anomalies'].append(f"High number of failed logins: {analysis['failed_logins']}")

        if analysis['privilege_escalations'] > 10:
            analysis['anomalies'].append(
                f"Multiple privilege escalation attempts: {analysis['privilege_escalations']}"
            )

        if len(analysis['suspicious_commands']) > 0:
            analysis['anomalies'].append(
                f"Suspicious commands detected: {len(analysis['suspicious_commands'])}"
            )

        return analysis

    def _format_log_context(
        self, logs: List[Dict[str, Any]], analysis: Dict[str, Any]
    ) -> Dict[str, str]:
        """Format log data for AI prompt.

        Args:
            logs: Log entries
            analysis: Statistical analysis

        Returns:
            Context dictionary for prompt
        """
        # Sample logs for AI context (first and last few)
        sample_logs = logs[:10] + logs[-10:] if len(logs) > 20 else logs
        sample_log_str = '\n'.join([
            json.dumps(log, indent=2)[:300] for log in sample_logs[:10]
        ])

        # Top sources
        top_sources = sorted(
            analysis['top_sources'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        top_sources_str = '\n'.join([f"- {ip}: {count} events" for ip, count in top_sources])

        # Suspicious commands
        suspicious_cmds_str = '\n'.join([
            f"- {cmd['command']} (from {cmd['source']}, user: {cmd['user']})"
            for cmd in analysis['suspicious_commands'][:20]
        ])

        return {
            'total_logs': str(analysis['total_logs']),
            'time_range': "Last 24 hours",  # TODO: Make dynamic
            'unique_ip_count': str(analysis['unique_ip_count']),
            'unique_user_count': str(analysis['unique_user_count']),
            'failed_logins': str(analysis['failed_logins']),
            'successful_logins': str(analysis['successful_logins']),
            'privilege_escalations': str(analysis['privilege_escalations']),
            'high_severity_count': str(analysis['high_severity_count']),
            'top_sources': top_sources_str if top_sources else "None",
            'suspicious_commands': suspicious_cmds_str if analysis['suspicious_commands'] else "None detected",
            'anomalies': '\n'.join([f"- {a}" for a in analysis['anomalies']]) if analysis['anomalies'] else "None detected",
            'sample_logs': sample_log_str,
        }

    def _extract_verdict(self, ai_response: str, analysis: Dict[str, Any]) -> Verdict:
        """Extract verdict from AI response and analysis.

        Args:
            ai_response: AI response text
            analysis: Statistical analysis

        Returns:
            Verdict
        """
        response_lower = ai_response.lower()

        # Check for indicators of compromise
        if analysis['anomalies'] and len(analysis['anomalies']) > 3:
            return Verdict.MALICIOUS

        # Check AI response
        if 'attack' in response_lower or 'compromise' in response_lower:
            return Verdict.MALICIOUS
        elif 'suspicious' in response_lower or 'anomal' in response_lower:
            return Verdict.SUSPICIOUS
        elif 'normal' in response_lower or 'clean' in response_lower:
            return Verdict.CLEAN
        else:
            return Verdict.UNKNOWN

    def _extract_all_iocs(
        self, ai_response: str, logs: List[Dict[str, Any]]
    ) -> List[IOC]:
        """Extract IOCs from AI response and logs.

        Args:
            ai_response: AI response text
            logs: Log entries

        Returns:
            List of IOCs
        """
        iocs = []

        # Extract from AI response
        ai_iocs = self.extract_iocs_from_text(ai_response)
        iocs.extend(ai_iocs)

        # Extract from logs (sample to avoid too many IOCs)
        seen_ips = set()
        for log in logs[:100]:
            source_ip = log.get('src_ip', log.get('source', ''))
            if source_ip and source_ip not in seen_ips and not source_ip.startswith(('127.', '192.168.', '10.')):
                seen_ips.add(source_ip)
                iocs.append(IOC(
                    type="ip",
                    value=source_ip,
                    confidence=0.7,
                    description="Source IP from logs"
                ))

        # Remove duplicates
        unique_iocs = []
        seen = set()

        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs[:50]  # Limit IOCs

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

    def _extract_tags(self, ai_response: str, analysis: Dict[str, Any]) -> List[str]:
        """Extract relevant tags.

        Args:
            ai_response: AI response text
            analysis: Statistical analysis

        Returns:
            List of tags
        """
        tags = ['siem', 'log_analysis']
        response_lower = ai_response.lower()

        # Attack types
        attack_types = [
            'brute_force', 'privilege_escalation', 'lateral_movement',
            'exfiltration', 'credential_dumping', 'reconnaissance',
        ]

        for attack_type in attack_types:
            if attack_type.replace('_', ' ') in response_lower:
                tags.append(attack_type)

        # Based on analysis
        if analysis['failed_logins'] > 50:
            tags.append('brute_force')

        if analysis['privilege_escalations'] > 0:
            tags.append('privilege_escalation')

        if analysis['suspicious_commands']:
            tags.append('suspicious_activity')

        return list(set(tags))
