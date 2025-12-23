"""SIEM integration module for log shipping and analysis.

This module provides integration with various SIEM platforms for:
- Sending BlueGuardian AI analysis logs to SIEM
- Fetching logs from SIEM for analysis
- Supporting multiple SIEM platforms
"""

import json
import socket
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from loguru import logger


@dataclass
class SIEMLog:
    """Standardized log entry for SIEM."""

    timestamp: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    source: str  # 'blueguardian'
    event_type: str  # 'analysis_complete', 'malware_detected', 'phishing_detected', etc.
    artifact_name: str
    verdict: str
    confidence: float
    agent_name: str
    iocs: List[str]
    mitre_techniques: List[str]
    summary: str
    details: Dict[str, Any]


class BaseSIEMClient(ABC):
    """Abstract base class for SIEM clients."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize SIEM client.

        Args:
            config: SIEM configuration dictionary
        """
        self.config = config
        self.enabled = config.get('enabled', False)

    @abstractmethod
    def send_log(self, log: SIEMLog) -> bool:
        """Send a log entry to SIEM.

        Args:
            log: Log entry to send

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    def query_logs(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query logs from SIEM.

        Args:
            query: Search query in SIEM-specific format
            start_time: Start time for query
            end_time: End time for query
            limit: Maximum number of results

        Returns:
            List of log entries
        """
        pass

    def format_log_for_siem(self, log: SIEMLog) -> Dict[str, Any]:
        """Convert SIEMLog to dictionary format.

        Args:
            log: Log entry

        Returns:
            Dictionary representation
        """
        return asdict(log)


class SplunkClient(BaseSIEMClient):
    """Splunk SIEM client.

    Supports Splunk HTTP Event Collector (HEC) for log ingestion
    and Splunk REST API for querying.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Splunk client.

        Args:
            config: Configuration with keys:
                - host: Splunk host
                - port: HEC port (default: 8088)
                - token: HEC token
                - index: Target index
                - verify_ssl: Verify SSL certificate
        """
        super().__init__(config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 8088)
        self.token = config.get('token')
        self.index = config.get('index', 'blueguardian')
        self.verify_ssl = config.get('verify_ssl', True)

        self.hec_url = f"https://{self.host}:{self.port}/services/collector/event"

        logger.info(f"Initialized SplunkClient (host={self.host}, index={self.index})")

    def send_log(self, log: SIEMLog) -> bool:
        """Send log to Splunk via HEC.

        Args:
            log: Log entry

        Returns:
            True if successful
        """
        if not self.enabled or not self.token:
            return False

        try:
            # Format for Splunk HEC
            payload = {
                'time': int(datetime.fromisoformat(log.timestamp).timestamp()),
                'host': socket.gethostname(),
                'source': log.source,
                'sourcetype': 'blueguardian:analysis',
                'index': self.index,
                'event': self.format_log_for_siem(log),
            }

            headers = {
                'Authorization': f'Splunk {self.token}',
                'Content-Type': 'application/json',
            }

            response = requests.post(
                self.hec_url,
                json=payload,
                headers=headers,
                verify=self.verify_ssl,
                timeout=10,
            )

            if response.status_code == 200:
                logger.debug(f"Log sent to Splunk: {log.event_type}")
                return True
            else:
                logger.error(f"Splunk HEC error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send log to Splunk: {e}")
            return False

    def query_logs(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query logs from Splunk.

        Args:
            query: Splunk search query (SPL)
            start_time: Start time
            end_time: End time
            limit: Result limit

        Returns:
            List of log entries
        """
        # Splunk REST API implementation would go here
        # For now, return empty list
        logger.warning("Splunk query not yet implemented")
        return []


class ElasticsearchClient(BaseSIEMClient):
    """Elasticsearch/ELK Stack SIEM client."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize Elasticsearch client.

        Args:
            config: Configuration with keys:
                - host: Elasticsearch host
                - port: Port (default: 9200)
                - username: Username (optional)
                - password: Password (optional)
                - index: Target index pattern
                - verify_ssl: Verify SSL certificate
        """
        super().__init__(config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 9200)
        self.username = config.get('username')
        self.password = config.get('password')
        self.index = config.get('index', 'blueguardian')
        self.verify_ssl = config.get('verify_ssl', True)

        self.base_url = f"http://{self.host}:{self.port}"

        logger.info(f"Initialized ElasticsearchClient (host={self.host}, index={self.index})")

    def send_log(self, log: SIEMLog) -> bool:
        """Send log to Elasticsearch.

        Args:
            log: Log entry

        Returns:
            True if successful
        """
        if not self.enabled:
            return False

        try:
            # Create document
            doc = self.format_log_for_siem(log)
            doc['@timestamp'] = log.timestamp

            # Index URL with timestamp-based index
            index_name = f"{self.index}-{datetime.now().strftime('%Y.%m.%d')}"
            url = f"{self.base_url}/{index_name}/_doc"

            # Authentication
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)

            response = requests.post(
                url,
                json=doc,
                auth=auth,
                verify=self.verify_ssl,
                timeout=10,
            )

            if response.status_code in [200, 201]:
                logger.debug(f"Log sent to Elasticsearch: {log.event_type}")
                return True
            else:
                logger.error(f"Elasticsearch error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send log to Elasticsearch: {e}")
            return False

    def query_logs(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query logs from Elasticsearch.

        Args:
            query: Elasticsearch query (Lucene syntax or Query DSL)
            start_time: Start time
            end_time: End time
            limit: Result limit

        Returns:
            List of log entries
        """
        try:
            # Build query
            search_query = {
                'query': {
                    'bool': {
                        'must': [
                            {'query_string': {'query': query}}
                        ]
                    }
                },
                'size': limit,
                'sort': [{'@timestamp': {'order': 'desc'}}]
            }

            # Add time range if specified
            if start_time or end_time:
                time_range = {'range': {'@timestamp': {}}}
                if start_time:
                    time_range['range']['@timestamp']['gte'] = start_time.isoformat()
                if end_time:
                    time_range['range']['@timestamp']['lte'] = end_time.isoformat()
                search_query['query']['bool']['must'].append(time_range)

            # Search
            url = f"{self.base_url}/{self.index}-*/_search"
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)

            response = requests.post(
                url,
                json=search_query,
                auth=auth,
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code == 200:
                results = response.json()
                hits = results.get('hits', {}).get('hits', [])
                return [hit['_source'] for hit in hits]
            else:
                logger.error(f"Elasticsearch query error: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Failed to query Elasticsearch: {e}")
            return []


class SyslogClient(BaseSIEMClient):
    """Generic Syslog client for SIEM integration."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize Syslog client.

        Args:
            config: Configuration with keys:
                - host: Syslog server host
                - port: Syslog port (default: 514)
                - protocol: 'udp' or 'tcp' (default: udp)
                - facility: Syslog facility (default: 16 - local0)
        """
        super().__init__(config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 514)
        self.protocol = config.get('protocol', 'udp').lower()
        self.facility = config.get('facility', 16)  # local0

        logger.info(f"Initialized SyslogClient (host={self.host}, protocol={self.protocol})")

    def send_log(self, log: SIEMLog) -> bool:
        """Send log via Syslog.

        Args:
            log: Log entry

        Returns:
            True if successful
        """
        if not self.enabled:
            return False

        try:
            # Map severity to syslog priority
            severity_map = {
                'critical': 2,  # Critical
                'high': 3,      # Error
                'medium': 4,    # Warning
                'low': 5,       # Notice
                'info': 6,      # Informational
            }
            severity = severity_map.get(log.severity.lower(), 6)

            # Calculate priority
            priority = (self.facility * 8) + severity

            # Format message
            timestamp = datetime.fromisoformat(log.timestamp).strftime('%b %d %H:%M:%S')
            hostname = socket.gethostname()
            tag = 'blueguardian'

            message_data = {
                'event': log.event_type,
                'artifact': log.artifact_name,
                'verdict': log.verdict,
                'confidence': log.confidence,
                'summary': log.summary,
            }

            message = f"<{priority}>{timestamp} {hostname} {tag}: {json.dumps(message_data)}"

            # Send via UDP or TCP
            if self.protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode('utf-8'), (self.host, self.port))
                sock.close()
            else:  # TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.host, self.port))
                sock.send(message.encode('utf-8'))
                sock.close()

            logger.debug(f"Log sent via Syslog: {log.event_type}")
            return True

        except Exception as e:
            logger.error(f"Failed to send log via Syslog: {e}")
            return False

    def query_logs(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query logs (not supported for Syslog).

        Syslog is send-only protocol.
        """
        logger.warning("Syslog does not support querying")
        return []


class AzureSentinelClient(BaseSIEMClient):
    """Azure Sentinel SIEM client."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize Azure Sentinel client.

        Args:
            config: Configuration with keys:
                - workspace_id: Log Analytics workspace ID
                - shared_key: Workspace shared key
                - log_type: Custom log type name
        """
        super().__init__(config)
        self.workspace_id = config.get('workspace_id')
        self.shared_key = config.get('shared_key')
        self.log_type = config.get('log_type', 'BlueGuardian')

        logger.info(f"Initialized AzureSentinelClient (log_type={self.log_type})")

    def send_log(self, log: SIEMLog) -> bool:
        """Send log to Azure Sentinel.

        Args:
            log: Log entry

        Returns:
            True if successful
        """
        if not self.enabled or not self.workspace_id or not self.shared_key:
            return False

        try:
            # Azure Log Analytics Data Collector API
            import base64
            import hashlib
            import hmac

            # Build signature
            date_string = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            body = json.dumps([self.format_log_for_siem(log)])
            content_length = len(body)

            string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{date_string}\n/api/logs"
            bytes_to_hash = string_to_hash.encode('utf-8')
            decoded_key = base64.b64decode(self.shared_key)
            encoded_hash = base64.b64encode(
                hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()
            ).decode('utf-8')

            authorization = f"SharedKey {self.workspace_id}:{encoded_hash}"

            # Send request
            url = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            headers = {
                'Content-Type': 'application/json',
                'Log-Type': self.log_type,
                'Authorization': authorization,
                'x-ms-date': date_string,
            }

            response = requests.post(url, data=body, headers=headers, timeout=10)

            if response.status_code == 200:
                logger.debug(f"Log sent to Azure Sentinel: {log.event_type}")
                return True
            else:
                logger.error(f"Azure Sentinel error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send log to Azure Sentinel: {e}")
            return False

    def query_logs(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query logs from Azure Sentinel (KQL query).

        Args:
            query: KQL query string
            start_time: Start time
            end_time: End time
            limit: Result limit

        Returns:
            List of log entries
        """
        # Azure Monitor API implementation would go here
        logger.warning("Azure Sentinel query not yet implemented")
        return []


class SIEMManager:
    """Manager for multiple SIEM integrations."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize SIEM manager.

        Args:
            config: SIEM configuration with client configs
        """
        self.config = config
        self.clients: List[BaseSIEMClient] = []

        # Initialize clients based on config
        self._initialize_clients()

        logger.info(f"Initialized SIEMManager with {len(self.clients)} clients")

    def _initialize_clients(self) -> None:
        """Initialize SIEM clients from configuration."""
        # Splunk
        if 'splunk' in self.config:
            client = SplunkClient(self.config['splunk'])
            if client.enabled:
                self.clients.append(client)

        # Elasticsearch/ELK
        if 'elasticsearch' in self.config:
            client = ElasticsearchClient(self.config['elasticsearch'])
            if client.enabled:
                self.clients.append(client)

        # Syslog
        if 'syslog' in self.config:
            client = SyslogClient(self.config['syslog'])
            if client.enabled:
                self.clients.append(client)

        # Azure Sentinel
        if 'azure_sentinel' in self.config:
            client = AzureSentinelClient(self.config['azure_sentinel'])
            if client.enabled:
                self.clients.append(client)

    def send_analysis_log(
        self,
        artifact_name: str,
        verdict: str,
        confidence: float,
        agent_name: str,
        summary: str,
        iocs: List[str],
        mitre_techniques: List[str],
        event_type: str = 'analysis_complete',
        severity: str = 'info',
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send analysis log to all configured SIEMs.

        Args:
            artifact_name: Name of analyzed artifact
            verdict: Analysis verdict
            confidence: Confidence score
            agent_name: Agent that performed analysis
            summary: Analysis summary
            iocs: List of IOCs
            mitre_techniques: List of MITRE techniques
            event_type: Event type
            severity: Log severity
            details: Additional details

        Returns:
            True if sent to at least one SIEM
        """
        if not self.clients:
            return False

        log = SIEMLog(
            timestamp=datetime.now().isoformat(),
            severity=severity,
            source='blueguardian',
            event_type=event_type,
            artifact_name=artifact_name,
            verdict=verdict,
            confidence=confidence,
            agent_name=agent_name,
            iocs=iocs,
            mitre_techniques=mitre_techniques,
            summary=summary,
            details=details or {},
        )

        success_count = 0
        for client in self.clients:
            if client.send_log(log):
                success_count += 1

        return success_count > 0

    def query_all_siems(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Query all configured SIEMs.

        Args:
            query: Search query
            start_time: Start time
            end_time: End time
            limit: Result limit

        Returns:
            Dictionary mapping SIEM type to results
        """
        results = {}

        for client in self.clients:
            client_type = client.__class__.__name__.replace('Client', '')
            try:
                client_results = client.query_logs(query, start_time, end_time, limit)
                results[client_type] = client_results
            except Exception as e:
                logger.error(f"Query failed for {client_type}: {e}")
                results[client_type] = []

        return results
