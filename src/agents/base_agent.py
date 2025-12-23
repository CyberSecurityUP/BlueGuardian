"""Base agent class for security analysis.

This module provides the foundation for all specialized analysis agents,
handling AI communication, tool orchestration, and result formatting.
"""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from src.ai_providers.base import BaseAIProvider, Message, MessageRole, Tool
from src.ai_providers.consensus import ConsensusEngine, ConsensusResult
from src.config.settings import Settings


class AnalysisStatus(str, Enum):
    """Status of an analysis."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class Verdict(str, Enum):
    """Analysis verdict."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    """Indicator of Compromise."""

    type: str  # ip, domain, url, hash, email, registry, mutex, etc.
    value: str
    confidence: float = 1.0
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Result from an analysis."""

    # Basic info
    artifact_path: str
    agent_type: str
    status: AnalysisStatus

    # Analysis results
    verdict: Verdict
    confidence: float
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)

    # Extracted data
    iocs: List[IOC] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Metadata
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    # AI response data
    ai_responses: Optional[ConsensusResult] = None
    tool_outputs: Dict[str, Any] = field(default_factory=dict)

    # Errors
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "artifact_path": self.artifact_path,
            "agent_type": self.agent_type,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "details": self.details,
            "iocs": [
                {
                    "type": ioc.type,
                    "value": ioc.value,
                    "confidence": ioc.confidence,
                    "description": ioc.description,
                }
                for ioc in self.iocs
            ],
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class BaseAgent(ABC):
    """Base class for all security analysis agents.

    This class provides common functionality for:
    - AI provider communication
    - Tool execution
    - Result formatting
    - Error handling
    - Logging and metrics
    """

    def __init__(
        self,
        settings: Settings,
        ai_providers: List[BaseAIProvider],
        consensus_engine: Optional[ConsensusEngine] = None,
    ):
        """Initialize the agent.

        Args:
            settings: Application settings
            ai_providers: List of AI providers to use
            consensus_engine: Optional consensus engine for multi-model validation
        """
        self.settings = settings
        self.ai_providers = ai_providers
        self.consensus_engine = consensus_engine
        self.agent_name = self.__class__.__name__

        logger.info(f"Initialized {self.agent_name}")

    @abstractmethod
    async def analyze(self, artifact_path: str, **kwargs: Any) -> AnalysisResult:
        """Analyze an artifact.

        Args:
            artifact_path: Path to the artifact to analyze
            **kwargs: Additional agent-specific parameters

        Returns:
            AnalysisResult with findings

        Raises:
            ValueError: If artifact is invalid
            Exception: If analysis fails
        """
        pass

    @abstractmethod
    def get_supported_file_types(self) -> List[str]:
        """Get list of supported file extensions.

        Returns:
            List of file extensions (e.g., ['.exe', '.dll', '.sys'])
        """
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent.

        Returns:
            System prompt describing the agent's role and capabilities
        """
        pass

    def can_analyze(self, file_path: str) -> bool:
        """Check if this agent can analyze the given file.

        Args:
            file_path: Path to file

        Returns:
            True if agent supports this file type
        """
        path = Path(file_path)
        supported = self.get_supported_file_types()

        if not supported:  # Agent supports all types
            return True

        return path.suffix.lower() in [ext.lower() for ext in supported]

    async def query_ai(
        self,
        user_message: str,
        context: Optional[Dict[str, Any]] = None,
        tools: Optional[List[Tool]] = None,
        temperature: float = 0.0,
    ) -> ConsensusResult:
        """Query AI providers with optional consensus.

        Args:
            user_message: Message to send to AI
            context: Additional context data
            tools: Optional tools for function calling
            temperature: Temperature for generation

        Returns:
            ConsensusResult if using consensus, otherwise single response
        """
        # Build messages
        messages = [
            Message(role=MessageRole.SYSTEM, content=self.get_system_prompt())
        ]

        # Add context if provided
        if context:
            context_str = self._format_context(context)
            messages.append(
                Message(
                    role=MessageRole.USER,
                    content=f"Context:\n{context_str}\n\nQuery: {user_message}"
                )
            )
        else:
            messages.append(Message(role=MessageRole.USER, content=user_message))

        # Use consensus if enabled and available
        if self.consensus_engine and self.settings.ai.enable_multi_model_consensus:
            logger.debug("Using multi-model consensus")
            return await self.consensus_engine.generate_with_consensus(
                messages=messages,
                tools=tools,
                temperature=temperature,
            )
        else:
            # Use primary provider only
            logger.debug(f"Using single provider: {self.ai_providers[0].provider_name.value}")
            response = await self.ai_providers[0].generate(
                messages=messages,
                tools=tools,
                temperature=temperature,
            )

            # Wrap in ConsensusResult for consistent interface
            from src.ai_providers.consensus import ConsensusResult
            return ConsensusResult(
                merged_response=response.content,
                confidence_score=1.0,
                all_responses=[response],
                agreements=[],
                disagreements=[],
                unique_claims=[],
                provider_scores={},
            )

    def _format_context(self, context: Dict[str, Any]) -> str:
        """Format context dictionary into readable text.

        Args:
            context: Context dictionary

        Returns:
            Formatted context string
        """
        lines = []
        for key, value in context.items():
            if isinstance(value, (list, dict)):
                import json
                value_str = json.dumps(value, indent=2)
            else:
                value_str = str(value)
            lines.append(f"{key}:\n{value_str}")

        return "\n\n".join(lines)

    def calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with md5, sha1, sha256 hashes
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
        }

    def extract_iocs_from_text(self, text: str) -> List[IOC]:
        """Extract IOCs from text using regex patterns.

        Args:
            text: Text to extract from

        Returns:
            List of extracted IOCs
        """
        import re

        iocs = []

        # IP addresses (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for match in re.finditer(ip_pattern, text):
            ip = match.group()
            # Basic validation
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                iocs.append(IOC(type="ip", value=ip, confidence=0.8))

        # Domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        for match in re.finditer(domain_pattern, text, re.IGNORECASE):
            domain = match.group().lower()
            # Filter out common false positives
            if domain not in ['example.com', 'localhost', 'test.com']:
                iocs.append(IOC(type="domain", value=domain, confidence=0.7))

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        for match in re.finditer(url_pattern, text):
            url = match.group()
            iocs.append(IOC(type="url", value=url, confidence=0.9))

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        for match in re.finditer(email_pattern, text):
            email = match.group()
            iocs.append(IOC(type="email", value=email, confidence=0.8))

        # MD5 hashes
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        for match in re.finditer(md5_pattern, text):
            iocs.append(IOC(type="hash_md5", value=match.group().lower(), confidence=0.9))

        # SHA256 hashes
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for match in re.finditer(sha256_pattern, text):
            iocs.append(IOC(type="hash_sha256", value=match.group().lower(), confidence=0.9))

        # Registry keys (Windows)
        registry_pattern = r'HK(EY_)?(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s]+'
        for match in re.finditer(registry_pattern, text, re.IGNORECASE):
            iocs.append(IOC(type="registry", value=match.group(), confidence=0.8))

        # Remove duplicates
        unique_iocs = []
        seen = set()
        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def validate_artifact(self, artifact_path: str) -> None:
        """Validate that artifact exists and is accessible.

        Args:
            artifact_path: Path to artifact

        Raises:
            ValueError: If artifact is invalid
        """
        path = Path(artifact_path)

        if not path.exists():
            raise ValueError(f"Artifact not found: {artifact_path}")

        if not path.is_file():
            raise ValueError(f"Artifact is not a file: {artifact_path}")

        # Check file size
        size_mb = path.stat().st_size / (1024 * 1024)
        max_size = self.settings.analysis.max_file_size_mb

        if size_mb > max_size:
            raise ValueError(
                f"Artifact too large: {size_mb:.2f}MB (max: {max_size}MB)"
            )

        # Check if agent supports this file type
        if not self.can_analyze(artifact_path):
            supported = ', '.join(self.get_supported_file_types())
            raise ValueError(
                f"Unsupported file type: {path.suffix} "
                f"(supported: {supported})"
            )

    def create_result_template(self, artifact_path: str) -> AnalysisResult:
        """Create an empty result template.

        Args:
            artifact_path: Path to artifact being analyzed

        Returns:
            AnalysisResult with basic info filled in
        """
        return AnalysisResult(
            artifact_path=artifact_path,
            agent_type=self.agent_name,
            status=AnalysisStatus.PENDING,
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            summary="",
            started_at=datetime.now(),
        )
