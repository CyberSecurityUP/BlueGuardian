"""Main orchestrator for BlueGuardian AI.

This module coordinates all components of the system, managing AI providers,
agents, and analysis workflows.
"""

from typing import Dict, List, Optional

from loguru import logger

from src.agents.base_agent import AnalysisResult, BaseAgent
from src.agents.document_agent import DocumentAgent
from src.agents.malware_agent import MalwareAgent
from src.agents.memory_agent import MemoryAgent
from src.agents.network_agent import NetworkAgent
from src.agents.phishing_agent import PhishingAgent
from src.agents.siem_log_agent import SIEMLogAgent
from src.ai_providers.base import AIProvider, BaseAIProvider, ProviderConfig
from src.ai_providers.claude_provider import ClaudeProvider
from src.ai_providers.consensus import ConsensusEngine
from src.ai_providers.openai_provider import OpenAIProvider
from src.config.settings import Settings, get_settings
from src.core.hallucination_guard import HallucinationGuard
from src.integrations.alienvault_otx import AlienVaultOTXClient
from src.integrations.hybrid_analysis import HybridAnalysisClient
from src.integrations.siem_integration import SIEMManager
from src.integrations.virustotal import VirusTotalClient


class Orchestrator:
    """Main orchestrator coordinating all system components.

    This class is the primary entry point for the BlueGuardian AI system,
    managing AI providers, agents, and orchestrating analysis workflows.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """Initialize orchestrator.

        Args:
            settings: Application settings (defaults to global settings)
        """
        self.settings = settings or get_settings()
        self.ai_providers: List[BaseAIProvider] = []
        self.consensus_engine: Optional[ConsensusEngine] = None
        self.hallucination_guard: Optional[HallucinationGuard] = None
        self.vt_client: Optional[VirusTotalClient] = None
        self.hybrid_analysis_client: Optional[HybridAnalysisClient] = None
        self.otx_client: Optional[AlienVaultOTXClient] = None
        self.siem_manager: Optional[SIEMManager] = None
        self.agents: Dict[str, BaseAgent] = {}

        logger.info("Initializing BlueGuardian AI Orchestrator")

        # Initialize components
        self._initialize_ai_providers()
        self._initialize_consensus()
        self._initialize_threat_intel()
        self._initialize_hallucination_guard()
        self._initialize_agents()

        logger.info("Orchestrator initialization complete")

    def _initialize_ai_providers(self) -> None:
        """Initialize AI providers based on settings."""
        logger.debug("Initializing AI providers")

        # Initialize Claude if API key available
        if self.settings.ai.anthropic_api_key:
            try:
                config = ProviderConfig(
                    api_key=self.settings.ai.anthropic_api_key,
                    model=self.settings.ai.claude_model,
                    temperature=0.0,
                    max_tokens=4096,
                )
                claude = ClaudeProvider(config)
                self.ai_providers.append(claude)
                logger.info(f"Initialized Claude provider: {config.model}")
            except Exception as e:
                logger.error(f"Failed to initialize Claude: {e}")

        # Initialize OpenAI if API key available
        if self.settings.ai.openai_api_key:
            try:
                config = ProviderConfig(
                    api_key=self.settings.ai.openai_api_key,
                    model=self.settings.ai.openai_model,
                    temperature=0.0,
                    max_tokens=4096,
                )
                openai = OpenAIProvider(config)
                self.ai_providers.append(openai)
                logger.info(f"Initialized OpenAI provider: {config.model}")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI: {e}")

        if not self.ai_providers:
            logger.warning(
                "No AI providers initialized - please configure API keys in .env"
            )

    def _initialize_consensus(self) -> None:
        """Initialize multi-model consensus engine."""
        if (
            self.settings.ai.enable_multi_model_consensus
            and len(self.ai_providers) >= 2
        ):
            logger.debug("Initializing consensus engine")

            self.consensus_engine = ConsensusEngine(
                providers=self.ai_providers,
                min_agreement_threshold=self.settings.ai.consensus_min_agreement,
                similarity_threshold=0.8,
            )

            logger.info(
                f"Consensus engine initialized with {len(self.ai_providers)} providers"
            )
        else:
            if self.settings.ai.enable_multi_model_consensus:
                logger.warning(
                    "Consensus requires at least 2 AI providers - disabled"
                )

    def _initialize_threat_intel(self) -> None:
        """Initialize threat intelligence integrations."""
        # VirusTotal
        if self.settings.threat_intel.virustotal_api_key:
            try:
                self.vt_client = VirusTotalClient(
                    self.settings.threat_intel.virustotal_api_key
                )
                logger.info("Initialized VirusTotal integration")
            except Exception as e:
                logger.error(f"Failed to initialize VirusTotal: {e}")

        # Hybrid Analysis
        if self.settings.threat_intel.hybrid_analysis_api_key:
            try:
                self.hybrid_analysis_client = HybridAnalysisClient(
                    self.settings.threat_intel.hybrid_analysis_api_key
                )
                logger.info("Initialized Hybrid Analysis integration")
            except Exception as e:
                logger.error(f"Failed to initialize Hybrid Analysis: {e}")

        # AlienVault OTX
        if self.settings.threat_intel.alienvault_otx_api_key:
            try:
                self.otx_client = AlienVaultOTXClient(
                    self.settings.threat_intel.alienvault_otx_api_key
                )
                logger.info("Initialized AlienVault OTX integration")
            except Exception as e:
                logger.error(f"Failed to initialize AlienVault OTX: {e}")

        # SIEM Integration
        if hasattr(self.settings, 'siem') and self.settings.siem:
            try:
                # Convert Pydantic model to dict for SIEM manager
                siem_config = self.settings.siem.dict() if hasattr(self.settings.siem, 'dict') else {}
                self.siem_manager = SIEMManager(siem_config)
                logger.info("Initialized SIEM integration")
            except Exception as e:
                logger.error(f"Failed to initialize SIEM: {e}")

    def _initialize_hallucination_guard(self) -> None:
        """Initialize hallucination detection system."""
        if self.settings.hallucination_guard.hallucination_guard_enabled:
            self.hallucination_guard = HallucinationGuard(
                min_confidence_threshold=self.settings.hallucination_guard.min_confidence_score
            )
            logger.info("Initialized hallucination guard")

    def _initialize_agents(self) -> None:
        """Initialize analysis agents."""
        if not self.ai_providers:
            logger.warning("No AI providers available - agents cannot be initialized")
            return

        # Initialize Malware Agent
        if self.settings.features.enable_malware_analysis:
            self.agents['malware'] = MalwareAgent(
                settings=self.settings,
                ai_providers=self.ai_providers,
                consensus_engine=self.consensus_engine,
                vt_client=self.vt_client,
                hallucination_guard=self.hallucination_guard,
            )
            logger.info("Initialized Malware Agent")

        # Initialize Document Agent
        if self.settings.features.enable_document_analysis:
            self.agents['document'] = DocumentAgent(
                settings=self.settings,
                ai_providers=self.ai_providers,
                consensus_engine=self.consensus_engine,
                vt_client=self.vt_client,
                hallucination_guard=self.hallucination_guard,
            )
            logger.info("Initialized Document Agent")

        # Initialize Phishing Agent
        if self.settings.features.enable_phishing_analysis:
            self.agents['phishing'] = PhishingAgent(
                settings=self.settings,
                ai_providers=self.ai_providers,
                consensus_engine=self.consensus_engine,
                vt_client=self.vt_client,
                hallucination_guard=self.hallucination_guard,
            )
            logger.info("Initialized Phishing Agent")

        # Initialize Memory Agent
        if self.settings.features.enable_memory_forensics:
            self.agents['memory'] = MemoryAgent(
                settings=self.settings,
                ai_providers=self.ai_providers,
                consensus_engine=self.consensus_engine,
                vt_client=self.vt_client,
                hallucination_guard=self.hallucination_guard,
            )
            logger.info("Initialized Memory Agent")

        # Initialize Network Agent
        if self.settings.features.enable_network_analysis:
            self.agents['network'] = NetworkAgent(
                settings=self.settings,
                ai_providers=self.ai_providers,
                consensus_engine=self.consensus_engine,
                vt_client=self.vt_client,
                hallucination_guard=self.hallucination_guard,
            )
            logger.info("Initialized Network Agent")

        # Initialize SIEM Log Agent (if SIEM is enabled)
        if self.siem_manager:
            self.agents['siem'] = SIEMLogAgent(
                settings=self.settings,
                ai_providers=self.ai_providers,
                consensus_engine=self.consensus_engine,
                siem_manager=self.siem_manager,
                hallucination_guard=self.hallucination_guard,
            )
            logger.info("Initialized SIEM Log Agent")

        # Future agents can be added here:
        # - IncidentResponseAgent
        # - ThreatHuntingAgent

    async def analyze_file(
        self,
        file_path: str,
        agent_type: Optional[str] = None,
        **kwargs,
    ) -> AnalysisResult:
        """Analyze a file using the appropriate agent.

        Args:
            file_path: Path to file to analyze
            agent_type: Specific agent to use (or auto-detect)
            **kwargs: Additional analysis parameters

        Returns:
            AnalysisResult with findings

        Raises:
            ValueError: If no suitable agent found
        """
        logger.info(f"Analyzing file: {file_path}")

        # Auto-detect agent if not specified
        if agent_type is None:
            agent_type = self._detect_agent_type(file_path)
            logger.debug(f"Auto-detected agent type: {agent_type}")

        # Get agent
        agent = self.agents.get(agent_type)

        if agent is None:
            raise ValueError(
                f"No agent available for type: {agent_type}. "
                f"Available agents: {list(self.agents.keys())}"
            )

        # Verify agent can handle this file
        if not agent.can_analyze(file_path):
            raise ValueError(
                f"Agent '{agent_type}' cannot analyze this file type. "
                f"Supported types: {agent.get_supported_file_types()}"
            )

        # Run analysis
        result = await agent.analyze(file_path, **kwargs)

        logger.info(
            f"Analysis complete: {result.verdict.value} "
            f"(confidence: {result.confidence:.0%})"
        )

        return result

    def _detect_agent_type(self, file_path: str) -> str:
        """Auto-detect appropriate agent for a file.

        Args:
            file_path: Path to file

        Returns:
            Agent type name

        Raises:
            ValueError: If no suitable agent found
        """
        from pathlib import Path

        path = Path(file_path)
        suffix = path.suffix.lower()

        # Malware files
        if suffix in ['.exe', '.dll', '.sys', '.bin', '.elf']:
            return 'malware'

        # Document files
        elif suffix in ['.pdf', '.docx', '.xlsx', '.doc', '.xls', '.lnk', '.rtf']:
            return 'document'

        # Email files
        elif suffix in ['.eml', '.msg']:
            return 'phishing'

        # Memory dumps
        elif suffix in ['.dmp', '.raw', '.mem', '.vmem', '.lime']:
            return 'memory'

        # Network indicators (text files with IOCs)
        elif suffix in ['.ioc']:
            return 'network'

        # SIEM logs
        elif suffix in ['.log'] and any(x in path.name.lower() for x in ['siem', 'security', 'auth', 'audit']):
            return 'siem'

        else:
            # Try each agent and see if any can handle it
            for agent_type, agent in self.agents.items():
                if agent.can_analyze(file_path):
                    return agent_type

            raise ValueError(
                f"Cannot determine appropriate agent for file type: {suffix}"
            )

    def get_status(self) -> Dict[str, any]:
        """Get orchestrator status and component health.

        Returns:
            Status dictionary
        """
        return {
            'providers': {
                'count': len(self.ai_providers),
                'models': [
                    p.config.model for p in self.ai_providers
                ],
            },
            'consensus': {
                'enabled': self.consensus_engine is not None,
                'providers': len(self.ai_providers) if self.consensus_engine else 0,
            },
            'hallucination_guard': {
                'enabled': self.hallucination_guard is not None,
            },
            'threat_intel': {
                'virustotal': self.vt_client is not None,
            },
            'agents': {
                'available': list(self.agents.keys()),
                'count': len(self.agents),
            },
        }

    def get_costs(self) -> Dict[str, float]:
        """Get cumulative API costs from all providers.

        Returns:
            Dictionary of provider costs
        """
        costs = {}

        for provider in self.ai_providers:
            costs[provider.provider_name.value] = provider.get_total_cost()

        costs['total'] = sum(costs.values())

        return costs

    async def shutdown(self) -> None:
        """Gracefully shutdown orchestrator and cleanup resources."""
        logger.info("Shutting down orchestrator")

        # Close VirusTotal client
        if self.vt_client:
            await self.vt_client.close()

        # Close Hybrid Analysis client
        if self.hybrid_analysis_client:
            await self.hybrid_analysis_client.close()

        # Close AlienVault OTX client
        if self.otx_client:
            await self.otx_client.close()

        logger.info("Orchestrator shutdown complete")
