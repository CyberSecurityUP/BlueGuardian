"""Configuration management for BlueGuardian AI.

This module handles all application settings using Pydantic for validation
and type safety. Settings can be loaded from environment variables or .env files.
"""

from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIProviderSettings(BaseSettings):
    """AI Provider configuration."""

    # API Keys
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    google_api_key: Optional[str] = Field(default=None, alias="GOOGLE_API_KEY")

    # Model Configuration
    default_ai_provider: str = Field(default="claude", alias="DEFAULT_AI_PROVIDER")
    claude_model: str = Field(
        default="claude-sonnet-4.5-20250929", alias="CLAUDE_MODEL"
    )
    openai_model: str = Field(default="gpt-4-turbo-preview", alias="OPENAI_MODEL")
    gemini_model: str = Field(default="gemini-1.5-pro", alias="GEMINI_MODEL")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="mistral", alias="OLLAMA_MODEL")

    # Consensus Configuration
    enable_multi_model_consensus: bool = Field(default=True, alias="ENABLE_MULTI_MODEL_CONSENSUS")
    consensus_min_agreement: float = Field(default=0.7, alias="CONSENSUS_MIN_AGREEMENT")
    consensus_providers: str = Field(default="claude,openai", alias="CONSENSUS_PROVIDERS")

    @field_validator("consensus_min_agreement")
    @classmethod
    def validate_agreement_threshold(cls, v: float) -> float:
        """Validate consensus agreement threshold is between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Consensus agreement threshold must be between 0.0 and 1.0")
        return v

    @field_validator("default_ai_provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """Validate AI provider choice."""
        allowed = ["claude", "openai", "gemini", "ollama"]
        if v not in allowed:
            raise ValueError(f"AI provider must be one of: {', '.join(allowed)}")
        return v

    def get_consensus_providers_list(self) -> List[str]:
        """Get list of providers for consensus."""
        return [p.strip() for p in self.consensus_providers.split(",")]


class ThreatIntelSettings(BaseSettings):
    """Threat Intelligence API configuration."""

    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    hybrid_analysis_api_key: Optional[str] = Field(
        default=None, alias="HYBRID_ANALYSIS_API_KEY"
    )
    alienvault_otx_api_key: Optional[str] = Field(default=None, alias="ALIENVAULT_OTX_API_KEY")


class HallucinationGuardSettings(BaseSettings):
    """Hallucination detection configuration."""

    hallucination_guard_enabled: bool = Field(default=True, alias="HALLUCINATION_GUARD_ENABLED")
    min_confidence_score: float = Field(default=0.6, alias="MIN_CONFIDENCE_SCORE")

    @field_validator("min_confidence_score")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Validate confidence score is between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")
        return v


class AnalysisSettings(BaseSettings):
    """Analysis configuration."""

    max_file_size_mb: int = Field(default=100, alias="MAX_FILE_SIZE_MB")
    analysis_timeout_seconds: int = Field(default=300, alias="ANALYSIS_TIMEOUT_SECONDS")
    enable_docker_sandbox: bool = Field(default=True, alias="ENABLE_DOCKER_SANDBOX")
    sandbox_network_isolation: bool = Field(default=True, alias="SANDBOX_NETWORK_ISOLATION")

    @field_validator("max_file_size_mb")
    @classmethod
    def validate_file_size(cls, v: int) -> int:
        """Validate max file size."""
        if v <= 0:
            raise ValueError("Max file size must be positive")
        return v

    @field_validator("analysis_timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        """Validate timeout value."""
        if v <= 0:
            raise ValueError("Timeout must be positive")
        return v


class DockerSettings(BaseSettings):
    """Docker sandbox configuration."""

    docker_sandbox_image: str = Field(
        default="blueguardian-ai-sandbox:latest", alias="DOCKER_SANDBOX_IMAGE"
    )
    docker_memory_limit: str = Field(default="512m", alias="DOCKER_MEMORY_LIMIT")
    docker_cpu_quota: int = Field(default=50000, alias="DOCKER_CPU_QUOTA")


class MCPSettings(BaseSettings):
    """Model Context Protocol configuration."""

    mcp_server_enabled: bool = Field(default=True, alias="MCP_SERVER_ENABLED")
    mcp_server_port: int = Field(default=3000, alias="MCP_SERVER_PORT")
    ghidra_path: Optional[str] = Field(default="/opt/ghidra", alias="GHIDRA_PATH")
    ida_path: Optional[str] = Field(default="/opt/ida", alias="IDA_PATH")
    volatility_path: Optional[str] = Field(
        default="/usr/local/bin/vol.py", alias="VOLATILITY_PATH"
    )


class APISettings(BaseSettings):
    """API server configuration."""

    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=4, alias="API_WORKERS")
    api_cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:5173", alias="API_CORS_ORIGINS"
    )
    api_rate_limit: int = Field(default=100, alias="API_RATE_LIMIT")
    enable_api_auth: bool = Field(default=True, alias="ENABLE_API_AUTH")
    api_secret_key: str = Field(
        default="change-this-to-a-random-secret-key", alias="API_SECRET_KEY"
    )
    session_expire_minutes: int = Field(default=60, alias="SESSION_EXPIRE_MINUTES")

    def get_cors_origins_list(self) -> List[str]:
        """Get list of CORS origins."""
        return [origin.strip() for origin in self.api_cors_origins.split(",")]


class LoggingSettings(BaseSettings):
    """Logging configuration."""

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="logs/blueguardian.log", alias="LOG_FILE")
    log_rotation: str = Field(default="10 MB", alias="LOG_ROTATION")
    log_retention: str = Field(default="30 days", alias="LOG_RETENTION")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in allowed:
            raise ValueError(f"Log level must be one of: {', '.join(allowed)}")
        return v_upper


class StorageSettings(BaseSettings):
    """Storage paths configuration."""

    artifacts_storage_path: str = Field(
        default="./storage/artifacts", alias="ARTIFACTS_STORAGE_PATH"
    )
    reports_storage_path: str = Field(default="./storage/reports", alias="REPORTS_STORAGE_PATH")
    yara_rules_path: str = Field(default="./data/yara_rules", alias="YARA_RULES_PATH")

    def get_artifacts_path(self) -> Path:
        """Get artifacts storage path."""
        return Path(self.artifacts_storage_path)

    def get_reports_path(self) -> Path:
        """Get reports storage path."""
        return Path(self.reports_storage_path)

    def get_yara_rules_path(self) -> Path:
        """Get YARA rules path."""
        return Path(self.yara_rules_path)


class PluginSettings(BaseSettings):
    """Plugin system configuration."""

    plugins_path: str = Field(default="./plugins", alias="PLUGINS_PATH")
    enable_github_plugins: bool = Field(default=True, alias="ENABLE_GITHUB_PLUGINS")
    plugin_auto_update: bool = Field(default=False, alias="PLUGIN_AUTO_UPDATE")

    def get_plugins_path(self) -> Path:
        """Get plugins directory path."""
        return Path(self.plugins_path)


class FeatureFlags(BaseSettings):
    """Feature flags configuration."""

    enable_web_ui: bool = Field(default=True, alias="ENABLE_WEB_UI")
    enable_phishing_analysis: bool = Field(default=True, alias="ENABLE_PHISHING_ANALYSIS")
    enable_memory_forensics: bool = Field(default=True, alias="ENABLE_MEMORY_FORENSICS")
    enable_document_analysis: bool = Field(default=True, alias="ENABLE_DOCUMENT_ANALYSIS")
    enable_malware_analysis: bool = Field(default=True, alias="ENABLE_MALWARE_ANALYSIS")
    enable_network_analysis: bool = Field(default=True, alias="ENABLE_NETWORK_ANALYSIS")


class Settings(BaseSettings):
    """Main application settings.

    This class aggregates all configuration sections and provides
    a single source of truth for application settings.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Debug mode
    debug: bool = Field(default=False, alias="DEBUG")
    development_mode: bool = Field(default=False, alias="DEVELOPMENT_MODE")

    # Sub-configurations
    ai: AIProviderSettings = Field(default_factory=AIProviderSettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    hallucination_guard: HallucinationGuardSettings = Field(
        default_factory=HallucinationGuardSettings
    )
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    docker: DockerSettings = Field(default_factory=DockerSettings)
    mcp: MCPSettings = Field(default_factory=MCPSettings)
    api: APISettings = Field(default_factory=APISettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    plugins: PluginSettings = Field(default_factory=PluginSettings)
    features: FeatureFlags = Field(default_factory=FeatureFlags)

    def __init__(self, **kwargs):
        """Initialize settings and create required directories."""
        super().__init__(**kwargs)
        self._create_directories()

    def _create_directories(self) -> None:
        """Create required storage directories if they don't exist."""
        directories = [
            self.storage.get_artifacts_path(),
            self.storage.get_reports_path(),
            self.storage.get_yara_rules_path(),
            self.plugins.get_plugins_path(),
            Path(self.logging.log_file).parent,
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def is_production(self) -> bool:
        """Check if running in production mode."""
        return not self.debug and not self.development_mode

    def validate_api_keys(self) -> dict[str, bool]:
        """Validate which API keys are configured.

        Returns:
            Dictionary mapping provider names to availability status
        """
        return {
            "claude": self.ai.anthropic_api_key is not None,
            "openai": self.ai.openai_api_key is not None,
            "gemini": self.ai.google_api_key is not None,
            "virustotal": self.threat_intel.virustotal_api_key is not None,
            "hybrid_analysis": self.threat_intel.hybrid_analysis_api_key is not None,
            "alienvault_otx": self.threat_intel.alienvault_otx_api_key is not None,
        }


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get global settings instance (singleton pattern).

    Returns:
        Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Reload settings from environment/files.

    Returns:
        New Settings instance
    """
    global _settings
    _settings = Settings()
    return _settings
