"""Plugin manager for extending BlueGuardian AI.

This module provides a plugin system that allows users to extend the framework
with custom analyzers, agents, and tools without modifying core code.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import yaml
from loguru import logger
from pydantic import BaseModel, Field

from src.agents.base_agent import BaseAgent
from src.config.settings import Settings


class PluginMetadata(BaseModel):
    """Plugin metadata information."""

    name: str
    version: str
    author: str
    description: str
    plugin_type: str  # 'analyzer', 'agent', 'tool', 'integration'
    entry_point: str  # Module path or class name
    dependencies: List[str] = Field(default_factory=list)
    config_schema: Optional[Dict[str, Any]] = None


class CustomAgentConfig(BaseModel):
    """Configuration for creating custom agents."""

    name: str
    description: str
    file_extensions: List[str]
    system_prompt: str
    analysis_prompt_template: str
    required_tools: List[str] = Field(default_factory=list)
    enabled: bool = True


class PluginManager:
    """Manages loading and registration of plugins.

    This class handles:
    - Loading plugins from local directories or GitHub
    - Registering custom analyzers, agents, and tools
    - Validating plugin dependencies
    - Managing plugin lifecycle
    """

    def __init__(self, settings: Settings):
        """Initialize plugin manager.

        Args:
            settings: Application settings
        """
        self.settings = settings
        self.plugins_dir = Path("plugins")
        self.plugins_dir.mkdir(exist_ok=True)

        self.loaded_plugins: Dict[str, Any] = {}
        self.custom_agents: Dict[str, Type[BaseAgent]] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}

        logger.info("Initialized PluginManager")

    def discover_plugins(self) -> List[PluginMetadata]:
        """Discover all available plugins.

        Returns:
            List of plugin metadata
        """
        discovered = []

        # Search in plugins directory
        for plugin_dir in self.plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            metadata_file = plugin_dir / "plugin.yaml"
            if metadata_file.exists():
                try:
                    with open(metadata_file) as f:
                        metadata_dict = yaml.safe_load(f)
                        metadata = PluginMetadata(**metadata_dict)
                        discovered.append(metadata)
                        logger.debug(f"Discovered plugin: {metadata.name}")
                except Exception as e:
                    logger.warning(f"Failed to load plugin metadata from {plugin_dir}: {e}")

        return discovered

    def load_plugin(self, plugin_path: str) -> Optional[Any]:
        """Load a plugin from a local path.

        Args:
            plugin_path: Path to plugin directory or Python file

        Returns:
            Loaded plugin module or None if failed
        """
        plugin_path_obj = Path(plugin_path)

        if not plugin_path_obj.exists():
            logger.error(f"Plugin path does not exist: {plugin_path}")
            return None

        try:
            # If it's a directory, look for plugin.yaml and entry point
            if plugin_path_obj.is_dir():
                metadata_file = plugin_path_obj / "plugin.yaml"
                if not metadata_file.exists():
                    logger.error(f"Plugin directory missing plugin.yaml: {plugin_path}")
                    return None

                with open(metadata_file) as f:
                    metadata_dict = yaml.safe_load(f)
                    metadata = PluginMetadata(**metadata_dict)

                # Install dependencies
                if metadata.dependencies:
                    self._install_dependencies(metadata.dependencies)

                # Load the entry point module
                entry_point = plugin_path_obj / metadata.entry_point
                if not entry_point.exists():
                    logger.error(f"Entry point not found: {entry_point}")
                    return None

                module = self._load_module_from_file(str(entry_point), metadata.name)

            # If it's a Python file, load it directly
            elif plugin_path_obj.suffix == ".py":
                module = self._load_module_from_file(
                    str(plugin_path_obj), plugin_path_obj.stem
                )
                metadata = PluginMetadata(
                    name=plugin_path_obj.stem,
                    version="unknown",
                    author="unknown",
                    description="Custom plugin",
                    plugin_type="custom",
                    entry_point=plugin_path_obj.name,
                )
            else:
                logger.error(f"Unsupported plugin format: {plugin_path}")
                return None

            # Register the plugin
            self.loaded_plugins[metadata.name] = module
            self.plugin_metadata[metadata.name] = metadata

            logger.info(f"Loaded plugin: {metadata.name} v{metadata.version}")
            return module

        except Exception as e:
            logger.error(f"Failed to load plugin from {plugin_path}: {e}", exc_info=True)
            return None

    def load_plugin_from_github(
        self, github_url: str, branch: str = "main"
    ) -> Optional[Any]:
        """Load a plugin from a GitHub repository.

        Args:
            github_url: GitHub repository URL
            branch: Branch to clone (default: main)

        Returns:
            Loaded plugin module or None if failed
        """
        try:
            # Extract repo name from URL
            repo_name = github_url.rstrip("/").split("/")[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]

            plugin_dir = self.plugins_dir / repo_name

            # Clone or update repository
            if plugin_dir.exists():
                logger.info(f"Updating existing plugin: {repo_name}")
                subprocess.run(
                    ["git", "-C", str(plugin_dir), "pull"],
                    check=True,
                    capture_output=True,
                )
            else:
                logger.info(f"Cloning plugin from GitHub: {github_url}")
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--branch",
                        branch,
                        "--depth",
                        "1",
                        github_url,
                        str(plugin_dir),
                    ],
                    check=True,
                    capture_output=True,
                )

            # Load the plugin
            return self.load_plugin(str(plugin_dir))

        except subprocess.CalledProcessError as e:
            logger.error(f"Git operation failed: {e.stderr.decode()}")
            return None
        except Exception as e:
            logger.error(f"Failed to load plugin from GitHub: {e}", exc_info=True)
            return None

    def load_custom_agent(self, config_path: str) -> Optional[Type[BaseAgent]]:
        """Load a custom agent from YAML/JSON configuration.

        Args:
            config_path: Path to agent configuration file

        Returns:
            Custom agent class or None if failed
        """
        try:
            config_path_obj = Path(config_path)

            # Load configuration
            with open(config_path_obj) as f:
                if config_path_obj.suffix == ".yaml" or config_path_obj.suffix == ".yml":
                    config_dict = yaml.safe_load(f)
                elif config_path_obj.suffix == ".json":
                    config_dict = json.load(f)
                else:
                    logger.error(f"Unsupported config format: {config_path_obj.suffix}")
                    return None

            agent_config = CustomAgentConfig(**config_dict)

            # Create dynamic agent class
            agent_class = self._create_dynamic_agent(agent_config)

            # Register the agent
            self.custom_agents[agent_config.name] = agent_class

            logger.info(f"Loaded custom agent: {agent_config.name}")
            return agent_class

        except Exception as e:
            logger.error(f"Failed to load custom agent: {e}", exc_info=True)
            return None

    def _load_module_from_file(self, file_path: str, module_name: str) -> Any:
        """Load a Python module from a file path.

        Args:
            file_path: Path to Python file
            module_name: Name to assign to the module

        Returns:
            Loaded module
        """
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module from {file_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        return module

    def _install_dependencies(self, dependencies: List[str]) -> None:
        """Install plugin dependencies.

        Args:
            dependencies: List of package names
        """
        if not dependencies:
            return

        logger.info(f"Installing plugin dependencies: {', '.join(dependencies)}")

        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", *dependencies],
                check=True,
                capture_output=True,
            )
            logger.info("Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {e.stderr.decode()}")
            raise

    def _create_dynamic_agent(self, config: CustomAgentConfig) -> Type[BaseAgent]:
        """Create a dynamic agent class from configuration.

        Args:
            config: Custom agent configuration

        Returns:
            Dynamically created agent class
        """
        from src.ai_providers.base import BaseAIProvider
        from src.ai_providers.consensus import ConsensusEngine

        class DynamicAgent(BaseAgent):
            """Dynamically created custom agent."""

            def __init__(
                self,
                settings: Settings,
                ai_providers: List[BaseAIProvider],
                consensus_engine: Optional[ConsensusEngine] = None,
            ):
                super().__init__(settings, ai_providers, consensus_engine)
                self.agent_config = config

            def get_supported_file_types(self) -> List[str]:
                return config.file_extensions

            def get_system_prompt(self) -> str:
                return config.system_prompt

            async def analyze(self, artifact_path: str, **kwargs: Any):
                """Analyze artifact using custom configuration."""
                import time
                from datetime import datetime

                from src.agents.base_agent import AnalysisResult, AnalysisStatus

                start_time = time.time()

                # Validate artifact
                self.validate_artifact(artifact_path)

                # Create result template
                result = self.create_result_template(artifact_path)
                result.status = AnalysisStatus.RUNNING

                logger.info(f"Starting {config.name} analysis: {artifact_path}")

                try:
                    # Calculate file hash
                    hashes = self.calculate_file_hash(artifact_path)
                    result.details["hashes"] = hashes

                    # Read file content (if text-based)
                    try:
                        with open(artifact_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(10000)  # Limit to 10KB
                    except:
                        content = "[Binary file - cannot display]"

                    # Format prompt
                    prompt = config.analysis_prompt_template.format(
                        file_path=artifact_path,
                        file_content=content,
                        file_size=Path(artifact_path).stat().st_size,
                        md5=hashes["md5"],
                        sha256=hashes["sha256"],
                    )

                    # Query AI
                    ai_response = await self.query_ai(user_message=prompt, temperature=0.0)

                    if ai_response:
                        result.summary = ai_response.merged_response
                        result.ai_responses = ai_response
                        result.confidence = ai_response.confidence_score

                        # Extract verdict and IOCs
                        result.verdict = self._extract_verdict(ai_response.merged_response)
                        result.iocs = self.extract_iocs_from_text(ai_response.merged_response)

                    result.completed_at = datetime.now()
                    result.duration_seconds = time.time() - start_time
                    result.status = AnalysisStatus.COMPLETED

                    logger.info(
                        f"{config.name} analysis complete: {result.verdict.value} "
                        f"(confidence: {result.confidence:.0%})"
                    )

                    return result

                except Exception as e:
                    logger.error(f"{config.name} analysis failed: {e}", exc_info=True)
                    result.status = AnalysisStatus.FAILED
                    result.errors.append(str(e))
                    result.completed_at = datetime.now()
                    result.duration_seconds = time.time() - start_time
                    raise

            def _extract_verdict(self, ai_response: str):
                """Extract verdict from AI response."""
                from src.agents.base_agent import Verdict

                response_lower = ai_response.lower()

                if "malicious" in response_lower:
                    return Verdict.MALICIOUS
                elif "suspicious" in response_lower:
                    return Verdict.SUSPICIOUS
                elif "clean" in response_lower or "benign" in response_lower:
                    return Verdict.CLEAN
                else:
                    return Verdict.UNKNOWN

        # Set class attributes
        DynamicAgent.__name__ = config.name
        DynamicAgent.__doc__ = config.description

        return DynamicAgent

    def get_plugin(self, plugin_name: str) -> Optional[Any]:
        """Get a loaded plugin by name.

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin module or None if not found
        """
        return self.loaded_plugins.get(plugin_name)

    def get_custom_agent(self, agent_name: str) -> Optional[Type[BaseAgent]]:
        """Get a custom agent by name.

        Args:
            agent_name: Name of the custom agent

        Returns:
            Agent class or None if not found
        """
        return self.custom_agents.get(agent_name)

    def list_plugins(self) -> List[str]:
        """List all loaded plugins.

        Returns:
            List of plugin names
        """
        return list(self.loaded_plugins.keys())

    def list_custom_agents(self) -> List[str]:
        """List all custom agents.

        Returns:
            List of custom agent names
        """
        return list(self.custom_agents.keys())

    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin.

        Args:
            plugin_name: Name of the plugin to unload

        Returns:
            True if successful, False otherwise
        """
        if plugin_name in self.loaded_plugins:
            del self.loaded_plugins[plugin_name]
            if plugin_name in self.plugin_metadata:
                del self.plugin_metadata[plugin_name]
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True
        return False

    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a plugin.

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin information dictionary or None if not found
        """
        if plugin_name not in self.plugin_metadata:
            return None

        metadata = self.plugin_metadata[plugin_name]
        return {
            "name": metadata.name,
            "version": metadata.version,
            "author": metadata.author,
            "description": metadata.description,
            "type": metadata.plugin_type,
            "dependencies": metadata.dependencies,
        }
