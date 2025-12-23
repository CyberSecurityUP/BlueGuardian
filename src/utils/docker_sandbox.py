"""Docker-based sandbox for safe malware execution.

This module provides isolated Docker containers for executing potentially malicious
files without risking the host system.
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from loguru import logger

try:
    import docker
    from docker.errors import DockerException
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
    logger.warning("docker library not installed - sandbox disabled")


@dataclass
class SandboxResult:
    """Result from sandbox execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    error: Optional[str] = None


class DockerSandbox:
    """Docker-based sandbox for safe malware execution.

    This class provides isolated container environments for analyzing
    malicious files without exposing the host system to risk.
    """

    def __init__(
        self,
        image: str = "blueguardian-ai-sandbox:latest",
        memory_limit: str = "512m",
        cpu_quota: int = 50000,
        network_mode: str = "none",
    ):
        """Initialize Docker sandbox.

        Args:
            image: Docker image to use
            memory_limit: Memory limit (e.g., "512m", "1g")
            cpu_quota: CPU quota (100000 = 100%)
            network_mode: Network isolation mode ("none" or "bridge")

        Raises:
            ImportError: If docker library not installed
            DockerException: If Docker daemon not available
        """
        if not HAS_DOCKER:
            raise ImportError(
                "docker library required for sandbox. "
                "Install with: pip install docker"
            )

        try:
            self.client = docker.from_env()
            self.client.ping()
        except DockerException as e:
            raise DockerException(
                f"Cannot connect to Docker daemon: {e}. "
                "Ensure Docker is installed and running."
            )

        self.image = image
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.network_mode = network_mode

        logger.info(f"Initialized Docker sandbox: {image}")

    async def execute(
        self,
        command: str,
        file_path: Optional[str] = None,
        timeout: int = 300,
        working_dir: str = "/workspace",
    ) -> SandboxResult:
        """Execute a command in isolated sandbox.

        Args:
            command: Command to execute
            file_path: Optional file to mount in sandbox
            timeout: Timeout in seconds
            working_dir: Working directory in container

        Returns:
            SandboxResult with execution details
        """
        import time

        start_time = time.time()

        logger.debug(f"Executing in sandbox: {command}")

        try:
            # Prepare volumes
            volumes = {}
            if file_path:
                volumes[file_path] = {
                    'bind': f'{working_dir}/sample',
                    'mode': 'ro'  # Read-only
                }

            # Create and run container
            container = self.client.containers.run(
                self.image,
                command=command,
                detach=True,
                remove=True,
                mem_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                network_mode=self.network_mode,
                working_dir=working_dir,
                volumes=volumes,
                user='sandbox',  # Run as non-root
            )

            # Wait for completion with timeout
            try:
                exit_code = container.wait(timeout=timeout)
                logs = container.logs(stdout=True, stderr=True).decode('utf-8')

                # Separate stdout and stderr (simplified)
                stdout = logs
                stderr = ""

                success = exit_code.get('StatusCode', 1) == 0

            except Exception as e:
                logger.error(f"Container execution error: {e}")
                try:
                    container.kill()
                except:
                    pass

                return SandboxResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="",
                    duration_seconds=time.time() - start_time,
                    error=f"Execution timeout or error: {str(e)}",
                )

            duration = time.time() - start_time

            logger.debug(f"Sandbox execution complete: {duration:.1f}s")

            return SandboxResult(
                success=success,
                exit_code=exit_code.get('StatusCode', -1),
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
            )

        except Exception as e:
            logger.error(f"Sandbox error: {e}")
            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_seconds=time.time() - start_time,
                error=str(e),
            )

    def verify_image(self) -> bool:
        """Verify sandbox image exists.

        Returns:
            True if image exists
        """
        try:
            self.client.images.get(self.image)
            return True
        except docker.errors.ImageNotFound:
            logger.warning(f"Sandbox image not found: {self.image}")
            return False

    def build_image(self, dockerfile_path: str, tag: Optional[str] = None) -> bool:
        """Build sandbox image from Dockerfile.

        Args:
            dockerfile_path: Path to Dockerfile directory
            tag: Optional tag (defaults to self.image)

        Returns:
            True if build successful
        """
        tag = tag or self.image

        try:
            logger.info(f"Building sandbox image: {tag}")
            self.client.images.build(
                path=dockerfile_path,
                tag=tag,
                rm=True,
            )
            logger.info(f"Successfully built image: {tag}")
            return True

        except Exception as e:
            logger.error(f"Failed to build image: {e}")
            return False
