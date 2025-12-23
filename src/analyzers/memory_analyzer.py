"""Memory dump analyzer using Volatility 3.

This module provides memory forensics analysis capabilities using Volatility 3,
analyzing process lists, network connections, loaded modules, and malware artifacts.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger


@dataclass
class ProcessInfo:
    """Information about a process found in memory."""

    pid: int
    ppid: int
    name: str
    offset: str
    threads: int
    handles: int
    create_time: Optional[str] = None
    exit_time: Optional[str] = None
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class NetworkConnection:
    """Network connection information."""

    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int
    process_name: Optional[str] = None
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class LoadedModule:
    """Information about loaded module/DLL."""

    pid: int
    process_name: str
    base: str
    size: int
    name: str
    path: str
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class MalwareIndicator:
    """Malware indicator found in memory."""

    type: str  # 'injection', 'hollowing', 'rootkit', 'hidden_process', etc.
    description: str
    evidence: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    related_pid: Optional[int] = None


@dataclass
class MemoryAnalysisResult:
    """Results from memory dump analysis."""

    file_size: int
    os_profile: Optional[str] = None
    os_version: Optional[str] = None
    process_count: int = 0
    processes: List[ProcessInfo] = field(default_factory=list)
    network_connections: List[NetworkConnection] = field(default_factory=list)
    loaded_modules: List[LoadedModule] = field(default_factory=list)
    malware_indicators: List[MalwareIndicator] = field(default_factory=list)
    suspicious_processes: List[ProcessInfo] = field(default_factory=list)
    hidden_processes: List[int] = field(default_factory=list)
    injected_code: List[Dict[str, Any]] = field(default_factory=list)
    registry_persistence: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    volatility_available: bool = False


class MemoryAnalyzer:
    """Memory forensics analyzer using Volatility 3.

    This analyzer extracts and analyzes artifacts from memory dumps including:
    - Process listings and relationships
    - Network connections
    - Loaded modules and DLLs
    - Code injection detection
    - Rootkit detection
    - Persistence mechanisms
    """

    # Suspicious process names (common malware)
    SUSPICIOUS_PROCESS_NAMES = {
        "mimikatz.exe",
        "psexec.exe",
        "procdump.exe",
        "nc.exe",
        "netcat.exe",
        "pwdump.exe",
        "fgdump.exe",
        "wce.exe",
    }

    # Processes that shouldn't have network connections
    NO_NETWORK_PROCESSES = {
        "notepad.exe",
        "calc.exe",
        "mspaint.exe",
        "wordpad.exe",
    }

    # Suspicious module paths
    SUSPICIOUS_PATHS = [
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\",
        "\\programdata\\",
    ]

    def __init__(self):
        """Initialize memory analyzer."""
        self.volatility_available = self._check_volatility()

        if not self.volatility_available:
            logger.warning(
                "Volatility 3 not found. Memory analysis will be limited. "
                "Install with: pip install volatility3"
            )
        else:
            logger.info("Volatility 3 available for memory analysis")

    def _check_volatility(self) -> bool:
        """Check if Volatility 3 is available.

        Returns:
            True if Volatility is available
        """
        try:
            result = subprocess.run(
                ["vol", "-h"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def analyze(self, file_path: str) -> MemoryAnalysisResult:
        """Analyze a memory dump file.

        Args:
            file_path: Path to memory dump

        Returns:
            MemoryAnalysisResult with findings
        """
        logger.debug(f"Analyzing memory dump: {file_path}")

        path = Path(file_path)
        result = MemoryAnalysisResult(
            file_size=path.stat().st_size,
            volatility_available=self.volatility_available,
        )

        if not self.volatility_available:
            result.anomalies.append(
                "Volatility 3 not available - analysis limited to basic checks"
            )
            return result

        try:
            # Step 1: Identify OS profile
            result.os_profile = self._identify_os(file_path)
            logger.debug(f"Identified OS: {result.os_profile}")

            # Step 2: Extract process list
            processes = self._extract_processes(file_path)
            result.processes = processes
            result.process_count = len(processes)

            # Step 3: Extract network connections
            result.network_connections = self._extract_network_connections(file_path)

            # Step 4: Extract loaded modules
            result.loaded_modules = self._extract_modules(file_path)

            # Step 5: Detect suspicious processes
            result.suspicious_processes = self._detect_suspicious_processes(
                processes, result.network_connections
            )

            # Step 6: Detect process injection
            result.injected_code = self._detect_injection(file_path)

            # Step 7: Check for hidden processes
            result.hidden_processes = self._detect_hidden_processes(file_path)

            # Step 8: Extract registry persistence
            result.registry_persistence = self._extract_registry_persistence(file_path)

            # Step 9: Generate malware indicators
            result.malware_indicators = self._generate_malware_indicators(result)

        except Exception as e:
            logger.error(f"Memory analysis error: {e}", exc_info=True)
            result.anomalies.append(f"Analysis error: {str(e)}")

        return result

    def _run_volatility(
        self, file_path: str, plugin: str, options: Optional[List[str]] = None
    ) -> Optional[str]:
        """Run a Volatility plugin.

        Args:
            file_path: Path to memory dump
            plugin: Plugin name (e.g., 'windows.pslist')
            options: Additional plugin options

        Returns:
            Plugin output or None if failed
        """
        try:
            cmd = ["vol", "-f", file_path, plugin, "--output", "json"]

            if options:
                cmd.extend(options)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            if result.returncode == 0:
                return result.stdout
            else:
                logger.warning(f"Volatility plugin {plugin} failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error(f"Volatility plugin {plugin} timed out")
            return None
        except Exception as e:
            logger.error(f"Volatility execution error: {e}")
            return None

    def _identify_os(self, file_path: str) -> Optional[str]:
        """Identify operating system from memory dump.

        Args:
            file_path: Path to memory dump

        Returns:
            OS profile string or None
        """
        output = self._run_volatility(file_path, "windows.info")

        if output:
            try:
                data = json.loads(output)
                # Extract OS version from info plugin
                # This is a simplified extraction - actual format may vary
                return "Windows (detected)"
            except:
                pass

        return None

    def _extract_processes(self, file_path: str) -> List[ProcessInfo]:
        """Extract process list from memory dump.

        Args:
            file_path: Path to memory dump

        Returns:
            List of processes
        """
        processes = []
        output = self._run_volatility(file_path, "windows.pslist")

        if not output:
            return processes

        try:
            data = json.loads(output)

            for row in data:
                try:
                    process = ProcessInfo(
                        pid=int(row.get("PID", 0)),
                        ppid=int(row.get("PPID", 0)),
                        name=row.get("ImageFileName", ""),
                        offset=row.get("Offset", "0x0"),
                        threads=int(row.get("Threads", 0)),
                        handles=int(row.get("Handles", 0)),
                        create_time=row.get("CreateTime"),
                        exit_time=row.get("ExitTime"),
                    )

                    # Check if suspicious
                    if process.name.lower() in self.SUSPICIOUS_PROCESS_NAMES:
                        process.suspicious = True
                        process.reasons.append(f"Known malicious tool: {process.name}")

                    processes.append(process)

                except (ValueError, KeyError) as e:
                    logger.debug(f"Failed to parse process row: {e}")
                    continue

        except json.JSONDecodeError:
            logger.error("Failed to parse Volatility pslist output")

        return processes

    def _extract_network_connections(
        self, file_path: str
    ) -> List[NetworkConnection]:
        """Extract network connections from memory.

        Args:
            file_path: Path to memory dump

        Returns:
            List of network connections
        """
        connections = []
        output = self._run_volatility(file_path, "windows.netscan")

        if not output:
            return connections

        try:
            data = json.loads(output)

            for row in data:
                try:
                    conn = NetworkConnection(
                        protocol=row.get("Proto", ""),
                        local_addr=row.get("LocalAddr", ""),
                        local_port=int(row.get("LocalPort", 0)),
                        remote_addr=row.get("ForeignAddr", ""),
                        remote_port=int(row.get("ForeignPort", 0)),
                        state=row.get("State", ""),
                        pid=int(row.get("PID", 0)),
                        process_name=row.get("Owner"),
                    )

                    # Check if suspicious
                    if conn.process_name and conn.process_name.lower() in self.NO_NETWORK_PROCESSES:
                        conn.suspicious = True
                        conn.reasons.append(
                            f"{conn.process_name} should not have network connections"
                        )

                    connections.append(conn)

                except (ValueError, KeyError) as e:
                    logger.debug(f"Failed to parse connection row: {e}")
                    continue

        except json.JSONDecodeError:
            logger.error("Failed to parse Volatility netscan output")

        return connections

    def _extract_modules(self, file_path: str) -> List[LoadedModule]:
        """Extract loaded modules/DLLs.

        Args:
            file_path: Path to memory dump

        Returns:
            List of loaded modules
        """
        modules = []
        output = self._run_volatility(file_path, "windows.dlllist")

        if not output:
            return modules

        try:
            data = json.loads(output)

            for row in data:
                try:
                    module = LoadedModule(
                        pid=int(row.get("PID", 0)),
                        process_name=row.get("Process", ""),
                        base=row.get("Base", "0x0"),
                        size=int(row.get("Size", 0)),
                        name=row.get("Name", ""),
                        path=row.get("Path", ""),
                    )

                    # Check for suspicious paths
                    path_lower = module.path.lower()
                    for susp_path in self.SUSPICIOUS_PATHS:
                        if susp_path in path_lower:
                            module.suspicious = True
                            module.reasons.append(f"Loaded from suspicious path: {susp_path}")

                    modules.append(module)

                except (ValueError, KeyError) as e:
                    logger.debug(f"Failed to parse module row: {e}")
                    continue

        except json.JSONDecodeError:
            logger.error("Failed to parse Volatility dlllist output")

        return modules

    def _detect_suspicious_processes(
        self, processes: List[ProcessInfo], connections: List[NetworkConnection]
    ) -> List[ProcessInfo]:
        """Detect suspicious processes based on behavior.

        Args:
            processes: List of all processes
            connections: List of network connections

        Returns:
            List of suspicious processes
        """
        suspicious = []

        # Create PID to process map
        pid_map = {p.pid: p for p in processes}

        # Check for processes with unexpected network activity
        for conn in connections:
            if conn.suspicious and conn.pid in pid_map:
                process = pid_map[conn.pid]
                if not process.suspicious:
                    process.suspicious = True
                    process.reasons.append("Unexpected network activity")
                    suspicious.append(process)

        # Add already flagged suspicious processes
        for process in processes:
            if process.suspicious and process not in suspicious:
                suspicious.append(process)

        return suspicious

    def _detect_injection(self, file_path: str) -> List[Dict[str, Any]]:
        """Detect code injection in processes.

        Args:
            file_path: Path to memory dump

        Returns:
            List of injection indicators
        """
        injections = []
        output = self._run_volatility(file_path, "windows.malfind")

        if not output:
            return injections

        try:
            data = json.loads(output)

            for row in data:
                injections.append({
                    "pid": row.get("PID"),
                    "process": row.get("Process"),
                    "address": row.get("Address"),
                    "protection": row.get("Protection"),
                    "type": "Code Injection (MalFind)",
                })

        except json.JSONDecodeError:
            logger.error("Failed to parse Volatility malfind output")

        return injections

    def _detect_hidden_processes(self, file_path: str) -> List[int]:
        """Detect hidden/rootkit processes.

        Args:
            file_path: Path to memory dump

        Returns:
            List of hidden process PIDs
        """
        hidden = []
        output = self._run_volatility(file_path, "windows.psscan")

        if not output:
            return hidden

        # Compare psscan (finds all processes) with pslist (uses OS structures)
        # Processes in psscan but not pslist are potentially hidden

        # This is a simplified implementation
        # Real implementation would compare the two lists

        return hidden

    def _extract_registry_persistence(self, file_path: str) -> List[str]:
        """Extract registry persistence mechanisms.

        Args:
            file_path: Path to memory dump

        Returns:
            List of registry keys used for persistence
        """
        persistence_keys = []
        output = self._run_volatility(file_path, "windows.registry.printkey", [
            "--key", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ])

        if output:
            # Parse registry output for Run keys
            # This is simplified - real implementation would parse properly
            persistence_keys.append("Run keys detected")

        return persistence_keys

    def _generate_malware_indicators(
        self, result: MemoryAnalysisResult
    ) -> List[MalwareIndicator]:
        """Generate high-level malware indicators from analysis.

        Args:
            result: Analysis result to analyze

        Returns:
            List of malware indicators
        """
        indicators = []

        # Check for code injection
        if result.injected_code:
            indicators.append(MalwareIndicator(
                type="injection",
                description="Code injection detected",
                evidence=f"{len(result.injected_code)} injection(s) found",
                severity="critical",
            ))

        # Check for hidden processes
        if result.hidden_processes:
            indicators.append(MalwareIndicator(
                type="rootkit",
                description="Hidden processes detected (possible rootkit)",
                evidence=f"PIDs: {', '.join(map(str, result.hidden_processes))}",
                severity="critical",
            ))

        # Check for suspicious processes
        if result.suspicious_processes:
            indicators.append(MalwareIndicator(
                type="suspicious_process",
                description="Suspicious processes detected",
                evidence=f"{len(result.suspicious_processes)} suspicious process(es)",
                severity="high",
            ))

        # Check for persistence mechanisms
        if result.registry_persistence:
            indicators.append(MalwareIndicator(
                type="persistence",
                description="Registry persistence mechanisms found",
                evidence=f"{len(result.registry_persistence)} persistence key(s)",
                severity="high",
            ))

        return indicators
