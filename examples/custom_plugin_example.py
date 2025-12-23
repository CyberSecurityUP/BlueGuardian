"""Example custom plugin for BlueGuardian AI.

This example demonstrates how to create a custom analyzer and agent
for extending BlueGuardian AI with new file types and analysis capabilities.

In this example, we create a simple script analyzer for Python, Bash, and PowerShell scripts.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

# Note: In a real plugin, you would import from src modules
# For this example, we show the structure


@dataclass
class ScriptAnalysisResult:
    """Results from script analysis."""

    file_size: int
    script_type: str  # 'python', 'bash', 'powershell'
    line_count: int
    has_shebang: bool
    imports: List[str] = field(default_factory=list)
    suspicious_functions: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    external_connections: List[str] = field(default_factory=list)
    file_operations: List[str] = field(default_factory=list)
    process_operations: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


class ScriptAnalyzer:
    """Analyzer for malicious script detection.

    Supports Python, Bash, and PowerShell scripts.
    """

    # Suspicious patterns for each script type
    PYTHON_SUSPICIOUS = {
        "network": [
            r"socket\.",
            r"urllib\.request",
            r"requests\.",
            r"http\.client",
            r"ftplib\.",
        ],
        "execution": [
            r"exec\(",
            r"eval\(",
            r"compile\(",
            r"__import__\(",
            r"subprocess\.",
            r"os\.system",
            r"os\.popen",
        ],
        "obfuscation": [
            r"base64\.b64decode",
            r"codecs\.decode",
            r"\\x[0-9a-f]{2}",  # Hex encoding
            r"chr\(\d+\)",
        ],
        "filesystem": [
            r"open\(['\"].*['\"],\s*['\"]w",
            r"os\.remove",
            r"shutil\.rmtree",
            r"os\.chmod",
        ],
    }

    BASH_SUSPICIOUS = {
        "network": [
            r"wget\s+",
            r"curl\s+",
            r"nc\s+",
            r"/dev/tcp/",
            r"ncat\s+",
        ],
        "execution": [
            r"bash\s+-c",
            r"sh\s+-c",
            r"eval\s+",
            r"\$\(.*\)",
            r"`.*`",
        ],
        "obfuscation": [
            r"base64\s+-d",
            r"xxd\s+",
            r"\\x[0-9a-f]{2}",
        ],
        "filesystem": [
            r"rm\s+-rf",
            r"dd\s+if=",
            r"chmod\s+777",
        ],
    }

    POWERSHELL_SUSPICIOUS = {
        "network": [
            r"Invoke-WebRequest",
            r"WebClient",
            r"DownloadString",
            r"DownloadFile",
            r"Net\.WebClient",
        ],
        "execution": [
            r"Invoke-Expression",
            r"IEX\s+",
            r"Start-Process",
            r"&\s*\(",
            r"Invoke-Command",
        ],
        "obfuscation": [
            r"-enc\s+",
            r"-encodedcommand\s+",
            r"FromBase64String",
            r"\[char\]\d+",
        ],
        "bypass": [
            r"-ExecutionPolicy\s+Bypass",
            r"-NoProfile",
            r"-WindowStyle\s+Hidden",
            r"-NonInteractive",
        ],
    }

    def detect_script_type(self, file_path: str) -> str:
        """Detect script type from extension or shebang.

        Args:
            file_path: Path to script file

        Returns:
            Script type: 'python', 'bash', 'powershell', or 'unknown'
        """
        path = Path(file_path)
        suffix = path.suffix.lower()

        # Check file extension
        if suffix in [".py", ".pyw"]:
            return "python"
        elif suffix in [".sh", ".bash"]:
            return "bash"
        elif suffix in [".ps1", ".psm1", ".psd1"]:
            return "powershell"

        # Check shebang
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
                if first_line.startswith("#!"):
                    if "python" in first_line:
                        return "python"
                    elif "bash" in first_line or "sh" in first_line:
                        return "bash"
        except:
            pass

        return "unknown"

    def analyze(self, file_path: str) -> ScriptAnalysisResult:
        """Analyze a script file for malicious patterns.

        Args:
            file_path: Path to script file

        Returns:
            ScriptAnalysisResult with findings
        """
        logger.debug(f"Analyzing script: {file_path}")

        path = Path(file_path)
        script_type = self.detect_script_type(file_path)

        result = ScriptAnalysisResult(
            file_size=path.stat().st_size,
            script_type=script_type,
            line_count=0,
            has_shebang=False,
        )

        # Read and analyze content
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")
                result.line_count = len(lines)

                # Check shebang
                if lines and lines[0].startswith("#!"):
                    result.has_shebang = True

                # Analyze based on script type
                if script_type == "python":
                    self._analyze_python(content, result)
                elif script_type == "bash":
                    self._analyze_bash(content, result)
                elif script_type == "powershell":
                    self._analyze_powershell(content, result)

        except Exception as e:
            logger.error(f"Error analyzing script: {e}")
            result.anomalies.append(f"Analysis error: {str(e)}")

        return result

    def _analyze_python(self, content: str, result: ScriptAnalysisResult) -> None:
        """Analyze Python script."""
        # Extract imports
        import_pattern = r"(?:from\s+[\w.]+\s+)?import\s+([\w.,\s*]+)"
        imports = re.findall(import_pattern, content)
        result.imports = [imp.strip() for imp_list in imports for imp in imp_list.split(",")]

        # Check suspicious patterns
        for category, patterns in self.PYTHON_SUSPICIOUS.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    result.suspicious_patterns.append(f"[{category}] {pattern}")

        # Specific checks
        if "exec(" in content or "eval(" in content:
            result.anomalies.append("Uses dynamic code execution (exec/eval)")

        if "base64.b64decode" in content:
            result.anomalies.append("Contains base64 decoding (possible obfuscation)")

        if re.search(r"socket\.|requests\.|urllib", content):
            result.external_connections.append("Network communication detected")

    def _analyze_bash(self, content: str, result: ScriptAnalysisResult) -> None:
        """Analyze Bash script."""
        # Check suspicious patterns
        for category, patterns in self.BASH_SUSPICIOUS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result.suspicious_patterns.append(f"[{category}] {pattern}")

        # Specific checks
        if re.search(r"wget|curl", content):
            result.external_connections.append("Downloads files from internet")

        if "base64 -d" in content:
            result.anomalies.append("Contains base64 decoding (possible obfuscation)")

        if re.search(r"rm\s+-rf\s+/", content):
            result.anomalies.append("CRITICAL: Recursive delete from root directory")

        if "/dev/tcp/" in content or "nc " in content:
            result.anomalies.append("Opens network connections")

    def _analyze_powershell(self, content: str, result: ScriptAnalysisResult) -> None:
        """Analyze PowerShell script."""
        # Check suspicious patterns
        for category, patterns in self.POWERSHELL_SUSPICIOUS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result.suspicious_patterns.append(f"[{category}] {pattern}")

        # Specific checks
        if re.search(r"Invoke-Expression|IEX\s+", content, re.IGNORECASE):
            result.anomalies.append("Uses Invoke-Expression (dynamic execution)")

        if re.search(r"-enc\s+|-encodedcommand\s+", content, re.IGNORECASE):
            result.anomalies.append("Uses encoded commands (obfuscation)")

        if re.search(
            r"DownloadString|DownloadFile", content, re.IGNORECASE
        ):
            result.external_connections.append("Downloads content from internet")

        if "-ExecutionPolicy Bypass" in content:
            result.anomalies.append("Bypasses PowerShell execution policy")


# Example of how to use the plugin with BlueGuardian AI
def create_custom_agent_config() -> Dict[str, Any]:
    """Create configuration for custom script analysis agent.

    This configuration can be saved as a YAML file and loaded by the plugin manager.

    Returns:
        Agent configuration dictionary
    """
    return {
        "name": "ScriptAgent",
        "description": "Analyzes Python, Bash, and PowerShell scripts for malicious patterns",
        "file_extensions": [".py", ".pyw", ".sh", ".bash", ".ps1", ".psm1"],
        "system_prompt": """You are an expert script security analyst specializing in:
- Python malware and backdoors
- Bash shell script attacks
- PowerShell exploit scripts
- Obfuscation and evasion techniques
- Code injection and execution

Your role is to analyze scripts for malicious behavior and security risks.

CRITICAL RULES:
1. Base analysis on actual code patterns and behaviors
2. Identify obfuscation techniques
3. Detect network communications and data exfiltration
4. Flag dangerous operations (file deletion, process execution)
5. Assess overall threat level with confidence score
6. Provide actionable defensive recommendations

OUTPUT FORMAT:
- Verdict: Malicious/Suspicious/Clean (with confidence %)
- Executive summary of findings
- Detailed analysis of suspicious patterns
- IOCs (URLs, IPs, domains)
- MITRE ATT&CK mapping
- Defensive recommendations""",
        "analysis_prompt_template": """Analyze this {file_path} script for malicious behavior:

FILE INFORMATION:
- Size: {file_size} bytes
- MD5: {md5}
- SHA256: {sha256}

SCRIPT CONTENT:
{file_content}

ANALYSIS TASKS:
1. **Verdict**: Malicious/Suspicious/Clean (confidence %)
2. **Threat Type**: What type of malicious activity? (backdoor, downloader, ransomware, etc.)
3. **Code Analysis**:
   - What does this script do?
   - Obfuscation techniques used?
   - External communications?
   - File system operations?
4. **IOCs**: Extract ALL indicators:
   - URLs and domains
   - IP addresses
   - File paths
   - Commands executed
5. **MITRE ATT&CK**: Map to techniques
6. **Recommendations**: How to detect and prevent?

Focus on evidence in the code. Be specific about malicious behaviors.""",
        "required_tools": ["script_analyzer"],
        "enabled": True,
    }


# Example usage
if __name__ == "__main__":
    # Initialize analyzer
    analyzer = ScriptAnalyzer()

    # Analyze a script
    result = analyzer.analyze("suspicious_script.py")

    print(f"Script Type: {result.script_type}")
    print(f"Lines: {result.line_count}")
    print(f"Imports: {', '.join(result.imports)}")
    print(f"\nSuspicious Patterns Found: {len(result.suspicious_patterns)}")
    for pattern in result.suspicious_patterns:
        print(f"  - {pattern}")

    print(f"\nAnomalies: {len(result.anomalies)}")
    for anomaly in result.anomalies:
        print(f"  - {anomaly}")

    # Create custom agent config (can be saved to YAML)
    config = create_custom_agent_config()
    print(f"\nCustom Agent Config:")
    print(f"  Name: {config['name']}")
    print(f"  Supported Extensions: {', '.join(config['file_extensions'])}")

    # To use with plugin manager:
    # from src.plugins.plugin_manager import PluginManager
    # manager = PluginManager(settings)
    # manager.load_custom_agent("script_agent_config.yaml")
