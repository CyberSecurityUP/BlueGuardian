"""LNK (Windows Shortcut) file analyzer.

This module analyzes Windows shortcut (.lnk) files which are commonly
used in phishing attacks to execute malicious commands.
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from loguru import logger


@dataclass
class LNKAnalysisResult:
    """Complete LNK file analysis result."""

    file_path: str
    file_size: int

    # Target information
    target_path: Optional[str] = None
    arguments: Optional[str] = None
    working_directory: Optional[str] = None
    icon_location: Optional[str] = None

    # Flags
    is_local: bool = False
    is_network: bool = False
    has_arguments: bool = False
    runs_minimized: bool = False
    runs_maximized: bool = False

    # Suspicious indicators
    suspicious_target: bool = False
    suspicious_arguments: bool = False
    uses_powershell: bool = False
    uses_cmd: bool = False
    uses_mshta: bool = False
    uses_wscript: bool = False
    uses_cscript: bool = False

    # Network information (if network target)
    network_share: Optional[str] = None

    # Anomalies
    anomalies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class LNKAnalyzer:
    """Analyzer for Windows LNK files."""

    # Suspicious interpreters
    SUSPICIOUS_INTERPRETERS = {
        'powershell.exe': 'PowerShell',
        'cmd.exe': 'Command Prompt',
        'mshta.exe': 'MSHTA (HTML Application)',
        'wscript.exe': 'Windows Script Host',
        'cscript.exe': 'Console Script Host',
        'regsvr32.exe': 'RegSvr32',
        'rundll32.exe': 'RunDLL32',
        'msiexec.exe': 'Windows Installer',
    }

    # Suspicious argument patterns
    SUSPICIOUS_PATTERNS = [
        '-encodedcommand',
        '-enc',
        '-noprofile',
        '-executionpolicy bypass',
        'downloadstring',
        'downloadfile',
        'invoke-expression',
        'iex',
        'hidden',
        'bypass',
        '^',  # CMD obfuscation
        'powershell',
    ]

    def __init__(self):
        """Initialize LNK analyzer."""
        pass

    def analyze(self, file_path: str) -> LNKAnalysisResult:
        """Analyze a LNK file.

        Args:
            file_path: Path to LNK file

        Returns:
            LNKAnalysisResult with comprehensive analysis

        Raises:
            ValueError: If file is not a valid LNK
        """
        path = Path(file_path)

        if not path.exists():
            raise ValueError(f"File not found: {file_path}")

        logger.info(f"Analyzing LNK file: {file_path}")

        result = LNKAnalysisResult(
            file_path=file_path,
            file_size=path.stat().st_size,
        )

        try:
            with open(file_path, 'rb') as f:
                # Read LNK header
                header = f.read(0x4C)

                if len(header) < 0x4C:
                    raise ValueError("File too small to be a valid LNK")

                # Check magic number
                if header[0:4] != b'\x4C\x00\x00\x00':
                    raise ValueError("Invalid LNK header")

                # Parse flags
                flags = struct.unpack('<I', header[0x14:0x18])[0]

                result.is_local = bool(flags & 0x01)
                result.is_network = bool(flags & 0x02)
                result.has_arguments = bool(flags & 0x2000)

                # Parse show command
                show_command = struct.unpack('<I', header[0x48:0x4C])[0]
                result.runs_minimized = (show_command == 7)
                result.runs_maximized = (show_command == 3)

                # Read rest of file to extract strings
                f.seek(0x4C)
                data = f.read()

                # Extract target path
                target = self._extract_string(data, 'target')
                if target:
                    result.target_path = target
                    self._analyze_target(target, result)

                # Extract arguments
                if result.has_arguments:
                    args = self._extract_string(data, 'arguments')
                    if args:
                        result.arguments = args
                        self._analyze_arguments(args, result)

                # Extract working directory
                working_dir = self._extract_string(data, 'working')
                if working_dir:
                    result.working_directory = working_dir

        except Exception as e:
            logger.error(f"LNK analysis error: {e}")
            result.warnings.append(f"Analysis error: {str(e)}")

        # Final checks
        if result.runs_minimized and (result.uses_powershell or result.uses_cmd):
            result.anomalies.append("Runs minimized with script interpreter - likely malicious")

        if result.is_network:
            result.anomalies.append("Points to network location")

        logger.info(
            f"LNK analysis complete: target={result.target_path}, "
            f"suspicious={result.suspicious_target or result.suspicious_arguments}"
        )

        return result

    def _extract_string(self, data: bytes, string_type: str) -> Optional[str]:
        """Extract strings from LNK data.

        Args:
            data: LNK file data
            string_type: Type of string to extract

        Returns:
            Extracted string or None
        """
        try:
            # Try to decode as UTF-16 (Windows default)
            text = data.decode('utf-16-le', errors='ignore')

            # Remove null characters
            text = text.replace('\x00', '')

            # Basic cleanup
            text = text.strip()

            if len(text) > 3:
                return text[:500]  # Limit size

        except:
            pass

        return None

    def _analyze_target(self, target: str, result: LNKAnalysisResult) -> None:
        """Analyze target path for suspicious content."""
        target_lower = target.lower()

        # Check for suspicious interpreters
        for interpreter, name in self.SUSPICIOUS_INTERPRETERS.items():
            if interpreter in target_lower:
                if 'powershell' in interpreter:
                    result.uses_powershell = True
                elif 'cmd' in interpreter:
                    result.uses_cmd = True
                elif 'mshta' in interpreter:
                    result.uses_mshta = True
                elif 'wscript' in interpreter or 'cscript' in interpreter:
                    result.uses_wscript = True
                    result.uses_cscript = True

                result.suspicious_target = True
                result.anomalies.append(f"Uses {name}")

        # Check for unusual locations
        suspicious_paths = [
            '%temp%',
            '%appdata%',
            '%programdata%',
            'c:\\users\\public',
            'c:\\windows\\temp',
        ]

        for sus_path in suspicious_paths:
            if sus_path in target_lower:
                result.anomalies.append(f"Target in suspicious location: {sus_path}")

    def _analyze_arguments(self, arguments: str, result: LNKAnalysisResult) -> None:
        """Analyze command arguments for suspicious patterns."""
        args_lower = arguments.lower()

        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in args_lower:
                result.suspicious_arguments = True
                result.anomalies.append(f"Suspicious argument pattern: {pattern}")

        # Check for obfuscation
        if args_lower.count('^') > 5:  # CMD caret obfuscation
            result.suspicious_arguments = True
            result.anomalies.append("Possible CMD obfuscation detected")

        # Check for base64 (common in PowerShell attacks)
        if len(arguments) > 100 and self._is_base64(arguments):
            result.suspicious_arguments = True
            result.anomalies.append("Possible base64-encoded payload")

    def _is_base64(self, text: str) -> bool:
        """Check if text appears to be base64 encoded.

        Args:
            text: Text to check

        Returns:
            True if likely base64
        """
        import re

        # Base64 uses A-Za-z0-9+/= characters
        base64_pattern = r'^[A-Za-z0-9+/=]+$'

        # Remove whitespace
        clean_text = ''.join(text.split())

        if len(clean_text) < 20:
            return False

        return bool(re.match(base64_pattern, clean_text))
