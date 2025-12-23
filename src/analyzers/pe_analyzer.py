"""PE (Portable Executable) file analyzer for Windows malware.

This module provides comprehensive static analysis of Windows PE files
including headers, sections, imports, exports, resources, and anomaly detection.
"""

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from loguru import logger

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    logger.warning("pefile not installed - PE analysis will be limited")


@dataclass
class PESection:
    """PE section information."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: List[str]
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class PEImport:
    """Imported function information."""

    dll: str
    function: str
    suspicious: bool = False
    category: Optional[str] = None


@dataclass
class PEExport:
    """Exported function information."""

    name: str
    ordinal: int
    address: int


@dataclass
class PEAnalysisResult:
    """Complete PE analysis result."""

    # Basic info
    file_path: str
    file_size: int
    file_type: str
    is_packed: bool
    packer_name: Optional[str] = None

    # PE structure
    architecture: str = "unknown"
    subsystem: str = "unknown"
    compiler: Optional[str] = None
    compilation_timestamp: Optional[str] = None

    # Sections
    sections: List[PESection] = field(default_factory=list)
    section_count: int = 0

    # Imports/Exports
    imports: List[PEImport] = field(default_factory=list)
    imports_count: int = 0
    exports: List[PEExport] = field(default_factory=list)
    exports_count: int = 0

    # Suspicious indicators
    suspicious_imports: List[str] = field(default_factory=list)
    suspicious_sections: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)

    # Metadata
    warnings: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)

    # Raw data for AI analysis
    raw_data: Dict[str, Any] = field(default_factory=dict)


class PEAnalyzer:
    """Analyzer for Windows PE files."""

    # Suspicious API calls commonly used by malware
    SUSPICIOUS_APIS = {
        # Process manipulation
        'CreateRemoteThread': 'process_injection',
        'WriteProcessMemory': 'process_injection',
        'VirtualAllocEx': 'process_injection',
        'NtQueueApcThread': 'process_injection',
        'SetWindowsHookEx': 'hooking',

        # Keylogging
        'GetAsyncKeyState': 'keylogging',
        'SetWindowsHookEx': 'keylogging',
        'GetForegroundWindow': 'keylogging',

        # Network
        'InternetOpen': 'network',
        'InternetOpenUrl': 'network',
        'HttpSendRequest': 'network',
        'WSAStartup': 'network',
        'send': 'network',
        'recv': 'network',

        # Persistence
        'RegSetValueEx': 'registry',
        'RegCreateKeyEx': 'registry',
        'CreateService': 'service',
        'StartService': 'service',

        # Anti-analysis
        'IsDebuggerPresent': 'anti_debug',
        'CheckRemoteDebuggerPresent': 'anti_debug',
        'NtQueryInformationProcess': 'anti_debug',
        'GetTickCount': 'anti_debug',

        # Crypto
        'CryptEncrypt': 'crypto',
        'CryptDecrypt': 'crypto',
        'CryptAcquireContext': 'crypto',

        # Code injection
        'LoadLibrary': 'dll_loading',
        'GetProcAddress': 'dll_loading',
    }

    # Known packer signatures
    PACKER_SIGNATURES = {
        'UPX': [b'UPX0', b'UPX1', b'UPX!'],
        'ASPack': [b'ASPack'],
        'PECompact': [b'PEC2'],
        'NSPack': [b'.nsp0', b'.nsp1', b'.nsp2'],
        'MEW': [b'MEW'],
        'Themida': [b'.themida'],
        'VMProtect': [b'.vmp0', b'.vmp1'],
    }

    def __init__(self):
        """Initialize PE analyzer."""
        if not HAS_PEFILE:
            raise ImportError(
                "pefile library required for PE analysis. "
                "Install with: pip install pefile"
            )

    def analyze(self, file_path: str) -> PEAnalysisResult:
        """Analyze a PE file.

        Args:
            file_path: Path to PE file

        Returns:
            PEAnalysisResult with comprehensive analysis

        Raises:
            ValueError: If file is not a valid PE
        """
        path = Path(file_path)

        if not path.exists():
            raise ValueError(f"File not found: {file_path}")

        logger.info(f"Analyzing PE file: {file_path}")

        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError as e:
            raise ValueError(f"Invalid PE file: {e}")

        result = PEAnalysisResult(
            file_path=file_path,
            file_size=path.stat().st_size,
            file_type="PE",
        )

        # Extract basic PE information
        self._extract_basic_info(pe, result)

        # Analyze sections
        self._analyze_sections(pe, result)

        # Analyze imports
        self._analyze_imports(pe, result)

        # Analyze exports
        self._analyze_exports(pe, result)

        # Detect packing
        self._detect_packing(pe, result)

        # Extract strings
        self._extract_strings(file_path, result)

        # Store raw PE data for AI
        result.raw_data = self._extract_raw_data(pe)

        pe.close()

        logger.info(
            f"PE analysis complete: {result.section_count} sections, "
            f"{result.imports_count} imports, packed: {result.is_packed}"
        )

        return result

    def _extract_basic_info(self, pe: pefile.PE, result: PEAnalysisResult) -> None:
        """Extract basic PE information."""
        # Architecture
        if pe.FILE_HEADER.Machine == 0x14c:
            result.architecture = "x86"
        elif pe.FILE_HEADER.Machine == 0x8664:
            result.architecture = "x64"
        else:
            result.architecture = f"unknown (0x{pe.FILE_HEADER.Machine:x})"

        # Subsystem
        subsystems = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI",
            5: "OS/2 CUI",
            7: "POSIX CUI",
            9: "Windows CE GUI",
            10: "EFI Application",
        }
        subsystem_id = pe.OPTIONAL_HEADER.Subsystem
        result.subsystem = subsystems.get(subsystem_id, f"Unknown ({subsystem_id})")

        # Timestamp
        import datetime
        try:
            timestamp = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            result.compilation_timestamp = timestamp.isoformat()

            # Check for suspicious timestamps
            now = datetime.datetime.now()
            if timestamp > now:
                result.anomalies.append("Compilation timestamp is in the future")
            elif timestamp.year < 1990:
                result.anomalies.append("Suspiciously old compilation timestamp")
        except (ValueError, OSError):
            result.warnings.append("Invalid compilation timestamp")

    def _analyze_sections(self, pe: pefile.PE, result: PEAnalysisResult) -> None:
        """Analyze PE sections."""
        result.section_count = len(pe.sections)

        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')

            # Calculate entropy
            data = section.get_data()
            entropy = self._calculate_entropy(data)

            # Get characteristics
            characteristics = []
            if section.Characteristics & 0x20000000:
                characteristics.append("EXECUTABLE")
            if section.Characteristics & 0x40000000:
                characteristics.append("READABLE")
            if section.Characteristics & 0x80000000:
                characteristics.append("WRITABLE")

            # Detect suspicious sections
            suspicious = False
            reasons = []

            # High entropy suggests encryption/compression
            if entropy > 7.0:
                suspicious = True
                reasons.append(f"High entropy ({entropy:.2f}) - possibly packed/encrypted")

            # Writable + executable is suspicious
            if "WRITABLE" in characteristics and "EXECUTABLE" in characteristics:
                suspicious = True
                reasons.append("Writable and executable section")

            # Unusual section names
            normal_sections = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.idata', '.edata'}
            if name not in normal_sections and not name.startswith('.'):
                suspicious = True
                reasons.append(f"Unusual section name: {name}")

            # Very large virtual size compared to raw size
            if section.Misc_VirtualSize > section.SizeOfRawData * 2:
                suspicious = True
                reasons.append("Virtual size much larger than raw size")

            pe_section = PESection(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=entropy,
                characteristics=characteristics,
                suspicious=suspicious,
                reasons=reasons,
            )

            result.sections.append(pe_section)

            if suspicious:
                result.suspicious_sections.append(name)

    def _analyze_imports(self, pe: pefile.PE, result: PEAnalysisResult) -> None:
        """Analyze imported functions."""
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')

                    # Check if function is suspicious
                    suspicious = func_name in self.SUSPICIOUS_APIS
                    category = self.SUSPICIOUS_APIS.get(func_name)

                    pe_import = PEImport(
                        dll=dll,
                        function=func_name,
                        suspicious=suspicious,
                        category=category,
                    )

                    result.imports.append(pe_import)

                    if suspicious:
                        result.suspicious_imports.append(f"{dll}!{func_name} ({category})")

        result.imports_count = len(result.imports)

    def _analyze_exports(self, pe: pefile.PE, result: PEAnalysisResult) -> None:
        """Analyze exported functions."""
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"ord_{exp.ordinal}"

            pe_export = PEExport(
                name=name,
                ordinal=exp.ordinal,
                address=exp.address,
            )

            result.exports.append(pe_export)

        result.exports_count = len(result.exports)

    def _detect_packing(self, pe: pefile.PE, result: PEAnalysisResult) -> None:
        """Detect if PE is packed."""
        # Check section names for known packers
        with open(result.file_path, 'rb') as f:
            data = f.read()

        for packer, signatures in self.PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in data:
                    result.is_packed = True
                    result.packer_name = packer
                    return

        # Heuristic: high entropy in code section suggests packing
        for section in result.sections:
            if 'EXECUTABLE' in section.characteristics and section.entropy > 7.5:
                result.is_packed = True
                result.packer_name = "Unknown (high entropy)"
                return

        # Check for low number of imports (packers often have few imports)
        if result.imports_count < 5 and result.file_size > 10000:
            result.is_packed = True
            result.packer_name = "Suspected (few imports)"
            return

        result.is_packed = False

    def _extract_strings(self, file_path: str, result: PEAnalysisResult, min_length: int = 6) -> None:
        """Extract suspicious strings from the file."""
        with open(file_path, 'rb') as f:
            data = f.read()

        # Extract ASCII strings
        ascii_pattern = rb'[ -~]{%d,}' % min_length
        strings = re.findall(ascii_pattern, data)

        # Extract Unicode strings
        unicode_pattern = rb'(?:[ -~]\x00){%d,}' % min_length
        unicode_strings = re.findall(unicode_pattern, data)
        unicode_strings = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings]

        all_strings = [s.decode('ascii', errors='ignore') for s in strings] + unicode_strings

        # Filter for suspicious patterns
        suspicious_patterns = [
            r'https?://',  # URLs
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'cmd\.exe',  # Command execution
            r'powershell',  # PowerShell
            r'HKEY_',  # Registry keys
            r'\\\\\.\\pipe\\',  # Named pipes
            r'[A-Za-z]:\\.*\.exe',  # File paths
        ]

        for string in all_strings:
            for pattern in suspicious_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    if string not in result.suspicious_strings:
                        result.suspicious_strings.append(string)
                    break

        # Limit to most interesting strings
        result.suspicious_strings = result.suspicious_strings[:50]

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Byte data

        Returns:
            Entropy value (0.0-8.0)
        """
        if not data:
            return 0.0

        entropy = 0.0
        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        data_len = len(data)

        for count in byte_counts:
            if count == 0:
                continue

            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _extract_raw_data(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract raw PE data for AI analysis.

        Args:
            pe: PE object

        Returns:
            Dictionary with raw data
        """
        return {
            'dos_header': str(pe.DOS_HEADER),
            'file_header': str(pe.FILE_HEADER),
            'optional_header': str(pe.OPTIONAL_HEADER),
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'number_of_symbols': pe.FILE_HEADER.NumberOfSymbols,
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        }
