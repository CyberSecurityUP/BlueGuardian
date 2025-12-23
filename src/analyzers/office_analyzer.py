"""Office document analyzer for detecting malicious Office files.

This module analyzes Microsoft Office documents (DOCX, XLSX, PPTX, DOC, XLS)
for macros, embedded objects, and other suspicious content.
"""

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False
    logger.warning("olefile not installed - legacy Office analysis limited")


@dataclass
class OfficeMacro:
    """Information about a VBA macro."""

    stream_name: str
    code: str
    suspicious_keywords: List[str] = field(default_factory=list)
    auto_exec: bool = False
    obfuscated: bool = False


@dataclass
class EmbeddedObject:
    """Information about an embedded object."""

    object_type: str
    size: int
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class OfficeAnalysisResult:
    """Complete Office document analysis result."""

    file_path: str
    file_size: int
    file_type: str  # docx, xlsx, doc, xls, etc.

    # Document format
    is_ooxml: bool = False  # Office Open XML (modern format)
    is_ole: bool = False    # OLE format (legacy)

    # Macros
    has_macros: bool = False
    macro_count: int = 0
    macros: List[OfficeMacro] = field(default_factory=list)

    # Embedded content
    has_embedded_objects: bool = False
    embedded_objects: List[EmbeddedObject] = field(default_factory=list)

    # External links
    has_external_links: bool = False
    external_urls: List[str] = field(default_factory=list)

    # DDE (Dynamic Data Exchange)
    has_dde: bool = False
    dde_links: List[str] = field(default_factory=list)

    # ActiveX
    has_activex: bool = False

    # Metadata
    metadata: Dict[str, str] = field(default_factory=dict)

    # Warnings
    warnings: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


class OfficeAnalyzer:
    """Analyzer for Microsoft Office documents."""

    # Suspicious VBA keywords
    SUSPICIOUS_VBA_KEYWORDS = {
        # Execution
        'Shell', 'WScript.Shell', 'CreateObject', 'GetObject',
        'Environ', 'ExecuteGlobal', 'Execute', 'Eval',

        # File operations
        'Open', 'Write', 'Put', 'Print', 'Kill',
        'FileCopy', 'CreateTextFile', 'OpenTextFile',

        # Network
        'XMLHTTP', 'WinHttp', 'URLDownloadToFile', 'InternetOpen',
        'ADODB.Stream', 'Microsoft.XMLHTTP',

        # Process
        'WMI', 'Win32_Process', 'Win32_ProcessStartup',

        # Registry
        'RegWrite', 'RegRead', 'RegDelete',

        # Obfuscation
        'Chr', 'StrReverse', 'Replace', 'Mid', 'Asc',
        'CallByName',

        # Auto-execution
        'AutoOpen', 'Auto_Open', 'Document_Open', 'Workbook_Open',
        'AutoExec', 'Auto_Close', 'Document_Close',
    }

    def __init__(self):
        """Initialize Office analyzer."""
        pass

    def analyze(self, file_path: str) -> OfficeAnalysisResult:
        """Analyze an Office document.

        Args:
            file_path: Path to Office file

        Returns:
            OfficeAnalysisResult with comprehensive analysis

        Raises:
            ValueError: If file is not a valid Office document
        """
        path = Path(file_path)

        if not path.exists():
            raise ValueError(f"File not found: {file_path}")

        logger.info(f"Analyzing Office document: {file_path}")

        # Determine file type
        suffix = path.suffix.lower()
        file_type = suffix[1:] if suffix else "unknown"

        result = OfficeAnalysisResult(
            file_path=file_path,
            file_size=path.stat().st_size,
            file_type=file_type,
        )

        # Check if OOXML (modern Office format - ZIP based)
        if self._is_ooxml(file_path):
            result.is_ooxml = True
            self._analyze_ooxml(file_path, result)

        # Check if OLE (legacy Office format)
        elif self._is_ole(file_path):
            result.is_ole = True
            self._analyze_ole(file_path, result)

        else:
            raise ValueError(f"Unrecognized Office format: {file_path}")

        # Post-analysis checks
        if result.has_macros and result.has_external_links:
            result.anomalies.append("Document has both macros and external links")

        if result.has_dde:
            result.anomalies.append("DDE links detected - can be used for code execution")

        if any(m.auto_exec for m in result.macros):
            result.anomalies.append("Auto-executing macros detected")

        logger.info(
            f"Office analysis complete: macros={result.has_macros}, "
            f"embedded={result.has_embedded_objects}, DDE={result.has_dde}"
        )

        return result

    def _is_ooxml(self, file_path: str) -> bool:
        """Check if file is OOXML format (ZIP-based)."""
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # OOXML files have specific structure
                return '[Content_Types].xml' in zf.namelist()
        except:
            return False

    def _is_ole(self, file_path: str) -> bool:
        """Check if file is OLE format."""
        if not HAS_OLEFILE:
            return False

        try:
            return olefile.isOleFile(file_path)
        except:
            return False

    def _analyze_ooxml(self, file_path: str, result: OfficeAnalysisResult) -> None:
        """Analyze OOXML format document."""
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Check for macros (vbaProject.bin)
                macro_files = [f for f in zf.namelist() if 'vbaProject.bin' in f]

                if macro_files:
                    result.has_macros = True

                    # Extract and analyze VBA project
                    for macro_file in macro_files:
                        try:
                            data = zf.read(macro_file)
                            self._analyze_vba_project(data, result)
                        except Exception as e:
                            result.warnings.append(f"Error reading macro: {e}")

                # Check for external relationships
                rel_files = [f for f in zf.namelist() if f.endswith('.rels')]

                for rel_file in rel_files:
                    try:
                        content = zf.read(rel_file).decode('utf-8', errors='ignore')

                        # Look for external targets
                        urls = re.findall(r'Target="(https?://[^"]+)"', content)
                        if urls:
                            result.has_external_links = True
                            result.external_urls.extend(urls)

                    except Exception as e:
                        result.warnings.append(f"Error reading relationships: {e}")

                # Check for DDE in document.xml
                doc_files = [f for f in zf.namelist() if 'document.xml' in f or 'worksheet' in f]

                for doc_file in doc_files:
                    try:
                        content = zf.read(doc_file).decode('utf-8', errors='ignore')

                        # Check for DDE
                        if 'ddeAuto' in content or 'DDE' in content:
                            result.has_dde = True

                            # Extract DDE links
                            dde_links = re.findall(r'<w:instrText[^>]*>(.*?)</w:instrText>', content)
                            result.dde_links.extend(dde_links)

                    except Exception as e:
                        result.warnings.append(f"Error checking DDE: {e}")

                # Check for embedded objects
                embed_files = [f for f in zf.namelist() if 'embeddings' in f.lower()]

                for embed_file in embed_files:
                    obj = EmbeddedObject(
                        object_type=Path(embed_file).suffix,
                        size=zf.getinfo(embed_file).file_size,
                    )

                    # Check if executable
                    if obj.object_type.lower() in ['.exe', '.dll', '.scr', '.bat', '.ps1']:
                        obj.suspicious = True
                        obj.reasons.append("Executable file type")

                    result.embedded_objects.append(obj)

                if result.embedded_objects:
                    result.has_embedded_objects = True

        except Exception as e:
            logger.error(f"OOXML analysis error: {e}")
            result.warnings.append(f"OOXML analysis error: {str(e)}")

    def _analyze_ole(self, file_path: str, result: OfficeAnalysisResult) -> None:
        """Analyze OLE format document."""
        if not HAS_OLEFILE:
            result.warnings.append("olefile library not available - analysis limited")
            return

        try:
            ole = olefile.OleFileIO(file_path)

            # Extract metadata
            meta = ole.get_metadata()
            if meta:
                result.metadata = {
                    'author': meta.author or '',
                    'title': meta.title or '',
                    'subject': meta.subject or '',
                    'create_time': str(meta.create_time) if meta.create_time else '',
                }

            # Check for VBA macros
            if ole.exists('Macros') or ole.exists('VBA'):
                result.has_macros = True

                # Try to extract VBA code
                for entry in ole.listdir():
                    entry_path = '/'.join(entry)

                    if 'VBA' in entry_path or 'Macro' in entry_path:
                        try:
                            data = ole.openstream(entry).read()
                            # VBA code is often in specific streams
                            if b'Attribute VB_Name' in data:
                                code = data.decode('latin-1', errors='ignore')
                                self._analyze_vba_code(entry_path, code, result)
                        except:
                            pass

            # Check for embedded objects
            for entry in ole.listdir():
                entry_name = '/'.join(entry)

                if 'ObjectPool' in entry_name or 'Embedding' in entry_name:
                    result.has_embedded_objects = True

                    try:
                        size = ole.get_size(entry_name)
                        obj = EmbeddedObject(
                            object_type="OLE Object",
                            size=size,
                        )
                        result.embedded_objects.append(obj)
                    except:
                        pass

            ole.close()

        except Exception as e:
            logger.error(f"OLE analysis error: {e}")
            result.warnings.append(f"OLE analysis error: {str(e)}")

    def _analyze_vba_project(self, data: bytes, result: OfficeAnalysisResult) -> None:
        """Analyze VBA project binary."""
        # Note: Full VBA decompression requires oletools
        # This is a basic implementation

        try:
            # Look for VBA code signatures
            if b'Attribute VB_Name' in data:
                # Try to extract readable code
                code = data.decode('latin-1', errors='ignore')
                self._analyze_vba_code("vbaProject.bin", code, result)

        except Exception as e:
            result.warnings.append(f"VBA project analysis error: {e}")

    def _analyze_vba_code(self, stream_name: str, code: str, result: OfficeAnalysisResult) -> None:
        """Analyze VBA macro code."""
        # Find suspicious keywords
        suspicious = []
        for keyword in self.SUSPICIOUS_VBA_KEYWORDS:
            if keyword.lower() in code.lower():
                suspicious.append(keyword)

        # Check for auto-execution
        auto_exec = any(
            ae in code
            for ae in ['AutoOpen', 'Auto_Open', 'Document_Open', 'Workbook_Open']
        )

        # Check for obfuscation (lots of Chr, Asc, etc.)
        obfuscation_count = sum(
            code.count(pattern)
            for pattern in ['Chr(', 'Asc(', 'StrReverse(']
        )
        obfuscated = obfuscation_count > 10

        macro = OfficeMacro(
            stream_name=stream_name,
            code=code[:5000],  # Limit size
            suspicious_keywords=suspicious,
            auto_exec=auto_exec,
            obfuscated=obfuscated,
        )

        result.macros.append(macro)
        result.macro_count += 1
