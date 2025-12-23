"""PDF file analyzer for detecting malicious PDFs.

This module analyzes PDF files for suspicious content, embedded JavaScript,
exploits, and other indicators of malicious activity.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

try:
    import PyPDF2
    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False
    logger.warning("PyPDF2 not installed - PDF analysis will be limited")


@dataclass
class PDFObject:
    """Information about a PDF object."""

    object_id: int
    object_type: str
    content: str
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class PDFAnalysisResult:
    """Complete PDF analysis result."""

    file_path: str
    file_size: int

    # PDF structure
    pdf_version: str = "unknown"
    page_count: int = 0
    is_encrypted: bool = False

    # Suspicious elements
    has_javascript: bool = False
    has_embedded_files: bool = False
    has_launch_actions: bool = False
    has_auto_action: bool = False

    # Objects
    total_objects: int = 0
    suspicious_objects: List[PDFObject] = field(default_factory=list)

    # JavaScript code found
    javascript_code: List[str] = field(default_factory=list)

    # URIs/URLs
    urls: List[str] = field(default_factory=list)

    # Metadata
    metadata: Dict[str, str] = field(default_factory=dict)

    # Suspicious keywords
    suspicious_keywords: List[str] = field(default_factory=list)

    # Warnings
    warnings: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


class PDFAnalyzer:
    """Analyzer for PDF files."""

    # Suspicious PDF keywords often used in exploits
    SUSPICIOUS_KEYWORDS = [
        '/JavaScript', '/JS', '/Launch', '/OpenAction', '/AA',
        '/AcroForm', '/XFA', '/RichMedia', '/EmbeddedFile',
        '/ObjStm', '/URI', '/SubmitForm', '/ImportData',
        'unescape', 'eval', 'shellcode', 'payload',
        '%u9090', 'spray', 'heap',
    ]

    # Exploit-related patterns
    EXPLOIT_PATTERNS = [
        r'%u[0-9a-fA-F]{4}',  # Unicode heap spray
        r'eval\s*\(',           # JavaScript eval
        r'unescape\s*\(',       # JavaScript unescape
        r'String\.fromCharCode',  # Obfuscation
        r'shellcode',
        r'0x[0-9a-fA-F]{8}',   # Memory addresses
    ]

    def __init__(self):
        """Initialize PDF analyzer."""
        if not HAS_PYPDF2:
            raise ImportError(
                "PyPDF2 library required for PDF analysis. "
                "Install with: pip install PyPDF2"
            )

    def analyze(self, file_path: str) -> PDFAnalysisResult:
        """Analyze a PDF file.

        Args:
            file_path: Path to PDF file

        Returns:
            PDFAnalysisResult with comprehensive analysis

        Raises:
            ValueError: If file is not a valid PDF
        """
        path = Path(file_path)

        if not path.exists():
            raise ValueError(f"File not found: {file_path}")

        logger.info(f"Analyzing PDF file: {file_path}")

        result = PDFAnalysisResult(
            file_path=file_path,
            file_size=path.stat().st_size,
        )

        try:
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)

                # Basic PDF info
                result.pdf_version = pdf.pdf_header if hasattr(pdf, 'pdf_header') else "unknown"
                result.page_count = len(pdf.pages)
                result.is_encrypted = pdf.is_encrypted

                # Extract metadata
                if pdf.metadata:
                    result.metadata = {
                        key: str(value) for key, value in pdf.metadata.items()
                        if value is not None
                    }

                # Analyze each page
                for page_num, page in enumerate(pdf.pages):
                    try:
                        # Extract text
                        text = page.extract_text()

                        # Check for URLs
                        urls = self._extract_urls(text)
                        result.urls.extend(urls)

                        # Check page object
                        if hasattr(page, 'get_object'):
                            page_obj = page.get_object()
                            self._analyze_page_object(page_obj, result)

                    except Exception as e:
                        result.warnings.append(f"Error analyzing page {page_num}: {e}")

                # Read raw PDF content for deep analysis
                f.seek(0)
                raw_content = f.read().decode('latin-1', errors='ignore')
                self._analyze_raw_content(raw_content, result)

        except PyPDF2.errors.PdfReadError as e:
            raise ValueError(f"Invalid or corrupted PDF: {e}")
        except Exception as e:
            logger.error(f"PDF analysis error: {e}", exc_info=True)
            result.warnings.append(f"Analysis error: {str(e)}")

        # Final checks
        if result.has_javascript and result.has_auto_action:
            result.anomalies.append("PDF has both JavaScript and auto-action - high risk")

        if result.is_encrypted:
            result.anomalies.append("PDF is encrypted - may hide malicious content")

        if len(result.javascript_code) > 0:
            result.anomalies.append(f"Found {len(result.javascript_code)} JavaScript blocks")

        logger.info(
            f"PDF analysis complete: {result.page_count} pages, "
            f"JS: {result.has_javascript}, "
            f"encrypted: {result.is_encrypted}"
        )

        return result

    def _analyze_page_object(self, obj: Any, result: PDFAnalysisResult) -> None:
        """Analyze a PDF page object."""
        if not isinstance(obj, dict):
            return

        obj_str = str(obj)

        # Check for JavaScript
        if '/JavaScript' in obj_str or '/JS' in obj_str:
            result.has_javascript = True

        # Check for auto-actions
        if '/OpenAction' in obj_str or '/AA' in obj_str:
            result.has_auto_action = True

        # Check for launch actions
        if '/Launch' in obj_str:
            result.has_launch_actions = True

        # Check for embedded files
        if '/EmbeddedFile' in obj_str:
            result.has_embedded_files = True

    def _analyze_raw_content(self, content: str, result: PDFAnalysisResult) -> None:
        """Analyze raw PDF content for suspicious patterns."""

        # Count objects
        result.total_objects = content.count('endobj')

        # Search for suspicious keywords
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in content:
                if keyword not in result.suspicious_keywords:
                    result.suspicious_keywords.append(keyword)

        # Extract JavaScript code
        js_pattern = r'/JavaScript\s*<<.*?>>\s*stream\s*(.*?)\s*endstream'
        js_matches = re.findall(js_pattern, content, re.DOTALL)

        for js_code in js_matches:
            if js_code and len(js_code) > 10:
                result.javascript_code.append(js_code[:1000])  # Limit size

        # Check for exploit patterns
        for pattern in self.EXPLOIT_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                result.anomalies.append(f"Found exploit pattern: {pattern}")

        # Check for shellcode-like patterns
        if self._contains_shellcode_patterns(content):
            result.anomalies.append("Possible shellcode detected")

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text.

        Args:
            text: Text to extract from

        Returns:
            List of URLs
        """
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))  # Remove duplicates

    def _contains_shellcode_patterns(self, content: str) -> bool:
        """Check if content contains shellcode-like patterns.

        Args:
            content: Content to check

        Returns:
            True if shellcode patterns detected
        """
        # Look for long sequences of hex values (common in shellcode)
        hex_sequences = re.findall(r'(?:\\x[0-9a-fA-F]{2}){10,}', content)

        if hex_sequences:
            return True

        # Look for NOP sleds (0x90 repeated)
        if re.search(r'(?:\\x90){10,}', content):
            return True

        return False

    def extract_streams(self, file_path: str) -> List[bytes]:
        """Extract all streams from PDF.

        Args:
            file_path: Path to PDF

        Returns:
            List of stream contents
        """
        streams = []

        try:
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)

                for page in pdf.pages:
                    if hasattr(page, 'get_contents'):
                        try:
                            content = page.get_contents()
                            if content:
                                streams.append(content.get_data())
                        except:
                            pass

        except Exception as e:
            logger.error(f"Error extracting streams: {e}")

        return streams
