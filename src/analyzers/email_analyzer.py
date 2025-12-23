"""Email analyzer for phishing and malicious email detection.

This module analyzes email messages for phishing indicators, suspicious
attachments, malicious links, and header anomalies.
"""

import email
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from loguru import logger


@dataclass
class EmailAttachment:
    """Information about an email attachment."""

    filename: str
    content_type: str
    size: int
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class EmailLink:
    """Information about a link in an email."""

    url: str
    display_text: str
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class EmailAnalysisResult:
    """Complete email analysis result."""

    file_path: str
    file_size: int

    # Headers
    sender: Optional[str] = None
    reply_to: Optional[str] = None
    recipients: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    date: Optional[datetime] = None
    message_id: Optional[str] = None

    # Authentication
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None

    # Content
    body_text: str = ""
    body_html: str = ""
    has_html: bool = False

    # Attachments
    has_attachments: bool = False
    attachments: List[EmailAttachment] = field(default_factory=list)

    # Links
    has_links: bool = False
    links: List[EmailLink] = field(default_factory=list)

    # Phishing indicators
    sender_domain_mismatch: bool = False
    contains_urgency_keywords: bool = False
    contains_financial_keywords: bool = False
    impersonates_brand: bool = False
    suspected_brand: Optional[str] = None

    # Header anomalies
    header_anomalies: List[str] = field(default_factory=list)

    # Suspicious patterns
    suspicious_patterns: List[str] = field(default_factory=list)

    # All headers (for reference)
    all_headers: Dict[str, str] = field(default_factory=dict)

    # Warnings
    warnings: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


class EmailAnalyzer:
    """Analyzer for email messages."""

    # Suspicious file extensions commonly used in phishing
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.scr', '.com', '.bat', '.cmd', '.pif', '.vbs', '.js',
        '.jar', '.hta', '.ps1', '.psm1', '.msi', '.dll', '.scf',
    }

    # Double extension tricks
    DOUBLE_EXTENSION_PATTERNS = [
        r'\.(pdf|doc|xls|jpg|png)\.exe$',
        r'\.(pdf|doc|xls|jpg|png)\.scr$',
    ]

    # Urgency keywords common in phishing
    URGENCY_KEYWORDS = [
        'urgent', 'immediate action', 'act now', 'expire', 'suspended',
        'verify', 'confirm', 'update', 'unusual activity', 'compromised',
        'unauthorized', 'locked', 'limited time', 'act immediately',
    ]

    # Financial/credential keywords
    FINANCIAL_KEYWORDS = [
        'bank', 'account', 'password', 'credit card', 'social security',
        'paypal', 'verify account', 'confirm identity', 'billing',
        'payment', 'transaction', 'suspicious activity', 'refund',
    ]

    # Common brands impersonated in phishing
    COMMON_BRANDS = {
        'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
        'netflix', 'ups', 'fedex', 'dhl', 'irs', 'wells fargo',
        'bank of america', 'chase', 'american express',
    }

    def __init__(self):
        """Initialize email analyzer."""
        pass

    def analyze(self, file_path: str) -> EmailAnalysisResult:
        """Analyze an email message.

        Args:
            file_path: Path to email file (.eml or .msg)

        Returns:
            EmailAnalysisResult with comprehensive analysis

        Raises:
            ValueError: If file is not a valid email
        """
        path = Path(file_path)

        if not path.exists():
            raise ValueError(f"File not found: {file_path}")

        logger.info(f"Analyzing email: {file_path}")

        result = EmailAnalysisResult(
            file_path=file_path,
            file_size=path.stat().st_size,
        )

        try:
            # Parse email
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)

            # Extract headers
            self._extract_headers(msg, result)

            # Extract authentication results
            self._extract_auth_results(msg, result)

            # Extract body
            self._extract_body(msg, result)

            # Extract attachments
            self._extract_attachments(msg, result)

            # Extract links
            self._extract_links(result)

            # Analyze for phishing indicators
            self._analyze_phishing_indicators(result)

            # Check header anomalies
            self._check_header_anomalies(result)

        except Exception as e:
            logger.error(f"Email analysis error: {e}")
            result.warnings.append(f"Analysis error: {str(e)}")

        logger.info(
            f"Email analysis complete: from={result.sender}, "
            f"attachments={len(result.attachments)}, links={len(result.links)}"
        )

        return result

    def _extract_headers(self, msg: email.message.Message, result: EmailAnalysisResult) -> None:
        """Extract email headers."""
        result.sender = msg.get('From', '')
        result.reply_to = msg.get('Reply-To')
        result.subject = msg.get('Subject', '')
        result.message_id = msg.get('Message-ID')

        # Extract recipients
        to = msg.get('To', '')
        cc = msg.get('Cc', '')
        recipients = []

        if to:
            recipients.extend([r.strip() for r in to.split(',')])
        if cc:
            recipients.extend([r.strip() for r in cc.split(',')])

        result.recipients = recipients

        # Parse date
        date_str = msg.get('Date')
        if date_str:
            try:
                result.date = email.utils.parsedate_to_datetime(date_str)
            except:
                result.warnings.append("Invalid date header")

        # Store all headers
        for key, value in msg.items():
            result.all_headers[key] = value

    def _extract_auth_results(
        self, msg: email.message.Message, result: EmailAnalysisResult
    ) -> None:
        """Extract email authentication results (SPF, DKIM, DMARC)."""
        # Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')

        if auth_results:
            auth_lower = auth_results.lower()

            # SPF
            if 'spf=pass' in auth_lower:
                result.spf_result = 'pass'
            elif 'spf=fail' in auth_lower:
                result.spf_result = 'fail'
                result.header_anomalies.append("SPF validation failed")
            elif 'spf=softfail' in auth_lower:
                result.spf_result = 'softfail'

            # DKIM
            if 'dkim=pass' in auth_lower:
                result.dkim_result = 'pass'
            elif 'dkim=fail' in auth_lower:
                result.dkim_result = 'fail'
                result.header_anomalies.append("DKIM validation failed")

            # DMARC
            if 'dmarc=pass' in auth_lower:
                result.dmarc_result = 'pass'
            elif 'dmarc=fail' in auth_lower:
                result.dmarc_result = 'fail'
                result.header_anomalies.append("DMARC validation failed")

    def _extract_body(self, msg: email.message.Message, result: EmailAnalysisResult) -> None:
        """Extract email body content."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()

                if content_type == 'text/plain':
                    try:
                        result.body_text += part.get_content()
                    except:
                        pass

                elif content_type == 'text/html':
                    result.has_html = True
                    try:
                        result.body_html += part.get_content()
                    except:
                        pass
        else:
            content_type = msg.get_content_type()

            if content_type == 'text/plain':
                try:
                    result.body_text = msg.get_content()
                except:
                    pass

            elif content_type == 'text/html':
                result.has_html = True
                try:
                    result.body_html = msg.get_content()
                except:
                    pass

    def _extract_attachments(
        self, msg: email.message.Message, result: EmailAnalysisResult
    ) -> None:
        """Extract and analyze attachments."""
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            if part.get('Content-Disposition') is None:
                continue

            filename = part.get_filename()
            if not filename:
                continue

            result.has_attachments = True

            content_type = part.get_content_type()
            size = len(part.get_payload(decode=True) or b'')

            attachment = EmailAttachment(
                filename=filename,
                content_type=content_type,
                size=size,
            )

            # Check if suspicious
            file_ext = Path(filename).suffix.lower()

            if file_ext in self.SUSPICIOUS_EXTENSIONS:
                attachment.suspicious = True
                attachment.reasons.append(f"Dangerous file extension: {file_ext}")

            # Check for double extension trick
            for pattern in self.DOUBLE_EXTENSION_PATTERNS:
                if re.search(pattern, filename, re.IGNORECASE):
                    attachment.suspicious = True
                    attachment.reasons.append("Double extension trick detected")

            # Check for misleading content type
            if file_ext == '.exe' and 'application/octet-stream' not in content_type:
                attachment.suspicious = True
                attachment.reasons.append("Misleading content type")

            result.attachments.append(attachment)

    def _extract_links(self, result: EmailAnalysisResult) -> None:
        """Extract and analyze links from email body."""
        # Combine text and HTML body
        combined_body = result.body_text + result.body_html

        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, combined_body)

        # Also extract HTML links
        html_link_pattern = r'<a\s+href=["\']([^"\']+)["\']>([^<]+)</a>'
        html_links = re.findall(html_link_pattern, result.body_html, re.IGNORECASE)

        for url in urls:
            link = EmailLink(url=url, display_text=url)
            self._analyze_link(link)
            result.links.append(link)

        for url, display_text in html_links:
            link = EmailLink(url=url, display_text=display_text)
            self._analyze_link(link)
            result.links.append(link)

        if result.links:
            result.has_links = True

    def _analyze_link(self, link: EmailLink) -> None:
        """Analyze a single link for suspicious characteristics."""
        try:
            parsed = urlparse(link.url)

            # Check for URL shorteners (often used in phishing)
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(s in parsed.netloc for s in shorteners):
                link.suspicious = True
                link.reasons.append("URL shortener detected")

            # Check for IP address in URL (suspicious)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc):
                link.suspicious = True
                link.reasons.append("IP address instead of domain")

            # Check for mismatched display text vs actual URL
            if link.display_text != link.url:
                display_lower = link.display_text.lower()
                url_lower = link.url.lower()

                # Check if display text suggests a different domain
                if 'http' in display_lower and display_lower not in url_lower:
                    link.suspicious = True
                    link.reasons.append("Display text doesn't match URL")

            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
            if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
                link.suspicious = True
                link.reasons.append("Suspicious top-level domain")

        except Exception as e:
            link.suspicious = True
            link.reasons.append(f"Invalid URL format: {e}")

    def _analyze_phishing_indicators(self, result: EmailAnalysisResult) -> None:
        """Analyze email for phishing indicators."""
        combined_text = (result.subject or '') + ' ' + result.body_text

        combined_lower = combined_text.lower()

        # Check for urgency keywords
        for keyword in self.URGENCY_KEYWORDS:
            if keyword in combined_lower:
                result.contains_urgency_keywords = True
                result.suspicious_patterns.append(f"Urgency keyword: {keyword}")

        # Check for financial keywords
        for keyword in self.FINANCIAL_KEYWORDS:
            if keyword in combined_lower:
                result.contains_financial_keywords = True
                result.suspicious_patterns.append(f"Financial keyword: {keyword}")

        # Check for brand impersonation
        for brand in self.COMMON_BRANDS:
            if brand in combined_lower:
                # Check if sender domain matches brand
                sender_lower = (result.sender or '').lower()
                if brand not in sender_lower:
                    result.impersonates_brand = True
                    result.suspected_brand = brand
                    result.anomalies.append(f"Possible {brand} impersonation")

        # Check sender/reply-to mismatch
        if result.reply_to and result.sender:
            sender_domain = self._extract_domain(result.sender)
            reply_domain = self._extract_domain(result.reply_to)

            if sender_domain and reply_domain and sender_domain != reply_domain:
                result.sender_domain_mismatch = True
                result.anomalies.append(
                    f"Sender domain ({sender_domain}) differs from "
                    f"Reply-To ({reply_domain})"
                )

    def _check_header_anomalies(self, result: EmailAnalysisResult) -> None:
        """Check for header anomalies."""
        # Check for missing headers
        if not result.message_id:
            result.header_anomalies.append("Missing Message-ID header")

        if not result.date:
            result.header_anomalies.append("Missing or invalid Date header")

        # Check for suspicious received headers
        received_headers = [v for k, v in result.all_headers.items() if k == 'Received']

        if len(received_headers) == 0:
            result.header_anomalies.append("No Received headers (possibly forged)")
        elif len(received_headers) > 20:
            result.header_anomalies.append("Unusually high number of Received headers")

    def _extract_domain(self, email_address: str) -> Optional[str]:
        """Extract domain from email address.

        Args:
            email_address: Email address

        Returns:
            Domain portion or None
        """
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
        return match.group(1).lower() if match else None
