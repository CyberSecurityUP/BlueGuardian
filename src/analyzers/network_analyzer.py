"""Network artifact analyzer for IPs, domains, and URLs.

This module provides analysis of network indicators including
IP addresses, domain names, and URLs for threat intelligence.
"""

import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

from loguru import logger


@dataclass
class IPAnalysisResult:
    """Results from IP address analysis."""

    ip_address: str
    is_private: bool
    is_reserved: bool
    reverse_dns: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    organization: Optional[str] = None
    is_tor: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_cloud: bool = False
    cloud_provider: Optional[str] = None
    reputation_score: Optional[int] = None
    threat_categories: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


@dataclass
class DomainAnalysisResult:
    """Results from domain analysis."""

    domain: str
    tld: str
    is_suspicious: bool = False
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    is_typosquat: bool = False
    typosquat_target: Optional[str] = None
    is_dga: bool = False
    entropy: Optional[float] = None
    length: int = 0
    subdomain_count: int = 0
    reputation_score: Optional[int] = None
    threat_categories: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


@dataclass
class URLAnalysisResult:
    """Results from URL analysis."""

    url: str
    scheme: str
    domain: str
    path: str
    query_params: List[str] = field(default_factory=list)
    is_obfuscated: bool = False
    is_shortened: bool = False
    original_url: Optional[str] = None
    uses_ip: bool = False
    has_suspicious_tld: bool = False
    suspicious_tld: Optional[str] = None
    has_suspicious_path: bool = False
    has_suspicious_params: bool = False
    port: Optional[int] = None
    uses_non_standard_port: bool = False
    domain_analysis: Optional[DomainAnalysisResult] = None
    reputation_score: Optional[int] = None
    threat_categories: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


class NetworkAnalyzer:
    """Analyzer for network indicators (IPs, domains, URLs).

    This analyzer performs static analysis of network artifacts without
    making external network requests (unless reverse DNS is needed).
    """

    # Private IP ranges (RFC 1918)
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
    ]

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
        'xyz', 'top', 'work', 'date', 'review',  # Often abused
        'click', 'link', 'loan', 'bid', 'win',
    }

    # URL shortener domains
    URL_SHORTENERS = {
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'shorte.st',
    }

    # Cloud providers
    CLOUD_PROVIDERS = {
        'amazon': ['amazonaws.com', 'aws.amazon.com'],
        'google': ['googleapis.com', 'gcp'],
        'microsoft': ['azure.com', 'microsoft.com', 'windows.net'],
        'digitalocean': ['digitalocean.com'],
        'cloudflare': ['cloudflare.com'],
    }

    # Suspicious URL patterns
    SUSPICIOUS_URL_PATTERNS = [
        r'login',
        r'signin',
        r'account',
        r'verify',
        r'update',
        r'secure',
        r'confirm',
        r'banking',
    ]

    # Suspicious parameters
    SUSPICIOUS_PARAMS = [
        'cmd', 'exec', 'command', 'shell', 'download',
        'upload', 'file', 'redirect', 'url', 'uri',
    ]

    def __init__(self):
        """Initialize network analyzer."""
        logger.info("Initialized NetworkAnalyzer")

    def analyze_ip(self, ip_address: str) -> IPAnalysisResult:
        """Analyze an IP address.

        Args:
            ip_address: IP address to analyze

        Returns:
            IPAnalysisResult with findings
        """
        logger.debug(f"Analyzing IP: {ip_address}")

        result = IPAnalysisResult(
            ip_address=ip_address,
            is_private=self._is_private_ip(ip_address),
            is_reserved=self._is_reserved_ip(ip_address),
        )

        # Reverse DNS lookup
        try:
            result.reverse_dns = socket.gethostbyaddr(ip_address)[0]
            logger.debug(f"Reverse DNS: {result.reverse_dns}")

            # Check for cloud providers
            for provider, patterns in self.CLOUD_PROVIDERS.items():
                for pattern in patterns:
                    if pattern in result.reverse_dns:
                        result.is_cloud = True
                        result.cloud_provider = provider
                        break

        except (socket.herror, socket.gaierror):
            logger.debug(f"No reverse DNS for {ip_address}")
            result.anomalies.append("No reverse DNS record")

        # Check anomalies
        if result.is_private:
            result.anomalies.append("Private IP address")

        return result

    def analyze_domain(self, domain: str) -> DomainAnalysisResult:
        """Analyze a domain name.

        Args:
            domain: Domain to analyze

        Returns:
            DomainAnalysisResult with findings
        """
        logger.debug(f"Analyzing domain: {domain}")

        # Extract TLD
        parts = domain.split('.')
        tld = parts[-1] if parts else ''
        subdomain_count = len(parts) - 2 if len(parts) > 2 else 0

        result = DomainAnalysisResult(
            domain=domain,
            tld=tld,
            length=len(domain),
            subdomain_count=subdomain_count,
        )

        # Check for suspicious TLD
        if tld in self.SUSPICIOUS_TLDS:
            result.is_suspicious = True
            result.anomalies.append(f"Suspicious TLD: .{tld}")

        # Calculate entropy (for DGA detection)
        result.entropy = self._calculate_entropy(domain)
        if result.entropy > 4.0:
            result.is_dga = True
            result.anomalies.append(f"High entropy ({result.entropy:.2f}) - possible DGA domain")

        # Check domain length
        if len(domain) > 50:
            result.anomalies.append("Unusually long domain name")

        # Check for excessive subdomains
        if subdomain_count > 3:
            result.anomalies.append(f"Many subdomains ({subdomain_count})")

        # DNS resolution
        try:
            ips = socket.getaddrinfo(domain, None)
            result.resolved_ips = list(set([ip[4][0] for ip in ips]))
            logger.debug(f"Resolved IPs: {result.resolved_ips}")
        except socket.gaierror:
            logger.debug(f"Failed to resolve domain: {domain}")
            result.anomalies.append("Domain does not resolve")

        return result

    def analyze_url(self, url: str) -> URLAnalysisResult:
        """Analyze a URL.

        Args:
            url: URL to analyze

        Returns:
            URLAnalysisResult with findings
        """
        logger.debug(f"Analyzing URL: {url}")

        # Parse URL
        parsed = urlparse(url)

        result = URLAnalysisResult(
            url=url,
            scheme=parsed.scheme or 'http',
            domain=parsed.netloc or '',
            path=parsed.path or '/',
            port=parsed.port,
        )

        # Extract query parameters
        if parsed.query:
            result.query_params = parsed.query.split('&')

        # Check if URL shortener
        if result.domain in self.URL_SHORTENERS:
            result.is_shortened = True
            result.anomalies.append(f"URL shortener: {result.domain}")

        # Check if using IP address instead of domain
        if self._is_ip_address(result.domain):
            result.uses_ip = True
            result.anomalies.append("URL uses IP address instead of domain")

        # Extract TLD from domain
        tld_parts = result.domain.split('.')
        if tld_parts:
            tld = tld_parts[-1]
            if tld in self.SUSPICIOUS_TLDS:
                result.has_suspicious_tld = True
                result.suspicious_tld = tld
                result.anomalies.append(f"Suspicious TLD: .{tld}")

        # Check for non-standard ports
        if result.port and result.port not in [80, 443, 8080, 8443]:
            result.uses_non_standard_port = True
            result.anomalies.append(f"Non-standard port: {result.port}")

        # Check path for suspicious patterns
        path_lower = result.path.lower()
        for pattern in self.SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, path_lower):
                result.has_suspicious_path = True
                result.anomalies.append(f"Suspicious path pattern: {pattern}")
                break

        # Check parameters for suspicious keywords
        for param in result.query_params:
            param_lower = param.lower()
            for susp_param in self.SUSPICIOUS_PARAMS:
                if susp_param in param_lower:
                    result.has_suspicious_params = True
                    result.anomalies.append(f"Suspicious parameter: {susp_param}")
                    break

        # Check for obfuscation
        if any(char in url for char in ['%', '@', '..', '//']):
            if url.count('%') > 5:  # Multiple URL encoding
                result.is_obfuscated = True
                result.anomalies.append("URL appears obfuscated (multiple encoding)")

        # Analyze the domain component
        if result.domain and not result.uses_ip:
            result.domain_analysis = self.analyze_domain(result.domain)

        return result

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is in private range.

        Args:
            ip_address: IP address to check

        Returns:
            True if private
        """
        try:
            ip_int = self._ip_to_int(ip_address)
            for start, end in self.PRIVATE_RANGES:
                if self._ip_to_int(start) <= ip_int <= self._ip_to_int(end):
                    return True
        except:
            pass
        return False

    def _is_reserved_ip(self, ip_address: str) -> bool:
        """Check if IP is reserved.

        Args:
            ip_address: IP address to check

        Returns:
            True if reserved
        """
        # Simplified check for common reserved ranges
        return ip_address.startswith(('0.', '224.', '240.', '255.'))

    def _ip_to_int(self, ip_address: str) -> int:
        """Convert IP address to integer.

        Args:
            ip_address: IP address string

        Returns:
            Integer representation
        """
        parts = ip_address.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
               (int(parts[2]) << 8) + int(parts[3])

    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address.

        Args:
            text: Text to check

        Returns:
            True if IP address
        """
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(pattern, text))

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text.

        Args:
            text: Text to analyze

        Returns:
            Entropy value
        """
        import math
        from collections import Counter

        if not text:
            return 0.0

        # Calculate frequency of each character
        counts = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy
