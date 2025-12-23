"""AlienVault OTX (Open Threat Exchange) integration.

This module provides integration with AlienVault OTX for threat intelligence
including IOC enrichment, pulse subscription, and threat context.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
from loguru import logger


@dataclass
class OTXIndicator:
    """OTX indicator information."""

    indicator: str
    type: str  # 'IPv4', 'domain', 'hostname', 'URL', 'FileHash-SHA256', etc.
    pulse_count: int = 0
    related_pulses: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    adversaries: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    reputation: int = 0  # 0-100, lower is more malicious
    geo_country: Optional[str] = None
    asn: Optional[str] = None


@dataclass
class OTXPulse:
    """OTX Pulse (threat intelligence report)."""

    id: str
    name: str
    description: str
    author_name: str
    created: str
    modified: str
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    attack_ids: List[str] = field(default_factory=list)  # ATT&CK IDs
    adversary: Optional[str] = None
    targeted_countries: List[str] = field(default_factory=list)
    industries: List[str] = field(default_factory=list)
    indicator_count: int = 0


class AlienVaultOTXClient:
    """Client for AlienVault OTX API.

    OTX provides community-driven threat intelligence including
    IOC enrichment, malware analysis, and threat actor tracking.
    """

    API_BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        """Initialize OTX client.

        Args:
            api_key: OTX API key
        """
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-OTX-API-KEY': api_key,
            'User-Agent': 'BlueGuardian AI',
        })

        logger.info("Initialized AlienVaultOTXClient")

    async def get_indicator_details(
        self, indicator: str, indicator_type: str
    ) -> Optional[OTXIndicator]:
        """Get detailed information about an indicator.

        Args:
            indicator: Indicator value (IP, domain, hash, etc.)
            indicator_type: Type of indicator ('IPv4', 'domain', 'file', etc.)

        Returns:
            OTXIndicator or None
        """
        # Map indicator types to OTX endpoints
        type_map = {
            'ip': 'IPv4',
            'ipv4': 'IPv4',
            'ipv6': 'IPv6',
            'domain': 'domain',
            'hostname': 'hostname',
            'url': 'url',
            'hash': 'file',
            'md5': 'file',
            'sha1': 'file',
            'sha256': 'file',
        }

        otx_type = type_map.get(indicator_type.lower(), indicator_type)

        try:
            # Get general info
            url = f"{self.API_BASE}/indicators/{otx_type}/{indicator}/general"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()

                result = OTXIndicator(
                    indicator=indicator,
                    type=otx_type,
                    pulse_count=data.get('pulse_info', {}).get('count', 0),
                    reputation=data.get('reputation', 0),
                )

                # Get pulses
                pulses = data.get('pulse_info', {}).get('pulses', [])
                for pulse in pulses[:10]:  # Limit to first 10
                    result.related_pulses.append(pulse.get('name', ''))

                    # Extract malware families
                    for family in pulse.get('malware_families', []):
                        if family.get('display_name') not in result.malware_families:
                            result.malware_families.append(family.get('display_name'))

                    # Extract tags
                    result.tags.extend(pulse.get('tags', []))

                    # Extract adversary
                    if pulse.get('adversary'):
                        if pulse['adversary'] not in result.adversaries:
                            result.adversaries.append(pulse['adversary'])

                # Get geo info for IPs
                if otx_type in ['IPv4', 'IPv6']:
                    geo_data = data.get('geo', {})
                    result.geo_country = geo_data.get('country_name')
                    result.asn = data.get('asn')

                # Deduplicate tags
                result.tags = list(set(result.tags))

                logger.debug(f"Retrieved OTX info for {indicator}: {result.pulse_count} pulses")
                return result

            elif response.status_code == 404:
                logger.debug(f"No OTX data found for {indicator}")
                return None
            else:
                logger.error(f"OTX query failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to query OTX: {e}")
            return None

    async def get_ip_reputation(self, ip_address: str) -> Optional[OTXIndicator]:
        """Get reputation for an IP address.

        Args:
            ip_address: IP address

        Returns:
            OTXIndicator or None
        """
        return await self.get_indicator_details(ip_address, 'IPv4')

    async def get_domain_reputation(self, domain: str) -> Optional[OTXIndicator]:
        """Get reputation for a domain.

        Args:
            domain: Domain name

        Returns:
            OTXIndicator or None
        """
        return await self.get_indicator_details(domain, 'domain')

    async def get_file_reputation(self, file_hash: str) -> Optional[OTXIndicator]:
        """Get reputation for a file hash.

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            OTXIndicator or None
        """
        return await self.get_indicator_details(file_hash, 'file')

    async def get_url_reputation(self, url: str) -> Optional[OTXIndicator]:
        """Get reputation for a URL.

        Args:
            url: URL

        Returns:
            OTXIndicator or None
        """
        return await self.get_indicator_details(url, 'url')

    async def get_pulse(self, pulse_id: str) -> Optional[OTXPulse]:
        """Get detailed information about a pulse.

        Args:
            pulse_id: Pulse ID

        Returns:
            OTXPulse or None
        """
        try:
            url = f"{self.API_BASE}/pulses/{pulse_id}"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()

                pulse = OTXPulse(
                    id=data.get('id', pulse_id),
                    name=data.get('name', ''),
                    description=data.get('description', ''),
                    author_name=data.get('author_name', ''),
                    created=data.get('created', ''),
                    modified=data.get('modified', ''),
                    tags=data.get('tags', []),
                    malware_families=[
                        f.get('display_name') for f in data.get('malware_families', [])
                    ],
                    attack_ids=[
                        a.get('id') for a in data.get('attack_ids', [])
                    ],
                    adversary=data.get('adversary'),
                    targeted_countries=data.get('targeted_countries', []),
                    industries=data.get('industries', []),
                    indicator_count=data.get('indicator_count', 0),
                )

                logger.debug(f"Retrieved OTX pulse: {pulse.name}")
                return pulse

            else:
                logger.error(f"OTX pulse query failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to get OTX pulse: {e}")
            return None

    async def search_pulses(
        self, query: str, limit: int = 10
    ) -> List[OTXPulse]:
        """Search for pulses by keyword.

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of pulses
        """
        try:
            url = f"{self.API_BASE}/search/pulses"
            params = {'q': query, 'limit': limit}
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])

                pulses = []
                for pulse_data in results:
                    pulse = OTXPulse(
                        id=pulse_data.get('id', ''),
                        name=pulse_data.get('name', ''),
                        description=pulse_data.get('description', ''),
                        author_name=pulse_data.get('author_name', ''),
                        created=pulse_data.get('created', ''),
                        modified=pulse_data.get('modified', ''),
                        tags=pulse_data.get('tags', []),
                        indicator_count=pulse_data.get('indicator_count', 0),
                    )
                    pulses.append(pulse)

                logger.debug(f"Found {len(pulses)} pulses for query: {query}")
                return pulses

            else:
                logger.error(f"OTX search failed: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Failed to search OTX: {e}")
            return []

    def format_indicator_for_ai(self, indicator: OTXIndicator) -> str:
        """Format indicator info for AI context.

        Args:
            indicator: OTX indicator

        Returns:
            Formatted string
        """
        lines = [
            f"ALIENVAULT OTX THREAT INTELLIGENCE:",
            f"Indicator: {indicator.indicator}",
            f"Type: {indicator.type}",
            f"Pulses: {indicator.pulse_count}",
        ]

        if indicator.reputation > 0:
            lines.append(f"Reputation: {indicator.reputation}/100")

        if indicator.malware_families:
            lines.append(f"Malware Families: {', '.join(indicator.malware_families)}")

        if indicator.adversaries:
            lines.append(f"Adversaries: {', '.join(indicator.adversaries)}")

        if indicator.tags:
            lines.append(f"Tags: {', '.join(indicator.tags[:10])}")

        if indicator.geo_country:
            lines.append(f"Country: {indicator.geo_country}")

        if indicator.asn:
            lines.append(f"ASN: {indicator.asn}")

        if indicator.related_pulses:
            lines.append(f"Related Pulses: {', '.join(indicator.related_pulses[:5])}")

        return '\n'.join(lines)

    async def close(self):
        """Close the HTTP session."""
        self.session.close()
