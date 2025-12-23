"""MITRE ATT&CK framework integration.

This module provides integration with the MITRE ATT&CK framework for
mapping malware and attack behaviors to techniques, tactics, and procedures (TTPs).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from loguru import logger


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique information."""

    technique_id: str
    name: str
    description: str
    tactic: str
    detection: Optional[str] = None
    mitigation: Optional[str] = None
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)


class MITREATTACKMapper:
    """MITRE ATT&CK framework mapper.

    This class provides mapping of observed behaviors to MITRE ATT&CK
    techniques and provides context about techniques, tactics, and procedures.
    """

    # Common technique mappings for quick reference
    # In production, this would be loaded from MITRE's STIX data
    COMMON_TECHNIQUES = {
        # Initial Access
        'T1566.001': MITRETechnique(
            technique_id='T1566.001',
            name='Phishing: Spearphishing Attachment',
            description='Adversaries send spearphishing emails with malicious attachments',
            tactic='Initial Access',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Email Gateway', 'File monitoring'],
        ),
        'T1566.002': MITRETechnique(
            technique_id='T1566.002',
            name='Phishing: Spearphishing Link',
            description='Adversaries send spearphishing emails with malicious links',
            tactic='Initial Access',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Email Gateway', 'Web Proxy'],
        ),

        # Execution
        'T1204.002': MITRETechnique(
            technique_id='T1204.002',
            name='User Execution: Malicious File',
            description='User executes malicious file',
            tactic='Execution',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Process monitoring', 'File monitoring'],
        ),
        'T1059.001': MITRETechnique(
            technique_id='T1059.001',
            name='Command and Scripting Interpreter: PowerShell',
            description='Execution via PowerShell',
            tactic='Execution',
            platforms=['Windows'],
            data_sources=['PowerShell logs', 'Process monitoring'],
        ),
        'T1059.003': MITRETechnique(
            technique_id='T1059.003',
            name='Command and Scripting Interpreter: Windows Command Shell',
            description='Execution via CMD',
            tactic='Execution',
            platforms=['Windows'],
            data_sources=['Process monitoring', 'Command-line logging'],
        ),
        'T1059.005': MITRETechnique(
            technique_id='T1059.005',
            name='Command and Scripting Interpreter: Visual Basic',
            description='Execution via VBA macros',
            tactic='Execution',
            platforms=['Windows', 'macOS'],
            data_sources=['Process monitoring', 'Script logging'],
        ),
        'T1059.007': MITRETechnique(
            technique_id='T1059.007',
            name='Command and Scripting Interpreter: JavaScript',
            description='Execution via JavaScript',
            tactic='Execution',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Script logging', 'Process monitoring'],
        ),

        # Persistence
        'T1547.001': MITRETechnique(
            technique_id='T1547.001',
            name='Boot or Logon Autostart Execution: Registry Run Keys',
            description='Persistence via registry run keys',
            tactic='Persistence',
            platforms=['Windows'],
            data_sources=['Windows Registry', 'Process monitoring'],
        ),
        'T1053.005': MITRETechnique(
            technique_id='T1053.005',
            name='Scheduled Task/Job: Scheduled Task',
            description='Persistence via scheduled tasks',
            tactic='Persistence',
            platforms=['Windows'],
            data_sources=['Process monitoring', 'Windows Event Logs'],
        ),

        # Defense Evasion
        'T1027': MITRETechnique(
            technique_id='T1027',
            name='Obfuscated Files or Information',
            description='Obfuscation to hide malicious code',
            tactic='Defense Evasion',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['File monitoring', 'Process monitoring'],
        ),
        'T1140': MITRETechnique(
            technique_id='T1140',
            name='Deobfuscate/Decode Files or Information',
            description='Deobfuscation at runtime',
            tactic='Defense Evasion',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Process monitoring', 'File monitoring'],
        ),
        'T1055': MITRETechnique(
            technique_id='T1055',
            name='Process Injection',
            description='Injection into other processes',
            tactic='Defense Evasion',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['API monitoring', 'Process monitoring'],
        ),
        'T1221': MITRETechnique(
            technique_id='T1221',
            name='Template Injection',
            description='Malicious template injection in documents',
            tactic='Defense Evasion',
            platforms=['Windows', 'macOS'],
            data_sources=['File monitoring', 'Network monitoring'],
        ),

        # Discovery
        'T1082': MITRETechnique(
            technique_id='T1082',
            name='System Information Discovery',
            description='Gathering system information',
            tactic='Discovery',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Process monitoring', 'Command-line logging'],
        ),
        'T1083': MITRETechnique(
            technique_id='T1083',
            name='File and Directory Discovery',
            description='Enumerating files and directories',
            tactic='Discovery',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['File monitoring', 'Process monitoring'],
        ),

        # Collection
        'T1056.001': MITRETechnique(
            technique_id='T1056.001',
            name='Input Capture: Keylogging',
            description='Capturing keystrokes',
            tactic='Collection',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['API monitoring', 'Kernel drivers'],
        ),
        'T1113': MITRETechnique(
            technique_id='T1113',
            name='Screen Capture',
            description='Taking screenshots',
            tactic='Collection',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['API monitoring', 'Process monitoring'],
        ),

        # Command and Control
        'T1071.001': MITRETechnique(
            technique_id='T1071.001',
            name='Application Layer Protocol: Web Protocols',
            description='C2 via HTTP/HTTPS',
            tactic='Command and Control',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Network monitoring', 'Packet capture'],
        ),
        'T1105': MITRETechnique(
            technique_id='T1105',
            name='Ingress Tool Transfer',
            description='Downloading additional tools',
            tactic='Command and Control',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Network monitoring', 'File monitoring'],
        ),
        'T1573': MITRETechnique(
            technique_id='T1573',
            name='Encrypted Channel',
            description='Encrypted C2 communications',
            tactic='Command and Control',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Network monitoring', 'SSL/TLS inspection'],
        ),

        # Exfiltration
        'T1041': MITRETechnique(
            technique_id='T1041',
            name='Exfiltration Over C2 Channel',
            description='Data exfiltration via C2',
            tactic='Exfiltration',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Network monitoring', 'Packet capture'],
        ),
        'T1048': MITRETechnique(
            technique_id='T1048',
            name='Exfiltration Over Alternative Protocol',
            description='Exfiltration via alternative protocols',
            tactic='Exfiltration',
            platforms=['Windows', 'macOS', 'Linux'],
            data_sources=['Network monitoring', 'Packet capture'],
        ),
    }

    def __init__(self):
        """Initialize MITRE ATT&CK mapper."""
        logger.info("Initialized MITRE ATT&CK mapper")

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique information by ID.

        Args:
            technique_id: MITRE technique ID (e.g., 'T1566.001')

        Returns:
            MITRETechnique or None if not found
        """
        return self.COMMON_TECHNIQUES.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> List[MITRETechnique]:
        """Get all techniques for a given tactic.

        Args:
            tactic: Tactic name (e.g., 'Execution')

        Returns:
            List of techniques
        """
        return [
            tech for tech in self.COMMON_TECHNIQUES.values()
            if tech.tactic.lower() == tactic.lower()
        ]

    def map_behaviors_to_techniques(
        self, behaviors: List[str]
    ) -> List[MITRETechnique]:
        """Map observed behaviors to MITRE techniques.

        Args:
            behaviors: List of observed behaviors

        Returns:
            List of matching techniques
        """
        techniques = []

        behavior_mappings = {
            'macro': ['T1059.005'],
            'vba': ['T1059.005'],
            'powershell': ['T1059.001'],
            'cmd': ['T1059.003'],
            'javascript': ['T1059.007'],
            'phishing': ['T1566.001', 'T1566.002'],
            'attachment': ['T1566.001'],
            'link': ['T1566.002'],
            'obfuscation': ['T1027'],
            'injection': ['T1055'],
            'registry': ['T1547.001'],
            'scheduled task': ['T1053.005'],
            'keylog': ['T1056.001'],
            'screenshot': ['T1113'],
            'c2': ['T1071.001', 'T1573'],
            'download': ['T1105'],
        }

        for behavior in behaviors:
            behavior_lower = behavior.lower()
            for keyword, tech_ids in behavior_mappings.items():
                if keyword in behavior_lower:
                    for tech_id in tech_ids:
                        tech = self.get_technique(tech_id)
                        if tech and tech not in techniques:
                            techniques.append(tech)

        return techniques

    def generate_attack_matrix(
        self, technique_ids: List[str]
    ) -> Dict[str, List[MITRETechnique]]:
        """Generate ATT&CK matrix organized by tactics.

        Args:
            technique_ids: List of technique IDs

        Returns:
            Dictionary mapping tactics to techniques
        """
        matrix: Dict[str, List[MITRETechnique]] = {}

        for tech_id in technique_ids:
            tech = self.get_technique(tech_id)
            if tech:
                if tech.tactic not in matrix:
                    matrix[tech.tactic] = []
                matrix[tech.tactic].append(tech)

        return matrix

    def format_for_navigator(
        self, technique_ids: List[str]
    ) -> Dict[str, Any]:
        """Format techniques for ATT&CK Navigator.

        Args:
            technique_ids: List of technique IDs

        Returns:
            Navigator layer JSON
        """
        # Simplified Navigator format
        # Full implementation would match ATT&CK Navigator schema
        layer = {
            "name": "BlueGuardian AI Analysis",
            "versions": {
                "attack": "13",
                "navigator": "4.8",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": "Techniques identified by BlueGuardian AI",
            "techniques": []
        }

        for tech_id in technique_ids:
            tech = self.get_technique(tech_id)
            if tech:
                layer["techniques"].append({
                    "techniqueID": tech.technique_id,
                    "tactic": tech.tactic.lower().replace(" ", "-"),
                    "color": "#ff0000",
                    "comment": tech.name,
                    "enabled": True,
                    "score": 1,
                })

        return layer

    def get_detection_guidance(
        self, technique_id: str
    ) -> Optional[str]:
        """Get detection guidance for a technique.

        Args:
            technique_id: MITRE technique ID

        Returns:
            Detection guidance or None
        """
        tech = self.get_technique(technique_id)
        if tech and tech.data_sources:
            return f"Monitor: {', '.join(tech.data_sources)}"
        return None

    def get_mitigation_guidance(
        self, technique_id: str
    ) -> Optional[str]:
        """Get mitigation guidance for a technique.

        Args:
            technique_id: MITRE technique ID

        Returns:
            Mitigation guidance or None
        """
        tech = self.get_technique(technique_id)
        return tech.mitigation if tech else None
