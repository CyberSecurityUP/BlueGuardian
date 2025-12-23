"""Hallucination guard system for validating AI responses.

This module implements sophisticated validation to detect and prevent AI hallucinations
by cross-referencing AI claims against actual tool outputs and consensus results.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from loguru import logger

from src.ai_providers.consensus import ConsensusResult


@dataclass
class ValidationResult:
    """Result of hallucination validation."""

    is_valid: bool
    confidence: float
    validated_claims: List[str] = field(default_factory=list)
    unvalidated_claims: List[str] = field(default_factory=list)
    contradictions: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class HallucinationGuard:
    """Guards against AI hallucinations by validating claims against evidence.

    This class implements multiple validation strategies:
    1. Cross-reference AI claims with tool outputs
    2. Check consensus between multiple models
    3. Detect unsupported assertions
    4. Flag contradictions between AI and evidence
    """

    def __init__(self, min_confidence_threshold: float = 0.6):
        """Initialize hallucination guard.

        Args:
            min_confidence_threshold: Minimum confidence to consider valid (0.0-1.0)
        """
        self.min_confidence = min_confidence_threshold
        logger.info(f"Initialized hallucination guard (threshold: {min_confidence_threshold})")

    def validate(
        self,
        consensus_result: ConsensusResult,
        tool_outputs: Dict[str, Any],
        expected_evidence_types: Optional[List[str]] = None,
    ) -> ValidationResult:
        """Validate AI consensus result against tool outputs.

        Args:
            consensus_result: Result from consensus engine
            tool_outputs: Actual outputs from analysis tools
            expected_evidence_types: Expected types of evidence (e.g., ['hashes', 'imports'])

        Returns:
            ValidationResult with validation details
        """
        logger.debug("Validating AI response for hallucinations")

        # Extract claims from AI responses
        claims = self._extract_claims(consensus_result.merged_response)

        # Validate each claim against tool outputs
        validated = []
        unvalidated = []
        contradictions = []

        for claim in claims:
            validation_status = self._validate_claim(claim, tool_outputs)

            if validation_status == "validated":
                validated.append(claim)
            elif validation_status == "contradiction":
                contradictions.append({
                    "claim": claim,
                    "evidence": "Contradicts tool output",
                })
                unvalidated.append(claim)
            else:
                unvalidated.append(claim)

        # Check consensus confidence
        consensus_confidence = consensus_result.confidence_score

        # Calculate overall validation confidence
        total_claims = len(claims)
        if total_claims == 0:
            validation_confidence = 0.0
        else:
            validated_ratio = len(validated) / total_claims
            contradiction_penalty = len(contradictions) * 0.2
            validation_confidence = max(
                0.0,
                min(1.0, validated_ratio * consensus_confidence - contradiction_penalty)
            )

        # Generate warnings
        warnings = []

        if len(unvalidated) > len(validated):
            warnings.append(
                f"More unvalidated claims ({len(unvalidated)}) than validated ({len(validated)})"
            )

        if contradictions:
            warnings.append(f"Found {len(contradictions)} contradictions with tool evidence")

        if consensus_confidence < self.min_confidence:
            warnings.append(
                f"Consensus confidence ({consensus_confidence:.0%}) below threshold "
                f"({self.min_confidence:.0%})"
            )

        if len(consensus_result.disagreements) > 0:
            warnings.append(
                f"Models disagreed on {len(consensus_result.disagreements)} points"
            )

        # Check for expected evidence types
        if expected_evidence_types:
            missing = self._check_expected_evidence(tool_outputs, expected_evidence_types)
            if missing:
                warnings.append(f"Missing expected evidence types: {', '.join(missing)}")

        is_valid = (
            validation_confidence >= self.min_confidence
            and len(contradictions) == 0
        )

        return ValidationResult(
            is_valid=is_valid,
            confidence=validation_confidence,
            validated_claims=validated,
            unvalidated_claims=unvalidated,
            contradictions=contradictions,
            warnings=warnings,
            metadata={
                "consensus_confidence": consensus_confidence,
                "total_claims": total_claims,
                "validated_count": len(validated),
                "unvalidated_count": len(unvalidated),
                "contradiction_count": len(contradictions),
                "model_disagreements": len(consensus_result.disagreements),
            },
        )

    def _extract_claims(self, response: str) -> List[str]:
        """Extract individual claims from AI response.

        Args:
            response: AI response text

        Returns:
            List of claims
        """
        # Split into sentences
        sentences = re.split(r'[.!?]+', response)
        claims = []

        for sentence in sentences:
            sentence = sentence.strip()

            # Skip very short sentences
            if len(sentence.split()) < 4:
                continue

            # Skip questions
            if '?' in sentence:
                continue

            # Skip meta-statements
            skip_patterns = [
                'based on',
                'according to',
                'i cannot',
                'i don\'t know',
                'it appears',
                'it seems',
                'possibly',
                'maybe',
            ]

            if any(pattern in sentence.lower() for pattern in skip_patterns):
                continue

            claims.append(sentence)

        return claims

    def _validate_claim(self, claim: str, tool_outputs: Dict[str, Any]) -> str:
        """Validate a single claim against tool outputs.

        Args:
            claim: Claim to validate
            tool_outputs: Tool outputs to check against

        Returns:
            "validated", "unvalidated", or "contradiction"
        """
        claim_lower = claim.lower()

        # Extract factual elements from claim
        facts = self._extract_facts(claim)

        if not facts:
            return "unvalidated"

        # Check each fact against tool outputs
        validated_count = 0
        contradiction_found = False

        for fact_type, fact_value in facts.items():
            # Check if this fact appears in tool outputs
            if self._fact_in_outputs(fact_type, fact_value, tool_outputs):
                validated_count += 1
            elif self._fact_contradicts_outputs(fact_type, fact_value, tool_outputs):
                contradiction_found = True
                break

        if contradiction_found:
            return "contradiction"
        elif validated_count > 0:
            return "validated"
        else:
            return "unvalidated"

    def _extract_facts(self, claim: str) -> Dict[str, Any]:
        """Extract verifiable facts from a claim.

        Args:
            claim: Claim text

        Returns:
            Dictionary of fact types to values
        """
        facts = {}

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, claim)
        if ips:
            facts['ip'] = ips

        # Domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(domain_pattern, claim, re.IGNORECASE)
        if domains:
            facts['domain'] = domains

        # Hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        hashes = re.findall(hash_pattern, claim)
        if hashes:
            facts['hash'] = hashes

        # Registry keys
        if 'HKEY_' in claim or 'HKLM' in claim or 'HKCU' in claim:
            facts['registry'] = True

        # File paths
        if ':\\' in claim or '.exe' in claim.lower() or '.dll' in claim.lower():
            facts['file_path'] = True

        # Function names (imports)
        func_pattern = r'\b([A-Z][a-zA-Z0-9]+(?:Ex|A|W)?)\b'
        funcs = re.findall(func_pattern, claim)
        if funcs:
            facts['functions'] = funcs

        return facts

    def _fact_in_outputs(self, fact_type: str, fact_value: Any, tool_outputs: Dict[str, Any]) -> bool:
        """Check if a fact appears in tool outputs.

        Args:
            fact_type: Type of fact
            fact_value: Fact value
            tool_outputs: Tool outputs

        Returns:
            True if fact is found in outputs
        """
        # Convert tool outputs to string for searching
        outputs_str = str(tool_outputs).lower()

        if fact_type == 'ip':
            for ip in fact_value:
                if ip in outputs_str:
                    return True

        elif fact_type == 'domain':
            for domain in fact_value:
                if domain.lower() in outputs_str:
                    return True

        elif fact_type == 'hash':
            for h in fact_value:
                if h.lower() in outputs_str:
                    return True

        elif fact_type == 'registry':
            if 'registry' in outputs_str or 'hkey' in outputs_str:
                return True

        elif fact_type == 'file_path':
            if ':\\' in outputs_str or '.exe' in outputs_str or '.dll' in outputs_str:
                return True

        elif fact_type == 'functions':
            # Check if imported functions match
            if 'imports' in tool_outputs:
                imports_str = str(tool_outputs['imports']).lower()
                for func in fact_value:
                    if func.lower() in imports_str:
                        return True

        return False

    def _fact_contradicts_outputs(
        self, fact_type: str, fact_value: Any, tool_outputs: Dict[str, Any]
    ) -> bool:
        """Check if a fact contradicts tool outputs.

        Args:
            fact_type: Type of fact
            fact_value: Fact value
            tool_outputs: Tool outputs

        Returns:
            True if fact contradicts evidence
        """
        # Check for explicit contradictions
        # For example, if AI claims "no network activity" but tools show network APIs

        outputs_str = str(tool_outputs).lower()

        # Example: AI claims no packing, but tool detected packing
        if 'not packed' in str(fact_value).lower():
            if tool_outputs.get('is_packed', False):
                return True

        # Example: AI claims no suspicious imports, but tools found them
        if 'no suspicious' in str(fact_value).lower():
            if tool_outputs.get('suspicious_imports'):
                return True

        return False

    def _check_expected_evidence(
        self, tool_outputs: Dict[str, Any], expected_types: List[str]
    ) -> List[str]:
        """Check if all expected evidence types are present.

        Args:
            tool_outputs: Tool outputs
            expected_types: Expected evidence types

        Returns:
            List of missing evidence types
        """
        missing = []

        for evidence_type in expected_types:
            if evidence_type not in tool_outputs or not tool_outputs[evidence_type]:
                missing.append(evidence_type)

        return missing

    def flag_high_confidence_disagreements(self, consensus_result: ConsensusResult) -> List[str]:
        """Flag disagreements that occurred despite high individual confidence.

        Args:
            consensus_result: Consensus result

        Returns:
            List of flagged disagreements
        """
        flags = []

        for disagreement in consensus_result.disagreements:
            # If models with high confidence disagree, that's suspicious
            flags.append(
                f"High-confidence disagreement in {disagreement.get('category', 'unknown')} "
                f"category: {disagreement.get('claim1', {}).get('model')} vs "
                f"{disagreement.get('claim2', {}).get('model')}"
            )

        return flags
