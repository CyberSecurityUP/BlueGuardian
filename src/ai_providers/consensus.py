"""Multi-model consensus system for hallucination detection.

This module implements a sophisticated consensus mechanism that queries
multiple AI models and compares their responses to detect hallucinations
and ensure reliable security analysis.
"""

import asyncio
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set

from loguru import logger

from .base import AIResponse, BaseAIProvider, Message, Tool


@dataclass
class Claim:
    """Represents a specific claim or assertion made by an AI model."""

    text: str
    model: str
    confidence: float = 1.0
    category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConsensusResult:
    """Results from consensus analysis."""

    merged_response: str
    confidence_score: float
    all_responses: List[AIResponse]
    agreements: List[Claim]
    disagreements: List[Dict[str, Any]]
    unique_claims: List[Claim]
    provider_scores: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConsensusEngine:
    """Engine for multi-model consensus and hallucination detection.

    This class orchestrates multiple AI providers, compares their outputs,
    and produces a high-confidence merged result with disagreement tracking.
    """

    def __init__(
        self,
        providers: List[BaseAIProvider],
        min_agreement_threshold: float = 0.7,
        similarity_threshold: float = 0.8,
    ):
        """Initialize consensus engine.

        Args:
            providers: List of AI providers to use for consensus
            min_agreement_threshold: Minimum agreement ratio (0.0-1.0)
            similarity_threshold: Threshold for claim similarity (0.0-1.0)
        """
        if len(providers) < 2:
            raise ValueError("Consensus requires at least 2 AI providers")

        self.providers = providers
        self.min_agreement_threshold = min_agreement_threshold
        self.similarity_threshold = similarity_threshold

        logger.info(
            f"Initialized consensus engine with {len(providers)} providers: "
            f"{[p.provider_name.value for p in providers]}"
        )

    async def generate_with_consensus(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ConsensusResult:
        """Generate responses from multiple models and compute consensus.

        Args:
            messages: Conversation messages
            tools: Optional tools for function calling
            temperature: Temperature override
            max_tokens: Max tokens override
            **kwargs: Additional provider-specific parameters

        Returns:
            ConsensusResult with merged response and analysis
        """
        logger.info(f"Querying {len(self.providers)} models for consensus")

        # Query all providers in parallel
        tasks = [
            provider.generate(
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )
            for provider in self.providers
        ]

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out errors and extract valid responses
        valid_responses: List[AIResponse] = []
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.warning(
                    f"Provider {self.providers[i].provider_name.value} failed: {response}"
                )
            else:
                valid_responses.append(response)

        if len(valid_responses) < 2:
            logger.warning(
                f"Only {len(valid_responses)} valid responses, "
                "consensus may be unreliable"
            )

        # Extract claims from each response
        all_claims = self._extract_claims(valid_responses)

        # Find agreements and disagreements
        agreements = self._find_agreements(all_claims)
        disagreements = self._find_disagreements(all_claims)
        unique_claims = self._find_unique_claims(all_claims)

        # Calculate confidence scores
        confidence_score = self._calculate_consensus_confidence(
            agreements, disagreements, len(valid_responses)
        )

        # Calculate per-provider scores
        provider_scores = self._calculate_provider_scores(valid_responses, agreements)

        # Merge responses with weighted voting
        merged_response = self._merge_responses(valid_responses, provider_scores)

        logger.info(
            f"Consensus complete: {len(agreements)} agreements, "
            f"{len(disagreements)} disagreements, "
            f"confidence: {confidence_score:.2%}"
        )

        return ConsensusResult(
            merged_response=merged_response,
            confidence_score=confidence_score,
            all_responses=valid_responses,
            agreements=agreements,
            disagreements=disagreements,
            unique_claims=unique_claims,
            provider_scores=provider_scores,
            metadata={
                "total_providers": len(self.providers),
                "successful_providers": len(valid_responses),
                "failed_providers": len(self.providers) - len(valid_responses),
            },
        )

    def _extract_claims(self, responses: List[AIResponse]) -> List[Claim]:
        """Extract individual claims from responses.

        Args:
            responses: List of AI responses

        Returns:
            List of extracted claims
        """
        claims = []

        for response in responses:
            if not response.content:
                continue

            # Split content into sentences (basic claim extraction)
            sentences = self._split_into_sentences(response.content)

            for sentence in sentences:
                # Skip very short sentences
                if len(sentence.split()) < 3:
                    continue

                # Categorize claim type
                category = self._categorize_claim(sentence)

                claim = Claim(
                    text=sentence.strip(),
                    model=response.metrics.model if response.metrics else "unknown",
                    category=category,
                    metadata={
                        "response_confidence": response.stop_reason,
                    },
                )
                claims.append(claim)

        logger.debug(f"Extracted {len(claims)} claims from {len(responses)} responses")
        return claims

    def _split_into_sentences(self, text: str) -> List[str]:
        """Split text into sentences.

        Args:
            text: Input text

        Returns:
            List of sentences
        """
        # Simple sentence splitting (can be enhanced with NLP)
        sentences = re.split(r'[.!?]+', text)
        return [s.strip() for s in sentences if s.strip()]

    def _categorize_claim(self, sentence: str) -> str:
        """Categorize a claim by type.

        Args:
            sentence: Claim text

        Returns:
            Category string
        """
        sentence_lower = sentence.lower()

        # Security-specific categories
        if any(word in sentence_lower for word in ["malicious", "malware", "threat"]):
            return "threat_assessment"
        elif any(word in sentence_lower for word in ["ioc", "indicator", "c2", "c&c"]):
            return "ioc_identification"
        elif any(word in sentence_lower for word in ["technique", "ttp", "tactic"]):
            return "technique_analysis"
        elif any(word in sentence_lower for word in ["hash", "md5", "sha"]):
            return "hash_identification"
        elif any(word in sentence_lower for word in ["file", "executable", "binary"]):
            return "file_analysis"
        else:
            return "general"

    def _find_agreements(self, claims: List[Claim]) -> List[Claim]:
        """Find claims that multiple models agree on.

        Args:
            claims: List of all claims

        Returns:
            List of agreed-upon claims
        """
        agreements = []
        processed: Set[int] = set()

        for i, claim1 in enumerate(claims):
            if i in processed:
                continue

            similar_claims = [claim1]

            for j, claim2 in enumerate(claims[i + 1 :], start=i + 1):
                if j in processed:
                    continue

                similarity = self._calculate_similarity(claim1.text, claim2.text)

                if similarity >= self.similarity_threshold:
                    similar_claims.append(claim2)
                    processed.add(j)

            # If multiple models made similar claims, it's an agreement
            if len(similar_claims) >= 2:
                # Create merged claim with higher confidence
                merged_claim = Claim(
                    text=claim1.text,  # Use first claim's text
                    model=f"consensus ({len(similar_claims)} models)",
                    confidence=len(similar_claims) / len(self.providers),
                    category=claim1.category,
                    metadata={
                        "supporting_models": [c.model for c in similar_claims],
                        "agreement_count": len(similar_claims),
                    },
                )
                agreements.append(merged_claim)
                processed.add(i)

        return agreements

    def _find_disagreements(self, claims: List[Claim]) -> List[Dict[str, Any]]:
        """Find claims where models disagree.

        Args:
            claims: List of all claims

        Returns:
            List of disagreement records
        """
        disagreements = []

        # Group claims by category
        by_category: Dict[str, List[Claim]] = {}
        for claim in claims:
            category = claim.category or "general"
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(claim)

        # Find contradictions within each category
        for category, category_claims in by_category.items():
            # Look for opposing claims (basic contradiction detection)
            for i, claim1 in enumerate(category_claims):
                for claim2 in category_claims[i + 1 :]:
                    if self._are_contradictory(claim1.text, claim2.text):
                        disagreements.append(
                            {
                                "category": category,
                                "claim1": {"text": claim1.text, "model": claim1.model},
                                "claim2": {"text": claim2.text, "model": claim2.model},
                                "type": "contradiction",
                            }
                        )

        return disagreements

    def _find_unique_claims(self, claims: List[Claim]) -> List[Claim]:
        """Find claims made by only one model.

        Args:
            claims: List of all claims

        Returns:
            List of unique claims
        """
        unique = []
        processed: Set[int] = set()

        for i, claim1 in enumerate(claims):
            if i in processed:
                continue

            is_unique = True

            for j, claim2 in enumerate(claims):
                if i == j:
                    continue

                similarity = self._calculate_similarity(claim1.text, claim2.text)

                if similarity >= self.similarity_threshold:
                    is_unique = False
                    break

            if is_unique:
                unique.append(claim1)
                processed.add(i)

        return unique

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate semantic similarity between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            Similarity score (0.0-1.0)
        """
        # Use sequence matcher for basic similarity
        # Can be enhanced with embeddings for semantic similarity
        return SequenceMatcher(None, text1.lower(), text2.lower()).ratio()

    def _are_contradictory(self, text1: str, text2: str) -> bool:
        """Check if two claims contradict each other.

        Args:
            text1: First claim
            text2: Second claim

        Returns:
            True if contradictory
        """
        # Basic contradiction detection using negation words
        negation_words = ["not", "no", "never", "isn't", "doesn't", "won't", "can't"]

        text1_lower = text1.lower()
        text2_lower = text2.lower()

        # Check if one has negation and the other doesn't
        has_negation1 = any(word in text1_lower for word in negation_words)
        has_negation2 = any(word in text2_lower for word in negation_words)

        if has_negation1 != has_negation2:
            # They have opposite polarity, check if similar topic
            base_similarity = self._calculate_similarity(
                re.sub(r'\b(' + '|'.join(negation_words) + r')\b', '', text1_lower),
                re.sub(r'\b(' + '|'.join(negation_words) + r')\b', '', text2_lower),
            )
            return base_similarity >= 0.7

        return False

    def _calculate_consensus_confidence(
        self, agreements: List[Claim], disagreements: List[Dict[str, Any]], total_models: int
    ) -> float:
        """Calculate overall consensus confidence score.

        Args:
            agreements: List of agreed claims
            disagreements: List of disagreements
            total_models: Total number of models

        Returns:
            Confidence score (0.0-1.0)
        """
        if not agreements:
            return 0.0

        # Base score from agreement ratio
        avg_agreement = sum(c.confidence for c in agreements) / len(agreements)

        # Penalty for disagreements
        disagreement_penalty = len(disagreements) * 0.05

        # Bonus for having all models participate
        participation_bonus = 0.1 if total_models >= 3 else 0.0

        confidence = max(0.0, min(1.0, avg_agreement - disagreement_penalty + participation_bonus))

        return confidence

    def _calculate_provider_scores(
        self, responses: List[AIResponse], agreements: List[Claim]
    ) -> Dict[str, float]:
        """Calculate reliability scores for each provider.

        Args:
            responses: List of responses
            agreements: List of agreed claims

        Returns:
            Dictionary mapping provider to score
        """
        scores: Dict[str, float] = {}

        for response in responses:
            if not response.metrics:
                continue

            model = response.metrics.model
            score = 0.5  # Base score

            # Bonus for claims that were agreed upon
            for agreement in agreements:
                if model in agreement.metadata.get("supporting_models", []):
                    score += 0.1

            scores[model] = min(1.0, score)

        return scores

    def _merge_responses(
        self, responses: List[AIResponse], provider_scores: Dict[str, float]
    ) -> str:
        """Merge multiple responses with weighted voting.

        Args:
            responses: List of responses
            provider_scores: Reliability scores per provider

        Returns:
            Merged response text
        """
        if not responses:
            return ""

        # For now, use simple approach: select response from highest-scoring provider
        # Can be enhanced with actual text merging
        best_response = max(
            responses,
            key=lambda r: provider_scores.get(r.metrics.model if r.metrics else "", 0.0),
        )

        return best_response.content
