"""Base abstraction layer for AI providers.

This module defines the interface that all AI providers must implement,
ensuring consistent behavior across different models (Claude, GPT, Gemini, Ollama).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional, Union

from loguru import logger
from pydantic import BaseModel, Field


class AIProvider(str, Enum):
    """Supported AI providers."""

    CLAUDE = "claude"
    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"


class MessageRole(str, Enum):
    """Message roles in conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Message(BaseModel):
    """Represents a message in the conversation."""

    role: MessageRole
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


class Tool(BaseModel):
    """Represents a tool/function that can be called by the AI."""

    name: str
    description: str
    parameters: Dict[str, Any]


class ProviderConfig(BaseModel):
    """Configuration for an AI provider."""

    api_key: str
    model: str
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, gt=0)
    timeout: int = Field(default=60, gt=0)
    max_retries: int = Field(default=3, ge=0)
    base_url: Optional[str] = None


@dataclass
class GenerationMetrics:
    """Metrics for a generation request."""

    provider: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    cached: bool = False


@dataclass
class AIResponse:
    """Response from an AI provider."""

    content: str
    role: MessageRole = MessageRole.ASSISTANT
    tool_calls: Optional[List[Dict[str, Any]]] = None
    stop_reason: Optional[str] = None
    metrics: Optional[GenerationMetrics] = None
    raw_response: Optional[Dict[str, Any]] = None


class BaseAIProvider(ABC):
    """Abstract base class for all AI providers.

    This class defines the interface that all AI provider implementations must follow.
    It handles common functionality like rate limiting, retries, cost tracking, and caching.
    """

    def __init__(self, config: ProviderConfig) -> None:
        """Initialize the AI provider.

        Args:
            config: Provider configuration including API key, model, etc.
        """
        self.config = config
        self.provider_name: AIProvider
        self._total_cost = 0.0
        self._total_requests = 0
        self._cache: Dict[str, AIResponse] = {}

    @abstractmethod
    async def generate(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AIResponse:
        """Generate a response from the AI model.

        Args:
            messages: List of conversation messages
            tools: Optional list of tools the model can call
            temperature: Override default temperature
            max_tokens: Override default max tokens
            **kwargs: Additional provider-specific parameters

        Returns:
            AIResponse containing the model's response and metadata

        Raises:
            ProviderError: If the provider request fails
        """
        pass

    @abstractmethod
    async def stream(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream a response from the AI model.

        Args:
            messages: List of conversation messages
            tools: Optional list of tools the model can call
            temperature: Override default temperature
            max_tokens: Override default max tokens
            **kwargs: Additional provider-specific parameters

        Yields:
            str: Chunks of the response as they arrive

        Raises:
            ProviderError: If the provider request fails
        """
        pass

    @abstractmethod
    async def embed(self, text: Union[str, List[str]]) -> Union[List[float], List[List[float]]]:
        """Generate embeddings for text.

        Args:
            text: Single text or list of texts to embed

        Returns:
            Embedding vector(s)

        Raises:
            ProviderError: If the provider request fails
        """
        pass

    def get_cache_key(self, messages: List[Message], **kwargs: Any) -> str:
        """Generate a cache key for a request.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Returns:
            str: Cache key
        """
        import hashlib
        import json

        msg_dict = [{"role": m.role.value, "content": m.content} for m in messages]
        data = {"messages": msg_dict, "config": kwargs}
        key_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()

    async def _with_retry(self, func, *args, **kwargs) -> Any:
        """Execute a function with retry logic.

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Exception: If all retries fail
        """
        import asyncio

        last_exception = None
        for attempt in range(self.config.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.config.max_retries:
                    backoff = 2**attempt
                    logger.warning(
                        f"Retry {attempt + 1}/{self.config.max_retries} "
                        f"after {backoff}s due to: {str(e)}"
                    )
                    await asyncio.sleep(backoff)
                else:
                    logger.error(f"All retries failed: {str(e)}")

        raise last_exception or Exception("Unknown error during retry")

    def _calculate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate the cost of a request.

        Args:
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            float: Cost in USD
        """
        # Default cost calculation - override in subclasses for provider-specific pricing
        cost_per_1k_prompt = 0.01
        cost_per_1k_completion = 0.03
        cost = (
            prompt_tokens / 1000 * cost_per_1k_prompt
            + completion_tokens / 1000 * cost_per_1k_completion
        )
        self._total_cost += cost
        return cost

    def get_total_cost(self) -> float:
        """Get total cost of all requests.

        Returns:
            float: Total cost in USD
        """
        return self._total_cost

    def get_total_requests(self) -> int:
        """Get total number of requests made.

        Returns:
            int: Total requests
        """
        return self._total_requests

    def reset_metrics(self) -> None:
        """Reset cost and request counters."""
        self._total_cost = 0.0
        self._total_requests = 0
        self._cache.clear()


class ProviderError(Exception):
    """Base exception for provider errors."""

    def __init__(self, message: str, provider: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.provider = provider
        self.original_error = original_error


class RateLimitError(ProviderError):
    """Exception raised when rate limit is exceeded."""

    pass


class AuthenticationError(ProviderError):
    """Exception raised for authentication failures."""

    pass


class InvalidRequestError(ProviderError):
    """Exception raised for invalid requests."""

    pass
