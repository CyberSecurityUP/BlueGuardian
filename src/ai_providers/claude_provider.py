"""Claude AI provider implementation using Anthropic API.

This module provides integration with Anthropic's Claude models,
supporting Claude Sonnet, Opus, and Haiku variants.
"""

import time
from typing import Any, AsyncIterator, Dict, List, Optional, Union

import anthropic
from anthropic import AsyncAnthropic
from loguru import logger

from .base import (
    AIProvider,
    AIResponse,
    AuthenticationError,
    BaseAIProvider,
    GenerationMetrics,
    InvalidRequestError,
    Message,
    MessageRole,
    ProviderConfig,
    ProviderError,
    RateLimitError,
    Tool,
)


class ClaudeProvider(BaseAIProvider):
    """Claude AI provider using Anthropic API."""

    # Pricing per 1M tokens (as of Dec 2025)
    PRICING = {
        "claude-opus-4.5": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4.5": {"input": 3.00, "output": 15.00},
        "claude-sonnet-3.5": {"input": 3.00, "output": 15.00},
        "claude-haiku-3.5": {"input": 0.80, "output": 4.00},
        "claude-3-opus": {"input": 15.00, "output": 75.00},
        "claude-3-sonnet": {"input": 3.00, "output": 15.00},
        "claude-3-haiku": {"input": 0.25, "output": 1.25},
    }

    def __init__(self, config: ProviderConfig) -> None:
        """Initialize Claude provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)
        self.provider_name = AIProvider.CLAUDE
        self.client = AsyncAnthropic(
            api_key=config.api_key,
            timeout=config.timeout,
        )
        logger.info(f"Initialized Claude provider with model: {config.model}")

    def _convert_messages(
        self, messages: List[Message]
    ) -> tuple[Optional[str], List[Dict[str, Any]]]:
        """Convert internal messages to Anthropic format.

        Args:
            messages: Internal message format

        Returns:
            Tuple of (system_prompt, anthropic_messages)
        """
        system_prompt = None
        anthropic_messages = []

        for msg in messages:
            if msg.role == MessageRole.SYSTEM:
                system_prompt = msg.content
            elif msg.role in [MessageRole.USER, MessageRole.ASSISTANT]:
                anthropic_msg = {
                    "role": msg.role.value,
                    "content": msg.content,
                }
                if msg.tool_calls:
                    anthropic_msg["tool_calls"] = msg.tool_calls
                anthropic_messages.append(anthropic_msg)
            elif msg.role == MessageRole.TOOL:
                # Tool results are user messages in Claude
                anthropic_messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.tool_call_id,
                                "content": msg.content,
                            }
                        ],
                    }
                )

        return system_prompt, anthropic_messages

    def _convert_tools(self, tools: Optional[List[Tool]]) -> Optional[List[Dict[str, Any]]]:
        """Convert internal tools to Anthropic format.

        Args:
            tools: Internal tool format

        Returns:
            Anthropic tools format
        """
        if not tools:
            return None

        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.parameters,
            }
            for tool in tools
        ]

    async def generate(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AIResponse:
        """Generate a response using Claude.

        Args:
            messages: Conversation messages
            tools: Optional tools for function calling
            temperature: Override default temperature
            max_tokens: Override default max tokens
            **kwargs: Additional Anthropic-specific parameters

        Returns:
            AIResponse with Claude's response

        Raises:
            ProviderError: If the request fails
        """
        start_time = time.time()
        self._total_requests += 1

        # Check cache
        cache_key = self.get_cache_key(messages, temperature=temperature, max_tokens=max_tokens)
        if cache_key in self._cache:
            logger.debug(f"Cache hit for request")
            cached_response = self._cache[cache_key]
            if cached_response.metrics:
                cached_response.metrics.cached = True
            return cached_response

        try:
            system_prompt, anthropic_messages = self._convert_messages(messages)
            anthropic_tools = self._convert_tools(tools)

            # Prepare request parameters
            request_params = {
                "model": self.config.model,
                "messages": anthropic_messages,
                "max_tokens": max_tokens or self.config.max_tokens,
                "temperature": temperature if temperature is not None else self.config.temperature,
            }

            if system_prompt:
                request_params["system"] = system_prompt

            if anthropic_tools:
                request_params["tools"] = anthropic_tools

            # Add any additional kwargs
            request_params.update(kwargs)

            # Make API request with retry logic
            response = await self._with_retry(
                self.client.messages.create,
                **request_params,
            )

            # Calculate metrics
            latency_ms = (time.time() - start_time) * 1000
            prompt_tokens = response.usage.input_tokens
            completion_tokens = response.usage.output_tokens
            total_tokens = prompt_tokens + completion_tokens

            # Calculate cost
            cost = self._calculate_cost_claude(prompt_tokens, completion_tokens)

            metrics = GenerationMetrics(
                provider=self.provider_name.value,
                model=self.config.model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                latency_ms=latency_ms,
                cost_usd=cost,
            )

            # Extract content and tool calls
            content = ""
            tool_calls = None

            for block in response.content:
                if block.type == "text":
                    content += block.text
                elif block.type == "tool_use":
                    if tool_calls is None:
                        tool_calls = []
                    tool_calls.append(
                        {
                            "id": block.id,
                            "type": "function",
                            "function": {
                                "name": block.name,
                                "arguments": block.input,
                            },
                        }
                    )

            ai_response = AIResponse(
                content=content,
                tool_calls=tool_calls,
                stop_reason=response.stop_reason,
                metrics=metrics,
                raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
            )

            # Cache the response
            self._cache[cache_key] = ai_response

            logger.debug(
                f"Claude response: {completion_tokens} tokens, "
                f"{latency_ms:.0f}ms, ${cost:.4f}"
            )

            return ai_response

        except anthropic.AuthenticationError as e:
            raise AuthenticationError(
                f"Claude authentication failed: {str(e)}",
                provider=self.provider_name.value,
                original_error=e,
            )
        except anthropic.RateLimitError as e:
            raise RateLimitError(
                f"Claude rate limit exceeded: {str(e)}",
                provider=self.provider_name.value,
                original_error=e,
            )
        except anthropic.BadRequestError as e:
            raise InvalidRequestError(
                f"Invalid Claude request: {str(e)}",
                provider=self.provider_name.value,
                original_error=e,
            )
        except Exception as e:
            raise ProviderError(
                f"Claude request failed: {str(e)}",
                provider=self.provider_name.value,
                original_error=e,
            )

    async def stream(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream a response from Claude.

        Args:
            messages: Conversation messages
            tools: Optional tools for function calling
            temperature: Override default temperature
            max_tokens: Override default max tokens
            **kwargs: Additional Anthropic-specific parameters

        Yields:
            Response chunks as they arrive

        Raises:
            ProviderError: If the request fails
        """
        try:
            system_prompt, anthropic_messages = self._convert_messages(messages)
            anthropic_tools = self._convert_tools(tools)

            request_params = {
                "model": self.config.model,
                "messages": anthropic_messages,
                "max_tokens": max_tokens or self.config.max_tokens,
                "temperature": temperature if temperature is not None else self.config.temperature,
                "stream": True,
            }

            if system_prompt:
                request_params["system"] = system_prompt

            if anthropic_tools:
                request_params["tools"] = anthropic_tools

            request_params.update(kwargs)

            async with self.client.messages.stream(**request_params) as stream:
                async for text in stream.text_stream:
                    yield text

        except Exception as e:
            raise ProviderError(
                f"Claude streaming failed: {str(e)}",
                provider=self.provider_name.value,
                original_error=e,
            )

    async def embed(self, text: Union[str, List[str]]) -> Union[List[float], List[List[float]]]:
        """Generate embeddings (not supported by Claude).

        Args:
            text: Text to embed

        Raises:
            NotImplementedError: Claude doesn't support embeddings
        """
        raise NotImplementedError(
            "Claude doesn't provide embedding models. "
            "Use OpenAI or a dedicated embedding service."
        )

    def _calculate_cost_claude(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate cost for Claude models.

        Args:
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            Cost in USD
        """
        # Find pricing for this model
        pricing = None
        for model_key in self.PRICING:
            if model_key in self.config.model:
                pricing = self.PRICING[model_key]
                break

        if pricing is None:
            logger.warning(f"Unknown model pricing: {self.config.model}, using default")
            pricing = self.PRICING["claude-sonnet-3.5"]

        cost = (
            prompt_tokens / 1_000_000 * pricing["input"]
            + completion_tokens / 1_000_000 * pricing["output"]
        )
        self._total_cost += cost
        return cost
