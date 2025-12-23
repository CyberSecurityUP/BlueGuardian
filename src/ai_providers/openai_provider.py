"""OpenAI AI provider implementation.

This module provides integration with OpenAI's models,
supporting GPT-4, GPT-4-Turbo, GPT-3.5, and embedding models.
"""

import time
from typing import Any, AsyncIterator, Dict, List, Optional, Union

from loguru import logger
from openai import AsyncOpenAI, OpenAIError

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


class OpenAIProvider(BaseAIProvider):
    """OpenAI provider using OpenAI API."""

    # Pricing per 1M tokens (as of Dec 2025)
    PRICING = {
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4-turbo": {"input": 10.00, "output": 30.00},
        "gpt-4": {"input": 30.00, "output": 60.00},
        "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
        "embedding-ada-002": {"input": 0.10, "output": 0.0},
        "text-embedding-3-small": {"input": 0.02, "output": 0.0},
        "text-embedding-3-large": {"input": 0.13, "output": 0.0},
    }

    def __init__(self, config: ProviderConfig) -> None:
        """Initialize OpenAI provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)
        self.provider_name = AIProvider.OPENAI
        self.client = AsyncOpenAI(
            api_key=config.api_key,
            timeout=config.timeout,
            base_url=config.base_url,
        )
        logger.info(f"Initialized OpenAI provider with model: {config.model}")

    def _convert_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        """Convert internal messages to OpenAI format.

        Args:
            messages: Internal message format

        Returns:
            OpenAI messages format
        """
        openai_messages = []

        for msg in messages:
            openai_msg = {
                "role": msg.role.value,
                "content": msg.content,
            }

            if msg.name:
                openai_msg["name"] = msg.name

            if msg.tool_calls:
                openai_msg["tool_calls"] = msg.tool_calls

            if msg.tool_call_id:
                openai_msg["tool_call_id"] = msg.tool_call_id

            openai_messages.append(openai_msg)

        return openai_messages

    def _convert_tools(self, tools: Optional[List[Tool]]) -> Optional[List[Dict[str, Any]]]:
        """Convert internal tools to OpenAI format.

        Args:
            tools: Internal tool format

        Returns:
            OpenAI tools format
        """
        if not tools:
            return None

        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
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
        """Generate a response using OpenAI.

        Args:
            messages: Conversation messages
            tools: Optional tools for function calling
            temperature: Override default temperature
            max_tokens: Override default max tokens
            **kwargs: Additional OpenAI-specific parameters

        Returns:
            AIResponse with OpenAI's response

        Raises:
            ProviderError: If the request fails
        """
        start_time = time.time()
        self._total_requests += 1

        # Check cache
        cache_key = self.get_cache_key(messages, temperature=temperature, max_tokens=max_tokens)
        if cache_key in self._cache:
            logger.debug("Cache hit for request")
            cached_response = self._cache[cache_key]
            if cached_response.metrics:
                cached_response.metrics.cached = True
            return cached_response

        try:
            openai_messages = self._convert_messages(messages)
            openai_tools = self._convert_tools(tools)

            # Prepare request parameters
            request_params = {
                "model": self.config.model,
                "messages": openai_messages,
                "temperature": temperature if temperature is not None else self.config.temperature,
            }

            if max_tokens:
                request_params["max_tokens"] = max_tokens

            if openai_tools:
                request_params["tools"] = openai_tools
                request_params["tool_choice"] = "auto"

            # Add any additional kwargs
            request_params.update(kwargs)

            # Make API request with retry logic
            response = await self._with_retry(
                self.client.chat.completions.create,
                **request_params,
            )

            # Calculate metrics
            latency_ms = (time.time() - start_time) * 1000
            usage = response.usage
            prompt_tokens = usage.prompt_tokens if usage else 0
            completion_tokens = usage.completion_tokens if usage else 0
            total_tokens = usage.total_tokens if usage else 0

            # Calculate cost
            cost = self._calculate_cost_openai(prompt_tokens, completion_tokens)

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
            choice = response.choices[0]
            content = choice.message.content or ""
            tool_calls = None

            if choice.message.tool_calls:
                tool_calls = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in choice.message.tool_calls
                ]

            ai_response = AIResponse(
                content=content,
                tool_calls=tool_calls,
                stop_reason=choice.finish_reason,
                metrics=metrics,
                raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
            )

            # Cache the response
            self._cache[cache_key] = ai_response

            logger.debug(
                f"OpenAI response: {completion_tokens} tokens, " f"{latency_ms:.0f}ms, ${cost:.4f}"
            )

            return ai_response

        except OpenAIError as e:
            error_msg = str(e)
            if "authentication" in error_msg.lower() or "api key" in error_msg.lower():
                raise AuthenticationError(
                    f"OpenAI authentication failed: {error_msg}",
                    provider=self.provider_name.value,
                    original_error=e,
                )
            elif "rate limit" in error_msg.lower():
                raise RateLimitError(
                    f"OpenAI rate limit exceeded: {error_msg}",
                    provider=self.provider_name.value,
                    original_error=e,
                )
            elif "invalid" in error_msg.lower():
                raise InvalidRequestError(
                    f"Invalid OpenAI request: {error_msg}",
                    provider=self.provider_name.value,
                    original_error=e,
                )
            else:
                raise ProviderError(
                    f"OpenAI request failed: {error_msg}",
                    provider=self.provider_name.value,
                    original_error=e,
                )
        except Exception as e:
            raise ProviderError(
                f"OpenAI request failed: {str(e)}",
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
        """Stream a response from OpenAI.

        Args:
            messages: Conversation messages
            tools: Optional tools for function calling
            temperature: Override default temperature
            max_tokens: Override default max tokens
            **kwargs: Additional OpenAI-specific parameters

        Yields:
            Response chunks as they arrive

        Raises:
            ProviderError: If the request fails
        """
        try:
            openai_messages = self._convert_messages(messages)
            openai_tools = self._convert_tools(tools)

            request_params = {
                "model": self.config.model,
                "messages": openai_messages,
                "temperature": temperature if temperature is not None else self.config.temperature,
                "stream": True,
            }

            if max_tokens:
                request_params["max_tokens"] = max_tokens

            if openai_tools:
                request_params["tools"] = openai_tools
                request_params["tool_choice"] = "auto"

            request_params.update(kwargs)

            stream = await self.client.chat.completions.create(**request_params)

            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except Exception as e:
            raise ProviderError(
                f"OpenAI streaming failed: {str(e)}",
                provider=self.provider_name.value,
                original_error=e,
            )

    async def embed(self, text: Union[str, List[str]]) -> Union[List[float], List[List[float]]]:
        """Generate embeddings using OpenAI.

        Args:
            text: Single text or list of texts to embed

        Returns:
            Embedding vector(s)

        Raises:
            ProviderError: If the request fails
        """
        try:
            is_single = isinstance(text, str)
            texts = [text] if is_single else text

            # Use a default embedding model if not specified
            embedding_model = "text-embedding-3-small"

            response = await self._with_retry(
                self.client.embeddings.create,
                model=embedding_model,
                input=texts,
            )

            embeddings = [data.embedding for data in response.data]

            # Calculate cost for embeddings
            total_tokens = response.usage.total_tokens
            cost = self._calculate_cost_openai(total_tokens, 0, model=embedding_model)

            logger.debug(f"Generated embeddings for {len(texts)} texts, ${cost:.4f}")

            return embeddings[0] if is_single else embeddings

        except Exception as e:
            raise ProviderError(
                f"OpenAI embedding failed: {str(e)}",
                provider=self.provider_name.value,
                original_error=e,
            )

    def _calculate_cost_openai(
        self, prompt_tokens: int, completion_tokens: int, model: Optional[str] = None
    ) -> float:
        """Calculate cost for OpenAI models.

        Args:
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens
            model: Optional model override

        Returns:
            Cost in USD
        """
        model_name = model or self.config.model

        # Find pricing for this model
        pricing = None
        for model_key in self.PRICING:
            if model_key in model_name:
                pricing = self.PRICING[model_key]
                break

        if pricing is None:
            logger.warning(f"Unknown model pricing: {model_name}, using default")
            pricing = self.PRICING["gpt-4-turbo"]

        cost = (
            prompt_tokens / 1_000_000 * pricing["input"]
            + completion_tokens / 1_000_000 * pricing["output"]
        )
        self._total_cost += cost
        return cost
