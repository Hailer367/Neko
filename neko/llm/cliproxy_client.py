import aiohttp
import json
import time
import asyncio
import logging
from typing import Any, Optional, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ChatMessage:
    role: str
    content: str
    name: Optional[str] = None

@dataclass
class Usage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cached_tokens: int = 0

@dataclass
class Choice:
    index: int
    message: ChatMessage
    finish_reason: Optional[str]

@dataclass
class ChatCompletion:
    id: str
    object: str
    created: int
    model: str
    choices: List[Choice]
    usage: Usage

class NekoError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details

class AuthenticationError(NekoError): pass
class RateLimitError(NekoError): pass
class ServerError(NekoError): pass
class ModelNotFoundError(NekoError): pass

class NekoClient:
    """Neko's Pure HTTP Client for CLIProxyAPI (No LiteLLM)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: str = "http://localhost:8085",
        timeout: int = 300,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        self.api_key = api_key
        self.endpoint = endpoint
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._total_tokens = 0
        self._total_requests = 0

    async def _make_request(self, method: str, path: str, json_data: Optional[dict] = None) -> dict:
        url = f"{self.endpoint.rstrip('/')}{path}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.request(method, url, headers=headers, json=json_data) as response:
                        response_text = await response.text()

                        if response.status == 200:
                            return json.loads(response_text)

                        error_msg = f"API error: {response.status}"
                        try:
                            error_data = json.loads(response_text)
                            if "error" in error_data:
                                error_msg = error_data["error"].get("message", error_msg) if isinstance(error_data["error"], dict) else str(error_data["error"])
                        except: pass

                        if response.status == 429: raise RateLimitError(error_msg, status_code=response.status)
                        if response.status in (401, 403): raise AuthenticationError(error_msg, status_code=response.status)
                        if response.status == 404: raise ModelNotFoundError(error_msg, status_code=response.status)
                        if response.status >= 500: raise ServerError(error_msg, status_code=response.status)
                        raise NekoError(error_msg, status_code=response.status, details=response_text)

            except (RateLimitError, ServerError) as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                else: raise
            except aiohttp.ClientError as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                else: raise NekoError(f"Connection error: {e}")
            except asyncio.TimeoutError:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                else: raise NekoError(f"Request timeout after {self.timeout}s")

        raise NekoError("Unknown error")

    async def chat_completion(
        self,
        model: str,
        messages: List[dict],
        **kwargs
    ) -> ChatCompletion:
        request_data = {"model": model, "messages": messages, **kwargs}
        self._total_requests += 1

        response_data = await self._make_request("POST", "/chat/completions", json_data=request_data)

        choices = [
            Choice(
                index=c["index"],
                message=ChatMessage(role=c["message"]["role"], content=c["message"]["content"]),
                finish_reason=c.get("finish_reason")
            ) for c in response_data.get("choices", [])
        ]

        usage_data = response_data.get("usage", {})
        usage = Usage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0)
        )
        self._total_tokens += usage.total_tokens

        return ChatCompletion(
            id=response_data.get("id", ""),
            object="chat.completion",
            created=int(time.time()),
            model=model,
            choices=choices,
            usage=usage
        )
