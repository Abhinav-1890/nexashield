
"""LLM provider adapters for the NexaShield gateway."""

import os
from typing import Protocol

import httpx


class LLMProvider(Protocol):
    """Interface implemented by all LLM providers."""

    def generate(self, prompt: str) -> str:
        ...


class MockLLMProvider:
    """Local mock provider for development and testing."""

    name = "mock"
    model = "mock-llm"

    def generate(self, prompt: str) -> str:
        return (
            "Mock LLM response: "
            "Your request was successfully inspected and forwarded."
        )


class OpenAICompatibleProvider:
    """Provider adapter for OpenAI-compatible chat completion APIs."""

    name = "openai_compatible"

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        """Send an inspected prompt to the configured provider."""

        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0.2,
        }

        try:
            response = httpx.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )

            response.raise_for_status()
            data = response.json()

            return data["choices"][0]["message"]["content"]

        except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                "The configured LLM provider request failed."
            ) from exc


def get_llm_provider() -> LLMProvider:
    """Construct the configured provider."""

    provider_name = os.getenv(
        "NEXASHIELD_LLM_PROVIDER",
        "mock",
    ).strip().lower()

    if provider_name == "mock":
        return MockLLMProvider()

    if provider_name == "openai_compatible":
        api_key = os.getenv("NEXASHIELD_LLM_API_KEY", "").strip()

        if not api_key:
            raise RuntimeError(
                "NEXASHIELD_LLM_API_KEY is required "
                "for the OpenAI-compatible provider."
            )

        base_url = os.getenv(
            "NEXASHIELD_LLM_BASE_URL",
            "https://api.openai.com/v1",
        ).strip()

        model = os.getenv(
            "NEXASHIELD_LLM_MODEL",
            "gpt-4o-mini",
        ).strip()

        if not base_url or not model:
            raise RuntimeError(
                "LLM base URL and model must not be empty."
            )

        try:
            timeout = float(
                os.getenv("NEXASHIELD_LLM_TIMEOUT", "30")
            )
        except ValueError as exc:
            raise RuntimeError(
                "NEXASHIELD_LLM_TIMEOUT must be a number."
            ) from exc

        if timeout <= 0:
            raise RuntimeError(
                "NEXASHIELD_LLM_TIMEOUT must be positive."
            )

        return OpenAICompatibleProvider(
            api_key=api_key,
            base_url=base_url,
            model=model,
            timeout=timeout,
        )

    raise RuntimeError(
        f"Unsupported LLM provider: {provider_name}"
    )
