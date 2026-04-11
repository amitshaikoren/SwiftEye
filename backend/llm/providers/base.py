"""
ProviderAdapter — abstract base class for all LLM providers.
Phase 2/3 can add new providers by subclassing this.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterator


class ProviderAdapter(ABC):
    """Common interface all provider adapters must implement."""

    @abstractmethod
    def stream_chat(
        self,
        system_prompt: str,
        user_content: str,
        config,
    ) -> Iterator[str]:
        """
        Yield text delta strings as they arrive from the provider.
        Raises on connection/auth errors.
        config is a ProviderConfig dataclass.
        """
        ...

    def supports_tools(self) -> bool:
        return False

    def supports_json_mode(self) -> bool:
        return False
