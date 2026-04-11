# backend/llm/providers — provider registry
from .base import ProviderAdapter
from .ollama import OllamaAdapter
from .openai_compatible import OpenAICompatibleAdapter

_REGISTRY = {
    "ollama": OllamaAdapter,
    "openai": OpenAICompatibleAdapter,
    "openai_compatible": OpenAICompatibleAdapter,
}


def get_provider(kind: str) -> type:
    """Return the ProviderAdapter class for the given kind string."""
    cls = _REGISTRY.get(kind)
    if cls is None:
        raise ValueError(f"Unknown provider kind: {kind!r}. Supported: {list(_REGISTRY)}")
    return cls
