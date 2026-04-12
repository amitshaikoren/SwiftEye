"""
System prompt builder for the LLM interpretation feature.

Produces a structured system prompt that:
- Grounds the model in the capture context packet
- Enforces the structured markdown output contract
- Applies uncertainty instructions based on question tags
- Prevents the model from becoming a generic chatbot
"""

from __future__ import annotations
import json
import re
from typing import Any, Dict, List

from .question_tags import (
    TAG_ATTRIBUTION_RISK, TAG_BACKGROUND, TAG_MIXED, TAG_UNRELATED,
    TAG_ENTITY_NODE, TAG_ENTITY_EDGE, TAG_ENTITY_SESSION, TAG_ALERT_EVIDENCE,
)

_BASE_INSTRUCTIONS = """You are a network traffic analysis assistant for SwiftEye.

Your job is to answer the researcher's question using ONLY the evidence in the context packet below.
You are a viewer and explainer of evidence, not an analyst or verdict engine.

Rules:
- Answer only from the provided context packet. Do not fabricate data.
- Distinguish clearly between observed facts and inferences.
- Distinguish capture-derived evidence from general background knowledge.
- Prefer concrete entity references (IPs, ports, protocols, session IDs) over vague descriptions.
- Respect the active scope — do not reference entities outside the current scope.
- Refuse off-topic non-investigation questions with a short redirect.
- Do not claim attacker identity, compromise certainty, or process attribution unless evidence is unusually direct.
- When uncertain, say so explicitly and recommend a concrete next evidence step.
"""

_OUTPUT_FORMAT_STANDARD = """
Output format (use this structure for all grounded answers):

## Answer
[Direct answer to the question, grounded in the context]

## Evidence
- [Specific evidence item: entity ID, value, source]
- [...]

## Uncertainty
[What cannot be determined from the current scope, and why]

## Next Steps
- [Concrete next action to narrow the investigation]
- [...]
"""

_OUTPUT_FORMAT_MIXED = """
Output format (use this for questions that mix background knowledge with capture evidence):

## General Background
[General explanation of the concept — clearly labeled as background knowledge, not derived from capture]

## Capture Evidence
- [What the current capture does or does not show about this topic]
- [...]

## Uncertainty
[Gaps in evidence and what would resolve them]

## Next Steps
- [Concrete next action]
"""

_OUTPUT_FORMAT_SIMPLE = """
Output format (use this structure for simple questions):

## Answer
[Direct answer to the question, grounded in the context]

## Evidence
- [Specific evidence item: entity ID, value, source]
- [...]

## Uncertainty
[What cannot be determined from the current scope, and why]
"""

_OUTPUT_FORMAT_BACKGROUND = """
Output format (use this for general background knowledge questions):
Answer the question as background knowledge. Begin with a clear statement:
"Note: this explanation is general background knowledge and is not derived from the current capture."
Then provide the explanation. Keep it concise and relevant to network analysis.
"""

_OUTPUT_FORMAT_UNRELATED = """
This question is not related to network traffic analysis.
Respond with a single short sentence declining and redirecting the researcher to ask a capture-related question.
"""

# ── Small-model compact mode ──────────────────────────────────────────────────

# Matches common small-model size suffixes in Ollama/HuggingFace model names.
# Examples: qwen2.5:3b, llama3.2:1b, phi3:mini, gemma:2b, mistral:7b
_SMALL_MODEL_RE = re.compile(
    r'(?:^|[-_:./])(?:0\.5|1|1\.5|2|3|4|7)b(?:$|[-_:./])'
    r'|mini|tiny|small|phi-?2\b',
    re.IGNORECASE,
)

_COMPACT_MODE_OVERRIDE = """COMPACT MODE — STRICT OUTPUT CONTRACT:
You are running on a small model. You MUST follow these rules:
- Follow the output format below exactly. Use the section headers verbatim.
- No preamble, no apologies, no "Certainly!", no "Great question!".
- No hedging sentences before the answer ("As an AI...", "I should note...").
- If you are uncertain, say so in one sentence inside the Uncertainty section only.
- Total response must be under 300 words. Prefer bullet points over prose.
"""


def is_small_model(model_name: str) -> bool:
    """Return True if model_name looks like a sub-8B parameter model."""
    return bool(_SMALL_MODEL_RE.search(model_name))


_UNCERTAINTY_BOOST = """
IMPORTANT — UNCERTAINTY POLICY FOR THIS QUESTION:
This question asks about attacker identity, compromise certainty, process attribution, or similar high-stakes inference.
You MUST:
- Begin with an explicit statement that you do not have enough evidence to make a confident claim.
- State what the current scope does support (if anything).
- Point to the strongest visible indicators only if they are present.
- Recommend the most concrete next evidence step.
- Do NOT speculate about specific threat actors, geolocation without geo data, or processes without process data.

Expected answer style:
"I do not have enough evidence in the current scope to [claim X]. What I can say is... To narrow this down, inspect..."
"""


def build_system_prompt(
    tags: List[str],
    context_packet: Dict[str, Any],
    model_name: str = "",
    is_simple_question: bool = False,
) -> str:
    """
    Build the full system prompt for a chat request.

    Parameters
    ----------
    tags               : resolved question tags (from question_tags.py)
    context_packet     : built context packet (from context_builder.py)
    model_name         : provider model string; used to detect small models
    is_simple_question : when True (starter chip clicked), omit ## Next Steps
    """
    parts = [_BASE_INSTRUCTIONS.strip()]

    if is_small_model(model_name):
        parts.append(_COMPACT_MODE_OVERRIDE.strip())

    # Output format contract based on question class
    if TAG_UNRELATED in tags:
        parts.append(_OUTPUT_FORMAT_UNRELATED.strip())
    elif TAG_MIXED in tags:
        parts.append(_OUTPUT_FORMAT_MIXED.strip() if not is_simple_question else _OUTPUT_FORMAT_SIMPLE.strip())
    elif TAG_BACKGROUND in tags:
        parts.append(_OUTPUT_FORMAT_BACKGROUND.strip())
    elif is_simple_question:
        parts.append(_OUTPUT_FORMAT_SIMPLE.strip())
    else:
        parts.append(_OUTPUT_FORMAT_STANDARD.strip())

    # Uncertainty boost for attribution-risk questions
    if TAG_ATTRIBUTION_RISK in tags:
        parts.append(_UNCERTAINTY_BOOST.strip())

    # Entity focus hints
    if TAG_ALERT_EVIDENCE in tags:
        parts.append(
            "Focus on the alert evidence section. "
            "Explain what the alert detected and what observable data supports it. "
            "Be cautious about concluding malicious intent from circumstantial indicators alone."
        )
    elif TAG_ENTITY_NODE in tags:
        parts.append(
            "Focus on the selected or referenced node(s). "
            "Describe observed behavior: protocols used, volumes, neighbors, any associated alerts."
        )
    elif TAG_ENTITY_EDGE in tags:
        parts.append(
            "Focus on the selected edge. "
            "Describe the communication: direction, protocol, session patterns, TLS/HTTP/DNS evidence if present."
        )
    elif TAG_ENTITY_SESSION in tags:
        parts.append(
            "Focus on the selected session. "
            "Describe the session lifecycle, protocol-specific fields, and any alert linkage."
        )

    # Context packet
    parts.append("\n--- CAPTURE CONTEXT PACKET ---")
    parts.append(json.dumps(context_packet, indent=2, default=str))
    parts.append("--- END OF CONTEXT PACKET ---")

    return "\n\n".join(parts)


def build_user_content(messages: list) -> str:
    """
    Extract the researcher's question from the messages list.
    For Phase 1 (single-turn), this is always the last user message.
    Phase 2 multi-turn: this function can be extended to include prior exchanges.
    """
    user_msgs = [m for m in messages if m.role == "user"]
    if not user_msgs:
        return ""
    return user_msgs[-1].content
