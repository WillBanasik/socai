"""
Structured LLM call helper — wraps the Anthropic API ``output_config``
parameter with a Pydantic model to guarantee JSON-schema structured outputs.

Usage::

    from tools.schemas import ExecutiveSummary
    from tools.structured_llm import structured_call

    result, usage = structured_call(
        model="claude-sonnet-4-6",
        system="You are ...",
        messages=[{"role": "user", "content": "..."}],
        output_schema=ExecutiveSummary,
        max_tokens=4096,
    )
    if result:
        print(result.risk_rating)
"""
from __future__ import annotations

import json
from typing import Type, TypeVar

import anthropic
from pydantic import BaseModel

from config.settings import ANTHROPIC_KEY

T = TypeVar("T", bound=BaseModel)


def _schema_for_model(model_cls: Type[T]) -> dict:
    """Build the ``output_config`` JSON-schema dict from a Pydantic model."""
    raw = model_cls.model_json_schema()
    return {
        "type": "json_schema",
        "name": model_cls.__name__,
        "schema": raw,
    }


def structured_call(
    model: str,
    system: str | list[dict],
    messages: list[dict],
    output_schema: Type[T],
    max_tokens: int = 4096,
    *,
    thinking: dict | None = None,
) -> tuple[T | None, dict]:
    """Make a Claude API call with structured JSON-schema output.

    Parameters
    ----------
    model : str
        Model ID (e.g. ``"claude-sonnet-4-6"``).
    system : str or list[dict]
        System prompt — plain string or cached content blocks.
    messages : list[dict]
        Conversation messages.
    output_schema : Type[BaseModel]
        Pydantic model class defining the expected output structure.
    max_tokens : int
        Maximum tokens in the response.
    thinking : dict | None
        Optional thinking config (e.g. ``{"type": "adaptive"}``).

    Returns
    -------
    tuple[T | None, dict]
        (parsed_result, usage_dict).  ``parsed_result`` is ``None`` on
        refusal or parse failure.
    """
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    kwargs: dict = {
        "model": model,
        "system": system,
        "messages": messages,
        "max_tokens": max_tokens,
        "output_config": {"format": _schema_for_model(output_schema)},
    }
    if thinking:
        kwargs["thinking"] = thinking

    response = client.messages.create(**kwargs)

    usage = {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "cache_read_input_tokens": getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        "cache_creation_input_tokens": getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
    }

    # Handle refusal
    if response.stop_reason == "refusal":
        return None, usage

    # Extract the JSON text from content blocks
    json_text = ""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            json_text += block.text

    if not json_text.strip():
        return None, usage

    try:
        data = json.loads(json_text)
        parsed = output_schema.model_validate(data)
        return parsed, usage
    except Exception:
        return None, usage


def structured_call_params(
    model: str,
    system: str | list[dict],
    messages: list[dict],
    output_schema: Type[T],
    max_tokens: int = 4096,
    *,
    custom_id: str = "",
) -> dict:
    """Build ``messages.create()`` kwargs for batch submission (no execution).

    Returns a dict suitable for ``client.messages.batches.create()`` requests.
    """
    params: dict = {
        "model": model,
        "system": system,
        "messages": messages,
        "max_tokens": max_tokens,
        "output_config": {"format": _schema_for_model(output_schema)},
    }
    return {
        "custom_id": custom_id,
        "params": params,
    }
