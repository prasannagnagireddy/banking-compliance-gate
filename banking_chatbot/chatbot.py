"""
Module 3 — Banking Chatbot (lab stub)
Extended in Module 6 Project 3 with PCI DSS compliance guardrails.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_client import get_llm_client, resolve_model

load_dotenv()

# Session tracking for rate limiting (in-memory)
session_counters: dict[str, int] = {}
MAX_FINANCIAL_QUERIES_PER_SESSION = 20

# PII patterns for filtering (PCI DSS compliance)
PII_PATTERNS = [
    (re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'), lambda m: f"****-****-****-{m.group()[-4:]}"),  # Card numbers
    (re.compile(r'\b\d{3}[\s-]?\d{2}[\s-]?\d{4}\b'), "***-**-****"),  # SSN
    (re.compile(r'\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b'), "***-***-****"),  # Phone numbers
]

FINANCIAL_KEYWORDS = frozenset({
    "balance", "transfer", "account", "statement", "loan",
    "credit", "debit", "transaction", "payment",
})


def is_financial_query(user_message: str) -> bool:
    """Return True if the message looks like a financial query."""
    tokens = set(user_message.lower().split())
    return bool(tokens & FINANCIAL_KEYWORDS)


def call_claude(user_message: str, tools: list[dict[str, Any]] | None = None) -> str:
    """Send a user message to Claude and return the text response."""
    client = get_llm_client()
    response = client.messages.create(
        model=resolve_model("claude-sonnet-4-5"),
        max_tokens=1024,
        tools=tools or [],
        messages=[{"role": "user", "content": user_message}],
    )
    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


def pre_response_pii_filter(response: str) -> str:
    """
    Mask PII in response text per PCI DSS requirements.
    Returns sanitized response with masked card numbers, SSN, phone numbers.
    """
    filtered = response
    for pattern, replacement in PII_PATTERNS:
        if callable(replacement):
            filtered = pattern.sub(replacement, filtered)
        else:
            filtered = pattern.sub(replacement, filtered)
    return filtered


def rate_limit_check(session_id: str, is_financial: bool) -> tuple[bool, str | None]:
    """
    Check if session has exceeded financial query rate limit.

    Args:
        session_id: Unique session identifier
        is_financial: Whether the current query is financial

    Returns:
        (allowed, error_message) tuple
    """
    if not is_financial:
        return True, None

    current_count = session_counters.get(session_id, 0)

    if current_count >= MAX_FINANCIAL_QUERIES_PER_SESSION:
        return False, f"Rate limit exceeded: maximum {MAX_FINANCIAL_QUERIES_PER_SESSION} financial queries per session"

    session_counters[session_id] = current_count + 1
    return True, None


def write_audit_log_entry(
    session_id: str,
    query: str,
    response: str,
    is_financial: bool,
    tool_calls: list[str] | None = None,
    error: str | None = None,
) -> None:
    """
    Write audit log entry in JSONL format per PCI DSS requirements.
    No plaintext PII in logs - response is pre-filtered.
    """
    audit_dir = Path("audit_log")
    audit_dir.mkdir(exist_ok=True)

    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "session_id": session_id,
        "query_masked": query[:50] + "..." if len(query) > 50 else query,
        "is_financial": is_financial,
        "tool_calls": tool_calls or [],
        "error": error,
        "response_length": len(response) if response else 0,
    }

    log_file = audit_dir / "chatbot_tool_calls.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def run_with_guardrails(
    user_message: str,
    session_id: str = "default",
    tools: list[dict[str, Any]] | None = None,
) -> str:
    """
    Execute chatbot query with full PCI DSS compliance guardrails.

    Pipeline:
    1. Check if query is financial
    2. Rate limit check
    3. Call Claude API
    4. Filter PII from response
    5. Write audit log

    Returns sanitized response or error message.
    """
    is_financial = is_financial_query(user_message)

    # Guardrail 1: Rate limiting
    allowed, error = rate_limit_check(session_id, is_financial)
    if not allowed:
        write_audit_log_entry(
            session_id=session_id,
            query=pre_response_pii_filter(user_message),
            response="",
            is_financial=is_financial,
            error=error,
        )
        return error

    try:
        # Call Claude API
        response = call_claude(user_message, tools)

        # Guardrail 2: PII filtering
        filtered_response = pre_response_pii_filter(response)

        # Guardrail 3: Audit logging
        write_audit_log_entry(
            session_id=session_id,
            query=pre_response_pii_filter(user_message),
            response=filtered_response,
            is_financial=is_financial,
            tool_calls=[tool.get("name", "unknown") for tool in (tools or [])],
        )

        return filtered_response

    except Exception as e:
        error_msg = "An error occurred processing your request"
        write_audit_log_entry(
            session_id=session_id,
            query=pre_response_pii_filter(user_message),
            response="",
            is_financial=is_financial,
            error=type(e).__name__,
        )
        return error_msg


def handle_message(user_message: str) -> str:
    """Basic chatbot handler — guardrails added in Module 6 Project 3."""
    return run_with_guardrails(user_message)


if __name__ == "__main__":
    print(handle_message("What services does Heritage National Bank offer?"))
