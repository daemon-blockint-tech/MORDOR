from __future__ import annotations

import logging

from agents.schemas import PayPaymentSchema
from tools.openrouter_client import chat_structured
from tools.pay_tools import (
    check_health,
    get_balance,
    send_payment,
    skills_search,
    skills_update_cache,
    topup_account,
)

logger = logging.getLogger("mordor.agents.pay")


PAY_SYSTEM_PROMPT = (
    "You are PAY, the programmable-money agent of MORDOR. "
    "You manage blockchain-based payments, account top-ups, and API cost tracking. "
    "You use the `pay` CLI toolchain to send stablecoins, check balances, "
    "and maintain the payment skills catalog.\n\n"
    "Respond with a JSON object containing exactly these fields:\n"
    '- "action": string — one of "balance_check", "payment", "topup", "skills_update", "health_check"\n'
    '- "status": string — "ok" or "error"\n'
    '- "detail": string — human-readable summary of what happened\n'
    '- "tx_data": object | null — any returned transaction or account data\n\n'
    "Never send payments unless explicitly instructed. "
    "Default to read-only operations (balance, health, skills search) when in doubt."
)


def process_payment_action(
    action: str,
    recipient: str | None = None,
    amount: str | None = None,
    query: str | None = None,
    tier: str = "standard",
) -> dict:
    if action == "health_check":
        result = check_health()
        return {
            "action": "health_check",
            "status": "ok" if result.get("status") == "ok" else "error",
            "detail": "pay CLI is reachable" if result.get("status") == "ok" else result.get("message", "unreachable"),
            "tx_data": result.get("data"),
        }

    elif action == "balance_check":
        result = get_balance()
        return {
            "action": "balance_check",
            "status": "ok" if result.get("status") == "ok" else "error",
            "detail": "Balance retrieved" if result.get("status") == "ok" else result.get("message", "failed"),
            "tx_data": result.get("data"),
        }

    elif action == "payment":
        if not recipient or not amount:
            return {
                "action": "payment",
                "status": "error",
                "detail": "recipient and amount are required",
                "tx_data": None,
            }
        result = send_payment(recipient, amount)
        return {
            "action": "payment",
            "status": "ok" if result.get("status") == "ok" else "error",
            "detail": f"Sent {amount} to {recipient}" if result.get("status") == "ok" else result.get("message", "failed"),
            "tx_data": result.get("data"),
        }

    elif action == "topup":
        if not amount:
            return {
                "action": "topup",
                "status": "error",
                "detail": "amount is required for top-up",
                "tx_data": None,
            }
        result = topup_account(amount)
        return {
            "action": "topup",
            "status": "ok" if result.get("status") == "ok" else "error",
            "detail": f"Topped up {amount}" if result.get("status") == "ok" else result.get("message", "failed"),
            "tx_data": result.get("data"),
        }

    elif action == "skills_update":
        result = skills_update_cache()
        return {
            "action": "skills_update",
            "status": "ok" if result.get("status") == "ok" else "error",
            "detail": "Skills cache updated" if result.get("status") == "ok" else result.get("message", "failed"),
            "tx_data": result.get("data"),
        }

    elif action == "skills_search":
        if not query:
            return {
                "action": "skills_search",
                "status": "error",
                "detail": "search query is required",
                "tx_data": None,
            }
        result = skills_search(query)
        return {
            "action": "skills_search",
            "status": "ok" if result.get("status") == "ok" else "error",
            "detail": f"Skills search: {query}" if result.get("status") == "ok" else result.get("message", "failed"),
            "tx_data": result.get("data"),
        }

    else:
        return {
            "action": action,
            "status": "error",
            "detail": f"unknown action: {action}",
            "tx_data": None,
        }


def handle_payment_request(
    request: str,
    tier: str = "standard",
) -> dict:
    messages = [
        {"role": "system", "content": PAY_SYSTEM_PROMPT},
        {"role": "user", "content": request},
    ]
    result = chat_structured(
        messages, schema=PayPaymentSchema,
        temperature=0.2, agent_name="pay", phase="payment",
    )
    if result is not None:
        parsed = result.model_dump()
        return process_payment_action(
            action=parsed.get("action", "health_check"),
            recipient=parsed.get("recipient"),
            amount=parsed.get("amount"),
            query=parsed.get("query"),
            tier=tier,
        )

    return {"action": "unknown", "status": "error", "detail": "failed to parse request", "tx_data": None}
