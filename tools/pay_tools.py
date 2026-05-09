from __future__ import annotations

import json
import logging
import os
import re
import subprocess

from tools.safe_util import safe_subprocess_env

logger = logging.getLogger("mordor.tools.pay")

PAY_BIN = os.environ.get("PAY_BIN_PATH", "pay")


def _run_pay(args: list[str], timeout: int = 30) -> dict:
    try:
        result = subprocess.run(
            [PAY_BIN, *args],
            capture_output=True, text=True, timeout=timeout,
            env=safe_subprocess_env(),
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            logger.warning("pay CLI error (exit %d): %s", result.returncode, stderr)
            return {"status": "error", "message": stderr}
        stdout = result.stdout.strip()
        try:
            return {"status": "ok", "data": json.loads(stdout)}
        except (json.JSONDecodeError, ValueError):
            return {"status": "ok", "data": stdout}
    except FileNotFoundError:
        logger.warning("pay binary not found at %s", PAY_BIN)
        return {"status": "error", "message": f"pay binary not found at {PAY_BIN}"}
    except subprocess.TimeoutExpired:
        logger.warning("pay CLI timed out after %ds", timeout)
        return {"status": "error", "message": "timeout"}
    except Exception as e:
        logger.warning("pay CLI exception: %s", e)
        return {"status": "error", "message": str(e)}


def check_health() -> dict:
    return _run_pay(["--help"], timeout=10)


def get_account_info() -> dict:
    return _run_pay(["account", "list"])


def send_payment(
    recipient: str,
    amount: str,
    token: str = "usdc",
    network: str = "solana",
) -> dict:
    from tools.safe_util import validate_solana_address, validate_amount
    if not validate_solana_address(recipient):
        return {"status": "error", "message": "invalid recipient address"}
    if not validate_amount(amount):
        return {"status": "error", "message": "invalid amount"}
    if not re.match(r"^[a-z0-9_]{1,32}$", token):
        return {"status": "error", "message": "invalid token"}
    if network not in ("solana", "eclipse", "mainnet"):
        return {"status": "error", "message": "unsupported network"}
    return _run_pay([
        "send",
        "--recipient", recipient,
        "--amount", amount,
        "--token", token,
        "--network", network,
    ])


def topup_account(amount: str, method: str = "auto") -> dict:
    return _run_pay(["topup", "--amount", amount, "--method", method])


def get_balance() -> dict:
    return _run_pay(["account", "balance"])


def skills_search(query: str) -> dict:
    return _run_pay(["skills", "search", query])


def skills_list_sources() -> dict:
    return _run_pay(["skills", "list"])


def skills_update_cache() -> dict:
    return _run_pay(["skills", "update"])


def mcp_server_status() -> dict:
    return _run_pay(["mcp", "--help"], timeout=10)
