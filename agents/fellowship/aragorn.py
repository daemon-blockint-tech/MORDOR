from __future__ import annotations

import logging

from agents.gates import skip_llm
from agents.schemas import AragornOSINTSchema
from tools.openrouter_client import chat_structured
from tools.shodan_tools import search_hash

logger = logging.getLogger("mordor.agents.aragorn")


ARAGORN_SYSTEM_PROMPT = (
    "You are ARAGORN, an OSINT and threat-intel analyst. "
    "Given a SHA-256 hash, return structured threat intelligence.\n\n"
    "Respond with a JSON object containing exactly these fields:\n"
    '- "threat_intel": a dict with "malicious" (bool) and "summary" (string)\n'
    '- "hash_lookups": an array of objects, each with "source" (string), "found" (bool), "results_count" (int)\n'
    '- "tags": an array of strings (threat tags like "malware", "c2", "ransomware", or empty)\n\n'
    "Base your analysis on the hash alone. If no intelligence is available, "
    'return {"threat_intel": {"malicious": false, "summary": "No threat intelligence found"}, '
    '"hash_lookups": [], "tags": []}.'
)


def run_osint(sha256: str, tier: str = "standard") -> dict:
    shodan_result = search_hash(sha256)
    if shodan_result.get("status") == "ok":
        has_results = shodan_result.get("results") or shodan_result.get("total", 0) > 0
        if has_results:
            ip_results = [r.get("ip", "") for r in shodan_result.get("results", []) if r.get("ip")]
            return {
                "threat_intel": {
                    "malicious": bool(ip_results),
                    "summary": f"Found {shodan_result.get('total', 0)} Shodan results for hash",
                },
                "hash_lookups": [
                    {"source": "shodan", "found": True, "results_count": shodan_result.get("total", 0)}
                ],
                "tags": ["shodan_hit"] if ip_results else [],
            }

    if not skip_llm(tier):
        messages = [
            {"role": "system", "content": ARAGORN_SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this SHA-256 hash for threat intelligence: {sha256}"},
        ]
        result = chat_structured(
            messages, schema=AragornOSINTSchema,
            temperature=0.2, agent_name="aragorn", phase="fingerprint",
        )
        if result is not None:
            return result.model_dump()

    return {"threat_intel": {}, "hash_lookups": [], "tags": []}
