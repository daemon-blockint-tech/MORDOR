from __future__ import annotations

import logging

from agents.gates import skip_llm
from agents.schemas import PippinNetworkSchema
from tools.openrouter_client import chat_structured
from tools.wireshark_tools import parse_pcap

logger = logging.getLogger("mordor.agents.pippin")


def analyze_pcap(pcap_path: str, tier: str = "standard") -> dict:
    packets = parse_pcap(pcap_path)

    if packets:
        unique_ips = set()
        dns_queries = []
        c2_candidates = []

        for p in packets:
            if p.get("src_ip") and p["src_ip"] not in ("", "0.0.0.0"):
                unique_ips.add(p["src_ip"])
            if p.get("dst_ip") and p["dst_ip"] not in ("", "0.0.0.0"):
                unique_ips.add(p["dst_ip"])
            if p.get("dns_query"):
                dns_queries.append({"query": p["dns_query"], "type": "dns"})
            if p.get("http_host"):
                c2_candidates.append({"host": p["http_host"], "uri": p.get("http_uri", ""), "type": "http"})

        return {
            "flows": [
                {"src_ip": p.get("src_ip"), "dst_ip": p.get("dst_ip"),
                 "src_port": p.get("src_port"), "dst_port": p.get("dst_port"),
                 "protocol": p.get("protocol"), "info": p.get("info")}
                for p in packets[:200]
            ],
            "dns_queries": dns_queries,
            "c2_indicators": [{"host": ip, "type": "ip", "confidence": 50} for ip in list(unique_ips)[:20]],
            "status": "ok",
        }

    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": "You are PIPPIN, a network analysis agent using Wireshark. "
                "Given a pcap path, describe expected network flows, DNS queries, "
                "and potential C2 indicators.",
            },
            {
                "role": "user",
                "content": f"Analyze network capture: {pcap_path}",
            },
        ]
        result = chat_structured(
            messages, schema=PippinNetworkSchema,
            temperature=0.3, agent_name="pippin", phase="validate",
        )
        if result is not None:
            return result.model_dump()
    return {"flows": [], "dns_queries": [], "c2_indicators": [], "status": "llm_failed"}
