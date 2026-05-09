from __future__ import annotations

import logging
import os
import subprocess
import tempfile

logger = logging.getLogger("mordor.tools.wireshark")


def _find_tshark() -> str | None:
    for candidate in ["tshark", "/Applications/Wireshark.app/Contents/MacOS/tshark"]:
        try:
            subprocess.run([candidate, "--version"], capture_output=True, check=False)
            return candidate
        except FileNotFoundError:
            continue
    return None


def capture_traffic(interface: str = "eth0", duration: int = 30) -> str:
    tshark = _find_tshark()
    if not tshark:
        logger.warning("tshark not found, cannot capture traffic")
        return ""

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name

    try:
        subprocess.run(
            [tshark, "-i", interface, "-a", f"duration:{duration}", "-w", pcap_path],
            capture_output=True,
            timeout=duration + 10,
            check=False,
        )
        return pcap_path
    except subprocess.TimeoutExpired:
        return pcap_path
    except Exception as e:
        logger.warning("tshark capture failed: %s", e)
        return ""


def parse_pcap(pcap_path: str) -> list[dict]:
    tshark = _find_tshark()
    if not tshark:
        logger.warning("tshark not found, cannot parse pcap")
        return []

    if not os.path.exists(pcap_path):
        logger.warning("pcap file not found: %s", pcap_path)
        return []

    try:
        result = subprocess.run(
            [tshark, "-r", pcap_path, "-T", "json", "-q"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode != 0:
            logger.warning("tshark parse returned %d: %s", result.returncode, result.stderr[:200])
            return []

        import json
        packets = json.loads(result.stdout) if result.stdout.strip() else []
        return [
            {
                "frame_number": p.get("_source", {}).get("layers", {}).get("frame", {}).get("frame.number"),
                "protocol": list(p.get("_source", {}).get("layers", {}).keys())[-1] if p.get("_source", {}).get("layers", {}) else "",
                "src_ip": p.get("_source", {}).get("layers", {}).get("ip", {}).get("ip.src", ""),
                "dst_ip": p.get("_source", {}).get("layers", {}).get("ip", {}).get("ip.dst", ""),
                "src_port": p.get("_source", {}).get("layers", {}).get("tcp", {}).get("tcp.srcport", "")
                          or p.get("_source", {}).get("layers", {}).get("udp", {}).get("udp.srcport", ""),
                "dst_port": p.get("_source", {}).get("layers", {}).get("tcp", {}).get("tcp.dstport", "")
                          or p.get("_source", {}).get("layers", {}).get("udp", {}).get("udp.dstport", ""),
                "info": p.get("_source", {}).get("layers", {}).get("frame", {}).get("frame.protocols", ""),
                "dns_query": p.get("_source", {}).get("layers", {}).get("dns", {}).get("Queries", ""),
                "http_host": p.get("_source", {}).get("layers", {}).get("http", {}).get("http.host", ""),
                "http_uri": p.get("_source", {}).get("layers", {}).get("http", {}).get("http.request.uri", ""),
            }
            for p in packets[:5000]
        ]
    except Exception as e:
        logger.warning("pcap parse failed: %s", e)
        return []
