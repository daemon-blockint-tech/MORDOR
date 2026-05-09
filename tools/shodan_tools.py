from __future__ import annotations

import logging
import os

logger = logging.getLogger("mordor.tools.shodan")


def _get_api_key() -> str | None:
    return os.environ.get("SHODAN_API_KEY") or None


def lookup_ip(ip: str) -> dict:
    api_key = _get_api_key()
    if not api_key:
        logger.warning("SHODAN_API_KEY not set")
        return {"ip": ip, "ports": [], "hostnames": [], "status": "no_api_key"}

    try:
        import shodan
    except ImportError:
        logger.warning("shodan Python package not installed")
        return {"ip": ip, "ports": [], "hostnames": [], "status": "pkg_missing"}

    try:
        api = shodan.Shodan(api_key)
        info = api.host(ip)
        return {
            "ip": info.get("ip_str", ip),
            "ports": info.get("ports", []),
            "hostnames": info.get("hostnames", []),
            "org": info.get("org", ""),
            "country": info.get("country_name", ""),
            "os": info.get("os", ""),
            "data": [
                {
                    "port": s.get("port"),
                    "transport": s.get("transport"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "banner": s.get("data", "")[:500],
                }
                for s in info.get("data", [])
            ],
            "vulns": info.get("vulns", []),
            "status": "ok",
        }
    except Exception as e:
        logger.warning("Shodan lookup failed for %s: %s", ip, e)
        return {"ip": ip, "ports": [], "hostnames": [], "status": f"error: {e}"}


def search_hash(hash_value: str) -> dict:
    api_key = _get_api_key()
    if not api_key:
        logger.warning("SHODAN_API_KEY not set")
        return {"hash": hash_value, "results": [], "status": "no_api_key"}

    try:
        import shodan
    except ImportError:
        logger.warning("shodan Python package not installed")
        return {"hash": hash_value, "results": [], "status": "pkg_missing"}

    try:
        api = shodan.Shodan(api_key)
        results = api.search(f"\"{hash_value}\"")
        return {
            "hash": hash_value,
            "total": results.get("total", 0),
            "results": [
                {
                    "ip": r.get("ip_str"),
                    "port": r.get("port"),
                    "data": r.get("data", "")[:300],
                    "hostname": r.get("hostnames", [None])[0],
                }
                for r in results.get("matches", [])
            ],
            "status": "ok",
        }
    except Exception as e:
        logger.warning("Shodan search failed for %s: %s", hash_value, e)
        return {"hash": hash_value, "results": [], "status": f"error: {e}"}
