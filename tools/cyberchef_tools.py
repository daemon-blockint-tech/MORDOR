from __future__ import annotations

import base64
import html
import urllib.parse


def decode_base64(data: str) -> str:
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except Exception:
        return ""


def decode_hex(data: str) -> str:
    try:
        clean = data.replace("\\x", "").replace("0x", "").replace(" ", "")
        return bytes.fromhex(clean).decode("utf-8", errors="replace")
    except Exception:
        return ""


def xor_decode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def decode_url(data: str) -> str:
    try:
        return urllib.parse.unquote(data)
    except Exception:
        return ""


def decode_html_entities(data: str) -> str:
    try:
        return html.unescape(data)
    except Exception:
        return ""


def try_all(data: str) -> list[dict]:
    results = []
    for name, decoder, expects_str in [
        ("base64", decode_base64, True),
        ("hex", decode_hex, True),
        ("url_decode", decode_url, True),
        ("html_entities", decode_html_entities, True),
    ]:
        decoded = decoder(data)
        if decoded and decoded != data:
            results.append({"encoding": name, "original": data, "decoded": decoded, "status": "ok"})

    for key in range(256):
        try:
            raw = data.encode("latin-1") if isinstance(data, str) else data
            decoded = xor_decode(raw, key)
            text = decoded.decode("utf-8", errors="replace")
            if text.isprintable() and len(text) > 4:
                results.append({"encoding": f"xor_key_0x{key:02x}", "original": data, "decoded": text, "status": "ok"})
                break
        except Exception:
            pass

    return results
