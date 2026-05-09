from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_security = HTTPBearer(auto_error=False)
_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def verify_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> str | None:
    api_key = os.environ.get("MORDOR_API_KEY", "")
    if not api_key:
        # No key configured — allow unauthenticated access
        return None
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing API key")
    if credentials.credentials != api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return credentials.credentials


class RateLimitError(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=429, detail="Rate limit exceeded")


def rate_limit(
    request: Request,
    max_requests: int = 30,
    window_seconds: int = 60,
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - window_seconds
    timestamps = _rate_limit_store[client_ip]
    timestamps[:] = [t for t in timestamps if t > window_start]
    if len(timestamps) >= max_requests:
        raise RateLimitError()
    timestamps.append(now)
