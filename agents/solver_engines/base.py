from __future__ import annotations

import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from agents.models import SolverRequest, RawResponse


class SolverEngine(ABC):
    """Base class for dimension-specific solver engines.

    Provides shared HTTP dispatch (`_send_single`) and concurrent sending
    (`send`). Subclasses only need to implement `generate()`.
    """

    dimension: str = ""  # subclasses must set this

    def __init__(self, concurrency: int = 5, timeout: int = 15, **kwargs):
        self.concurrency = concurrency
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False

    @abstractmethod
    def generate(self, request: SolverRequest) -> list[str]:
        ...

    def _pre_send_hook(self) -> None:
        """Called before each HTTP send. Override for delays, etc."""

    def _send_single(self, payload: str, target) -> RawResponse:
        """Send a single payload to the target. Override for custom dispatch."""
        self._pre_send_hook()
        start = time.monotonic()

        headers = dict(target.headers)

        if target.method.upper() == "POST":
            body = (target.body or "").replace("{{INJECT}}", quote(payload, safe="%"))
            resp = self.session.post(
                target.url, data=body, headers=headers,
                timeout=self.timeout, allow_redirects=False,
            )
        else:
            params = {k: v.replace("{{INJECT}}", payload) for k, v in (target.params or {}).items()}
            resp = self.session.get(
                target.url, params=params, headers=headers,
                timeout=self.timeout, allow_redirects=False,
            )

        elapsed = int((time.monotonic() - start) * 1000)
        return RawResponse(
            payload=payload, status_code=resp.status_code,
            headers=dict(resp.headers), body=resp.text[:50000],
            elapsed_ms=elapsed, dimension=self.dimension,
        )

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """Concurrent sending using shared session and thread pool."""
        target = request.target
        results: list[RawResponse] = []
        effective_concurrency = min(self.concurrency, len(payloads))

        with ThreadPoolExecutor(max_workers=effective_concurrency) as executor:
            futures = {
                executor.submit(self._send_single, p, target): p
                for p in payloads
            }
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    results.append(RawResponse(
                        payload=futures[fut], status_code=0,
                        headers={}, body="", elapsed_ms=0,
                        dimension=self.dimension,
                    ))
        return results
