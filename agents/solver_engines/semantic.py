from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import (
    generate_initial_payloads,
    mutate_payloads,
)


class SemanticSolver(SolverEngine):
    def __init__(self, concurrency: int = 5, timeout: int = 15, model: str = "mimo-v2.5-pro"):
        self.concurrency = concurrency
        self.timeout = timeout
        self.model = model
        self.session = requests.Session()
        self.session.trust_env = False

    def generate(self, request: SolverRequest) -> list[str]:
        """Call LLM to generate/mutate payloads."""
        if request.round_num == 0:
            result = generate_initial_payloads(
                vuln_type=request.target.vuln_type,
                target_url=request.target.url,
                model=self.model,
                kb_context=request.kb_context,
            )
        else:
            result = mutate_payloads(
                failed_payloads=request.blocked_payloads,
                vuln_type=request.target.vuln_type,
                target_url=request.target.url,
                model=self.model,
                kb_context=request.kb_context,
                force_strategy_change=False,
            )

        return result.get("payloads", [])

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """Concurrent sending of payloads."""
        target = request.target
        results: list[RawResponse] = []

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {}
            for payload in payloads:
                fut = executor.submit(self._send_single, payload, target)
                futures[fut] = payload

            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    payload = futures[fut]
                    results.append(RawResponse(
                        payload=payload,
                        status_code=0,
                        headers={},
                        body="",
                        elapsed_ms=0,
                        dimension="semantic",
                    ))

        return results

    def _send_single(self, payload: str, target) -> RawResponse:
        """Send a single payload."""
        start = time.monotonic()

        if target.method.upper() == "POST":
            body = target.body.replace("{{INJECT}}", quote(payload, safe="%"))
            resp = self.session.post(
                target.url,
                data=body,
                headers=target.headers,
                timeout=self.timeout,
                allow_redirects=False,
            )
        else:
            params = {
                k: v.replace("{{INJECT}}", payload)
                for k, v in (target.params or {}).items()
            }
            resp = self.session.get(
                target.url,
                params=params,
                headers=target.headers,
                timeout=self.timeout,
                allow_redirects=False,
            )

        elapsed = int((time.monotonic() - start) * 1000)

        return RawResponse(
            payload=payload,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text[:50000],
            elapsed_ms=elapsed,
            dimension="semantic",
        )
