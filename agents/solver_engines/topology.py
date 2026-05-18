from __future__ import annotations

import time

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class TopologySolver(SolverEngine):
    """拓扑层绕过：发现真实源 IP，绕过前端 WAF 直接访问源站。"""

    def __init__(self, timeout: int = 15, model: str = "mimo-v2.5-pro"):
        self.timeout = timeout
        self.model = model

    def generate(self, request: SolverRequest) -> list[str]:
        """生成源 IP 探测命令和直连 payload。"""
        from urllib.parse import urlparse
        parsed = urlparse(request.target.url)
        hostname = parsed.hostname

        prompt = f"""你是架构拓扑分析师。目标域名: {hostname}

请分析可能的绕过方式：
1. 如果目标有 CDN，如何发现真实源 IP？
2. 如果发现源 IP，如何构造直连请求？

返回 JSON：{{
  "analysis": "分析",
  "source_ips": ["可能的源 IP 列表"],
  "direct_payloads": ["直连 payload 列表"]
}}"""

        result = _chat_json(prompt, model=self.model, temperature=0.3, max_tokens=1024)
        if not isinstance(result, dict):
            return []

        payloads = result.get("direct_payloads", [])
        source_ips = result.get("source_ips", [])

        # 如果发现源 IP，生成直连 URL 的 payload
        if source_ips:
            for ip in source_ips:
                direct_url = request.target.url.replace(hostname, ip)
                payloads.append(f"DIRECT:{direct_url}")

        return payloads

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """对源 IP 直连发包。"""
        results: list[RawResponse] = []
        session = requests.Session()
        session.trust_env = False

        for payload in payloads:
            if payload.startswith("DIRECT:"):
                url = payload[7:]  # 去掉 "DIRECT:" 前缀
                try:
                    start = time.monotonic()
                    resp = session.get(url, timeout=self.timeout, allow_redirects=False)
                    elapsed = int((time.monotonic() - start) * 1000)
                    results.append(RawResponse(
                        payload=payload, status_code=resp.status_code,
                        headers=dict(resp.headers), body=resp.text[:50000],
                        elapsed_ms=elapsed, dimension="topology",
                    ))
                except Exception:
                    results.append(RawResponse(
                        payload=payload, status_code=0,
                        headers={}, body="", elapsed_ms=0, dimension="topology",
                    ))
            else:
                # 非直连 payload，按普通方式发送
                results.append(RawResponse(
                    payload=payload, status_code=0,
                    headers={}, body="topology: non-direct payload", elapsed_ms=0,
                    dimension="topology",
                ))

        return results
