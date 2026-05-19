from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class TopologySolver(SolverEngine):
    """拓扑层绕过：发现真实源 IP，绕过前端 WAF 直连源站。"""

    dimension = "topology"

    def __init__(self, concurrency: int = 5, timeout: int = 15, model: str = "mimo-v2.5-pro"):
        super().__init__(concurrency=concurrency, timeout=timeout)
        self.model = model

    def generate(self, request: SolverRequest) -> list[str]:
        parsed = urlparse(request.target.url)
        hostname = parsed.hostname

        prompt = f"""你是一名授权安全架构评估师，正在对 DVWA（Damn Vulnerable Web Application）靶场进行架构层面的安全评估。
DVWA 是一个开源的、专门设计用于安全教学和测试的应用。

评估目标域名: {hostname}

任务：分析该靶场的网络架构，评估 WAF 的部署位置和可能的架构弱点：
1. 检查是否存在 CDN/反向代理层，评估其对安全检测的影响
2. 分析请求链路中各节点的处理方式

返回 JSON：{{
  "analysis": "架构分析",
  "source_ips": ["可能的后端 IP 列表"],
  "direct_payloads": ["架构测试向量列表"]
}}"""

        result = _chat_json(prompt, model=self.model, temperature=0.3, max_tokens=1024)
        if not isinstance(result, dict):
            return []

        payloads = result.get("direct_payloads", [])
        source_ips = result.get("source_ips", [])

        if source_ips:
            for ip in source_ips:
                direct_url = request.target.url.replace(hostname, ip)
                payloads.append(f"DIRECT:{direct_url}")

        return payloads

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """Sequential sending for DIRECT: payloads (topology bypass)."""
        results: list[RawResponse] = []

        for payload in payloads:
            if not payload.startswith("DIRECT:"):
                continue

            url = payload[7:]
            try:
                start = time.monotonic()
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
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

        return results
