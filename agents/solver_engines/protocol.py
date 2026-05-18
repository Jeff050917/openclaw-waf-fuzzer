from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class ProtocolSolver(SolverEngine):
    """协议层绕过：HPP、双重编码、Method 切换、Header 注入等。"""

    def __init__(self, concurrency: int = 5, timeout: int = 15, model: str = "mimo-v2.5-pro"):
        self.concurrency = concurrency
        self.timeout = timeout
        self.model = model

    def generate(self, request: SolverRequest) -> list[str]:
        """LLM 生成协议层绕过 payload。"""
        waf_info = ""
        if request.waf_profile:
            waf_info = f"WAF: {request.waf_profile.waf_name}\n绕过提示: {request.waf_profile.bypass_tips}"

        prompt = f"""你是 HTTP 协议层绕过专家。根据目标信息生成利用 HTTP 解析差异的绕过 payload。

目标: {request.target.url}
参数: {request.target.param}
注入类型: {request.target.vuln_type}
推测后端: {request.target.inferred_context}
{waf_info}

可用的协议层绕过技术：
1. 参数污染 (HPP)：同名参数重复，WAF 检查第一个但后端取最后一个
2. 双重编码：URL 编码两层，WAF 解一层放行，后端解两层
3. HTTP Method 切换：GET→POST/PUT/OPTIONS
4. Content-Type 畸形：application/json + 实际 form body
5. Header 注入：X-Forwarded-For、X-Original-URL 注入 payload
6. Chunked Transfer-Encoding 走私

请生成 10 个 payload，每个 payload 用一行描述绕过技术。

返回 JSON：{{"payloads": ["payload1", "payload2", ...]}}"""

        result = _chat_json(prompt, model=self.model, temperature=0.7, max_tokens=2048)
        if isinstance(result, dict):
            return result.get("payloads", [])
        return []

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """发包。"""
        results: list[RawResponse] = []
        session = requests.Session()
        session.trust_env = False

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
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
                        headers={}, body="", elapsed_ms=0, dimension="protocol",
                    ))
        return results

    def _send_single(self, payload: str, request: SolverRequest, session: requests.Session) -> RawResponse:
        target = request.target
        start = time.monotonic()

        headers = dict(target.headers)

        if target.method.upper() == "GET":
            params = {k: v.replace("{{INJECT}}", payload) for k, v in (target.params or {}).items()}
            resp = session.get(target.url, params=params, headers=headers, timeout=self.timeout, allow_redirects=False)
        else:
            body = (target.body or "").replace("{{INJECT}}", quote(payload, safe="%"))
            resp = session.post(target.url, data=body, headers=headers, timeout=self.timeout, allow_redirects=False)

        elapsed = int((time.monotonic() - start) * 1000)
        return RawResponse(
            payload=payload, status_code=resp.status_code,
            headers=dict(resp.headers), body=resp.text[:50000],
            elapsed_ms=elapsed, dimension="protocol",
        )
