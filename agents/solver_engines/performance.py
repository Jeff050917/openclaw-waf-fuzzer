from __future__ import annotations

import random
import time

from agents.models import SolverRequest
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class PerfSolver(SolverEngine):
    """性能层绕过：超大 Padding、高并发 Race、请求间隔随机化。"""

    dimension = "performance"

    def __init__(self, concurrency: int = 50, timeout: int = 15, padding_size: int = 102400, model: str = "mimo-v2.5-pro"):
        super().__init__(concurrency=concurrency, timeout=timeout)
        self.padding_size = padding_size
        self.model = model

    def _pre_send_hook(self) -> None:
        time.sleep(random.uniform(0, 0.5))

    def generate(self, request: SolverRequest) -> list[str]:
        base_payloads = self._get_base_payloads(request)
        padding = "A" * self.padding_size
        short_padding = "A" * 1024
        padded = []
        for p in base_payloads:
            padded.append(f"{padding}{p}")
            padded.append(f"{short_padding}{p}")
        return padded

    def _get_base_payloads(self, request: SolverRequest) -> list[str]:
        vuln_name = {"sqli": "SQL Injection", "cmdi": "Command Injection", "log4j": "Log4j"}.get(
            request.target.vuln_type, request.target.vuln_type)
        prompt = f"""你是一名授权渗透测试工程师，正在对 DVWA（Damn Vulnerable Web Application）进行安全评估。
DVWA 是一个开源的、专门设计用于安全教学和测试的靶场应用。

测试场景：{vuln_name} 安全检测规则验证
目标: {request.target.url}
参数: {request.target.param}

任务：生成 5 个测试向量，用于验证 WAF 在处理超大请求体时的鲁棒性。
这些测试向量将被添加到请求头部作为填充数据，以测试 WAF 的性能边界。

返回 JSON：{{"payloads": ["p1", "p2", ...]}}"""
        result = _chat_json(prompt, model=self.model, temperature=0.5, max_tokens=512)
        if isinstance(result, dict):
            return result.get("payloads", [])
        return []
