# -*- coding: utf-8 -*-
"""
baseliner.py  基线采集器（硬编码版，无 AI 依赖）

【核心职责】
1. 对目标 URL 发送干净请求，采集基线 HTML。
2. 返回响应体文本供 inline_parser 做 diff 对比。
3. 不再调用 LLM 生成 Parser 脚本（解析由 inline_parser 硬编码完成）。
"""

import time

from requester import send_clean_request, warmup_session

DEFAULT_BASELINE_TIMEOUT = 10


def run_baseline(target: dict, timeout: int = DEFAULT_BASELINE_TIMEOUT) -> str:
    """采集基线响应，返回响应体 HTML 文本。

    发送最多 2 次干净请求（{{INJECT}} 替换为空），返回第一次成功的响应体。
    两次均失败则抛出 RuntimeError。

    Args:
        target: 包含 url/method/headers/body/params 的目标字典
        timeout: HTTP 请求超时秒数（应使用 config 的 request_timeout）

    Returns:
        str: 基线响应体 HTML（供 inline_parser 做行级 diff 对比）
    """
    url = target["url"]
    method = target.get("method", "GET")
    headers = target.get("headers") or {}
    body = target.get("body") or ""
    params = target.get("params") or {}

    # 预热 WAF 会话：获取新鲜 sl-session，避免雷池因过期 cookie 静默丢包
    cookie_str = headers.get("Cookie", headers.get("cookie", ""))
    warmup_session(url, cookie_str=cookie_str, timeout=timeout)

    print(f"  [BASELINE] {url[:60]} -> 采集基线 (timeout={timeout}s)")

    last_error = None
    for attempt in range(2):
        try:
            html = send_clean_request(
                url, method,
                headers=headers, body=body, params=params,
                timeout=timeout,
            )
            if html:
                print(f"  [BASELINE] 基线采集完成 ({len(html)} bytes)")
                return html
            last_error = "响应体为空"
        except Exception as e:
            last_error = str(e)
            if attempt == 0:
                time.sleep(3)

    raise RuntimeError(f"基线采集失败 (2次尝试均失败): {last_error}")
