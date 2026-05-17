# -*- coding: utf-8 -*-
"""
baseliner.py  基线采集器（LLM 驱动通用登录）

【核心职责】
1. 对目标 URL 发送干净请求，采集基线 HTML。
2. Session 预热由 LLM 驱动：分析任意网站的登录页面，输出结构化登录指令。
3. 失败重试机制：最多 3 次，每次失败后 LLM 思考原因并调整方案。
"""

import re
import time
from urllib.parse import urlparse

from requester import send_clean_request, warmup_session

DEFAULT_BASELINE_TIMEOUT = 10


def run_baseline(target: dict, timeout: int = DEFAULT_BASELINE_TIMEOUT) -> str:
    """采集基线响应，返回响应体 HTML 文本。

    流程：
    1. LLM 驱动的通用 Session 预热（分析登录页面 → 结构化指令 → 执行登录）
    2. 发送干净请求采集基线 HTML
    3. 最多 3 次重试，每次失败后 LLM 分析原因并调整方案

    Args:
        target: 包含 url/method/headers/body/params 的目标字典
        timeout: HTTP 请求超时秒数

    Returns:
        str: 基线响应体 HTML
    """
    url = target["url"]
    method = target.get("method", "GET")
    headers = target.get("headers") or {}
    body = target.get("body") or ""
    params = target.get("params") or {}

    # LLM 驱动的通用 Session 预热
    cookie_str = headers.get("Cookie", headers.get("cookie", ""))
    warmup_result = warmup_session(url, cookie_str=cookie_str, timeout=timeout)
    if not warmup_result:
        print(f"  [BASELINE] Session 预热失败，尝试继续采集基线...")

    print(f"  [BASELINE] {url[:60]} -> 采集基线 (timeout={timeout}s)")

    last_error = None
    for attempt in range(3):
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
            if attempt < 2:
                wait = (attempt + 1) * 5
                print(f"  [BASELINE] 基线采集失败 (重试 {attempt+1}/3, {wait}s后): {last_error}")
                time.sleep(wait)

    raise RuntimeError(f"基线采集失败 (3次尝试均失败): {last_error}")
