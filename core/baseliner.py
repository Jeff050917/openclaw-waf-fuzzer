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

import requests

DEFAULT_TIMEOUT = 10

# 共享 Session：trust_env=False 阻止 Windows 系统代理检测（WPAD/PAC），
# 否则即使显式传 proxies=None 也会因代理检测 hang 住直到超时。
_SESSION = requests.Session()
_SESSION.trust_env = False

# 记录已预热过的 host:port，避免重复预热
_WARMED_HOSTS: set[str] = set()

# WAF 可能需要的基础浏览器特征头（UA/Cookie 由调用方传入，此处补 Accept 等）
_FALLBACK_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
}


# ============================================================
# 工具函数
# ============================================================

def _prepare_headers(raw_headers: dict | None) -> dict:
    """合并基础头 + 调用方头，剥离 Cookie（由 Session jar 管理）。"""
    merged = dict(_FALLBACK_HEADERS)
    if raw_headers:
        raw_headers.pop("Cookie", raw_headers.pop("cookie", None))
        merged.update(raw_headers)
    return merged


# ============================================================
# LLM 驱动的 Session 预热
# ============================================================

def warmup_session(target_url: str, cookie_str: str = "", timeout: int = DEFAULT_TIMEOUT) -> bool:
    """LLM 驱动的通用 Session 预热。

    流程：
    1. GET 目标页面 → 获取页面内容和初始 Cookie
    2. LLM 分析页面 → 判断是否需要登录、登录表单字段、CSRF token 等
    3. 按 LLM 指令执行登录流程（GET/POST 序列）
    4. 失败时将错误反馈给 LLM，LLM 分析原因并调整方案，最多 3 次

    Returns:
        True 表示预热成功（或不需要登录），False 表示失败。
    """
    parsed = urlparse(target_url)
    host_key = f"{parsed.hostname}:{parsed.port or 80}"

    if host_key in _WARMED_HOSTS:
        return True

    base_url = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        base_url += f":{parsed.port}"

    try:
        # 1. 访问目标页面获取初始 Cookie 和页面内容
        resp = _SESSION.get(
            target_url,
            headers=_FALLBACK_HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
        page_content = resp.text

        # 2. 调用 LLM 分析页面
        from llm_engine import analyze_login_page, analyze_warmup_failure
        analysis = analyze_login_page(target_url, page_content)

        if not analysis.get("need_login", False):
            _WARMED_HOSTS.add(host_key)
            return True

        # 3. 按 LLM 指令执行登录流程（最多 3 次尝试）
        current_plan = analysis
        for attempt in range(3):
            success, status_code, response_text, error = _execute_login(
                base_url, current_plan, timeout
            )
            if success:
                _WARMED_HOSTS.add(host_key)
                return True

            # 失败 → LLM 分析原因并调整方案
            if attempt < 2:
                failure_analysis = analyze_warmup_failure(
                    target_url=target_url,
                    last_plan=current_plan,
                    status_code=status_code,
                    response_text=response_text,
                    error=error,
                )
                diagnosis = failure_analysis.get("diagnosis", "")
                new_plan = failure_analysis.get("new_plan", {})
                if new_plan:
                    current_plan = {**current_plan, **new_plan}
                print(f"  [WARMUP] 登录失败 (尝试 {attempt+1}/3): {diagnosis[:100]}")
            else:
                print(f"  [WARMUP] 登录失败 (3次均失败): {error[:100]}")

        return False

    except Exception as e:
        print(f"  [WARMUP] 预热异常: {e}")
        return False


def _execute_login(base_url: str, plan: dict, timeout: int) -> tuple[bool, int, str, str]:
    """按 LLM 指令执行登录流程。

    Returns:
        (success, status_code, response_text, error)
    """
    login_url = plan.get("login_url", "")
    if not login_url:
        return False, 0, "", "无登录 URL"

    # 处理相对 URL
    if login_url.startswith("/"):
        login_url = base_url + login_url
    elif not login_url.startswith("http"):
        login_url = base_url + "/" + login_url

    fields = plan.get("fields", {})
    credentials = plan.get("credentials", {})
    csrf_info = plan.get("csrf_token", {})
    extra_steps = plan.get("extra_steps", [])

    try:
        # 执行额外步骤（如先访问某个页面获取 cookie）
        for step in extra_steps:
            if step.startswith("GET "):
                step_url = step[4:].strip()
                if step_url.startswith("/"):
                    step_url = base_url + step_url
                _SESSION.get(step_url, headers=_FALLBACK_HEADERS, timeout=timeout, allow_redirects=False)
            elif step.startswith("POST "):
                step_url = step[5:].strip()
                if step_url.startswith("/"):
                    step_url = base_url + step_url
                _SESSION.post(step_url, headers=_FALLBACK_HEADERS, timeout=timeout, allow_redirects=False)

        # 提取 CSRF token（如果需要）
        csrf_token = ""
        if csrf_info.get("exists", False):
            # 先 GET 登录页面
            login_page_resp = _SESSION.get(login_url, headers=_FALLBACK_HEADERS, timeout=timeout)
            page_text = login_page_resp.text

            regex = csrf_info.get("regex", "")
            selector = csrf_info.get("selector", "")

            if regex:
                match = re.search(regex, page_text)
                if match:
                    csrf_token = match.group(1) if match.lastindex else match.group(0)
            elif selector:
                # 尝试从 name='xxx' 的 input 中提取
                match = re.search(
                    rf"name=['\"]{re.escape(selector)}['\"]\s+value=['\"]([^'\"]+)['\"]",
                    page_text,
                )
                if match:
                    csrf_token = match.group(1)

        # 构造登录数据
        username_field = fields.get("username_field", "username")
        password_field = fields.get("password_field", "password")
        username = credentials.get("username", "admin")
        password = credentials.get("password", "password")

        login_data = f"{username_field}={username}&{password_field}={password}"
        if csrf_token:
            # 尝试常见的 CSRF 字段名
            for csrf_field in ["user_token", "csrf_token", "_token", "authenticity_token"]:
                if csrf_field in str(plan):
                    login_data += f"&{csrf_field}={csrf_token}"
                    break
            else:
                login_data += f"&user_token={csrf_token}"

        login_data += "&Login=Login&Submit=Submit"

        resp = _SESSION.post(
            login_url,
            data=login_data,
            headers={**_FALLBACK_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
            allow_redirects=False,
        )

        # 检查登录是否成功
        verify_feature = plan.get("verify_feature", "")
        if resp.status_code in (301, 302, 303, 307, 308):
            # 重定向通常表示登录成功
            return True, resp.status_code, "", ""
        elif resp.status_code == 200:
            if verify_feature and verify_feature in resp.text:
                return True, resp.status_code, resp.text[:1500], ""
            elif "logout" in resp.text.lower() or "dashboard" in resp.text.lower():
                return True, resp.status_code, "", ""
            else:
                return False, resp.status_code, resp.text[:1500], "登录后未检测到成功特征"
        else:
            return False, resp.status_code, resp.text[:1500], f"HTTP {resp.status_code}"

    except Exception as e:
        return False, 0, "", str(e)


# ============================================================
# 干净请求（供 Manager 使用）
# ============================================================

def send_clean_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str = "",
    params: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """
    发送不带 Payload 的干净请求（{{INJECT}} 替换为空字符串）。
    返回响应体文本。
    """
    headers = _prepare_headers(headers)
    params = dict(params or {})

    clean_body = body.replace("{{INJECT}}", "")
    clean_params = {k: v.replace("{{INJECT}}", "") for k, v in params.items()}

    if method.upper() == "POST":
        resp = _SESSION.post(
            url,
            data=clean_body,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )
    else:
        resp = _SESSION.get(
            url,
            params=clean_params,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )

    return resp.text


DEFAULT_BASELINE_TIMEOUT = DEFAULT_TIMEOUT


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
