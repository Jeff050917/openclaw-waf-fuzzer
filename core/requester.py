# -*- coding: utf-8 -*-
"""
requester.py  HTTP 发包客户端

【核心职责】
1. 根据 target.yaml 配置构建 HTTP 请求（支持 GET/POST）。
2. 将 Payload 替换进 {{INJECT}} 占位符后发送。
3. 短路拦截：403/406 等状态码直接返回 blocked 信号，不读取响应体。
4. LLM 驱动的通用 Session 预热（非硬编码 DVWA）。
5. 超时控制 + 异常捕获，保证高频发包稳定性。
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, quote, urlparse

import requests

from inline_parser import extract_evidence as parse_evidence

DEFAULT_TIMEOUT = 10
BLOCKED_STATUSES = {403, 406, 501, 429}

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
# Cookie 与 Session 管理
# ============================================================

def _parse_cookies(cookie_str: str) -> dict[str, str]:
    """解析原始 Cookie 头字符串 → {key: value}。"""
    cookies: dict[str, str] = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if "=" in item:
            key, _, value = item.partition("=")
            cookies[key.strip()] = value.strip()
    return cookies


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


def _prepare_headers(raw_headers: dict | None) -> dict:
    """合并基础头 + 调用方头，剥离 Cookie（由 Session jar 管理）。"""
    merged = dict(_FALLBACK_HEADERS)
    if raw_headers:
        raw_headers.pop("Cookie", raw_headers.pop("cookie", None))
        merged.update(raw_headers)
    return merged


# ============================================================
# 工具函数：替换 {{INJECT}} 占位符
# ============================================================

def _inject_payload(template: str, payload: str, inject_tag: str = "{{INJECT}}") -> str:
    """将模板字符串中的 inject_tag 替换为 payload，若没有占位符则追加到末尾。"""
    if inject_tag in template:
        return template.replace(inject_tag, payload)
    return template + payload


# ============================================================
# 干净请求（供 baseliner 使用）
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


# ============================================================
# 单 Payload 发送
# ============================================================

def send_payload(
    url: str,
    method: str = "GET",
    payload: str = "",
    headers: dict | None = None,
    body: str = "",
    params: dict | None = None,
    inject_tag: str = "{{INJECT}}",
    timeout: int = DEFAULT_TIMEOUT,
    baseline_html: str = "",
    vuln_type: str = "",
) -> dict:
    """
    发送单个 Payload。响应到达后第一时间调用 Parser 提取证据。

    返回格式:
    {
        "payload": str,        # 原始 payload
        "status_code": int,    # HTTP 状态码 (异常时为 0)
        "text": str,           # Parser 提取的证据文本（不再是完整 HTML）
        "evidence": str | None,# 提取到的漏洞利用证据
        "elapsed": float,      # 耗时(秒)
        "blocked": bool,       # 是否被 WAF 拦截
        "error": str | None,   # 异常信息（成功时为 None）
    }
    """
    headers = _prepare_headers(headers)
    _params = dict(params or {})

    result = {
        "payload": payload,
        "status_code": 0,
        "text": "",
        "evidence": None,
        "elapsed": 0.0,
        "blocked": False,
        "error": None,
    }

    # 构造请求参数（替换 {{INJECT}}）
    req_body = _inject_payload(body, quote(payload, safe='%'), inject_tag) if body else ""
    req_params = {
        k: _inject_payload(v, payload, inject_tag) for k, v in _params.items()
    } if _params else {}

    try:
        t0 = time.perf_counter()

        if method.upper() == "POST":
            resp = _SESSION.post(
                url,
                data=req_body,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            resp = _SESSION.get(
                url,
                params=req_params,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )

        elapsed = time.perf_counter() - t0
        result["status_code"] = resp.status_code
        result["elapsed"] = round(elapsed, 3)

        # 短路拦截 —— 不读 body
        if resp.status_code in BLOCKED_STATUSES:
            result["blocked"] = True
            result["text"] = ""
        else:
            full_html = resp.text
            # 第一时间调用 Parser 提取证据，传递 vuln_type/payload/elapsed 供 LLM 判定
            evidence = parse_evidence(
                full_html, baseline_html,
                payload=payload, vuln_type=vuln_type,
                response_time_ms=elapsed * 1000,
            )
            if evidence:
                result["evidence"] = evidence
                result["text"] = evidence
            else:
                result["evidence"] = None
                result["text"] = ""

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        result["blocked"] = True
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection_error: {e}"
        result["blocked"] = True
    except requests.exceptions.RequestException as e:
        result["error"] = f"request_exception: {e}"
        result["blocked"] = True
    except Exception as e:
        result["error"] = f"unexpected: {e}"
        result["blocked"] = True

    return result


# ============================================================
# CMDI 标记文件清理（防止跨轮 ls 污染）
# ============================================================

_CMDI_CLEANUP_PAYLOADS = [
    "rm -f /tmp/fz_* /tmp/fuzz_* /tmp/fuzztest_* /tmp/cmdi_* /tmp/waf_*",
    "rm -f /var/tmp/fz_* /var/tmp/fuzz_*",
    "rm -f /dev/shm/fz_* /dev/shm/fuzz_*",
]


def send_cmdi_cleanup(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str = "",
    params: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> None:
    """Best-effort 清理 CMDI 测试残留的标记文件。"""
    for cleanup_payload in _CMDI_CLEANUP_PAYLOADS:
        try:
            send_payload(
                url=url,
                method=method,
                payload=cleanup_payload,
                headers=headers,
                body=body,
                params=params,
                timeout=timeout,
            )
        except Exception:
            pass


# ============================================================
# 批量发送（并发）
# ============================================================

def batch_send(
    url: str,
    method: str = "GET",
    payloads: list[str] | None = None,
    headers: dict | None = None,
    body: str = "",
    params: dict | None = None,
    concurrency: int = 5,
    timeout: int = DEFAULT_TIMEOUT,
    baseline_html: str = "",
    vuln_type: str = "",
) -> list[dict]:
    """
    批量发送 Payload（ThreadPoolExecutor 并发）。

    返回: list[dict]  每个元素同 send_payload 的返回值
    """
    if payloads is None:
        payloads = []

    results = []

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        futures = {
            executor.submit(
                send_payload,
                url,
                method,
                p,
                headers,
                body,
                params,
                "{{INJECT}}",
                timeout,
                baseline_html,
                vuln_type,
            ): i
            for i, p in enumerate(payloads)
        }
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                idx = futures[fut]
                results.append(
                    {
                        "payload": payloads[idx] if idx < len(payloads) else "?",
                        "status_code": 0,
                        "text": "",
                        "elapsed": 0,
                        "blocked": True,
                        "error": str(e),
                    }
                )

    return results
