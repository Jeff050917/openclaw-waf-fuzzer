# -*- coding: utf-8 -*-
"""
requester.py  HTTP 发包客户端

【核心职责】
1. 根据 target.yaml 配置构建 HTTP 请求（支持 GET/POST）。
2. 将 Payload 替换进 {{INJECT}} 占位符后发送。
3. 短路拦截：403/406 等状态码直接返回 blocked 信号，不读取响应体。
4. 超时控制 + 异常捕获，保证高频发包稳定性。
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
    """预热 WAF 会话：访问根路径获取新鲜 sl-session，然后自动登录 DVWA。

    雷池 WAF 将 sl-session 与 PHPSESSID 绑定——不同 sl-session 下的 PHPSESSID
    混用会被判定为 session 篡改并静默丢包。因此预热流程必须：
    1. GET / 获取 WAF 分配的 sl-session + 新的 PHPSESSID
    2. POST /login.php 用 admin/password 登录，使新 PHPSESSID 得到认证

    cookie_str 参数仅用于提取 security 等级（若存在），PHPSESSID 不再保留。

    Returns:
        True 表示预热+登录成功，False 表示失败（不阻塞主流程）。
    """
    parsed = urlparse(target_url)
    host_key = f"{parsed.hostname}:{parsed.port or 80}"

    if host_key in _WARMED_HOSTS:
        return True

    base_url = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        base_url += f":{parsed.port}"

    try:
        # 1. 访问根路径 → WAF 分配 sl-session + DVWA 分配 PHPSESSID
        _SESSION.get(
            base_url + "/",
            headers=_FALLBACK_HEADERS,
            timeout=timeout,
            allow_redirects=False,
        )

        # 2. DVWA 登录 — 需要先 GET login.php 获取 CSRF user_token
        login_page = _SESSION.get(
            base_url + "/login.php",
            headers=_FALLBACK_HEADERS,
            timeout=timeout,
        )
        token_match = re.search(
            r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]",
            login_page.text,
        )
        user_token = token_match.group(1) if token_match else ""

        _SESSION.post(
            base_url + "/login.php",
            data=f"username=admin&password=password&Login=Login&user_token={user_token}",
            headers={**_FALLBACK_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
            allow_redirects=False,
        )

        # 3. 设置 security=low（DVWA 安全等级）
        _SESSION.get(
            base_url + "/security.php",
            params={"security": "low", "seclev_submit": "Submit"},
            headers=_FALLBACK_HEADERS,
            timeout=timeout,
            allow_redirects=False,
        )

        _WARMED_HOSTS.add(host_key)
        return True
    except Exception:
        return False


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
    # POST body: URL 编码 payload，防止 &&、| 等被当作参数分隔符截断。
    # safe='%' 保留已编码的 %XX 序列（如 %0a 换行注入），防止双重编码。
    # GET params: requests 库自动编码，此处不预编码。
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
            # 第一时间调用 Parser 提取证据，严禁将完整 HTML 传递给下游
            evidence = parse_evidence(full_html, baseline_html)
            if evidence:
                result["evidence"] = evidence
                result["text"] = evidence  # 下游只看到证据，看不到 HTML
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
    """Best-effort 清理 CMDI 测试残留的标记文件。

    每次 CMDI fuzzing 前调用，删除上一轮可能残留的临时文件，
    防止 ls 输出中出现旧文件导致假阳性。清理失败不影响主流程。
    """
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
            pass  # Best-effort，被 WAF 拦截也无所谓


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
                baseline_html,  # 传递基线以便 parser 做差异对比
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

    # 结果以线程完成顺序返回（调用方按 payload 字符串匹配，不依赖顺序）
    return results
