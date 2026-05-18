# -*- coding: utf-8 -*-
"""
DEPRECATED: 此文件已被 agents/observer.py 替代。
证据提取和判定逻辑已迁入 Observer Agent 的 Judge 类。
保留仅为向后兼容。新代码请使用 agents/observer.py。

inline_parser.py  响应即时解析器

【核心职责】
1. 三级回退提取页面文本块（<pre> → <code>/<samp>/output容器 → <body>纯文本）。
2. baseline diff 优先：先排除页面框架内容，再做后续过滤和校验。
3. CMDI：硬编码正则证据校验（零 Token）。
4. SQLi：交 LLM 综合判断（消耗 Token，仅在有增量回显或延时时触发）。
"""
import warnings
warnings.warn("inline_parser.py is deprecated. Use agents/observer.py instead.", DeprecationWarning, stacklevel=2)

import html as _html_mod
import re

# ============================================================
# 文本块提取：三级回退
# ============================================================

_OUTPUT_CONTAINERS = [
    re.compile(r'<pre[^>]*>([\s\S]*?)</pre>', re.IGNORECASE),
    re.compile(r'<code[^>]*>([\s\S]*?)</code>', re.IGNORECASE),
    re.compile(r'<samp[^>]*>([\s\S]*?)</samp>', re.IGNORECASE),
    re.compile(r'<div[^>]*class\s*=\s*["\'][^"\']*output[^"\']*["\'][^>]*>([\s\S]*?)</div>', re.IGNORECASE),
    re.compile(r'<output[^>]*>([\s\S]*?)</output>', re.IGNORECASE),
    re.compile(r'<textarea[^>]*readonly[^>]*>([\s\S]*?)</textarea>', re.IGNORECASE),
]


_STRIP_TAGS = re.compile(r'<[^>]*>')
_STRIP_SCRIPT = re.compile(r'<script[^>]*>[\s\S]*?</script>', re.IGNORECASE)
_STRIP_STYLE = re.compile(r'<style[^>]*>[\s\S]*?</style>', re.IGNORECASE)
_BODY_EXTRACT = re.compile(r'<body[^>]*>([\s\S]*?)</body>', re.IGNORECASE)


def _extract_text_blocks(html: str) -> str:
    """从 HTML 中提取命令输出可能存在的文本块。"""
    if not html:
        return ""

    for pattern in _OUTPUT_CONTAINERS:
        blocks = pattern.findall(html)
        if blocks:
            text = "\n".join(blocks)
            text = _STRIP_TAGS.sub('', text)
            text = _html_mod.unescape(text)
            stripped = text.strip()
            if stripped:
                return stripped

    body_match = _BODY_EXTRACT.search(html)
    body = body_match.group(1) if body_match else html
    body = _STRIP_SCRIPT.sub('', body)
    body = _STRIP_STYLE.sub('', body)

    text = _STRIP_TAGS.sub('', body)
    text = _html_mod.unescape(text)
    return text.strip()


# ============================================================
# 假阳性过滤正则
# ============================================================

_WAF_BLOCKED = re.compile(
    r'access\s+denied|blocked|forbidden|被拦截|拦截页面|403\s+Forbidden|406\s+Not\s+Acceptable',
    re.IGNORECASE,
)

_SHELL_ERRORS = re.compile(
    r'command\s+not\s+found|No\s+such\s+file|Permission\s+denied|'
    r'not\s+recognized|syntax\s+error|bad\s+substitution|'
    r'parse\s+error|unexpected\s+token|cannot\s+open|'
    r'is\s+a\s+directory|No\s+such\s+process|cannot\s+execute',
    re.IGNORECASE,
)

_EMPTY_OR_TRIVIAL = re.compile(r'^\s*$|^[\s\W_]+$')

# 无信息价值的 ping 回显（不作为证据输出）
_PING_NOISE = re.compile(
    r'(?:\d+\s+bytes\s+from|icmp_seq=|ttl=|time=[\d.]+\s*ms|'
    r'ping\s+statistics|packets\s+transmitted|rtt\s+min/avg/max)',
    re.IGNORECASE,
)


def _filter_lines(text: str) -> str:
    """对提取的文本逐行过滤，移除 WAF 拦截信息/Shell报错/空行/ping噪声。"""
    clean = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or _EMPTY_OR_TRIVIAL.match(stripped):
            continue
        if _WAF_BLOCKED.search(stripped):
            return ""
        if _SHELL_ERRORS.search(stripped):
            continue
        if _PING_NOISE.search(stripped):
            continue
        clean.append(stripped)
    return "\n".join(clean)


# ============================================================
# CMDI 证据校验（硬编码，零 Token）
# ============================================================

_SYSTEM_ACCOUNTS = (
    r'root:|daemon:|bin:|sys:|sync:|games:|man:|lp:|mail:|news:|uucp:|proxy:|'
    r'www-data:|backup:|list:|irc:|nobody:|systemd:|messagebus:|'
    r'_apt:|postgres:|mysql:|redis:|nginx:|apache:|tomcat:|jenkins:'
)

_CMDI_PASSWD_LINE = re.compile(_SYSTEM_ACCOUNTS)

_CMDI_LS_BLINDSIGHT = re.compile(
    r'[-d][r-][w-][xSs-][r-][w-][xSs-][r-][w-][xTt-]\s+\d+\s+[\w-]+\s+[\w-]+\s+\d+.*'
    r'(?:fz_|fuzz_|cmdi_|waf_)[A-Za-z0-9]{3,}'
)

_CMDI_BASE64 = re.compile(r'[A-Za-z0-9+/]{60,}')

_CMDI_CREATE_MARKER = re.compile(r'fzcr_[A-Za-z0-9]{4}')


def _has_cmdi_evidence(text: str) -> str | None:
    """CMDI 硬编码证据校验。返回匹配的证据文本或 None。"""
    lines = text.splitlines()
    evidence_lines = []

    for line in lines:
        if _CMDI_PASSWD_LINE.search(line):
            evidence_lines.append(line)
        elif _CMDI_BASE64.search(line):
            evidence_lines.append(line[:200])
        elif _CMDI_CREATE_MARKER.search(line):
            evidence_lines.append(line)
        elif _CMDI_LS_BLINDSIGHT.search(line):
            evidence_lines.append(line)

    if evidence_lines:
        return "\n".join(evidence_lines)[:2000]
    return None


# ============================================================
# SQLi 证据校验（LLM 判定，消耗 Token）
# ============================================================

def _has_sqli_evidence(
    text: str,
    payload: str,
    response_time_ms: float,
) -> str | None:
    """SQLi LLM 判定。将 payload + 回显 + 延时提交 LLM 综合判断。

    Returns:
        证据文本（含 LLM 判断原因）或 None
    """
    from llm_engine import judge_sqli_evidence

    result = judge_sqli_evidence(
        payload=payload,
        response_text=text,
        response_time_ms=response_time_ms,
    )

    if result.get("bypass", False):
        confidence = result.get("confidence", 0.0)
        reason = result.get("reason", "")
        # 构造证据摘要
        evidence_parts = []
        if text:
            evidence_parts.append(f"回显: {text[:500]}")
        if response_time_ms > 3000:
            evidence_parts.append(f"延时: {response_time_ms:.0f}ms")
        evidence_parts.append(f"LLM判定: {reason} (置信度: {confidence:.0%})")
        return " | ".join(evidence_parts)[:2000]

    return None


# ============================================================
# 硬编码证据提取：基线 diff 优先
# ============================================================

def _hardcoded_extract(
    html: str,
    baseline_html: str = "",
    payload: str = "",
    vuln_type: str = "",
    response_time_ms: float = 0.0,
) -> str | None:
    """核心提取流程：提取文本 → 基线 diff → 过滤 → 按 vuln_type 分流判定。"""
    if not html:
        return None

    # 1. 提取文本块
    text = _extract_text_blocks(html)
    if not text:
        return None

    # 2. 基线 diff
    if baseline_html:
        base_text = _extract_text_blocks(baseline_html)
        if base_text:
            base_lines = set(base_text.splitlines())
            new_lines = [l for l in text.splitlines() if l.strip() and l not in base_lines]
            if not new_lines:
                return None
            text = "\n".join(new_lines)

    # 3. 逐行过滤假阳性
    text = _filter_lines(text)
    if not text:
        return None

    # 4. 按 vuln_type 分流判定
    if vuln_type == "sqli":
        return _has_sqli_evidence(text, payload, response_time_ms)
    else:
        # CMDI / Log4j / 其他：硬编码正则判定
        return _has_cmdi_evidence(text)


# ============================================================
# 对外入口
# ============================================================

def extract_evidence(
    html: str,
    baseline_html: str = "",
    payload: str = "",
    vuln_type: str = "",
    response_time_ms: float = 0.0,
) -> str | None:
    """提取漏洞利用证据。

    分层提取文本块 → 基线行级 diff → 假阳性过滤 → 按 vuln_type 分流：
    - CMDI：硬编码正则校验（零 Token）
    - SQLi：LLM 综合判断（消耗 Token）

    Args:
        html: 完整 HTML 响应
        baseline_html: 基线 HTML（用于 diff）
        payload: 原始 payload（供 SQLi LLM 判定）
        vuln_type: 漏洞类型（cmdi/sqli/log4j）
        response_time_ms: 响应延时毫秒（供时间盲注判定）
    """
    return _hardcoded_extract(
        html, baseline_html,
        payload=payload, vuln_type=vuln_type,
        response_time_ms=response_time_ms,
    )
