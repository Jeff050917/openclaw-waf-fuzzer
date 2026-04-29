# -*- coding: utf-8 -*-
"""
inline_parser.py  响应即时解析器（硬编码版，无 AI 依赖）

【核心职责】
1. 三级回退提取页面文本块（<pre> → <code>/<samp>/output容器 → <body>纯文本）。
2. baseline diff 优先：先排除页面框架内容，再做后续过滤和校验。
3. 收紧的正则证据校验，避免假阳性。
"""

import html as _html_mod
import re

# ============================================================
# 文本块提取：三级回退
# ============================================================

# 常见命令输出容器（<pre> 之外）
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
    """从 HTML 中提取命令输出可能存在的文本块。

    三级回退：
    1. <pre> / <code> / <samp> / <output> / <div class="output"> 等常见输出容器
    2. 若以上都没有，提取 <body> 内纯文本（排除 <script> / <style>）
    3. 最终剥离残留 HTML 标签并实体解码
    """
    if not html:
        return ""

    # 1. 尝试从已知输出容器提取
    for pattern in _OUTPUT_CONTAINERS:
        blocks = pattern.findall(html)
        if blocks:
            text = "\n".join(blocks)
            text = _STRIP_TAGS.sub('', text)
            text = _html_mod.unescape(text)
            stripped = text.strip()
            if stripped:
                return stripped

    # 2. 没有已知容器 — 提取 <body> 文本
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


def _filter_lines(text: str) -> str:
    """对提取的文本逐行过滤，移除 WAF 拦截信息/Shell报错/空行。"""
    clean = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or _EMPTY_OR_TRIVIAL.match(stripped):
            continue
        if _WAF_BLOCKED.search(stripped):
            return ""  # 整页拦截 — 直接返回空
        if _SHELL_ERRORS.search(stripped):
            continue
        clean.append(stripped)
    return "\n".join(clean)


# ============================================================
# 真实证据校验 — 收紧正则
# ============================================================

# CMDI: 系统账户名+冒号（不匹配孤立的冒号）
_SYSTEM_ACCOUNTS = (
    r'root:|daemon:|bin:|sys:|sync:|games:|man:|lp:|mail:|news:|uucp:|proxy:|'
    r'www-data:|backup:|list:|irc:|nobody:|systemd:|messagebus:|'
    r'_apt:|postgres:|mysql:|redis:|nginx:|apache:|tomcat:|jenkins:'
)

_CMDI_PASSWD_LINE = re.compile(_SYSTEM_ACCOUNTS)

# CMDI: ls -la 输出中出现 fuzzer 创建的随机前缀文件
_CMDI_LS_BLINDSIGHT = re.compile(
    r'[-d][r-][w-][xSs-][r-][w-][xSs-][r-][w-][xTt-]\s+\d+\s+[\w-]+\s+[\w-]+\s+\d+.*'
    r'(?:fz_|fuzz_|cmdi_|waf_)[A-Za-z0-9]{3,}'
)

# CMDI: 长 base64 串（编码传输敏感文件，≥60 字符）
_CMDI_BASE64 = re.compile(r'[A-Za-z0-9+/]{60,}')

# SQLi: ASCII 表格边框
_SQLI_ASCII_TABLE = re.compile(r'\+\-+\+.*\n\|.*\|.*\n\+\-+\+')

# SQLi: schema 字段名
_SQLI_SCHEMA = re.compile(r'(?:TABLE_NAME|COLUMN_NAME|TABLE_SCHEMA)\s*[=:]\s*')

# SQLi: 用户数据标签（DVWA / CMS）
_SQLI_USER_DATA = re.compile(
    r'(?:First\s+name|Surname|User:|user:|Password:|pass(?:word)?:|email:)\s*\S+',
    re.IGNORECASE,
)

# SQLi: MD5 哈希（密码字段典型特征）
_SQLI_MD5 = re.compile(r'[a-fA-F0-9]{32}')

# Log4j: JNDI 引用
_LOG4J_JNDI = re.compile(r'Reference\s+Class\s+Name', re.IGNORECASE)


_EVIDENCE_PATTERNS = [
    _CMDI_PASSWD_LINE,
    _CMDI_LS_BLINDSIGHT,
    _CMDI_BASE64,
    _SQLI_ASCII_TABLE,
    _SQLI_SCHEMA,
    _SQLI_USER_DATA,
    _SQLI_MD5,
    _LOG4J_JNDI,
]


def _has_real_evidence(text: str) -> bool:
    """收紧后的证据校验：系统账户名+冒号 / ls盲注 / base64 / SQL表格 / MD5 / JNDI。"""
    return any(p.search(text) for p in _EVIDENCE_PATTERNS)


# ============================================================
# 硬编码证据提取：基线 diff 优先
# ============================================================

def _hardcoded_extract(html: str, baseline_html: str = "") -> str | None:
    """核心提取流程：提取文本 → 基线 diff → 过滤 → 证据校验。"""
    if not html:
        return None

    # 1. 提取文本块
    text = _extract_text_blocks(html)
    if not text:
        return None

    # 2. 基线 diff（第一步就做，尽早排除页面框架）
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

    # 4. 真实证据校验
    if not _has_real_evidence(text):
        return None

    return text[:2000]


# ============================================================
# 对外入口
# ============================================================

def extract_evidence(html: str, baseline_html: str = "") -> str | None:
    """提取漏洞利用证据（硬编码版）。

    分层提取文本块 → 基线行级 diff → 假阳性过滤 → 收紧的证据正则校验。
    任何环节失败均返回 None（判定为无效/被拦截）。
    """
    return _hardcoded_extract(html, baseline_html)
