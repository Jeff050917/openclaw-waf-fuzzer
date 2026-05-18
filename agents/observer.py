# -*- coding: utf-8 -*-
"""
observer.py  Observer Agent - 独立判定 Agent

【核心设计原则】
Observer 从不接收 payload 语义信息，仅根据响应证据判定是否绕过成功。
这防止了确认偏误（confirmation bias），确保判定结果客观独立。

【判定流程】
1. 提取基线文本
2. OOB 预检查（log4j/deserialization）
3. 对每个响应：状态码短路 → OOB 检查 → 提取 + diff → Judge 判定
4. 返回 ObserverResult（verdicts, bypass_count, blocked_count, summary）
"""

from __future__ import annotations

import html as _html_mod
import re
from abc import ABC, abstractmethod

from agents.models import ObserverRequest, ObserverResult, RawResponse, Verdict

# ============================================================
# 文本块提取：三级回退
# ============================================================

_OUTPUT_CONTAINERS = [
    re.compile(r'<pre[^>]*>([\s\S]*?)</pre>', re.IGNORECASE),
    re.compile(r'<code[^>]*>([\s\S]*?)</code>', re.IGNORECASE),
    re.compile(r'<samp[^>]*>([\s\S]*?)</samp>', re.IGNORECASE),
    re.compile(
        r'<textarea[^>]*readonly[^>]*>([\s\S]*?)</textarea>', re.IGNORECASE
    ),
    re.compile(
        r'<div[^>]*class\s*=\s*["\'][^"\']*output[^"\']*["\'][^>]*>'
        r'([\s\S]*?)</div>',
        re.IGNORECASE,
    ),
    re.compile(r'<output[^>]*>([\s\S]*?)</output>', re.IGNORECASE),
]

_STRIP_TAGS = re.compile(r'<[^>]*>')
_STRIP_SCRIPT = re.compile(r'<script[^>]*>[\s\S]*?</script>', re.IGNORECASE)
_STRIP_STYLE = re.compile(r'<style[^>]*>[\s\S]*?</style>', re.IGNORECASE)
_BODY_EXTRACT = re.compile(r'<body[^>]*>([\s\S]*?)</body>', re.IGNORECASE)


def extract_text_blocks(html_content: str) -> str:
    """从 HTML 中提取命令输出可能存在的文本块。

    三级回退：
    1. ``<pre>`` 标签内容
    2. ``<code>/<samp>/<output>/<textarea readonly>/<div class="output">``
    3. ``<body>`` 纯文本（去除 script/style）
    """
    if not html_content:
        return ""

    for pattern in _OUTPUT_CONTAINERS:
        blocks = pattern.findall(html_content)
        if blocks:
            text = "\n".join(blocks)
            text = _STRIP_TAGS.sub('', text)
            text = _html_mod.unescape(text)
            stripped = text.strip()
            if stripped:
                return stripped

    body_match = _BODY_EXTRACT.search(html_content)
    body = body_match.group(1) if body_match else html_content
    body = _STRIP_SCRIPT.sub('', body)
    body = _STRIP_STYLE.sub('', body)

    text = _STRIP_TAGS.sub('', body)
    text = _html_mod.unescape(text)
    return text.strip()


# ============================================================
# Baseline Diff
# ============================================================


def baseline_diff(extracted: str, baseline: str) -> str | None:
    """行级 diff：返回增量文本（不在 baseline 中的行），或 None。"""
    if not extracted or not baseline:
        return extracted if extracted else None

    base_lines = set(baseline.splitlines())
    new_lines = [
        line for line in extracted.splitlines()
        if line.strip() and line not in base_lines
    ]
    if not new_lines:
        return None
    return "\n".join(new_lines)


# ============================================================
# 假阳性过滤
# ============================================================

_WAF_BLOCKED = re.compile(
    r'access\s+denied|blocked|forbidden|被拦截|拦截页面|'
    r'403\s+Forbidden|406\s+Not\s+Acceptable',
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

_PING_NOISE = re.compile(
    r'(?:\d+\s+bytes\s+from|icmp_seq=|ttl=|time=[\d.]+\s*ms|'
    r'ping\s+statistics|packets\s+transmitted|rtt\s+min/avg/max)',
    re.IGNORECASE,
)


def filter_lines(text: str) -> str:
    """对提取的文本逐行过滤，移除 WAF 拦截信息/Shell 报错/空行/ping 噪声。"""
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
# 状态码短路（被 WAF 拦截的常见状态码）
# ============================================================

_BLOCKED_STATUS_CODES = {403, 406, 501, 429}


# ============================================================
# CMDI 证据正则
# ============================================================

_SYSTEM_ACCOUNTS = (
    r'root:|daemon:|bin:|sys:|sync:|games:|man:|lp:|mail:|news:|uucp:|proxy:|'
    r'www-data:|backup:|list:|irc:|nobody:|systemd:|messagebus:|'
    r'_apt:|postgres:|mysql:|redis:|nginx:|apache:|tomcat:|jenkins:'
)

_CMDI_PASSWD_LINE = re.compile(_SYSTEM_ACCOUNTS)
_CMDI_BASE64 = re.compile(r'[A-Za-z0-9+/]{60,}')
_CMDI_CREATE_MARKER = re.compile(r'fzcr_[A-Za-z0-9]{4}')
_CMDI_LS_BLINDSIGHT = re.compile(
    r'[-d][r-][w-][xSs-][r-][w-][xSs-][r-][w-][xTt-]\s+\d+\s+[\w-]+\s+'
    r'[\w-]+\s+\d+.*(?:fz_|fuzz_|cmdi_|waf_)[A-Za-z0-9]{3,}'
)

# ============================================================
# SQLi 数据库错误正则
# ============================================================

_DB_ERROR_PATTERNS = re.compile(
    r'(?:'
    # MySQL
    r'You have an error in your SQL syntax|'
    r'Warning.*mysql_|'
    r'MySQLSyntaxErrorException|'
    r'valid MySQL result|'
    r'check the manual that corresponds to your MySQL|'
    r'MySqlClient\.|'
    # PostgreSQL
    r'PostgreSQL.*ERROR|'
    r'Warning.*pg_|'
    r'valid PostgreSQL result|'
    r'Npgsql\.|'
    r'PG::SyntaxError|'
    r'org\.postgresql\.util\.PSQLException|'
    r'ERROR:\s+syntax error at or near|'
    # Oracle
    r'ORA-\d{5}|'
    r'Oracle error|'
    r'Oracle.*Driver|'
    r'Warning.*oci_|'
    r'Warning.*ora_|'
    # SQLite
    r'SQLite/JDBCDriver|'
    r'SQLite\.Exception|'
    r'System\.Data\.SQLite\.SQLiteException|'
    r'Warning.*sqlite_|'
    r'Warning.*SQLite3::|'
    r'\[SQLITE_ERROR\]|'
    r'SQLite error|'
    # MSSQL
    r'\[SQL Server\]|'
    r'\[ODBC SQL Server Driver\]|'
    r'\[SQL Server Driver\]|'
    r'Warning.*mssql_|'
    r'MSSQLServer|'
    r'Driver.*SQL[\-\_\ ]*Server|'
    r'OLE DB.*SQL Server|'
    r'\bSQL Server[^&lt;&quot;]+Driver|'
    r'Warning.*sybase_|'
    r'Sybase message|'
    r'Sybase.*Server message.*|'
    r'SybSQLException|'
    r'Sybase::|'
    r'com\.sybase\.|'
    # Generic
    r'SQL syntax.*MySQL|'
    r'Unexpected end of command in statement|'
    r'\[Microsoft\]\[ODBC|'
    r'SQLSTATE\b|'
    r'SQLSTATE\b.*\b42000\b'
    r')',
    re.IGNORECASE,
)

# ============================================================
# Log4j JNDI 异常正则
# ============================================================

_JNDI_EXCEPTION_PATTERNS = re.compile(
    r'(?:'
    r'javax\.naming\.\w+Exception|'
    r'javax\.naming\.\w+Error|'
    r'java\.lang\.ClassNotFoundException|'
    r'java\.lang\.NoClassDefFoundError|'
    r'java\.rmi\.RemoteException|'
    r'com\.sun\.jndi\.rmi\.|'
    r'com\.sun\.jndi\.ldap\.|'
    r'JndiLookup|'
    r'Lookup\.lookup|'
    r'InitialContext\.doLookup|'
    r'Error looking up JNDI resource|'
    r'Failed to parse JNDI|'
    r'log4j.*JndiLookup|'
    r'log4j.*lookup|'
    r'org\.apache\.logging\.log4j\.core\.lookup\.JndiLookup'
    r')',
    re.IGNORECASE,
)


# ============================================================
# Judge 抽象基类
# ============================================================


class Judge(ABC):
    """判定器抽象基类。

    所有 Judge 子类仅接收响应证据，不接收 payload 语义信息。
    """

    @abstractmethod
    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        """判定单个响应是否表示绕过成功。

        Args:
            response: 原始响应对象
            extracted_text: 提取后的文本（已过滤）
            diff_text: 与 baseline 的增量文本（可能为 None）
            baseline_elapsed_ms: 基线响应耗时（毫秒）

        Returns:
            Verdict 判定结果
        """
        ...


# ============================================================
# CMDIJudge - 硬编码正则，零 Token 消耗
# ============================================================


class CMDIJudge(Judge):
    """CMDI 判定器：使用硬编码正则校验证据，零 Token 消耗。"""

    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        payload = response.payload

        # 状态码短路
        if response.status_code in _BLOCKED_STATUS_CODES:
            return Verdict(
                payload=payload,
                is_bypass=False,
                confidence=0.95,
                reason=f"HTTP {response.status_code} 拦截",
            )

        # 无增量文本 → blocked
        if not diff_text:
            return Verdict(
                payload=payload,
                is_bypass=False,
                confidence=0.8,
                reason="无增量回显",
            )

        # Read-class: /etc/passwd 账户行
        if _CMDI_PASSWD_LINE.search(diff_text):
            evidence = self._collect_evidence(diff_text, _CMDI_PASSWD_LINE)
            return Verdict(
                payload=payload,
                is_bypass=True,
                evidence=evidence[:2000],
                confidence=0.98,
                reason="/etc/passwd 账户行匹配",
            )

        # Read-class: base64 字符串 >= 60 字符
        if _CMDI_BASE64.search(diff_text):
            match = _CMDI_BASE64.search(diff_text)
            evidence = match.group()[:200] if match else ""
            return Verdict(
                payload=payload,
                is_bypass=True,
                evidence=evidence,
                confidence=0.85,
                reason="Base64 编码字符串匹配（>=60 字符）",
            )

        # Create-class: fzcr_ 标记
        if _CMDI_CREATE_MARKER.search(diff_text):
            evidence = self._collect_evidence(diff_text, _CMDI_CREATE_MARKER)
            return Verdict(
                payload=payload,
                is_bypass=True,
                evidence=evidence[:2000],
                confidence=0.95,
                reason="fzcr_ 创建标记匹配",
            )

        # Delete-class: ls 输出含 fz_/fuzz_/cmdi_/waf_ 文件
        if _CMDI_LS_BLINDSIGHT.search(diff_text):
            evidence = self._collect_evidence(diff_text, _CMDI_LS_BLINDSIGHT)
            return Verdict(
                payload=payload,
                is_bypass=True,
                evidence=evidence[:2000],
                confidence=0.90,
                reason="ls 输出含 fuzz 标记文件",
            )

        return Verdict(
            payload=payload,
            is_bypass=False,
            confidence=0.6,
            reason="无 CMDI 证据匹配",
        )

    @staticmethod
    def _collect_evidence(text: str, pattern: re.Pattern) -> str:
        """收集匹配行作为证据。"""
        lines = []
        for line in text.splitlines():
            if pattern.search(line):
                lines.append(line.strip())
        return "\n".join(lines)


# ============================================================
# SQLiJudge - LLM 深度判定（独立 prompt，不含 payload 语义）
# ============================================================

_SQLI_JUDGE_PROMPT = (
    "你是一名 Web 安全响应分析专家。以下是某个 HTTP 请求的响应信息，"
    "请判断该响应是否包含 SQL 注入成功的证据。\n\n"
    "注意：你不会被告知具体的 payload 内容，你需要纯粹根据响应内容做出判断。\n\n"
    "## 响应信息\n"
    "回显文本（与基线的增量 diff，已过滤页面框架）：\n{diff_text}\n\n"
    "响应状态码：{status_code}\n"
    "响应延时：{response_time_ms}ms\n"
    "基线延时：{baseline_elapsed_ms}ms\n\n"
    "## 判断标准\n"
    "1. **数据库报错注入**：回显中是否包含 MySQL/PostgreSQL/Oracle/SQLite/MSSQL "
    "语法错误信息，且错误信息中可能夹带了查询结果数据？\n"
    "2. **UNION 注入**：回显中是否出现了数据库结构信息（表名、列名、用户数据）？\n"
    "   - 应出现类似 user/admin/password/email 等字段值\n"
    "   - 应出现数据库系统表信息\n"
    "3. **时间盲注**：响应延时是否显著大于基线延时（>=3 倍）？\n"
    "   - 延时 >= 3 倍基线 → 可能是时间盲注\n"
    "   - 延时 >= 5 倍基线 → 高度怀疑时间盲注\n"
    "4. **排除假阳性**：\n"
    "   - 回显是纯数字时间戳但延时正常 → 判定假阳性\n"
    "   - 回显是页面原有框架内容的残留 → 判定假阳性\n"
    "   - 回显是随机噪声或无关内容 → 判定假阳性\n\n"
    "### 输出格式（严格 JSON）：\n"
    '{{"bypass": true/false, "confidence": 0.0-1.0, "reason": "判断原因（简要说明）"}}\n\n'
    "JSON 内所有双引号必须转义为 \\\"，确保可被 Python json.loads 直接解析。"
)


class SQLiJudge(Judge):
    """SQLi 判定器：快速匹配 + LLM 深度判定。

    不接收 payload 语义信息，仅根据响应证据判定。
    """

    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        payload = response.payload

        # 状态码短路
        if response.status_code in _BLOCKED_STATUS_CODES:
            return Verdict(
                payload=payload,
                is_bypass=False,
                confidence=0.95,
                reason=f"HTTP {response.status_code} 拦截",
            )

        # 无增量文本且无显著延时 → blocked
        has_significant_delay = (
            baseline_elapsed_ms > 0
            and response.elapsed_ms >= 3 * baseline_elapsed_ms
        )
        if not diff_text and not has_significant_delay:
            return Verdict(
                payload=payload,
                is_bypass=False,
                confidence=0.8,
                reason="无增量回显且无显著延时",
            )

        # 时间异常快速判定
        if has_significant_delay:
            ratio = response.elapsed_ms / baseline_elapsed_ms
            if ratio >= 5:
                return Verdict(
                    payload=payload,
                    is_bypass=True,
                    confidence=0.75,
                    reason=(
                        f"响应延时 {response.elapsed_ms}ms 为基线 "
                        f"{baseline_elapsed_ms}ms 的 {ratio:.1f} 倍（疑似时间盲注）"
                    ),
                )
            # 3-5 倍延时：可能，继续 LLM 判定

        # DB 错误快速匹配
        if diff_text and _DB_ERROR_PATTERNS.search(diff_text):
            match = _DB_ERROR_PATTERNS.search(diff_text)
            error_snippet = match.group()[:300] if match else ""
            return Verdict(
                payload=payload,
                is_bypass=True,
                evidence=error_snippet,
                confidence=0.90,
                reason=f"数据库错误信息匹配: {error_snippet[:100]}",
            )

        # LLM 深度判定
        return self._llm_judge(
            response=response,
            diff_text=diff_text,
            baseline_elapsed_ms=baseline_elapsed_ms,
        )

    def _llm_judge(
        self,
        response: RawResponse,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        """LLM 深度判定 - 独立 prompt，不含 payload 语义。"""
        try:
            from llm_engine import _chat_json
        except ImportError:
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=0.0,
                reason="LLM 引擎不可用",
            )

        prompt = _SQLI_JUDGE_PROMPT.format(
            diff_text=diff_text[:2000] if diff_text else "(无增量回显)",
            status_code=response.status_code,
            response_time_ms=response.elapsed_ms,
            baseline_elapsed_ms=baseline_elapsed_ms,
        )

        try:
            result = _chat_json(prompt, max_tokens=1024)
            if isinstance(result, dict):
                is_bypass = result.get("bypass", False)
                confidence = float(result.get("confidence", 0.0))
                reason = result.get("reason", "")
                return Verdict(
                    payload=response.payload,
                    is_bypass=is_bypass,
                    evidence=diff_text[:500] if diff_text and is_bypass else None,
                    confidence=confidence,
                    reason=f"LLM 判定: {reason}",
                )
        except Exception:
            pass

        return Verdict(
            payload=response.payload,
            is_bypass=False,
            confidence=0.0,
            reason="LLM 判定失败",
        )


# ============================================================
# Log4jJudge - OOB + 异常堆栈 + 时序判定
# ============================================================


class Log4jJudge(Judge):
    """Log4j 判定器：JNDI 异常堆栈检测 + 时序判定。

    OOB 回调检查由 Observer.evaluate() 统一处理。
    """

    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        payload = response.payload

        # 状态码短路
        if response.status_code in _BLOCKED_STATUS_CODES:
            return Verdict(
                payload=payload,
                is_bypass=False,
                confidence=0.95,
                reason=f"HTTP {response.status_code} 拦截",
            )

        # JNDI 异常堆栈检测（搜索完整文本，不仅 diff）
        search_text = diff_text if diff_text else extracted_text
        if search_text and _JNDI_EXCEPTION_PATTERNS.search(search_text):
            match = _JNDI_EXCEPTION_PATTERNS.search(search_text)
            evidence = match.group()[:300] if match else ""
            return Verdict(
                payload=payload,
                is_bypass=True,
                evidence=evidence,
                confidence=0.92,
                reason=f"JNDI 异常堆栈匹配: {evidence[:100]}",
            )

        # 时序判定：响应 >= 3000ms 且基线 < 500ms
        if (
            baseline_elapsed_ms < 500
            and response.elapsed_ms >= 3000
        ):
            return Verdict(
                payload=payload,
                is_bypass=True,
                confidence=0.70,
                reason=(
                    f"响应延时 {response.elapsed_ms}ms 异常 "
                    f"（基线 {baseline_elapsed_ms}ms < 500ms，疑似 JNDI 触发）"
                ),
            )

        # 时序判定：响应 >= 3 倍基线
        if (
            baseline_elapsed_ms > 0
            and response.elapsed_ms >= 3 * baseline_elapsed_ms
        ):
            ratio = response.elapsed_ms / baseline_elapsed_ms
            return Verdict(
                payload=payload,
                is_bypass=True,
                confidence=0.55,
                reason=(
                    f"响应延时 {response.elapsed_ms}ms 为基线 "
                    f"{baseline_elapsed_ms}ms 的 {ratio:.1f} 倍"
                ),
            )

        return Verdict(
            payload=payload,
            is_bypass=False,
            confidence=0.6,
            reason="无 Log4j 证据匹配",
        )


# ============================================================
# GenericJudge - 通用回退判定器
# ============================================================


class GenericJudge(Judge):
    """通用判定器：对未知漏洞类型的回退处理。"""

    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        payload = response.payload

        # 状态码短路
        if response.status_code in _BLOCKED_STATUS_CODES:
            return Verdict(
                payload=payload,
                is_bypass=False,
                confidence=0.95,
                reason=f"HTTP {response.status_code} 拦截",
            )

        # 有 diff → 可能绕过（低置信度）
        if diff_text:
            return Verdict(
                payload=payload,
                is_bypass=True,
                evidence=diff_text[:500],
                confidence=0.3,
                reason="有增量回显（通用判定，低置信度）",
            )

        return Verdict(
            payload=payload,
            is_bypass=False,
            confidence=0.7,
            reason="无增量回显",
        )


# ============================================================
# OOB 回调检查
# ============================================================


async def _check_oob(
    oob_poll_api: str,
    oob_tokens: dict[str, str],
    timeout_ms: int = 5000,
) -> dict[str, bool]:
    """轮询 OOB 回调服务器，检查每个 token 是否收到回调。

    Args:
        oob_poll_api: OOB 轮询 API 地址
        oob_tokens: token 字典，key 为响应列表索引（字符串），value 为 token
        timeout_ms: 超时毫秒

    Returns:
        dict[str, bool] - token 索引到是否收到回调的映射
    """
    import asyncio

    results: dict[str, bool] = {}
    try:
        import aiohttp
    except ImportError:
        # 回退到 urllib
        return _check_oob_sync(oob_poll_api, oob_tokens, timeout_ms)

    try:
        timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for idx, token in oob_tokens.items():
                try:
                    url = f"{oob_poll_api}?token={token}"
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            results[idx] = data.get("received", False)
                        else:
                            results[idx] = False
                except Exception:
                    results[idx] = False
    except Exception:
        for idx in oob_tokens:
            results.setdefault(idx, False)

    return results


def _check_oob_sync(
    oob_poll_api: str,
    oob_tokens: dict[str, str],
    timeout_ms: int = 5000,
) -> dict[str, bool]:
    """同步版本的 OOB 检查（当 aiohttp 不可用时回退使用）。"""
    import json as _json
    import urllib.request
    import urllib.error

    results: dict[str, bool] = {}
    for idx, token in oob_tokens.items():
        try:
            url = f"{oob_poll_api}?token={token}"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as resp:
                data = _json.loads(resp.read().decode())
                results[idx] = data.get("received", False)
        except Exception:
            results[idx] = False

    return results


# ============================================================
# Observer 主类
# ============================================================

# 默认 Judge 注册表
_DEFAULT_JUDGES: dict[str, Judge] = {
    "cmdi": CMDIJudge(),
    "sqli": SQLiJudge(),
    "log4j": Log4jJudge(),
    "deserialization": Log4jJudge(),
}


class Observer:
    """Observer Agent - 独立判定 Agent。

    接收 RawResponse 和 baseline HTML，不接收 payload 语义。
    通过 Judge 注册模式支持可扩展的漏洞类型判定。

    Attributes:
        judges: Judge 注册表，vuln_type → Judge 实例
    """

    JUDGES: dict[str, Judge] = {
        "cmdi": CMDIJudge(),
        "sqli": SQLiJudge(),
        "log4j": Log4jJudge(),
        "deserialization": Log4jJudge(),
    }

    def __init__(self, judges: dict[str, Judge] | None = None) -> None:
        """初始化 Observer。

        Args:
            judges: 自定义 Judge 注册表，为 None 则使用默认注册表
        """
        self.judges = judges if judges is not None else dict(_DEFAULT_JUDGES)

    def get_judge(self, vuln_type: str) -> Judge:
        """获取指定漏洞类型的 Judge，未注册则回退到 GenericJudge。"""
        return self.judges.get(vuln_type, GenericJudge())

    def evaluate(self, request: ObserverRequest) -> ObserverResult:
        """评估一组响应，判定每个 payload 是否绕过成功。

        流程：
        1. 提取基线文本
        2. OOB 预检查（log4j/deserialization）
        3. 对每个响应：状态码短路 → OOB 检查 → 提取 + diff → Judge 判定
        4. 返回 ObserverResult

        Args:
            request: ObserverRequest，包含响应列表、基线 HTML、漏洞类型等

        Returns:
            ObserverResult，包含判定列表、绕过计数、拦截计数、摘要
        """
        import asyncio

        verdicts: list[Verdict] = []
        oob_received: dict[str, bool] = {}

        # 1. 提取基线文本
        baseline_text = extract_text_blocks(request.baseline_html)

        # 2. OOB 预检查（log4j / deserialization）
        needs_oob = request.vuln_type in ("log4j", "deserialization")
        if (
            needs_oob
            and request.oob_poll_api
            and request.oob_tokens
        ):
            try:
                oob_received = asyncio.get_event_loop().run_until_complete(
                    _check_oob(request.oob_poll_api, request.oob_tokens)
                )
            except RuntimeError:
                # 已有事件循环运行中，使用同步版本
                oob_received = _check_oob_sync(
                    request.oob_poll_api, request.oob_tokens
                )
            except Exception:
                oob_received = {}

        # 3. 获取 Judge
        judge = self.get_judge(request.vuln_type)

        # 4. 逐个响应判定
        for idx, response in enumerate(request.responses):
            idx_str = str(idx)

            # 状态码短路（Observer 层级）
            if response.status_code in _BLOCKED_STATUS_CODES:
                verdicts.append(Verdict(
                    payload=response.payload,
                    is_bypass=False,
                    confidence=0.95,
                    reason=f"HTTP {response.status_code} 拦截",
                ))
                continue

            # OOB 检查（log4j/deserialization）
            if needs_oob and idx_str in oob_received:
                if oob_received[idx_str]:
                    verdicts.append(Verdict(
                        payload=response.payload,
                        is_bypass=True,
                        confidence=0.99,
                        reason="OOB 回调已确认",
                    ))
                    continue

            # 提取文本
            extracted = extract_text_blocks(response.body)
            filtered = filter_lines(extracted) if extracted else ""

            # Diff
            if filtered and baseline_text:
                diff = baseline_diff(filtered, baseline_text)
            elif filtered:
                diff = filtered
            else:
                diff = None

            # 过滤 diff
            if diff:
                diff = filter_lines(diff)
                if not diff:
                    diff = None

            # Judge 判定
            verdict = judge.judge(
                response=response,
                extracted_text=filtered,
                diff_text=diff,
                baseline_elapsed_ms=request.baseline_elapsed_ms,
            )
            verdicts.append(verdict)

        # 5. 统计
        bypass_count = sum(1 for v in verdicts if v.is_bypass)
        blocked_count = len(verdicts) - bypass_count

        return ObserverResult(
            verdicts=verdicts,
            bypass_count=bypass_count,
            blocked_count=blocked_count,
            summary=f"{bypass_count} bypass / {blocked_count} blocked",
        )
