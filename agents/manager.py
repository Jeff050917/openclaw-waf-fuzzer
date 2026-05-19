# -*- coding: utf-8 -*-
"""
manager.py  Manager Agent -- 系统的"大脑"

【核心职责】
1. 爬取站点，发现表单和参数
2. WAF 指纹识别
3. 从爬虫结果推断注入点类型
4. 采集基线响应
5. 利用 LLM 分析攻击面，制定 AttackPlan
6. 每轮 LLM 策略决策（RoundDecision）
7. 记录轮次结果，更新知识库
8. 生成最终 Bypass 报告
"""

from __future__ import annotations

import collections
import json
import os
import re
import sys
import time
from collections import OrderedDict
from pathlib import Path

# 确保 core/ 在 import 路径中
_CORE_DIR = str(Path(__file__).resolve().parent.parent / "core")
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)

from agents.models import (
    AttackPlan,
    BypassFact,
    BlockedFact,
    CompactedResponse,
    IdeaBoard,
    InjectionPoint,
    MemoryBoard,
    MutationHypothesis,
    ObserverResult,
    RoundDecision,
    RoundRecord,
    SteerReminder,
    Verdict,
    WAFProfile,
)
from baseliner import run_baseline
from crawler import CandidateForm, SiteCrawler
from llm_engine import _chat_json
from memory_compressor import compress_cot_analyses, consolidate_kb, get_kb_context
from waf_fingerprinter import WAFFingerprinter


# ============================================================
# Payload 分类正则（从 workflow.py 迁移）
# ============================================================

# CMDI 分类
_CMDI_CAT_PATH_BYPASS = re.compile(r'/[\w.-]*[\?*\[\]][\w?*\[\]./-]*')
_CMDI_CAT_CMD_BYPASS = re.compile(r'\$\{ifs\}|\$[1-9@]|c[\x27"]a[\x27"]t|echo\s+[`$]')
_CMDI_CAT_NEWLINE = re.compile(r'%0[aAdD]')
_CMDI_CAT_CREATE = re.compile(r'touch\s|mkdir\s|wget\s|curl\s.*-o\s')
_CMDI_CAT_DELETE = re.compile(r'rm\s+-[fFrR]|rmdir\s')

_CMDI_CAT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("绕过文件路径", _CMDI_CAT_PATH_BYPASS),
    ("绕过命令", _CMDI_CAT_CMD_BYPASS),
    ("换行注入", _CMDI_CAT_NEWLINE),
    ("创建命令", _CMDI_CAT_CREATE),
    ("删除命令", _CMDI_CAT_DELETE),
]

# SQLi 分类
_SQLI_CAT_UNION = re.compile(r'(?:union[\s/\*!]+select|/\*!.*union)')
_SQLI_CAT_ERROR = re.compile(r'(?:extractvalue|updatexml|floor\s*\(|exp~|polygon)')
_SQLI_CAT_BLIND = re.compile(r'(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()')
_SQLI_CAT_STACKED = re.compile(r';\s*(?:insert|update|delete|drop|create|alter|truncate)\s')

_SQLI_CAT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("UNION注入", _SQLI_CAT_UNION),
    ("报错注入", _SQLI_CAT_ERROR),
    ("盲注", _SQLI_CAT_BLIND),
    ("堆叠查询", _SQLI_CAT_STACKED),
]


def _categorize_payload(payload: str, vuln_type: str = "") -> str:
    """根据 Payload 特征自动识别绕过技术类型。"""
    p = payload.lower()

    if vuln_type == "sqli":
        for label, pat in _SQLI_CAT_PATTERNS:
            if pat.search(p):
                return label
        return "直接注入"

    # CMDI
    for label, pat in _CMDI_CAT_PATTERNS:
        if pat.search(p):
            return label
    if any(k in p for k in ['base64', 'xxd', 'od -', 'hexdump']):
        return "绕过命令"
    if any(k in p for k in ['%0a', '%0d%0a']):
        return "换行注入"
    return "直接读取"


# ============================================================
# 注入点推断关键词
# ============================================================

_CMDI_KEYWORDS = [
    "ip", "host", "cmd", "command", "ping", "域名", "ip地址", "execute",
    "exec", "shell", "system", "nslookup", "dig", "traceroute",
]

_SQLI_KEYWORDS = [
    "id", "uid", "userid", "user_id", "search", "query", "查询", "搜索",
    "sort", "order", "cat", "category", "limit", "offset",
    "item", "product", "article", "post", "page", "table",
    "column", "record", "select", "where", "group", "having",
]

_LOG4J_KEYWORDS = [
    "url", "uri", "callback", "jndi", "api", "remote", "fetch",
    "redirect", "referer", "ua", "user-agent", "x-forwarded-for",
]


def _is_login_form(form: CandidateForm) -> bool:
    """检测是否为登录/认证表单，这类表单不应作为注入点。"""
    _LOGIN_FIELDS = {"password", "passwd", "pwd", "pass"}
    for name in form.inputs:
        if name.lower() in _LOGIN_FIELDS:
            return True
    url_lower = (form.action or form.url or "").lower()
    _AUTH_PATHS = ("/login", "/signin", "/sign-in", "/auth", "/register", "/signup", "/logon")
    return any(p in url_lower for p in _AUTH_PATHS)


def _infer_single(
    url: str,
    param_name: str,
    hint: str = "",
    title: str = "",
    context: str = "",
) -> str | None:
    """根据 URL / 参数名 / hint / title / context 推断单个参数的漏洞类型。"""
    search_text = f"{url} {param_name} {hint} {title} {context}".lower()

    # 排除认证/注册页面 URL
    _AUTH_URL_PATTERNS = [
        "/login", "/signin", "/sign-in", "/auth", "/register",
        "/signup", "/sign-up", "/logon", "/forgot", "/reset",
    ]
    if any(pat in url.lower() for pat in _AUTH_URL_PATTERNS):
        return None

    def _hit(keywords: list[str]) -> bool:
        return any(kw in search_text for kw in keywords)

    if _hit(_CMDI_KEYWORDS):
        return "cmdi"
    if _hit(_SQLI_KEYWORDS):
        return "sqli"
    if _hit(_LOG4J_KEYWORDS):
        return "log4j"
    return None


def _build_injection_point(
    form: CandidateForm, param_name: str, hint: str, vuln_type: str,
) -> InjectionPoint:
    """从表单和参数构建单个注入点。"""
    method = form.method.upper()
    if method == "POST":
        body_parts: list[str] = []
        for k, v in form.inputs.items():
            body_parts.append(f"{k}={{{{INJECT}}}}" if k == param_name else f"{k}={v}")
        body = "&".join(body_parts)
        params = None
    else:
        body = None
        params = {k: ("{{INJECT}}" if k == param_name else v) for k, v in form.inputs.items()}

    return InjectionPoint(
        url=form.action or form.url,
        param=param_name,
        method=method,
        vuln_type=vuln_type,
        page_hint=hint,
        inferred_context=form.page_text[:200] if form.page_text else "",
        body=body,
        params=params,
    )


# ============================================================
# Manager
# ============================================================

class Manager:
    """WAF Fuzzer 的中央调度器。"""

    def __init__(self, config: dict):
        self.config = config
        self.bypass_records: list[dict] = []
        self.round_history: list[RoundRecord] = []
        self._output_dir = Path("output")
        self._output_dir.mkdir(exist_ok=True)

        # 双层状态板
        self.memory_board = MemoryBoard()
        self.idea_board = IdeaBoard()
        self._steer_reminder: SteerReminder | None = None
        self._blocked_payloads_window: collections.deque[str] = collections.deque(maxlen=30)

        # 初始化内部工具
        fuzz_cfg = config.get("fuzzing", {})
        timeout = fuzz_cfg.get("request_timeout", 15)
        self._crawler = SiteCrawler(timeout=timeout)
        self._fingerprinter = WAFFingerprinter(timeout=timeout)

    # ----------------------------------------------------------
    # 1. 站点爬取
    # ----------------------------------------------------------

    def crawl_site(self, entry_url: str) -> list[CandidateForm]:
        """爬取入口 URL，返回发现的表单列表。"""
        return self._crawler.crawl(entry_url)

    # ----------------------------------------------------------
    # 2. WAF 指纹识别
    # ----------------------------------------------------------

    def fingerprint_waf(self, url: str) -> WAFProfile:
        """对目标 URL 进行 WAF 指纹识别。"""
        return self._fingerprinter.fingerprint(url)

    # ----------------------------------------------------------
    # 3. 注入点推断
    # ----------------------------------------------------------

    def infer_injection_types(self, forms: list[CandidateForm]) -> list[InjectionPoint]:
        """从爬虫表单中推断注入点，返回 InjectionPoint 列表。"""
        injection_points: list[InjectionPoint] = []
        target_paths = self.config.get("fuzzing", {}).get("target_paths", [])

        for form in forms:
            # 跳过登录/认证表单
            if _is_login_form(form):
                continue

            # 可选：限制到用户指定的目标路径
            if target_paths:
                form_url = (form.action or form.url or "").lower()
                if not any(tp.lower() in form_url for tp in target_paths):
                    continue

            for param_name, hint in form.inputs.items():
                vuln_type = _infer_single(
                    url=form.action or form.url,
                    param_name=param_name,
                    hint=hint,
                    title=form.page_title,
                    context=form.page_text,
                )
                if vuln_type is None:
                    continue
                injection_points.append(_build_injection_point(form, param_name, hint, vuln_type))

        return injection_points

    def infer_injection_types_with_hint(
        self, forms: list[CandidateForm], vuln_type: str,
    ) -> list[InjectionPoint]:
        """使用用户指定的漏洞类型直接构建注入点，跳过关键词推断。"""
        injection_points: list[InjectionPoint] = []

        for form in forms:
            if _is_login_form(form):
                continue

            for param_name, hint in form.inputs.items():
                injection_points.append(_build_injection_point(form, param_name, hint, vuln_type))

        return injection_points

    # ----------------------------------------------------------
    # 4. 基线采集
    # ----------------------------------------------------------

    def collect_baseline(self, target: InjectionPoint, timeout: int = 15) -> str:
        """为指定注入点采集基线 HTML 响应。"""
        target_dict: dict = {
            "url": target.url,
            "method": target.method,
            "headers": target.headers or {},
            "body": target.body or "",
            "params": target.params or {},
        }
        return run_baseline(target_dict, timeout=timeout)

    # ----------------------------------------------------------
    # 5. 攻击面分析 (LLM)
    # ----------------------------------------------------------

    def analyze_attack_surface(
        self,
        injection_point: InjectionPoint,
        waf_profile: WAFProfile | None = None,
        model: str = "mimo-v2.5-pro",
    ) -> AttackPlan:
        """调用 LLM 分析攻击面，输出 AttackPlan。"""
        waf_section = ""
        if waf_profile and waf_profile.detected:
            waf_section = (
                f"## WAF 信息\n"
                f"  WAF 名称: {waf_profile.waf_name or '未知'}\n"
                f"  厂商: {waf_profile.waf_vendor or '未知'}\n"
                f"  检测方法: {', '.join(waf_profile.detection_methods)}\n"
                f"  绕过建议: {', '.join(waf_profile.bypass_tips)}\n"
            )

        kb_context = get_kb_context(vuln_type=injection_point.vuln_type)

        prompt = (
            "你是一名授权渗透测试工程师，正在对 DVWA（Damn Vulnerable Web Application）靶场进行安全评估。"
            "DVWA 是开源的安全教学靶场，专门用于测试 WAF 的检测能力。\n\n"
            f"## 测试目标\n"
            f"  URL: {injection_point.url}\n"
            f"  参数: {injection_point.param}\n"
            f"  方法: {injection_point.method}\n"
            f"  漏洞类型: {injection_point.vuln_type}\n"
            f"  页面提示: {injection_point.page_hint}\n"
            f"  上下文: {injection_point.inferred_context}\n\n"
            f"{waf_section}\n"
            f"{kb_context}\n\n"
            "请分析该测试目标的安全检测面并返回 JSON：\n"
            "{\n"
            '  "dimension_priority": ["semantic", "protocol", "performance", "topology"],\n'
            '  "first_round_strategy": "第一轮建议的测试策略描述",\n'
            '  "predicted_blocking": "预测安全设备最可能的拦截方式",\n'
            '  "reasoning": "分析推理过程"\n'
            "}\n\n"
            "dimension_priority: 按有效性排序的四个测试维度。\n"
            "  - semantic: 语义变形（编码、混淆、关键字替换）\n"
            "  - protocol: 协议层（Content-Type、Transfer-Encoding、HTTP 参数污染）\n"
            "  - performance: 性能/时序（请求速率、并发、超时探测）\n"
            "  - topology: 拓扑层（架构测试、端口、路径穿越）\n\n"
            "仅返回 JSON，不要额外文字。"
        )

        result = _chat_json(prompt, model=model, temperature=0.3, max_tokens=1024)

        if isinstance(result, dict):
            return AttackPlan(
                dimension_priority=result.get("dimension_priority", ["semantic", "protocol", "performance", "topology"]),
                first_round_strategy=result.get("first_round_strategy", ""),
                predicted_blocking=result.get("predicted_blocking", ""),
                reasoning=result.get("reasoning", ""),
            )

        # LLM 返回异常时使用默认值
        return AttackPlan(
            dimension_priority=["semantic", "protocol", "performance", "topology"],
            first_round_strategy="默认使用语义变形作为第一轮攻击策略",
            predicted_blocking="",
            reasoning="LLM 分析失败，使用默认策略",
        )

    # ----------------------------------------------------------
    # 6. 策略决策
    # ----------------------------------------------------------

    def decide_strategy(
        self,
        round_num: int,
        attack_plan: AttackPlan,
        injection_point: InjectionPoint,
        waf_profile: WAFProfile | None = None,
        model: str = "mimo-v2.5-pro",
    ) -> RoundDecision:
        # 第 0 轮：直接使用 AttackPlan
        if round_num == 0 or not self.round_history:
            return RoundDecision(
                dimension=attack_plan.dimension_priority[0] if attack_plan.dimension_priority else "semantic",
                strategy=attack_plan.first_round_strategy,
                reasoning="首轮使用 AttackPlan 预设策略",
            )

        # 检查连续全拦截，是否需要切换维度
        dimension_switch_threshold = self.config.get("fuzzing", {}).get("dimension_switch_threshold", 3)
        recent_all_blocked = 0
        for rec in reversed(self.round_history):
            if rec.blocked_count > 0 and rec.bypass_count == 0:
                recent_all_blocked += 1
            else:
                break
        force_dimension_switch = recent_all_blocked >= dimension_switch_threshold

        available_dims = attack_plan.dimension_priority.copy()
        if force_dimension_switch and self.round_history:
            current_dim = self.round_history[-1].dimension
            if current_dim in available_dims and len(available_dims) > 1:
                available_dims.remove(current_dim)

        # 构建 prompt：Memory Board + Idea Board + 可选 SteerReminder
        prompt = (
            "你是一名授权渗透测试策略师，正在对 DVWA 靶场进行安全检测规则验证。"
            "根据以下测试记录决定下一轮的测试策略。\n\n"
            f"## 测试目标\n"
            f"  URL: {injection_point.url}\n"
            f"  参数: {injection_point.param}\n"
            f"  漏洞类型: {injection_point.vuln_type}\n\n"
            f"{self.memory_board.to_prompt_text()}\n\n"
            f"{self.idea_board.to_prompt_text()}\n\n"
            f"## 可选测试维度（按优先级排序）\n{json.dumps(available_dims, ensure_ascii=False)}\n\n"
            f"## 维度说明\n"
            f"  - semantic: 语义变形（编码、混淆、关键字替换）\n"
            f"  - protocol: 协议层（Content-Type、Transfer-Encoding、HTTP 参数污染）\n"
            f"  - performance: 性能/时序（请求速率、并发、超时探测）\n"
            f"  - topology: 拓扑层（架构测试、端口、路径穿越）\n\n"
        )

        # 注入 Observer 旁路纠偏提醒
        if self._steer_reminder:
            prompt += (
                f"## Observer 旁路纠偏提醒\n"
                f"  紧急度: {self._steer_reminder.urgency}\n"
                f"  {self._steer_reminder.message}\n"
            )
            if self._steer_reminder.suggested_dimension:
                prompt += f"  建议维度: {self._steer_reminder.suggested_dimension}\n"
            prompt += "\n"
            self._steer_reminder = None

        if force_dimension_switch:
            prompt += (
                "【重要】连续多轮全部被拦截，请切换到不同的攻击维度，"
                "不要继续使用之前的维度。\n\n"
            )

        prompt += (
            "请返回 JSON：\n"
            "{\n"
            '  "dimension": "选择的攻击维度",\n'
            '  "strategy": "具体的攻击策略描述",\n'
            '  "reasoning": "决策推理过程"\n'
            "}\n\n"
            "仅返回 JSON，不要额外文字。"
        )

        result = _chat_json(prompt, model=model, temperature=0.3, max_tokens=2048)

        if isinstance(result, dict):
            chosen_dim = result.get("dimension", available_dims[0] if available_dims else "semantic")
            return RoundDecision(
                dimension=chosen_dim,
                strategy=result.get("strategy", ""),
                reasoning=result.get("reasoning", ""),
            )

        fallback_dim = available_dims[0] if available_dims else "semantic"
        return RoundDecision(
            dimension=fallback_dim,
            strategy=f"LLM 决策失败，使用 {fallback_dim} 维度",
            reasoning="LLM 返回异常，回退到默认策略",
        )

    # ----------------------------------------------------------
    # 7. 双板管理 + 结果记录
    # ----------------------------------------------------------

    def update_boards(
        self,
        round_num: int,
        dimension: str,
        observer_result: ObserverResult,
        vuln_type: str = "",
    ) -> None:
        """更新 Memory Board 和 Idea Board。"""
        for v in observer_result.verdicts:
            if v.is_bypass:
                self.memory_board.bypass_facts.append(BypassFact(
                    payload_summary=v.payload[:120],
                    evidence_summary=(v.evidence or "")[:200],
                    dimension=dimension,
                    round_num=round_num,
                ))
            else:
                waf_sig = v.reason[:80] if v.reason else ""
                self.memory_board.blocked_facts.append(BlockedFact(
                    payload_summary=v.payload[:120],
                    status_code=v.status_code,
                    waf_signature=waf_sig,
                    dimension=dimension,
                    round_num=round_num,
                ))
                self._blocked_payloads_window.append(v.payload)

        # 更新维度统计
        stats = self.memory_board.dimension_stats.setdefault(dimension, {"blocked": 0, "bypass": 0})
        stats["blocked"] += observer_result.blocked_count
        stats["bypass"] += observer_result.bypass_count

        # 更新 Idea Board 维度追踪
        if dimension != self.idea_board.current_dimension:
            self.idea_board.current_dimension = dimension
            self.idea_board.rounds_since_dimension_switch = 0
        else:
            self.idea_board.rounds_since_dimension_switch += 1

        # 将已尝试维度的 pending 假设标记为 tried
        for h in self.idea_board.hypotheses:
            if h.target_dimension == dimension and h.status == "pending":
                h.status = "tried"

    def build_solver_blocked_payloads(self) -> list[str]:
        return list(self._blocked_payloads_window)

    def set_steer_reminder(self, reminder: SteerReminder) -> None:
        self._steer_reminder = reminder

    def record_round(
        self,
        round_num: int,
        dimension: str,
        strategy: str,
        observer_result: ObserverResult,
        vuln_type: str = "",
        target_url: str = "",
    ) -> RoundRecord:
        # 更新双板
        self.update_boards(round_num, dimension, observer_result, vuln_type)

        # 生成压缩响应
        compacted = []
        for v in observer_result.verdicts:
            compacted.append(CompactedResponse(
                payload_summary=v.payload[:80],
                status_code=v.status_code,
                dimension=dimension,
                elapsed_ms=0,
                evidence_snippet=(v.evidence or "")[:300],
                is_bypass=v.is_bypass,
            ))

        record = RoundRecord(
            round_num=round_num,
            dimension=dimension,
            strategy=strategy,
            bypass_count=observer_result.bypass_count,
            blocked_count=observer_result.blocked_count,
            compacted_responses=compacted,
            summary=observer_result.summary,
        )
        self.round_history.append(record)

        # 保留 bypass_records 用于最终报告
        for v in observer_result.verdicts:
            if v.is_bypass:
                self.bypass_records.append({
                    "target": target_url,
                    "vuln_type": vuln_type,
                    "payload": v.payload,
                    "category": _categorize_payload(v.payload, vuln_type=vuln_type),
                    "evidence": v.evidence or "",
                    "round": round_num,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                })

        return record

    # ----------------------------------------------------------
    # 8. 知识库更新
    # ----------------------------------------------------------

    def update_kb(
        self,
        vuln_type: str,
        cot_entries: list[str],
        target_url: str,
        model: str = "mimo-v2.5-pro",
    ) -> None:
        """压缩本轮 CoT 分析并更新知识库。"""
        if not cot_entries:
            return
        try:
            compressed = compress_cot_analyses(cot_entries, vuln_type=vuln_type, model=model)
            if compressed:
                consolidate_kb(
                    vuln_type=vuln_type,
                    compressed_rules=compressed,
                    target_url=target_url,
                )
        except Exception as e:
            print(f"  [WARN] KB 更新失败: {e}")

    # ----------------------------------------------------------
    # 9. 终止条件判断
    # ----------------------------------------------------------

    def should_stop(self, current_round: int) -> bool:
        """检查是否应提前终止 fuzzing 循环。"""
        fuzz_cfg = self.config.get("fuzzing", {})
        max_iterations = fuzz_cfg.get("max_iterations", 20)
        early_stop_threshold = fuzz_cfg.get("early_stop_on_all_blocked", 5)

        # 超过最大轮次
        if current_round >= max_iterations:
            return True

        # 连续全拦截检测
        if len(self.round_history) >= early_stop_threshold:
            recent = self.round_history[-early_stop_threshold:]
            all_blocked = all(
                r.bypass_count == 0 and r.blocked_count > 0
                for r in recent
            )
            if all_blocked:
                return True

        return False

    # ----------------------------------------------------------
    # 10. 报告生成
    # ----------------------------------------------------------

    def generate_final_report(self, output_path: str | None = None) -> str:
        """将 bypass 记录按 vuln_type + target 分组，分类后写入报告。"""
        if output_path is None:
            output_path = str(self._output_dir / "bypass_report.txt")

        if not self.bypass_records:
            sep = "=" * 80
            lines = [sep, "WAF-Fuzzer Bypass Report", sep, "", "  (无绕过记录)", ""]
            report_text = "\n".join(lines)
        else:
            # 按 (vuln_type, target) 分组
            groups: dict[tuple[str, str], dict[str, list[dict]]] = OrderedDict()
            for entry in self.bypass_records:
                key = (entry["vuln_type"], entry["target"])
                if key not in groups:
                    groups[key] = OrderedDict()
                cat = entry.get("category", "直接读取")
                if cat not in groups[key]:
                    groups[key][cat] = []
                groups[key][cat].append(entry)

            sep = "=" * 80
            lines = [sep]
            lines.append("WAF-Fuzzer Bypass Report")
            lines.append(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}  |  共 {len(self.bypass_records)} 条记录")
            lines.append(sep)
            lines.append("")

            for (vuln_type, target), categories in groups.items():
                lines.append(f"#### {vuln_type.upper()} - {target} ####")
                lines.append("")

                for cat, entries in categories.items():
                    lines.append(f"  -- {cat} ({len(entries)}条) --")
                    lines.append(f"  {'Payload':<55s} 证据摘要")
                    lines.append("  " + "-" * 53 + "  " + "-" * 30)
                    for e in entries:
                        pl = e.get("payload", "")
                        ev = e.get("evidence", "")[:120].replace("\n", " / ")
                        lines.append(f"  {pl[:53]:<55s} {ev}")
                    lines.append("")

                lines.append(sep)
                lines.append("")

            report_text = "\n".join(lines)

        # 确保输出目录存在
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        return report_text
