# -*- coding: utf-8 -*-
"""
manager.py  Manager Agent -- 系统的"大脑"

【核心职责】
1. 从爬虫结果推断注入点类型
2. 采集基线响应
3. 利用 LLM 分析攻击面，制定 AttackPlan
4. 每轮 LLM 策略决策（RoundDecision）
5. 记录轮次结果，更新知识库
6. 生成最终 Bypass 报告
"""

from __future__ import annotations

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
    InjectionPoint,
    ObserverResult,
    RoundDecision,
    RoundRecord,
    Verdict,
    WAFProfile,
)
from baseliner import run_baseline
from crawler import CandidateForm
from llm_engine import _chat_json
from memory_compressor import compress_cot_analyses, consolidate_kb, get_kb_context


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
    "id", "uid", "user", "search", "query", "查询", "搜索", "用户",
    "username", "userid", "account", "login", "name", "email",
    "page", "sort", "order", "cat", "category", "limit", "offset",
]

_LOG4J_KEYWORDS = [
    "url", "uri", "callback", "jndi", "api", "remote", "fetch",
    "redirect", "referer", "ua", "user-agent", "x-forwarded-for",
]


def _infer_single(
    url: str,
    param_name: str,
    hint: str = "",
    title: str = "",
    context: str = "",
) -> str | None:
    """根据 URL / 参数名 / hint / title / context 推断单个参数的漏洞类型。"""
    search_text = f"{url} {param_name} {hint} {title} {context}".lower()

    def _hit(keywords: list[str]) -> bool:
        return any(kw in search_text for kw in keywords)

    if _hit(_CMDI_KEYWORDS):
        return "cmdi"
    if _hit(_SQLI_KEYWORDS):
        return "sqli"
    if _hit(_LOG4J_KEYWORDS):
        return "log4j"
    return None


# ============================================================
# Manager
# ============================================================

class Manager:
    """WAF Fuzzer 的中央调度器。"""

    def __init__(self, config: dict):
        self.config = config
        self.bypass_records: list[dict] = []
        self.blocked_history: list[str] = []
        self.round_history: list[RoundRecord] = []
        self._output_dir = Path("output")
        self._output_dir.mkdir(exist_ok=True)

    # ----------------------------------------------------------
    # 1. 注入点推断
    # ----------------------------------------------------------

    def infer_injection_types(self, forms: list[CandidateForm]) -> list[InjectionPoint]:
        """从爬虫表单中推断注入点，返回 InjectionPoint 列表。"""
        injection_points: list[InjectionPoint] = []

        for form in forms:
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

                method = form.method.upper()
                if method == "POST":
                    body_parts: list[str] = []
                    for k, v in form.inputs.items():
                        if k == param_name:
                            body_parts.append(f"{k}={{{{INJECT}}}}")
                        else:
                            body_parts.append(f"{k}={v}")
                    body = "&".join(body_parts)
                    params = None
                else:
                    # GET
                    body = None
                    params = {
                        k: ("{{INJECT}}" if k == param_name else v)
                        for k, v in form.inputs.items()
                    }

                injection_points.append(InjectionPoint(
                    url=form.action or form.url,
                    param=param_name,
                    method=method,
                    vuln_type=vuln_type,
                    page_hint=hint,
                    inferred_context=form.page_text[:200] if form.page_text else "",
                    body=body,
                    params=params,
                ))

        return injection_points

    # ----------------------------------------------------------
    # 2. 基线采集
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
    # 3. 攻击面分析 (LLM)
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
            "你是一名 Red-Team WAF 绕过专家。请分析以下注入点的攻击面，"
            "制定多维度攻击策略。\n\n"
            f"## 目标信息\n"
            f"  URL: {injection_point.url}\n"
            f"  参数: {injection_point.param}\n"
            f"  方法: {injection_point.method}\n"
            f"  漏洞类型: {injection_point.vuln_type}\n"
            f"  页面提示: {injection_point.page_hint}\n"
            f"  上下文: {injection_point.inferred_context}\n\n"
            f"{waf_section}\n"
            f"{kb_context}\n\n"
            "请分析该目标的攻击面并返回 JSON：\n"
            "{\n"
            '  "dimension_priority": ["semantic", "protocol", "performance", "topology"],\n'
            '  "first_round_strategy": "第一轮建议的攻击策略描述",\n'
            '  "predicted_blocking": "预测 WAF 最可能拦截的方式",\n'
            '  "reasoning": "分析推理过程"\n'
            "}\n\n"
            "dimension_priority: 按有效性排序的四个攻击维度。\n"
            "  - semantic: 语义变形（编码、混淆、关键字替换）\n"
            "  - protocol: 协议层（Content-Type、Transfer-Encoding、HTTP 参数污染）\n"
            "  - performance: 性能/时序（请求速率、并发、超时探测）\n"
            "  - topology: 拓扑层（WAF 绕过 IP、端口、路径穿越）\n\n"
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
    # 4. 策略决策
    # ----------------------------------------------------------

    def decide_strategy(
        self,
        round_num: int,
        attack_plan: AttackPlan,
        injection_point: InjectionPoint,
        waf_profile: WAFProfile | None = None,
        model: str = "mimo-v2.5-pro",
    ) -> RoundDecision:
        """根据轮次历史调用 LLM 决策下一轮策略。

        - round 0: 直接使用 AttackPlan 的 first_round_strategy
        - 后续轮次: LLM 根据历史记录决策
        """
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

        # 构建轮次历史摘要
        history_lines: list[str] = []
        for rec in self.round_history[-5:]:
            history_lines.append(
                f"  第{rec.round_num}轮: 维度={rec.dimension}, 策略={rec.strategy[:80]}, "
                f"绕过={rec.bypass_count}, 拦截={rec.blocked_count}"
            )
        history_text = "\n".join(history_lines) if history_lines else "  (无历史)"

        available_dims = attack_plan.dimension_priority.copy()
        # 如果连续全拦截，排除当前维度
        if force_dimension_switch and self.round_history:
            current_dim = self.round_history[-1].dimension
            if current_dim in available_dims and len(available_dims) > 1:
                available_dims.remove(current_dim)

        prompt = (
            "你是一名 Red-Team WAF 绕过策略专家。根据以下轮次历史，决定下一轮的攻击策略。\n\n"
            f"## 目标信息\n"
            f"  URL: {injection_point.url}\n"
            f"  参数: {injection_point.param}\n"
            f"  漏洞类型: {injection_point.vuln_type}\n\n"
            f"## 轮次历史（最近 5 轮）\n{history_text}\n\n"
            f"## 可选攻击维度（按优先级排序）\n{json.dumps(available_dims, ensure_ascii=False)}\n\n"
            f"## 维度说明\n"
            f"  - semantic: 语义变形（编码、混淆、关键字替换）\n"
            f"  - protocol: 协议层（Content-Type、Transfer-Encoding、HTTP 参数污染）\n"
            f"  - performance: 性能/时序（请求速率、并发、超时探测）\n"
            f"  - topology: 拓扑层（WAF 绕过 IP、端口、路径穿越）\n\n"
        )

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

        result = _chat_json(prompt, model=model, temperature=0.3, max_tokens=1024)

        if isinstance(result, dict):
            chosen_dim = result.get("dimension", available_dims[0] if available_dims else "semantic")
            return RoundDecision(
                dimension=chosen_dim,
                strategy=result.get("strategy", ""),
                reasoning=result.get("reasoning", ""),
            )

        # LLM 失败时回退
        fallback_dim = available_dims[0] if available_dims else "semantic"
        return RoundDecision(
            dimension=fallback_dim,
            strategy=f"LLM 决策失败，使用 {fallback_dim} 维度",
            reasoning="LLM 返回异常，回退到默认策略",
        )

    # ----------------------------------------------------------
    # 5. 结果记录
    # ----------------------------------------------------------

    def record_round(
        self,
        round_num: int,
        dimension: str,
        strategy: str,
        observer_result: ObserverResult,
        vuln_type: str = "",
        target_url: str = "",
    ) -> RoundRecord:
        """记录一轮结果，更新内部状态。"""
        record = RoundRecord(
            round_num=round_num,
            dimension=dimension,
            strategy=strategy,
            bypass_count=observer_result.bypass_count,
            blocked_count=observer_result.blocked_count,
            verdicts=observer_result.verdicts,
        )
        self.round_history.append(record)

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
            else:
                self.blocked_history.append(v.payload)

        return record

    # ----------------------------------------------------------
    # 6. 知识库更新
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
    # 7. 终止条件判断
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
    # 8. 报告生成
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
