from __future__ import annotations

import time
from dataclasses import dataclass, field


# ============================================================
# 基础数据流对象
# ============================================================

@dataclass
class InjectionPoint:
    url: str
    param: str
    method: str  # "GET" | "POST"
    vuln_type: str  # "cmdi" | "sqli" | "log4j"
    page_hint: str = ""
    inferred_context: str = ""
    closure_chars: list[str] = field(default_factory=list)
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
    dimension: str
    kb_context: str
    round_num: int
    blocked_payloads: list[str] = field(default_factory=list)
    waf_profile: WAFProfile | None = None
    immutable_payload: str = ""  # 协议层变异时不可变的基准 payload


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
    baseline_elapsed_ms: int = 200
    oob_server: str | None = None
    oob_poll_api: str | None = None
    oob_tokens: dict[str, str] | None = None
    round_num: int = 0
    dimension: str = ""
    oob_received: dict[str, bool] | None = None  # provider 直接 poll 的结果


@dataclass
class Verdict:
    payload: str
    is_bypass: bool
    evidence: str | None = None
    confidence: float = 0.0
    reason: str = ""
    status_code: int = 0


@dataclass
class RoundDecision:
    dimension: str
    strategy: str
    reasoning: str


# ============================================================
# 双层状态板：Memory Board（事实板）
# ============================================================

@dataclass
class BlockedFact:
    payload_summary: str
    status_code: int
    waf_signature: str
    dimension: str
    round_num: int
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


@dataclass
class BypassFact:
    payload_summary: str
    evidence_summary: str
    dimension: str
    round_num: int
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


@dataclass
class MemoryBoard:
    blocked_facts: list[BlockedFact] = field(default_factory=list)
    bypass_facts: list[BypassFact] = field(default_factory=list)
    dimension_stats: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_prompt_text(self, max_blocked: int = 10) -> str:
        lines = ["## Memory Board（已确认事实）"]

        # 维度统计
        if self.dimension_stats:
            lines.append("维度统计:")
            for dim, stats in self.dimension_stats.items():
                lines.append(f"  {dim}: 拦截={stats.get('blocked', 0)}, 绕过={stats.get('bypass', 0)}")

        # 最近绕过事实
        if self.bypass_facts:
            lines.append(f"已确认绕过 ({len(self.bypass_facts)} 条):")
            for bf in self.bypass_facts[-5:]:
                lines.append(f"  - [{bf.dimension}] {bf.payload_summary}... → {bf.evidence_summary[:80]}...")

        # 最近拦截事实（截断）
        recent_blocked = self.blocked_facts[-max_blocked:]
        if recent_blocked:
            lines.append(f"最近拦截 ({len(recent_blocked)}/{len(self.blocked_facts)} 条):")
            for bf in recent_blocked:
                lines.append(f"  - [{bf.dimension}] {bf.payload_summary}... → HTTP {bf.status_code} {bf.waf_signature}")

        if len(lines) == 1:
            lines.append("  (暂无记录)")
        return "\n".join(lines)


# ============================================================
# 双层状态板：Idea Board（猜测板）
# ============================================================

@dataclass
class MutationHypothesis:
    hypothesis: str
    target_dimension: str
    confidence: float
    source: str  # "manager_llm" | "observer_steer" | "kb_inference"
    round_proposed: int
    status: str = "pending"  # "pending" | "tried" | "abandoned"


@dataclass
class IdeaBoard:
    hypotheses: list[MutationHypothesis] = field(default_factory=list)
    available_dimensions: list[str] = field(default_factory=list)
    current_dimension: str = ""
    rounds_since_dimension_switch: int = 0

    def to_prompt_text(self, max_hypotheses: int = 5) -> str:
        lines = ["## Idea Board（待验证假设 — 以下均为猜测）"]

        pending = [h for h in self.hypotheses if h.status == "pending"]
        tried = [h for h in self.hypotheses if h.status == "tried"]

        if pending:
            lines.append(f"待验证假设 ({len(pending)} 条):")
            for h in pending[-max_hypotheses:]:
                lines.append(f"  - [{h.target_dimension}] {h.hypothesis} (置信度: {h.confidence:.0%}, 来源: {h.source})")

        if tried:
            lines.append(f"已尝试假设 ({len(tried)} 条):")
            for h in tried[-3:]:
                lines.append(f"  - [{h.target_dimension}] {h.hypothesis} → 已尝试")

        if self.available_dimensions:
            lines.append(f"可用维度: {', '.join(self.available_dimensions)}")
            if self.current_dimension:
                lines.append(f"当前维度: {self.current_dimension}, 连续轮数: {self.rounds_since_dimension_switch}")

        if len(lines) == 1:
            lines.append("  (暂无假设)")
        return "\n".join(lines)


# ============================================================
# Observer 旁路纠偏
# ============================================================

@dataclass
class SteerReminder:
    message: str
    suggested_dimension: str | None = None
    urgency: str = "medium"  # "low" | "medium" | "high"
    source_pattern: str = ""


# ============================================================
# 上下文压缩
# ============================================================

@dataclass
class CompactedResponse:
    payload_summary: str
    status_code: int
    dimension: str
    elapsed_ms: int
    evidence_snippet: str
    is_bypass: bool


@dataclass
class ObserverResult:
    verdicts: list[Verdict] = field(default_factory=list)
    bypass_count: int = 0
    blocked_count: int = 0
    summary: str = ""
    steer_reminder: SteerReminder | None = None


@dataclass
class RoundRecord:
    round_num: int
    dimension: str
    strategy: str
    bypass_count: int
    blocked_count: int
    compacted_responses: list[CompactedResponse] = field(default_factory=list)
    summary: str = ""
