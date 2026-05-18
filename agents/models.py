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
