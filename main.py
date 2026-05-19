# -*- coding: utf-8 -*-
"""
main.py  Multi-Agent WAF Fuzzer 入口文件

组装 Manager、Solver、Observer、Crawler、WAFFingerprinter，驱动完整 Fuzzing 流程。

流程概览:
  1. 爬取入口 URL，发现表单
  2. Manager 推断注入类型 (cmdi/sqli/log4j)
  3. WAF 指纹识别
  4. 对每个注入点: 基线 -> 攻击面分析 -> Fuzzing 循环
  5. 生成最终报告
"""

import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

import yaml

# 确保 core/ 和 agents/ 在 Python import 路径中
_CORE_DIR = str(Path(__file__).parent / "core")
_AGENTS_DIR = str(Path(__file__).parent / "agents")
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)

from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from agents.manager import Manager
from agents.models import IdeaBoard, InjectionPoint, MemoryBoard, ObserverRequest, SolverRequest
from agents.observer import Observer
from agents.solver import Solver
from crawler import CandidateForm, parse_form_element
from llm_engine import init_client
from oob_provider import create_oob_provider

# ============================================================
# 终端颜色常量
# ============================================================

C_INFO = "\033[36m[INFO]\033[0m"
C_OK = "\033[32m[OK]\033[0m"
C_WARN = "\033[33m[WARN]\033[0m"
C_ERROR = "\033[41m\033[97m[ERROR]\033[0m"
C_PHASE = "\033[1m\033[37m[PHASE]\033[0m"
C_HEADER = "\033[1m\033[36m"
C_RESET = "\033[0m"

# Agent 角色标签
C_MANAGER = "\033[1m\033[35m[Manager]\033[0m"   # 紫色
C_SOLVER = "\033[1m\033[33m[Solver]\033[0m"     # 黄色
C_OBSERVER = "\033[1m\033[34m[Observer]\033[0m"  # 蓝色
C_BYPASS = "\033[1m\033[32m[BYPASS]\033[0m"     # 绿色
C_BLOCKED = "\033[1m\033[31m[BLOCKED]\033[0m"   # 红色
C_FLOW = "\033[90m"  # 灰色（流程线）


# ============================================================
# 运行日志文件（同时输出到终端和文件）
# ============================================================

class _Tee:
    """同时写入终端和日志文件，自动剥离 ANSI 颜色码。"""
    _ANSI_RE = __import__("re").compile(r"\033\[[0-9;]*m")

    def __init__(self, terminal, log_file):
        self.terminal = terminal
        self.log_file = log_file

    def write(self, msg):
        self.terminal.write(msg)
        self.log_file.write(self._ANSI_RE.sub("", msg))
        self.log_file.flush()

    def flush(self):
        self.terminal.flush()
        self.log_file.flush()


def _setup_log_file() -> Path:
    """创建运行日志文件，将 stdout/stderr 同时输出到终端和文件。返回日志路径。"""
    log_dir = Path("output/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"run_{timestamp}.log"
    log_file = open(log_path, "w", encoding="utf-8")
    sys.stdout = _Tee(sys.__stdout__, log_file)
    sys.stderr = _Tee(sys.__stderr__, log_file)
    return log_path


# ============================================================
# 配置加载
# ============================================================

def load_config(config_path: str) -> dict:
    """加载并校验 YAML 配置文件。"""
    if not Path(config_path).is_file():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not cfg:
        raise ValueError("配置文件为空")
    return cfg


# ============================================================
# 日志工具
# ============================================================

def _log(tag: str, msg: str) -> None:
    """带颜色的日志输出。"""
    print(f"{tag} {msg}")


# ============================================================
# 直接页面表单获取（替代全站爬取）
# ============================================================

# 模块级共享 session，保持登录态
_shared_session: requests.Session | None = None


def _get_shared_session() -> requests.Session:
    """获取或创建共享的 requests session。"""
    global _shared_session
    if _shared_session is None:
        _shared_session = requests.Session()
        _shared_session.trust_env = False
    return _shared_session


def _try_auto_login(session: requests.Session, soup: BeautifulSoup, page_url: str, timeout: int = 15) -> bool:
    """检测登录表单并尝试自动登录。返回是否成功。"""
    from llm_engine import _chat_json

    # 检测是否有 password 字段
    has_password = False
    for form in soup.find_all("form"):
        for inp in form.find_all("input"):
            inp_type = (inp.get("type") or "").lower()
            inp_name = (inp.get("name") or "").lower()
            if inp_type == "password" or "password" in inp_name or "pass" in inp_name:
                has_password = True
                break
        if has_password:
            break

    if not has_password:
        return False

    _log(C_INFO, "检测到登录页面，尝试自动登录...")

    # 获取登录表单
    form = None
    for f in soup.find_all("form"):
        for inp in f.find_all("input"):
            if (inp.get("type") or "").lower() == "password":
                form = f
                break
        if form:
            break

    if not form:
        return False

    action = form.get("action", "")
    method = (form.get("method") or "POST").upper()
    # action="#" 或空表示提交到当前页面
    if not action or action.strip() == "#":
        action_url = page_url.split("#")[0].split("?")[0]
    else:
        action_url = urljoin(page_url, action)

    # 收集表单字段
    fields: dict[str, str] = {}
    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        if not name:
            continue
        inp_type = (inp.get("type") or "").lower()
        if inp_type in ("submit", "button", "reset"):
            continue
        fields[name] = inp.get("value", "") or ""

    # 让 LLM 识别靶场类型并获取凭据
    field_names = list(fields.keys())
    page_title = soup.title.string.strip() if soup.title and soup.title.string else ""
    prompt = f"""你是一个 Web 安全专家。根据以下登录页面信息，识别靶场/应用类型并提供默认登录凭据。

页面标题: {page_title}
登录地址: {action_url}
表单字段: {field_names}

请返回 JSON：
{{"app_name": "应用名称", "username": "默认用户名", "password": "默认密码", "reasoning": "判断依据"}}

常见靶场默认凭据参考：
- DVWA: admin/password
- SQLi-labs: admin/password 或无认证
- Pikachu: admin/admin123
- WebGoat: guest/guest 或 webgoat/webgoat
- Mutillidae: admin/admin 或 blank/blank
- bWAPP: bee/bug
"""

    try:
        result = _chat_json(prompt, temperature=0.3, max_tokens=512)
        if not isinstance(result, dict):
            return False

        username = result.get("username", "")
        password = result.get("password", "")
        app_name = result.get("app_name", "")
        if not username and not password:
            return False

        _log(C_INFO, f"识别到 {app_name}，尝试登录: {username}/{password}")

        # 填充登录数据
        login_data: dict[str, str] = {}
        for name in fields:
            name_lower = name.lower()
            if "token" in name_lower or "csrf" in name_lower:
                login_data[name] = fields[name]
            elif "pass" in name_lower or "pwd" in name_lower:
                login_data[name] = password
            elif "user" in name_lower or "login" in name_lower or "account" in name_lower:
                login_data[name] = username
            else:
                login_data[name] = fields[name]

        # 提交按钮
        for inp in soup.find_all("input", {"type": "submit"}):
            btn_name = inp.get("name")
            btn_value = inp.get("value", "Login")
            if btn_name and btn_name not in login_data:
                login_data[btn_name] = btn_value

        # 提交登录
        if method == "POST":
            resp = session.post(action_url, data=login_data, timeout=timeout, allow_redirects=True)
        else:
            resp = session.get(action_url, params=login_data, timeout=timeout, allow_redirects=True)

        if resp.status_code in (200, 302):
            resp_text = resp.text.lower()
            if "logout" in resp_text or "dashboard" in resp_text or "vulnerabilities" in resp_text:
                _log(C_OK, f"登录成功: {app_name}")
                return True
            if "password" not in resp_text[:500]:
                _log(C_OK, f"登录成功: {app_name}")
                return True

        _log(C_WARN, f"登录失败 (HTTP {resp.status_code})")
        return False

    except Exception as e:
        _log(C_WARN, f"自动登录出错: {e}")
        return False


def fetch_page_forms(url: str, timeout: int = 15) -> list[CandidateForm]:
    """直接获取指定 URL 页面上的表单，不做全站爬取。自动处理登录。"""
    session = _get_shared_session()

    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        _log(C_WARN, f"获取页面失败 {url}: {e}")
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

    # 使用响应的实际 URL（处理重定向，如 /vulnerabilities/sqli/ → /login.php）
    resp_url = resp.url

    # 检测登录页面并自动登录
    if _try_auto_login(session, soup, resp_url, timeout):
        # 登录成功，重新获取目标页面
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            resp.raise_for_status()
        except requests.RequestException as e:
            _log(C_WARN, f"登录后重新获取页面失败 {url}: {e}")
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

    forms: list[CandidateForm] = []
    for form in soup.find_all("form"):
        parsed = parse_form_element(url, form, page_title)
        if parsed:
            forms.append(parsed)

    return forms


# ============================================================
# 对比模式：重放 + 报告
# ============================================================

def replay_against_target(
    blocked_payloads: list[str],
    target: InjectionPoint,
    observer: Observer,
    baseline_html: str,
    vuln_type: str,
    timeout: int,
) -> dict[str, dict]:
    """将 payload 列表重放到指定靶场，返回 {payload: {bypass, evidence, status_code}}。"""
    import requests as _requests

    session = _requests.Session()
    session.trust_env = False
    results: dict[str, dict] = {}

    for payload in blocked_payloads:
        try:
            start = time.monotonic()
            if target.method.upper() == "POST":
                from urllib.parse import quote
                body = (target.body or "").replace("{{INJECT}}", quote(payload, safe="%"))
                resp = session.post(
                    target.url, data=body, headers=target.headers,
                    timeout=timeout, allow_redirects=False,
                )
            else:
                params = {k: v.replace("{{INJECT}}", payload)
                          for k, v in (target.params or {}).items()}
                resp = session.get(
                    target.url, params=params, headers=target.headers,
                    timeout=timeout, allow_redirects=False,
                )
            elapsed = int((time.monotonic() - start) * 1000)

            from agents.models import RawResponse
            raw = RawResponse(
                payload=payload, status_code=resp.status_code,
                headers=dict(resp.headers), body=resp.text[:50000],
                elapsed_ms=elapsed, dimension="compare",
            )

            obs_req = ObserverRequest(
                responses=[raw], baseline_html=baseline_html,
                vuln_type=vuln_type, baseline_elapsed_ms=200,
            )
            obs_result = observer.evaluate(obs_req)

            bypass = obs_result.bypass_count > 0
            evidence = ""
            if obs_result.verdicts:
                v = obs_result.verdicts[0]
                if v.evidence:
                    evidence = v.evidence[:200]

            results[payload] = {
                "bypass": bypass, "evidence": evidence,
                "status_code": resp.status_code,
            }
        except Exception as e:
            results[payload] = {
                "bypass": False, "evidence": f"error: {e}",
                "status_code": 0,
            }
    return results


def generate_compare_report(
    compare_results: dict[str, dict],
    waf_profile,
    waf_url: str,
    no_waf_url: str,
) -> str:
    """生成 WAF vs 无 WAF 对比报告。"""
    sep = "=" * 72
    lines = [
        sep, "WAF-Fuzzer 对比报告", sep, "",
        f"WAF 靶场:    {waf_url}",
        f"无 WAF 靶场: {no_waf_url}",
    ]
    if waf_profile and waf_profile.detected:
        lines.append(f"WAF: {waf_profile.waf_name or '未知'} (置信度: {waf_profile.confidence:.0%})")
    lines += ["", sep, ""]

    waf_blocked, genuine_bypass, payload_broken = [], [], []
    for payload, result in compare_results.items():
        short = payload[:60] + ("..." if len(payload) > 60 else "")
        if result["bypass"]:
            genuine_bypass.append((short, result["evidence"][:80], result["status_code"]))
        else:
            payload_broken.append((short, result["evidence"][:80], result["status_code"]))

    # 真实绕过
    lines.append(f"  真实绕过 ({len(genuine_bypass)} 条)")
    lines.append("  同一 payload 在无 WAF 靶场也成功，说明绕过真实有效。")
    lines.append("")
    if genuine_bypass:
        lines.append(f"  {'Payload':<62} {'状态码':<6} 证据")
        lines.append(f"  {'-'*62} {'-'*6} {'-'*30}")
        for short, evidence, code in genuine_bypass:
            lines.append(f"  {short:<62} {code:<6} {evidence}")
    else:
        lines.append("  (无)")
    lines.append("")

    # WAF 拦截有效
    lines.append(f"  WAF 拦截有效 ({len(payload_broken)} 条)")
    lines.append("  payload 在无 WAF 靶场也失败，说明 payload 本身无效。")
    lines.append("")
    if payload_broken:
        lines.append(f"  {'Payload':<62} {'状态码':<6} 证据")
        lines.append(f"  {'-'*62} {'-'*6} {'-'*30}")
        for short, evidence, code in payload_broken:
            lines.append(f"  {short:<62} {code:<6} {evidence}")
    else:
        lines.append("  (无)")
    lines.append("")

    total = len(compare_results)
    lines.append(sep)
    lines.append(f"总计: {total} 条 payload | "
                 f"真实绕过: {len(genuine_bypass)} | "
                 f"payload 无效: {len(payload_broken)}")
    lines.append(sep)

    return "\n".join(lines)


# ============================================================
# 入口 URL 处理
# ============================================================

def process_entry_url(
    entry_url: str,
    config: dict,
    manager: Manager,
    solver: Solver,
    observer: Observer,
    llm_model: str,
    oob_provider=None,
) -> tuple[list[InjectionPoint], list[str]]:
    """处理单个入口 URL 的完整 Fuzzing 流程。

    Returns:
        (injection_points, blocked_payloads) — 供对比模式重放使用。

    Phases:
      1.   爬取站点，发现表单
      1.5. 推断注入类型
      2.   WAF 指纹识别
      3.   对每个注入点执行 Fuzzing 循环
    """
    all_blocked: list[str] = []
    _log(C_INFO, f"处理入口 URL: {entry_url}")

    # ----------------------------------------------------------
    # Phase 1: 站点爬取
    # ----------------------------------------------------------
    _log(C_PHASE, "Phase 1: 站点爬取")
    candidates = manager.crawl_site(entry_url)
    _log(C_OK, f"发现 {len(candidates)} 个候选表单")

    if not candidates:
        _log(C_WARN, "未发现任何表单，跳过此入口 URL")
        return [], []

    # ----------------------------------------------------------
    # Phase 1.5: 推断注入类型
    # ----------------------------------------------------------
    injection_points = manager.infer_injection_types(candidates)

    # 仅保留 cmdi / sqli / log4j
    _SUPPORTED_TYPES = {"cmdi", "sqli", "log4j"}
    injection_points = [p for p in injection_points if p.vuln_type in _SUPPORTED_TYPES]
    _log(C_OK, f"推断出 {len(injection_points)} 个注入点 (cmdi/sqli/log4j)")

    if not injection_points:
        _log(C_WARN, "未发现可识别的注入点，跳过此入口 URL")
        return [], []

    # ----------------------------------------------------------
    # Phase 2: WAF 指纹识别
    # ----------------------------------------------------------
    _log(C_PHASE, "Phase 2: WAF 指纹识别")
    waf_profile = manager.fingerprint_waf(entry_url)
    if waf_profile.detected:
        _log(C_OK, f"检测到 WAF: {waf_profile.waf_name or '未知'} "
             f"(置信度: {waf_profile.confidence:.0%})")
    else:
        _log(C_INFO, "未检测到 WAF")

    # ----------------------------------------------------------
    # Phase 3: 对每个注入点执行 Fuzzing
    # ----------------------------------------------------------
    fuzz_cfg = config.get("fuzzing", {})
    max_iterations = fuzz_cfg.get("max_iterations", 20)
    concurrency = fuzz_cfg.get("concurrency", 5)
    request_timeout = fuzz_cfg.get("request_timeout", 15)

    for pt_idx, point in enumerate(injection_points, 1):
        _log(C_PHASE, f"Phase 3: Fuzzing 注入点 [{pt_idx}/{len(injection_points)}] "
             f"{point.vuln_type.upper()} {point.method} {point.url}?{point.param}")

        # 每个注入点独立重置
        manager.round_history = []
        manager.memory_board = MemoryBoard()
        manager.idea_board = IdeaBoard()
        manager._blocked_payloads_window.clear()
        manager._steer_reminder = None

        # 3a. 基线采集
        _log(C_INFO, "采集基线响应...")
        baseline_html = manager.collect_baseline(point, timeout=request_timeout)
        baseline_elapsed_ms = 200  # 默认基线耗时

        # 3b. 攻击面分析
        _log(C_INFO, "分析攻击面...")
        attack_plan = manager.analyze_attack_surface(
            point, waf_profile=waf_profile, model=llm_model,
        )
        manager.idea_board.available_dimensions = attack_plan.dimension_priority
        _log(C_OK, f"攻击维度优先级: {attack_plan.dimension_priority}")

        # 3c. Fuzzing 循环
        _log(C_INFO, f"开始 Fuzzing 循环 (最多 {max_iterations} 轮)")
        for round_num in range(max_iterations):
            print(f"\n{C_FLOW}{'─' * 60}{C_RESET}")
            _log(C_INFO, f"━━━ 第 {round_num + 1}/{max_iterations} 轮 ━━━")

            # 3c-i. Manager 策略决策
            _log(C_MANAGER, f"分析攻击策略...")
            decision = manager.decide_strategy(
                round_num, attack_plan, point,
                waf_profile=waf_profile, model=llm_model,
            )
            _log(C_MANAGER, f"选定维度: [{decision.dimension}] 策略: {decision.strategy[:100]}")

            # 3c-ii. 构建 SolverRequest
            oob_session_token = ""
            needs_oob = point.vuln_type in ("log4j", "deserialization") and oob_provider
            if needs_oob:
                oob_session_token = str(uuid.uuid4())

            kb_context = decision.strategy
            if oob_session_token and oob_provider:
                kb_context += f"\n\nOOB token: {oob_session_token} @ {oob_provider.get_domain()}"

            # 协议层需要不可变基准 payload
            immutable_payload = ""
            if decision.dimension == "protocol" and manager._blocked_payloads_window:
                immutable_payload = manager._blocked_payloads_window[-1]

            solver_req = SolverRequest(
                target=point,
                strategy=decision.strategy,
                dimension=decision.dimension,
                kb_context=kb_context,
                round_num=round_num,
                blocked_payloads=manager.build_solver_blocked_payloads(),
                waf_profile=waf_profile,
                immutable_payload=immutable_payload,
            )

            # 3c-iii. Solver 生成并发送 Payload
            print(f"{C_FLOW}  ↓ {C_RESET}{C_SOLVER} 引擎: {decision.dimension} | 生成 Payload 并发送...{C_RESET}")
            responses = solver.solve(solver_req)

            if not responses:
                _log(C_WARN, "Solver 无响应，跳过本轮")
                continue

            # 展示 Solver 生成的 Payload 列表
            print(f"{C_FLOW}  ↓ {C_RESET}{C_SOLVER} 生成 {len(responses)} 个 Payload:{C_RESET}")
            for i, resp in enumerate(responses):
                payload_preview = resp.payload[:80].replace('\n', '\\n')
                status_str = f"HTTP {resp.status_code}" if resp.status_code else "ERR"
                print(f"{C_FLOW}  │  {C_RESET}[{i}] {status_str} | {payload_preview}")

            # 3c-iv. 构建 ObserverRequest
            oob_received = None
            if needs_oob and oob_provider and oob_session_token:
                oob_received = {
                    str(i): oob_provider.poll(oob_session_token)
                    for i in range(len(responses))
                }

            obs_req = ObserverRequest(
                responses=responses,
                baseline_html=baseline_html,
                vuln_type=point.vuln_type,
                baseline_elapsed_ms=baseline_elapsed_ms,
                oob_received=oob_received,
                round_num=round_num,
                dimension=decision.dimension,
            )

            # 3c-v. Observer 评估
            print(f"{C_FLOW}  ↓ {C_RESET}{C_OBSERVER} 独立评估响应证据...{C_RESET}")
            result = observer.evaluate(obs_req)

            # 展示 Observer 逐条判定结果
            for v in result.verdicts:
                tag = C_BYPASS if v.is_bypass else C_BLOCKED
                payload_preview = v.payload[:60].replace('\n', '\\n')
                evidence_preview = (v.evidence or "")[:80]
                print(f"{C_FLOW}  │  {C_RESET}{tag} {payload_preview} → {evidence_preview}")

            bypass_str = f"{C_BYPASS} {result.bypass_count}" if result.bypass_count > 0 else f"绕过 0"
            blocked_str = f"{C_BLOCKED} {result.blocked_count}" if result.blocked_count > 0 else f"拦截 0"
            print(f"{C_FLOW}  ↓ {C_RESET}{C_OBSERVER} 本轮: {bypass_str} | {blocked_str}")
            if result.summary:
                _log(C_OBSERVER, f"总结: {result.summary}")

            # 3c-vi. 转发纠偏提醒
            if result.steer_reminder:
                manager.set_steer_reminder(result.steer_reminder)
                _log(C_OBSERVER, f"纠偏提醒 [{result.steer_reminder.urgency}]: "
                     f"{result.steer_reminder.message[:100]}")

            # 3c-vii. Manager 记录结果
            manager.record_round(
                round_num=round_num,
                dimension=decision.dimension,
                strategy=decision.strategy,
                observer_result=result,
                vuln_type=point.vuln_type,
                target_url=point.url,
            )

            # 3c-viii. 更新知识库
            outcome_summary = f"[outcome] dim={decision.dimension}, bypass={result.bypass_count}, blocked={result.blocked_count}"
            if result.bypass_count > 0:
                bypass_evidence = "; ".join(
                    v.evidence[:80] for v in result.verdicts if v.is_bypass and v.evidence
                )
                outcome_summary += f", evidence: {bypass_evidence}"
            cot_entries = [f"[strategy] {decision.strategy}", outcome_summary]
            manager.update_kb(
                vuln_type=point.vuln_type,
                cot_entries=cot_entries,
                target_url=point.url,
                model=llm_model,
            )

            # 3c-ix. 检查是否应停止
            if manager.should_stop(round_num):
                _log(C_WARN, "满足停止条件，结束 Fuzzing 循环")
                break

        _log(C_OK, f"注入点 [{pt_idx}] Fuzzing 完成")
        all_blocked.extend(manager._blocked_payloads_window)

    return injection_points, all_blocked


# ============================================================
# 按漏洞类型的对比流程
# ============================================================

def run_vuln_type(
    vuln_type: str,
    waf_url: str,
    no_waf_url: str,
    config: dict,
    manager: Manager,
    solver: Solver,
    observer: Observer,
    llm_model: str,
    oob_provider,
) -> None:
    """单漏洞类型的完整 WAF vs 无-WAF 对比流程。

    直接获取目标页面表单，跳过全站爬取。
    """
    request_timeout = config.get("fuzzing", {}).get("request_timeout", 15)
    fuzz_cfg = config.get("fuzzing", {})
    max_iterations = fuzz_cfg.get("max_iterations", 20)

    _log(C_PHASE, f"[{vuln_type.upper()}] WAF: {waf_url}")
    _log(C_PHASE, f"[{vuln_type.upper()}] 无-WAF: {no_waf_url}")

    # ----------------------------------------------------------
    # Step 1: 直接获取 WAF 靶场页面表单
    # ----------------------------------------------------------
    _log(C_INFO, f"[{vuln_type}] 获取 WAF 靶场页面表单...")
    waf_forms = fetch_page_forms(waf_url, timeout=request_timeout)
    if not waf_forms:
        _log(C_WARN, f"[{vuln_type}] WAF 靶场页面无表单，跳过")
        return
    _log(C_OK, f"[{vuln_type}] 发现 {len(waf_forms)} 个表单")

    # ----------------------------------------------------------
    # Step 2: 使用 vuln_type 直接构建注入点
    # ----------------------------------------------------------
    injection_points = manager.infer_injection_types_with_hint(waf_forms, vuln_type)
    if not injection_points:
        _log(C_WARN, f"[{vuln_type}] 未找到注入点，跳过")
        return
    _log(C_OK, f"[{vuln_type}] 注入点: {', '.join(f'{p.param}({p.method})' for p in injection_points)}")

    # ----------------------------------------------------------
    # Step 3: WAF 指纹识别
    # ----------------------------------------------------------
    waf_profile = manager.fingerprint_waf(waf_url)
    if waf_profile.detected:
        _log(C_OK, f"[{vuln_type}] WAF: {waf_profile.waf_name or '未知'} (置信度: {waf_profile.confidence:.0%})")

    # ----------------------------------------------------------
    # Step 4: Fuzzing
    # ----------------------------------------------------------
    all_blocked: list[str] = []

    for pt_idx, point in enumerate(injection_points, 1):
        _log(C_PHASE, f"[{vuln_type}] Fuzzing 注入点 [{pt_idx}/{len(injection_points)}] "
             f"{point.method} {point.url}?{point.param}")

        # 每个注入点独立重置
        manager.round_history = []
        manager.memory_board = MemoryBoard()
        manager.idea_board = IdeaBoard()
        manager._blocked_payloads_window.clear()
        manager._steer_reminder = None

        # 基线采集
        baseline_html = manager.collect_baseline(point, timeout=request_timeout)

        # 攻击面分析
        attack_plan = manager.analyze_attack_surface(
            point, waf_profile=waf_profile, model=llm_model,
        )
        manager.idea_board.available_dimensions = attack_plan.dimension_priority

        # Fuzzing 循环
        for round_num in range(max_iterations):
            print(f"\n{C_FLOW}{'─' * 60}{C_RESET}")
            _log(C_INFO, f"━━━ [{vuln_type}] 第 {round_num + 1}/{max_iterations} 轮 ━━━")

            # Manager 策略决策
            _log(C_MANAGER, f"分析攻击策略...")
            decision = manager.decide_strategy(
                round_num, attack_plan, point,
                waf_profile=waf_profile, model=llm_model,
            )
            _log(C_MANAGER, f"选定维度: [{decision.dimension}] 策略: {decision.strategy[:100]}")

            # OOB token
            oob_session_token = ""
            needs_oob = point.vuln_type in ("log4j", "deserialization") and oob_provider
            if needs_oob:
                oob_session_token = str(uuid.uuid4())

            kb_context = decision.strategy
            if oob_session_token and oob_provider:
                kb_context += f"\n\nOOB token: {oob_session_token} @ {oob_provider.get_domain()}"

            immutable_payload = ""
            if decision.dimension == "protocol" and manager._blocked_payloads_window:
                immutable_payload = manager._blocked_payloads_window[-1]

            solver_req = SolverRequest(
                target=point, strategy=decision.strategy,
                dimension=decision.dimension, kb_context=kb_context,
                round_num=round_num,
                blocked_payloads=manager.build_solver_blocked_payloads(),
                waf_profile=waf_profile, immutable_payload=immutable_payload,
            )

            # Solver 生成并发送 Payload
            print(f"{C_FLOW}  ↓ {C_RESET}{C_SOLVER} 引擎: {decision.dimension} | 生成 Payload 并发送...{C_RESET}")
            responses = solver.solve(solver_req)

            if not responses:
                _log(C_WARN, "Solver 无响应，跳过本轮")
                continue

            # 展示 Solver 生成的 Payload 列表
            print(f"{C_FLOW}  ↓ {C_RESET}{C_SOLVER} 生成 {len(responses)} 个 Payload:{C_RESET}")
            for i, resp in enumerate(responses):
                payload_preview = resp.payload[:80].replace('\n', '\\n')
                status_str = f"HTTP {resp.status_code}" if resp.status_code else "ERR"
                print(f"{C_FLOW}  │  {C_RESET}[{i}] {status_str} | {payload_preview}")

            # Observer 评估
            oob_received = None
            if needs_oob and oob_provider and oob_session_token:
                oob_received = {str(i): oob_provider.poll(oob_session_token) for i in range(len(responses))}

            obs_req = ObserverRequest(
                responses=responses, baseline_html=baseline_html,
                vuln_type=point.vuln_type, baseline_elapsed_ms=200,
                oob_received=oob_received, round_num=round_num,
                dimension=decision.dimension,
            )
            print(f"{C_FLOW}  ↓ {C_RESET}{C_OBSERVER} 独立评估响应证据...{C_RESET}")
            result = observer.evaluate(obs_req)

            # 展示 Observer 逐条判定结果
            for v in result.verdicts:
                tag = C_BYPASS if v.is_bypass else C_BLOCKED
                payload_preview = v.payload[:60].replace('\n', '\\n')
                evidence_preview = (v.evidence or "")[:80]
                print(f"{C_FLOW}  │  {C_RESET}{tag} {payload_preview} → {evidence_preview}")

            bypass_str = f"{C_BYPASS} {result.bypass_count}" if result.bypass_count > 0 else f"绕过 0"
            blocked_str = f"{C_BLOCKED} {result.blocked_count}" if result.blocked_count > 0 else f"拦截 0"
            print(f"{C_FLOW}  ↓ {C_RESET}{C_OBSERVER} 本轮: {bypass_str} | {blocked_str}")
            if result.summary:
                _log(C_OBSERVER, f"总结: {result.summary}")

            if result.steer_reminder:
                manager.set_steer_reminder(result.steer_reminder)
                _log(C_OBSERVER, f"纠偏提醒 [{result.steer_reminder.urgency}]: {result.steer_reminder.message[:100]}")

            manager.record_round(
                round_num=round_num, dimension=decision.dimension,
                strategy=decision.strategy, observer_result=result,
                vuln_type=point.vuln_type, target_url=point.url,
            )

            # 更新知识库
            outcome_summary = f"[outcome] dim={decision.dimension}, bypass={result.bypass_count}, blocked={result.blocked_count}"
            if result.bypass_count > 0:
                bypass_evidence = "; ".join(v.evidence[:80] for v in result.verdicts if v.is_bypass and v.evidence)
                outcome_summary += f", evidence: {bypass_evidence}"
            manager.update_kb(
                vuln_type=point.vuln_type,
                cot_entries=[f"[strategy] {decision.strategy}", outcome_summary],
                target_url=point.url, model=llm_model,
            )

            if manager.should_stop(round_num):
                _log(C_WARN, "满足停止条件，结束 Fuzzing 循环")
                break

        all_blocked.extend(manager._blocked_payloads_window)
        _log(C_OK, f"[{vuln_type}] 注入点 [{pt_idx}] Fuzzing 完成")

    # ----------------------------------------------------------
    # Step 5: 重放到无-WAF 靶场
    # ----------------------------------------------------------
    if not all_blocked:
        _log(C_WARN, f"[{vuln_type}] 无被拦截的 payload，跳过对比")
        return

    _log(C_OK, f"[{vuln_type}] 收集到 {len(all_blocked)} 条被拦截的 payload")
    _log(C_PHASE, f"[{vuln_type}] 重放到无-WAF 靶场...")

    # 获取无-WAF 靶场注入点
    no_waf_forms = fetch_page_forms(no_waf_url, timeout=request_timeout)
    no_waf_points = manager.infer_injection_types_with_hint(no_waf_forms, vuln_type) if no_waf_forms else []

    if not no_waf_points:
        _log(C_WARN, f"[{vuln_type}] 无-WAF 靶场无注入点，跳过对比")
        return

    # 使用第一个注入点做重放
    no_waf_target = no_waf_points[0]
    no_waf_baseline = manager.collect_baseline(no_waf_target, timeout=request_timeout)

    compare_results = replay_against_target(
        blocked_payloads=all_blocked, target=no_waf_target,
        observer=observer, baseline_html=no_waf_baseline,
        vuln_type=vuln_type, timeout=request_timeout,
    )

    # ----------------------------------------------------------
    # Step 6: 生成对比报告
    # ----------------------------------------------------------
    report = generate_compare_report(
        compare_results=compare_results, waf_profile=waf_profile,
        waf_url=waf_url, no_waf_url=no_waf_url,
    )
    report_path = manager._output_dir / f"compare_report_{vuln_type}.txt"
    report_path.write_text(report, encoding="utf-8")
    _log(C_OK, f"[{vuln_type}] 对比报告已保存至: {report_path}")
    print()
    print(report)


# ============================================================
# 主入口
# ============================================================

def main(config_path: str = "config/target.yaml") -> int:
    """Multi-Agent WAF Fuzzer 主入口。"""
    # 初始化运行日志文件
    log_path = _setup_log_file()

    # 打印横幅
    print()
    print(f"{C_HEADER}================================================{C_RESET}")
    print(f"{C_HEADER}  WAF-Fuzzer :: Multi-Agent Semantic Bypass Test {C_RESET}")
    print(f"{C_HEADER}================================================{C_RESET}")
    print()
    _log(C_INFO, f"运行日志: {log_path.resolve()}")

    # 加载配置
    config = load_config(config_path)
    _log(C_OK, f"配置已加载: {config_path}")

    # 初始化 LLM 客户端
    llm_cfg = config.get("llm", {})
    api_key = llm_cfg.get("api_key", "")
    base_url = llm_cfg.get("base_url", "https://api.deepseek.com")
    llm_model = llm_cfg.get("model", "mimo-v2.5-pro")

    if not api_key:
        _log(C_ERROR, "请在 config/target.yaml 中填写 api_key")
        return 1

    init_client(api_key=api_key, base_url=base_url)
    _log(C_OK, f"LLM 客户端已初始化: {llm_model} @ {base_url}")

    # 初始化所有 Agent
    fuzz_cfg = config.get("fuzzing", {})
    manager = Manager(config)
    solver = Solver(
        concurrency=fuzz_cfg.get("concurrency", 5),
        timeout=fuzz_cfg.get("request_timeout", 15),
        model=llm_model,
    )
    observer = Observer()
    _log(C_OK, "所有 Agent 已初始化")

    # OOB 配置（自动 dnslog 或手动配置）
    oob_provider = create_oob_provider(config)
    if oob_provider:
        _log(C_OK, f"OOB 域名: {oob_provider.get_domain()}")

    # ----------------------------------------------------------
    # 按漏洞类型对比模式（targets 配置）
    # ----------------------------------------------------------
    targets = config.get("targets")
    if targets:
        for vuln_type, urls in targets.items():
            if not urls:
                _log(C_INFO, f"[{vuln_type}] 未配置 URL，跳过")
                continue
            waf_url = urls.get("waf", "")
            no_waf_url = urls.get("no_waf", "")
            if not waf_url:
                _log(C_WARN, f"[{vuln_type}] 缺少 waf URL，跳过")
                continue
            _log(C_HEADER, f"[{vuln_type.upper()}] " + "=" * 50)
            try:
                run_vuln_type(
                    vuln_type=vuln_type, waf_url=waf_url, no_waf_url=no_waf_url,
                    config=config, manager=manager, solver=solver,
                    observer=observer, llm_model=llm_model, oob_provider=oob_provider,
                )
            except Exception as e:
                _log(C_ERROR, f"[{vuln_type}] 处理失败: {e}")
                import traceback
                traceback.print_exc()

        # 生成标准报告
        _log(C_PHASE, "生成最终报告")
        report = manager.generate_final_report()
        _log(C_OK, f"报告已保存至: {manager._output_dir / 'bypass_report.txt'}")
        _log(C_OK, f"运行日志已保存至: {log_path.resolve()}")
        return 0

    # ----------------------------------------------------------
    # 旧格式：entry_urls（兼容）
    # ----------------------------------------------------------
    entry_urls = config.get("entry_urls", [])
    if not entry_urls:
        _log(C_ERROR, "配置文件中未定义 targets 或 entry_urls")
        return 1

    request_timeout = config.get("fuzzing", {}).get("request_timeout", 15)

    # ----------------------------------------------------------
    # 对比模式：2 个 URL
    # ----------------------------------------------------------
    if len(entry_urls) >= 2:
        waf_url = entry_urls[0]
        no_waf_url = entry_urls[1]
        _log(C_PHASE, "对比模式: WAF 靶场 vs 无 WAF 靶场")
        _log(C_INFO, f"WAF 靶场:    {waf_url}")
        _log(C_INFO, f"无 WAF 靶场: {no_waf_url}")

        # Step 1: 对 WAF 靶场执行完整 Fuzzing
        _log(C_HEADER, "[1/3] " + "=" * 50)
        try:
            waf_points, blocked_payloads = process_entry_url(
                entry_url=waf_url, config=config, manager=manager,
                solver=solver, observer=observer, llm_model=llm_model,
                oob_provider=oob_provider,
            )
        except Exception as e:
            _log(C_ERROR, f"处理 WAF 靶场 {waf_url} 时出错: {e}")
            import traceback
            traceback.print_exc()
            return 1

        if not blocked_payloads:
            _log(C_WARN, "无被拦截的 payload，跳过对比")
            return 0

        _log(C_OK, f"收集到 {len(blocked_payloads)} 条被拦截的 payload")

        # Step 2: 爬取无 WAF 靶场，匹配注入点
        _log(C_HEADER, "[2/3] " + "=" * 50)
        _log(C_PHASE, "爬取无 WAF 靶场")
        no_waf_candidates = manager.crawl_site(no_waf_url)
        no_waf_points = manager.infer_injection_types(no_waf_candidates) if no_waf_candidates else []
        no_waf_points = [p for p in no_waf_points if p.vuln_type in {"cmdi", "sqli", "log4j"}]
        _log(C_OK, f"无 WAF 靶场发现 {len(no_waf_points)} 个注入点")

        # 匹配注入点
        matched_target = None
        if waf_points and no_waf_points:
            for wp in waf_points:
                for np in no_waf_points:
                    if (wp.url.rstrip("/").split("//")[-1].split("/", 1)[-1] ==
                            np.url.rstrip("/").split("//")[-1].split("/", 1)[-1] and
                            wp.param == np.param):
                        matched_target = np
                        break
                if matched_target:
                    break
            if not matched_target:
                matched_target = no_waf_points[0]
        elif no_waf_points:
            matched_target = no_waf_points[0]

        if not matched_target:
            _log(C_WARN, "无 WAF 靶场未找到匹配注入点，使用 WAF 靶场的注入点模板")
            if waf_points:
                from copy import deepcopy
                matched_target = deepcopy(waf_points[0])
                matched_target.url = no_waf_url.rstrip("/") + "/" + matched_target.url.rstrip("/").split("//")[-1].split("/", 1)[-1]
            else:
                _log(C_ERROR, "无可用注入点，无法对比")
                return 1

        _log(C_OK, f"匹配注入点: {matched_target.method} {matched_target.url}?{matched_target.param}")

        # Step 3: 重放到无 WAF 靶场
        _log(C_HEADER, "[3/3] " + "=" * 50)
        _log(C_PHASE, f"重放 {len(blocked_payloads)} 条 payload 到无 WAF 靶场...")

        # 采集无 WAF 靶场基线
        no_waf_baseline = manager.collect_baseline(matched_target, timeout=request_timeout)

        # 重放
        compare_results = replay_against_target(
            blocked_payloads=blocked_payloads,
            target=matched_target,
            observer=observer,
            baseline_html=no_waf_baseline,
            vuln_type=matched_target.vuln_type,
            timeout=request_timeout,
        )

        # 生成对比报告
        _log(C_PHASE, "生成对比报告")
        waf_profile = manager.fingerprint_waf(waf_url)
        report = generate_compare_report(
            compare_results=compare_results,
            waf_profile=waf_profile,
            waf_url=waf_url,
            no_waf_url=no_waf_url,
        )
        report_path = manager._output_dir / "compare_report.txt"
        report_path.write_text(report, encoding="utf-8")
        _log(C_OK, f"对比报告已保存至: {report_path}")
        print()
        print(report)

        # 同时生成标准报告
        _log(C_PHASE, "生成标准报告")
        std_report = manager.generate_final_report()
        _log(C_OK, f"标准报告已保存至: {manager._output_dir / 'bypass_report.txt'}")

        return 0

    # ----------------------------------------------------------
    # 黑盒模式：1 个 URL
    # ----------------------------------------------------------
    for url_idx, entry_url in enumerate(entry_urls, 1):
        _log(C_HEADER, f"[{url_idx}/{len(entry_urls)}] " + "=" * 50)
        try:
            process_entry_url(
                entry_url=entry_url,
                config=config,
                manager=manager,
                solver=solver,
                observer=observer,
                llm_model=llm_model,
                oob_provider=oob_provider,
            )
        except Exception as e:
            _log(C_ERROR, f"处理 {entry_url} 时出错: {e}")
            import traceback
            traceback.print_exc()

    # 生成最终报告
    _log(C_PHASE, "生成最终报告")
    report = manager.generate_final_report()
    _log(C_OK, f"报告已保存至: {manager._output_dir / 'bypass_report.txt'}")
    print()
    print(report)

    _log(C_OK, f"运行日志已保存至: {log_path.resolve()}")
    return 0


if __name__ == "__main__":
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/target.yaml"
    try:
        sys.exit(main(config_path))
    except KeyboardInterrupt:
        print("\n[INFO] 用户中断，正在退出...")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] 未处理的异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # 关闭日志文件句柄
        if hasattr(sys.stdout, "log_file"):
            sys.stdout.log_file.close()
