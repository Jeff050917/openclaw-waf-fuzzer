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
from pathlib import Path

import yaml

# 确保 core/ 和 agents/ 在 Python import 路径中
_CORE_DIR = str(Path(__file__).parent / "core")
_AGENTS_DIR = str(Path(__file__).parent / "agents")
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)

from agents.manager import Manager
from agents.models import ObserverRequest, SolverRequest
from agents.observer import Observer
from agents.solver import Solver
from core.crawler import SiteCrawler
from core.llm_engine import init_client
from core.waf_fingerprinter import WAFFingerprinter

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
# 入口 URL 处理
# ============================================================

def process_entry_url(
    entry_url: str,
    config: dict,
    manager: Manager,
    solver: Solver,
    observer: Observer,
    crawler: SiteCrawler,
    fingerprinter: WAFFingerprinter,
    llm_model: str,
    oob_config: dict | None,
) -> None:
    """处理单个入口 URL 的完整 Fuzzing 流程。

    Phases:
      1.   爬取站点，发现表单
      1.5. 推断注入类型
      2.   WAF 指纹识别
      3.   对每个注入点执行 Fuzzing 循环
    """
    _log(C_INFO, f"处理入口 URL: {entry_url}")

    # ----------------------------------------------------------
    # Phase 1: 站点爬取
    # ----------------------------------------------------------
    _log(C_PHASE, "Phase 1: 站点爬取")
    candidates = crawler.crawl(entry_url)
    _log(C_OK, f"发现 {len(candidates)} 个候选表单")

    if not candidates:
        _log(C_WARN, "未发现任何表单，跳过此入口 URL")
        return

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
        return

    # ----------------------------------------------------------
    # Phase 2: WAF 指纹识别
    # ----------------------------------------------------------
    _log(C_PHASE, "Phase 2: WAF 指纹识别")
    waf_profile = fingerprinter.fingerprint(entry_url)
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

        # 每个注入点独立的 round 记录
        manager.round_history = []

        # 3a. 基线采集
        _log(C_INFO, "采集基线响应...")
        baseline_html = manager.collect_baseline(point, timeout=request_timeout)
        baseline_elapsed_ms = 200  # 默认基线耗时

        # 3b. 攻击面分析
        _log(C_INFO, "分析攻击面...")
        attack_plan = manager.analyze_attack_surface(
            point, waf_profile=waf_profile, model=llm_model,
        )
        _log(C_OK, f"攻击维度优先级: {attack_plan.dimension_priority}")

        # 3c. Fuzzing 循环
        _log(C_INFO, f"开始 Fuzzing 循环 (最多 {max_iterations} 轮)")
        for round_num in range(max_iterations):
            _log(C_INFO, f"--- 第 {round_num + 1}/{max_iterations} 轮 ---")

            # 3c-i. 策略决策
            decision = manager.decide_strategy(
                round_num, attack_plan, point,
                waf_profile=waf_profile, model=llm_model,
            )
            _log(C_INFO, f"策略: [{decision.dimension}] {decision.strategy[:80]}...")

            # 3c-ii. 构建 SolverRequest
            oob_session_token = ""
            if point.vuln_type in ("log4j", "deserialization") and oob_config:
                oob_session_token = str(uuid.uuid4())

            kb_context = decision.strategy
            if oob_session_token:
                kb_context += f"\n\nOOB token: {oob_session_token} @ {oob_config.get('server', '')}"

            solver_req = SolverRequest(
                target=point,
                strategy=decision.strategy,
                dimension=decision.dimension,
                kb_context=kb_context,
                round_num=round_num,
                blocked_payloads=list(manager.blocked_history),
                waf_profile=waf_profile,
            )

            # 3c-iii. Solver 生成并发送 Payload
            _log(C_INFO, f"Solver [{decision.dimension}] 生成并发送 Payload...")
            responses = solver.solve(solver_req)
            _log(C_OK, f"收到 {len(responses)} 个响应")

            if not responses:
                _log(C_WARN, "无响应，跳过本轮")
                continue

            # 3c-iv. 构建 ObserverRequest
            oob_tokens = None
            if oob_session_token and point.vuln_type in ("log4j", "deserialization"):
                oob_tokens = {str(i): oob_session_token for i in range(len(responses))}

            obs_req = ObserverRequest(
                responses=responses,
                baseline_html=baseline_html,
                vuln_type=point.vuln_type,
                baseline_elapsed_ms=baseline_elapsed_ms,
                oob_server=oob_config.get("server") if oob_config else None,
                oob_poll_api=oob_config.get("poll_api") if oob_config else None,
                oob_tokens=oob_tokens,
            )

            # 3c-v. Observer 评估
            result = observer.evaluate(obs_req)
            _log(C_OK, f"评估结果: {result.summary}")

            # 3c-vi. Manager 记录结果
            manager.record_round(
                round_num=round_num,
                dimension=decision.dimension,
                strategy=decision.strategy,
                observer_result=result,
                vuln_type=point.vuln_type,
                target_url=point.url,
            )

            # 3c-vii. 更新知识库
            cot_entries = [f"[strategy] {decision.strategy}"]
            manager.update_kb(
                vuln_type=point.vuln_type,
                cot_entries=cot_entries,
                target_url=point.url,
                model=llm_model,
            )

            # 3c-viii. 检查是否应停止
            if manager.should_stop(round_num):
                _log(C_WARN, "满足停止条件，结束 Fuzzing 循环")
                break

        _log(C_OK, f"注入点 [{pt_idx}] Fuzzing 完成")


# ============================================================
# 主入口
# ============================================================

def main(config_path: str = "config/target.yaml") -> int:
    """Multi-Agent WAF Fuzzer 主入口。"""
    # 打印横幅
    print()
    print(f"{C_HEADER}================================================{C_RESET}")
    print(f"{C_HEADER}  WAF-Fuzzer :: Multi-Agent Semantic Bypass Test {C_RESET}")
    print(f"{C_HEADER}================================================{C_RESET}")
    print()

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
    crawler = SiteCrawler(timeout=fuzz_cfg.get("request_timeout", 15))
    fingerprinter = WAFFingerprinter(timeout=fuzz_cfg.get("request_timeout", 15))
    _log(C_OK, "所有 Agent 已初始化")

    # OOB 配置
    oob_config = config.get("oob") or None
    if oob_config:
        _log(C_OK, f"OOB 服务器: {oob_config.get('server', 'N/A')}")

    # 获取入口 URL 列表
    entry_urls = config.get("entry_urls", [])
    if not entry_urls:
        _log(C_ERROR, "配置文件中未定义 entry_urls")
        return 1

    # 逐个处理入口 URL
    for url_idx, entry_url in enumerate(entry_urls, 1):
        _log(C_HEADER, f"[{url_idx}/{len(entry_urls)}] " + "=" * 50)
        try:
            process_entry_url(
                entry_url=entry_url,
                config=config,
                manager=manager,
                solver=solver,
                observer=observer,
                crawler=crawler,
                fingerprinter=fingerprinter,
                llm_model=llm_model,
                oob_config=oob_config,
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
