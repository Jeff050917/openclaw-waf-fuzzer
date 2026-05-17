# -*- coding: utf-8 -*-
"""
workflow.py  主调度器

【核心职责】
1. 交互式目标选择：列出 target.yaml 中所有目标，用户可选择单个或全部。
2. 加载历史 WAF 规则知识库，注入 LLM 提示词以加速绕过。
3. 驱动三个阶段循环：
   - 阶段一 (baseliner): 双基线探测
   - 阶段二 (requester): 高频 Fuzzing 发包，响应到达后第一时间调用 inline_parser 提取证据
   - 阶段三 (llm_engine): CoT 分析 + Payload 变异
4. 每轮即时压缩 CoT 分析，逐轮更新 WAF 规则知识库。
5. 控制循环终止条件，将成功 Bypass 的 Payload 落盘。
"""

import io
import json
import os
import re
import sys
import time
from collections import OrderedDict

import yaml

# Windows 控制台 UTF-8 兼容
if sys.stdout.encoding not in (None, "utf-8") and hasattr(sys.stdout, "buffer"):
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", write_through=True)
    except Exception:
        pass

from llm_engine import init_client as init_llm_client, generate_initial_payloads, mutate_payloads
from baseliner import run_baseline
from requester import batch_send, send_cmdi_cleanup
from memory_compressor import load_kb, load_base_rules, consolidate_kb, get_kb_context, compress_cot_analyses

# ============================================================
# 终端颜色
# ============================================================

C = {
    "INFO":           "\033[36m[INFO]\033[0m",
    "OK":             "\033[32m[OK]\033[0m",
    "WARN":           "\033[33m[WARN]\033[0m",
    "WAF_BLOCKED":    "\033[31m[WAF-BLOCKED]\033[0m",
    "PARSER_NONE":    "\033[31m[PARSER-NONE]\033[0m",
    "BYPASS_SUCCESS": "\033[42m\033[30m[BYPASS-SUCCESS]\033[0m",
    "BYPASS_MAYBE":   "\033[45m\033[97m[BYPASS-MAYBE]\033[0m",
    "SEND":           "\033[90m[SEND]\033[0m",
    "PHASE":          "\033[1m\033[37m[PHASE]\033[0m",
    "BATCH":          "\033[35m[BATCH]\033[0m",
    "ERROR":          "\033[41m\033[97m[ERROR]\033[0m",
    "COT_ANALYSIS":   "\033[1m\033[33m[CoT·分析]\033[0m",
    "COT_STRATEGY":   "\033[1m\033[35m[CoT·策略]\033[0m",
    "EVIDENCE":       "\033[1m\033[32m[证据]\033[0m",
    "KB":             "\033[1m\033[34m[KB]\033[0m",
    "HEADER":         "\033[1m\033[36m",
    "RESET":          "\033[0m",
}

BLOCKED_STATUSES = {403, 406, 501, 429}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CONFIG_PATH = os.path.join(PROJECT_DIR, "config", "target.yaml")
OUTPUT_PATH = os.path.join(PROJECT_DIR, "output", "bypass_report.txt")


# ============================================================
# 配置加载
# ============================================================

def load_config(path: str) -> dict:
    """加载并校验 YAML 配置"""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"配置文件不存在: {path}")
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not cfg or "targets" not in cfg:
        raise ValueError("配置文件缺少 targets 字段")
    return cfg


# ============================================================
# 交互式目标选择
# ============================================================

def select_targets(targets: list) -> list:
    """打印交互式菜单，让用户选择要测试的目标。

    支持输入序号（如 1, 2, 3）选择单个目标，或输入 'all' 测试全部。
    返回选中的目标列表。
    """
    print(f"{C['INFO']} 发现 {len(targets)} 个目标:\n")

    for i, t in enumerate(targets, 1):
        vuln = t.get("vuln_type", "?").upper()
        method = t.get("method", "GET")
        url = t.get("url", "?")
        print(f"  {C['HEADER']}[{i}]{C['RESET']} {vuln:<6s} {method:<4s} {url}")

    print()
    print(f"  输入序号选择目标 (1-{len(targets)})，或输入 {C['HEADER']}all{C['RESET']} 测试全部:")

    while True:
        try:
            choice = input("  > ").strip()
            if choice.lower() == "all":
                print(f"\n{C['OK']} 已选择: 全部 {len(targets)} 个目标\n")
                return targets
            idx = int(choice)
            if 1 <= idx <= len(targets):
                selected = targets[idx - 1]
                print(f"\n{C['OK']} 已选择: [{idx}] {selected.get('vuln_type', '?').upper()} {selected.get('url', '?')}\n")
                return [selected]
            print(f"  {C['WARN']} 无效序号，请输入 1-{len(targets)} 或 'all'")
        except ValueError:
            print(f"  {C['WARN']} 无效输入，请输入数字序号或 'all'")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C['WARN']} 已取消")
            return []


# ============================================================
# 绕过技术分类
# ============================================================

# 预编译 _categorize_payload 正则（避免每轮重复编译）
_CAT_SQLI_UNION = re.compile(r'(?:union[\s/\*!]+select|/\*!.*union)')
_CAT_SQLI_ERROR = re.compile(r'(?:extractvalue|updatexml|floor\s*\(|exp~|polygon)')
_CAT_SQLI_BLIND = re.compile(r'(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()')
_CAT_SQLI_STACKED = re.compile(r';\s*(?:insert|update|delete|drop|create|alter|truncate)\s')
_CAT_SQLI_INLINE = re.compile(r'/\*!\d{3,6}')
_CAT_SQLI_HEX = re.compile(r'0x[0-9a-fA-F]{4,}')
_CAT_SQLI_CHAR = re.compile(r'(?:char\s*\(|unhex\s*\()')
_CAT_SQLI_DOUBLE = re.compile(r'(?:uniun|selsel|frofrom|whewhere|oror|anand)')
_CAT_SQLI_WIDE = re.compile(r'%[dD][fF]')
_CAT_SQLI_WS = re.compile(r'%0[bBcC]')
_CAT_SQLI_WS2 = re.compile(r'%0[aA]')
_CAT_SQLI_CLOSE = re.compile(r'[\'"]\s*(?:--(?:\s*[+#-])?|#)')
_CAT_CMDI_BS_PATH = re.compile(r'/[\w.-]*[\?*\[\]][\w?*\[\]./-]*')
_CAT_CMDI_BS_CMD = re.compile(r'\$\{ifs\}|\$[1-9@]|c[\x27"]a[\x27"]t|echo\s+[`$]')


def _categorize_payload(payload: str, vuln_type: str = "") -> str:
    """根据 Payload 特征自动识别绕过技术类型（同时支持 CMDI 和 SQLi）。"""
    p = payload.lower()

    if vuln_type == "sqli":
        if _CAT_SQLI_UNION.search(p):
            return "UNION注入"
        if _CAT_SQLI_ERROR.search(p):
            return "报错注入"
        if _CAT_SQLI_BLIND.search(p):
            return "盲注"
        if _CAT_SQLI_STACKED.search(p):
            return "堆叠查询"
        if _CAT_SQLI_INLINE.search(p):
            return "内联注释绕过"
        if _CAT_SQLI_HEX.search(p) or _CAT_SQLI_CHAR.search(p):
            return "编码绕过"
        if _CAT_SQLI_DOUBLE.search(p):
            return "双写绕过"
        if _CAT_SQLI_WIDE.search(p):
            return "宽字节注入"
        if _CAT_SQLI_WS.search(p) or (_CAT_SQLI_WS2.search(p) and 'union' in p):
            return "空白符绕过"
        if _CAT_SQLI_CLOSE.search(p):
            return "闭合绕过"
        return "直接注入"

    # --- CMDI 专属分类 ---
    if any(k in p for k in ['touch ', 'mkdir ', 'rm -f', 'ls -la', 'ls -l ']):
        return "文件盲注"
    if _CAT_CMDI_BS_PATH.search(p):
        return "绕过文件路径"
    if any(k in p for k in ['base64', 'xxd', 'od -', 'hexdump']) or _CAT_CMDI_BS_CMD.search(p):
        return "绕过命令"
    if any(k in p for k in ['%0a', '%0d%0a']):
        return "换行注入"
    return "直接读取"


def _format_evidence_summary(evidence: str, vuln_type: str) -> str:
    """格式化证据摘要，输出有意义的内容，过滤无信息价值的噪声。

    - CMDI：输出有效回显（如 root:x:0:0:root...），过滤 ping 回显
    - SQLi：输出数据库提取数据或延时信息
    - 无意义回显不输出
    """
    if not evidence:
        return ""

    lines = evidence.splitlines()
    meaningful = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # 过滤无信息价值的 ping 回显
        if re.search(r'(?:bytes from|icmp_seq=|ttl=|time=[\d.]+\s*ms)', stripped, re.IGNORECASE):
            continue
        # 过滤纯数字时间戳（假阳性风险）
        if re.match(r'^\d{6,}$', stripped):
            continue
        meaningful.append(stripped)

    if not meaningful:
        return evidence[:120]

    summary = " | ".join(meaningful[:3])
    return summary[:200]


# ============================================================
# 报告落盘 (纯文本格式)
# ============================================================

_bypass_entries: list[dict] = []


def record_bypass(entry: dict):
    """记录一条成功绕过（追加到内存列表并即时写盘）。"""
    _bypass_entries.append(entry)
    _flush_report()


def _flush_report():
    """将当前所有绕过记录按目标→分类分组写入纯文本文件。"""
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    # 按 (vuln_type, target) 分组
    groups: dict[tuple[str, str], dict[str, list[dict]]] = OrderedDict()
    for e in _bypass_entries:
        key = (e["vuln_type"], e["target"])
        if key not in groups:
            groups[key] = OrderedDict()
        cat = e.get("category", "直接读取")
        if cat not in groups[key]:
            groups[key][cat] = []
        groups[key][cat].append(e)

    sep = "=" * 80
    lines = [sep]
    lines.append("WAF-Fuzzer Bypass Report")
    lines.append(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}  |  共 {len(_bypass_entries)} 条记录")
    lines.append(sep)
    lines.append("")

    for (vuln_type, target), categories in groups.items():
        lines.append(f"████ {vuln_type.upper()} · {target} ████")
        lines.append("")

        for cat, entries in categories.items():
            lines.append(f"── {cat} ─ {len(entries)}条 ──")
            lines.append(f"{'Payload':<55s} 证据摘要")
            lines.append("-" * 53 + "  " + "-" * 30)
            for e in entries:
                pl = e.get("payload", "")
                ev = e.get("evidence", "")[:120].replace("\n", " / ")
                lines.append(f"{pl[:53]:<55s} {ev}")
            lines.append("")

        lines.append(sep)
        lines.append("")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ============================================================
# CoT 打印
# ============================================================

def print_cot(result: dict):
    """在终端打印 LLM 的 Chain-of-Thought 推理过程"""
    analysis = result.get("analysis", "")
    strategy = result.get("strategy", "")
    if analysis:
        print(f"  {C['COT_ANALYSIS']} {analysis}")
    if strategy:
        print(f"  {C['COT_STRATEGY']} {strategy}")
    if analysis or strategy:
        print()


# ============================================================
# 主调度
# ============================================================

def main(config_path: str = CONFIG_PATH) -> int:
    # ---- 打印横幅 ----
    print()
    print(f"{C['HEADER']}╔════════════════════════════════════════════════╗{C['RESET']}")
    print(f"{C['HEADER']}║     WAF-FUZZER :: Semantic Engine Bypass Test ║{C['RESET']}")
    print(f"{C['HEADER']}╚════════════════════════════════════════════════╝{C['RESET']}")
    print()

    # ---- 加载配置 ----
    print(f"{C['INFO']} 加载配置: {config_path}")
    cfg = load_config(config_path)

    llm_cfg = cfg.get("llm", {})
    fuzz_cfg = cfg.get("fuzzing", {})
    targets = cfg.get("targets", [])

    if not targets:
        print(f"{C['ERROR']} 没有配置任何靶场目标，退出。")
        return 1

    # ---- 初始化 LLM ----
    api_key = llm_cfg.get("api_key", "")
    base_url = llm_cfg.get("base_url", "https://token-plan-cn.xiaomimimimo.com/v1")
    model = llm_cfg.get("model", "mimo-v2.5-pro")

    if not api_key:
        print(f"{C['ERROR']} 请在 target.yaml 中填写 api_key 后重试。")
        return 1

    init_llm_client(api_key=api_key, base_url=base_url)
    print(f"{C['OK']} LLM 已连接: {model} @ {base_url}")
    print()

    # ---- 加载历史 WAF 规则知识库 ----
    base_rules = load_base_rules()
    kb_context = get_kb_context()
    if base_rules:
        print(f"{C['KB']} 已加载基础规则 ({len(base_rules)} 条) + Agent 学习规则 ({len(load_kb())} 条)")
        print()
    elif kb_context:
        print(f"{C['KB']} 已加载历史 WAF 拦截经验 ({len(load_kb())} 条记录)")
        print()
    else:
        print(f"{C['INFO']} 知识库为空，将从零开始积累 WAF 规则经验")
        print()

    # ---- 交互式目标选择 ----
    selected = select_targets(targets)
    if not selected:
        return 0

    max_iterations = fuzz_cfg.get("max_iterations", 100)
    batch_size = fuzz_cfg.get("batch_size", 15)
    concurrency = fuzz_cfg.get("concurrency", 5)
    request_timeout = fuzz_cfg.get("request_timeout", 10)
    early_stop = fuzz_cfg.get("early_stop_on_all_blocked", 100)

    # ---- 逐 target 执行 ----
    for t_idx, target in enumerate(selected, 1):
        url = target["url"]
        method = target.get("method", "GET")
        vuln_type = target.get("vuln_type", "sqli")
        headers = target.get("headers") or {}
        body = target.get("body") or ""
        params = target.get("params") or {}

        # 计算原始 targets 中的序号（用于显示）
        try:
            orig_idx = targets.index(target) + 1
        except ValueError:
            orig_idx = t_idx

        print(f"{C['HEADER']}{'─'*50}{C['RESET']}")
        print(f"{C['INFO']} 目标 [{orig_idx}/{len(targets)}]: {vuln_type.upper()} {method} {url}")
        print(f"{C['HEADER']}{'─'*50}{C['RESET']}")
        print()

        # ============================================================
        # 阶段一：基线探测（采集 HTML + 重试，使用 config timeout）
        # ============================================================
        print(f"{C['PHASE']} 阶段一 · 基线探测")
        baseline_html = ""
        for retry in range(3):
            try:
                baseline_html = run_baseline(target, timeout=request_timeout)
                break
            except Exception as e:
                if retry < 2:
                    wait = (retry + 1) * 5
                    print(f"{C['WARN']} 基线探测失败 (重试 {retry+1}/3, {wait}s后): {e}")
                    time.sleep(wait)
                else:
                    print(f"{C['ERROR']} 基线探测失败，跳过此目标: {e}")
        if not baseline_html:
            print()
            continue

        print()

        # ============================================================
        # 阶段二~三：Fuzzing 循环（Parser 内联管道）
        # ============================================================
        print(f"{C['PHASE']} 阶段二~三 · CoT 驱动 Fuzzing 循环 (Parser 内联管道)")
        print(f"{C['INFO']} 最大迭代: {max_iterations} 轮 | 每轮 {batch_size} 个 Payload | 并发 {concurrency}")
        print(f"{C['INFO']} Parser 管道: 响应到达 → 第一时间提取证据 → 仅证据文本流入下游")
        print()

        iteration = 0
        consecutive_all_blocked = 0
        total_blocked = 0
        total_bypass = 0
        current_payloads: list[str] = []
        cot_entries: list[str] = []  # 收集本轮所有 CoT 分析字符串
        force_strategy_change = False

        while iteration < max_iterations:
            iteration += 1

            # ---- 生成 Payload（注入 KB 上下文）----
            kb_filtered = get_kb_context(vuln_type=vuln_type)  # 仅注入同类型 KB，防止 CMDI 规则污染 SQLi
            if iteration == 1:
                print(f"{C['BATCH']} 第 {iteration} 轮  调用 LLM 生成初始 Payload ({vuln_type})...")
                try:
                    result = generate_initial_payloads(vuln_type, target_url=url, model=model, kb_context=kb_filtered)
                except Exception as e:
                    print(f"{C['ERROR']} LLM 生成失败: {e}")
                    break
            else:
                print(f"{C['BATCH']} 第 {iteration} 轮  调用 LLM 变异 Payload...")
                try:
                    result = mutate_payloads(failed_list, vuln_type=vuln_type, target_url=url, model=model, kb_context=kb_filtered, force_strategy_change=force_strategy_change)
                except Exception as e:
                    print(f"{C['ERROR']} LLM 变异失败: {e}")
                    break

            # 提取 CoT 思考过程并打印
            print_cot(result)

            # 收集 CoT 用于后续记忆压缩
            analysis = result.get("analysis", "")
            strategy = result.get("strategy", "")
            if analysis:
                cot_entries.append(f"[analysis] {analysis}")
            if strategy:
                cot_entries.append(f"[strategy] {strategy}")

            current_payloads = result.get("payloads", [])
            if not current_payloads:
                print(f"{C['WARN']} LLM 返回空 Payload 列表，终止循环。")
                break

            # 规范化：LLM 有时返回 {"payload": "...", "description": "..."} 字典而非纯字符串
            normalized = []
            for p in current_payloads:
                if isinstance(p, dict):
                    normalized.append(p.get("payload", p.get("text", json.dumps(p, ensure_ascii=False))))
                else:
                    normalized.append(str(p))
            current_payloads = normalized

            # 限制本批次数量
            current_payloads = current_payloads[:batch_size]
            print(f"{C['SEND']} 准备发送 {len(current_payloads)} 个 Payload...")
            print()

            # ---- 批量发送（Parser 内联管道）----
            t_send_start = time.perf_counter()

            # CMDI 盲注：每轮发包前先清理上一轮残留的标记文件，
            # 防止 ls 输出中出现旧文件导致假阳性（best-effort，失败不阻塞）
            if vuln_type == "cmdi" and iteration > 1:
                send_cmdi_cleanup(
                    url=url, method=method,
                    headers=headers, body=body, params=params,
                    timeout=request_timeout,
                )

            results = batch_send(
                url=url,
                method=method,
                payloads=current_payloads,
                headers=headers,
                body=body,
                params=params,
                concurrency=concurrency,
                timeout=request_timeout,
                baseline_html=baseline_html,
                vuln_type=vuln_type,
            )
            t_send_elapsed = time.perf_counter() - t_send_start

            # ---- 统计本轮 ----
            blocked_in_round = 0
            bypass_in_round = 0
            failed_list: list[str] = []

            for r in results:
                sc = r["status_code"]
                pl = r.get("payload", "")

                # 严格拦截判定
                if r["blocked"] or sc in BLOCKED_STATUSES:
                    print(f"{C['WAF_BLOCKED']} {pl[:60]:<60s}  │ 状态码 {sc}  拦截")
                    blocked_in_round += 1
                    failed_list.append(pl)
                    continue

                # Parser 管道：优先使用预提取的 evidence
                pre_evidence = r.get("evidence")
                if pre_evidence:
                    # Parser 已成功提取证据 → Bypass 成功！
                    print(f"{C['BYPASS_SUCCESS']} {pl[:60]:<60s}  │ 状态码 {sc}  证据提取成功!")
                    # 输出有意义的证据摘要（过滤无信息价值的内容）
                    evidence_summary = _format_evidence_summary(pre_evidence, vuln_type)
                    print(f"  {C['EVIDENCE']} {evidence_summary}")
                    bypass_in_round += 1
                    total_bypass += 1
                    record_bypass({
                        "target": url,
                        "vuln_type": vuln_type,
                        "payload": pl,
                        "category": _categorize_payload(pl, vuln_type=vuln_type),
                        "status_code": sc,
                        "evidence": pre_evidence[:500],
                        "iteration": iteration,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    continue

                # 无预提取 evidence → Parser 判定无有效证据
                print(f"{C['PARSER_NONE']} {pl[:60]:<60s}  │ 状态码 {sc}  Parser 无证据（无效/被拦截）")
                failed_list.append(pl)

            # ---- 轮次汇总 ----
            total_blocked += blocked_in_round
            blocked_ratio = blocked_in_round / max(len(results), 1)
            print()
            print(
                f"{C['INFO']} 第 {iteration} 轮汇总: "
                f"发送 {len(results)} | "
                f"拦截 {blocked_in_round} ({blocked_ratio:.0%}) | "
                f"绕过 {bypass_in_round} | "
                f"耗时 {t_send_elapsed:.1f}s"
            )

            # ---- 连续全拦截检测 ----
            if blocked_ratio >= 1.0:
                consecutive_all_blocked += 1
                print(f"{C['WARN']} 本轮全部被拦截! 连续全拦截: {consecutive_all_blocked}/{early_stop}")
                if consecutive_all_blocked >= early_stop:
                    print(f"{C['WARN']} 连续 {early_stop} 轮全部被拦截，下一轮将提醒 LLM 换思路。")
                    force_strategy_change = True
                    consecutive_all_blocked = 0
            else:
                consecutive_all_blocked = 0
                force_strategy_change = False

            # ---- 每轮结束：压缩本轮的 CoT 分析 + 拦截规律，即时更新 KB ----
            if cot_entries:
                try:
                    compressed = compress_cot_analyses(cot_entries, vuln_type=vuln_type, model=model)
                    if compressed:
                        consolidate_kb(vuln_type=vuln_type, compressed_rules=compressed, target_url=url)
                        if iteration == 1 or bypass_in_round > 0:
                            print(f"  {C['KB']} KB 已更新: {compressed[:120]}...")
                        # 刷新 kb_context 供下一轮 Prompt 注入
                        kb_context = get_kb_context()
                except Exception as e:
                    print(f"  {C['WARN']} KB 压缩失败: {e}")

            print()

        # CMDI：目标结束后清理所有残留标记文件
        if vuln_type == "cmdi":
            try:
                send_cmdi_cleanup(
                    url=url, method=method,
                    headers=headers, body=body, params=params,
                    timeout=request_timeout,
                )
            except Exception:
                pass

        # ---- 目标完成汇总 ----
        print(f"{C['HEADER']}{'─'*50}{C['RESET']}")
        print(f"{C['OK']} 目标 [{orig_idx}/{len(targets)}] 完成: "
              f"拦截 {total_blocked}, "
              f"绕过 {total_bypass}")
        print(f"{C['HEADER']}{'─'*50}{C['RESET']}")

    print()
    print(f"{C['OK']} 全部目标执行完毕，报告已保存至: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    config_arg = sys.argv[1] if len(sys.argv) > 1 else CONFIG_PATH
    sys.exit(main(config_arg))
