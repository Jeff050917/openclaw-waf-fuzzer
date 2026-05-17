# -*- coding: utf-8 -*-
"""
memory_compressor.py  WAF 规则记忆压缩与知识库管理

【分层架构】
- config/base_rules.json    — 人工维护的基础规则（agent 只读，代码中无写入函数）
- output/learned_rules.json — agent 学习的规则（逐轮合并，只在此文件上写入）

【核心职责】
1. 收集每轮 fuzzing 的 CoT 分析字符串，调用 LLM 压缩为极简 WAF 规则要点（≤200 字）。
2. 持久化保存到 output/learned_rules.json（base_rules.json 永不被 agent 写入）。
3. 在后续生成 Payload 时，将两层历史经验拼接后注入系统提示词。
"""

import functools
import json
import os
import tempfile
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
KB_PATH = os.path.join(PROJECT_DIR, "output", "waf_rules_kb.json")
BASE_RULES_PATH = os.path.join(PROJECT_DIR, "config", "base_rules.json")
LEARNED_RULES_PATH = os.path.join(PROJECT_DIR, "output", "learned_rules.json")

_COMPRESS_PROMPT = (
    "你是一名 WAF 规则分析专家。以下是**本轮** {vuln_type_zh} WAF Fuzzing 的 Chain-of-Thought 分析记录。\n\n"
    "{history_section}"
    "请提炼出**一份精炼的拦截规律摘要**（不是逐条罗列！），供下一轮 Payload 生成直接参考。\n"
    "要求：\n"
    "1. 合并去重所有相似发现（包括历史记录），输出一个完整段落（不要列表、不要换行）。\n"
    "2. 每句话描述一项**独立的核心拦截规律**，格式：'WAF用正则拦截字面量X，需Y方式绕过'。\n"
    "3. 总输出严格 ≤150 字。超过 150 字的部分在注入 Prompt 时会被截断！\n"
    "4. 优先提炼「被拦截的关键字/正则模式 + 已验证可用的绕过手法」的组合。\n"
    "5. 如果本轮记录与历史记录指向同一个拦截模式，合并为一条，不要重复。\n"
    "6. 若本轮记录与历史记录存在矛盾（例如上轮说拦截cat字面量，本轮发现c?t也被拦截），\n"
    "   必须统一为更准确的推断（如'拦截了c.?t正则而非字面量cat'）。\n"
    "7. 排除所有推测性内容（\"可能是\"\"也许是\"），只保留已验证的拦截规律。\n\n"
    "CoT 分析记录：\n{combined_cot}"
)


@functools.lru_cache(maxsize=1)
def load_base_rules() -> list[dict]:
    """加载人工维护的基础规则（agent 只读，代码中无写入函数）。"""
    if not os.path.isfile(BASE_RULES_PATH):
        return []
    try:
        with open(BASE_RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


@functools.lru_cache(maxsize=1)
def load_kb() -> list[dict]:
    """加载 agent 学习的 WAF 规则（LRU 缓存）。自动从旧文件名迁移。"""
    # 一次性迁移旧文件名
    if not os.path.isfile(LEARNED_RULES_PATH) and os.path.isfile(KB_PATH):
        try:
            os.rename(KB_PATH, LEARNED_RULES_PATH)
        except OSError:
            pass

    path = LEARNED_RULES_PATH if os.path.isfile(LEARNED_RULES_PATH) else KB_PATH
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def consolidate_kb(vuln_type: str, compressed_rules: str, target_url: str):
    """整合式保存：同一 vuln_type 只保留一条，将新旧发现合并为单一整合摘要。

    若 KB 中已有该 vuln_type 的旧记录，调用 LLM 将旧规则与新发现整合去重，
    替换为一条完整记录。避免经验碎片化互相矛盾。
    """
    os.makedirs(os.path.dirname(LEARNED_RULES_PATH), exist_ok=True)
    kb = load_kb()

    # 查找同 vuln_type 的旧记录
    old_entry = None
    for entry in kb:
        if entry.get("vuln_type") == vuln_type:
            old_entry = entry
            break

    if old_entry and old_entry.get("rules"):
        # 有旧记录 → 调用 LLM 整合新旧规则去重
        try:
            merged = _merge_rules(
                old_rules=old_entry["rules"],
                new_rules=compressed_rules,
                vuln_type=vuln_type,
            )
            if merged:
                compressed_rules = merged
        except Exception:
            # LLM 整合失败 → 保留旧规则，追加新发现，避免历史经验丢失
            compressed_rules = old_entry["rules"] + "；" + compressed_rules

        # 移除旧条目
        kb = [e for e in kb if e.get("vuln_type") != vuln_type]

    kb.append({
        "vuln_type": vuln_type,
        "target": target_url,
        "rules": compressed_rules,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    })

    # 原子写入：先写临时文件再 rename，防止崩溃导致文件损坏
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=os.path.dirname(LEARNED_RULES_PATH), suffix=".tmp"
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(kb, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, LEARNED_RULES_PATH)
    except BaseException:
        os.close(tmp_fd)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    # 清除 load_kb 缓存，确保下次读取的是最新数据
    load_kb.cache_clear()


def _merge_rules(old_rules: str, new_rules: str, vuln_type: str) -> str:
    """调用 LLM 将历史规则与新发现整合为一条去重摘要。"""
    from llm_engine import _get_client
    vuln_name = {"sqli": "SQL 注入", "cmdi": "命令注入", "log4j": "Log4j"}.get(vuln_type, vuln_type)
    prompt = (
        f"你是一名 WAF 规则分析专家。将以下关于 {vuln_name} 漏洞的**历史经验**和**新发现**整合为一份精炼摘要。\n"
        "要求：合并去重、输出一个完整段落（≤150字）、排除推测性内容。\n"
        "专注描述 WAF 对该类型攻击的检测规则和被验证有效的绕过手法。\n\n"
        f"历史经验：{old_rules}\n\n"
        f"新发现：{new_rules}\n\n"
        "仅返回整合后的规则文本，不要任何额外内容。"
    )
    try:
        client = _get_client()
        resp = client.chat.completions.create(
            model="mimo-v2.5-pro",
            temperature=0.3,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.choices[0].message.content.strip()
        return raw[:500] if len(raw) > 500 else raw
    except Exception:
        return ""


def get_kb_context(vuln_type: str = "") -> str:
    """将两层知识库格式化为可注入 Prompt 的上下文字符串。

    base_rules（人工维护）在前，learned_rules（agent 学习）在后，
    同 vuln_type 两层都有条目时直接拼两行，不做跨层合并。

    Args:
        vuln_type: 若指定，仅返回该漏洞类型的条目；若为空，返回所有条目。
    """
    base = load_base_rules()
    learned = load_kb()

    lines = []

    # Layer 1: base rules (human-written, read-only)
    for entry in base:
        vuln = entry.get("vuln_type", "?").upper()
        rules = entry.get("rules", "")
        if not rules:
            continue
        # general 条目始终注入，不受 vuln_type 过滤
        if vuln_type and entry.get("vuln_type") != vuln_type and entry.get("vuln_type") != "general":
            continue
        lines.append(f"- [{vuln}] {rules}")

    # Layer 2: learned rules (agent-written)
    for entry in learned:
        vuln = entry.get("vuln_type", "?").upper()
        rules = entry.get("rules", "")
        if not rules:
            continue
        if vuln_type and entry.get("vuln_type") != vuln_type and entry.get("vuln_type") != "general":
            continue
        lines.append(f"- [{vuln}] {rules}")

    if not lines:
        return ""

    has_base = any(
        (not vuln_type or e.get("vuln_type") == vuln_type or e.get("vuln_type") == "general") and e.get("rules")
        for e in base
    )
    if has_base:
        header = "## WAF 拦截经验（基础规则 + Agent 学习，请务必参考）：\n"
    else:
        header = "## 历史 WAF 拦截经验（已整合去重，请务必参考）：\n"

    return header + "\n".join(lines)


def compress_cot_analyses(
    cot_entries: list[str],
    vuln_type: str,
    model: str = "mimo-v2.5-pro",
) -> str:
    """调用 LLM 将 CoT 分析记录压缩为极简 WAF 规则要点。

    Args:
        cot_entries: 本轮收集的所有 CoT 分析/策略字符串
        vuln_type: 漏洞类型
        model: LLM 模型名

    Returns:
        压缩后的规则要点文本（≤200 字），失败时返回空字符串。
    """
    if not cot_entries:
        return ""

    from llm_engine import _get_client

    # 检查是否有同 vuln_type 的历史记录，有则加入 Prompt 要求整合去重
    # general 条目始终注入（通用 WAF 绕过思路）
    history_section = ""
    wanted = {vuln_type, "general"}
    # 先注入 base_rules（人工维护，不可修改）
    base = load_base_rules()
    for entry in base:
        if entry.get("vuln_type") in wanted and entry.get("rules"):
            history_section += (
                "## 基础已验证规则（人工维护，不可修改）：\n"
                f"{entry['rules']}\n\n"
            )
    # 再注入 learned_rules（agent 学习）
    kb = load_kb()
    for entry in kb:
        if entry.get("vuln_type") in wanted and entry.get("rules"):
            history_section += (
                "## 历史已验证经验（必须与新发现整合去重，不要重复已有内容）：\n"
                f"{entry['rules']}\n\n"
            )

    combined = "\n---\n".join(
        e[:600] for e in cot_entries[-10:]  # 最多取最近 10 条，每条截断 600 字
    )
    vuln_name = {"sqli": "SQL 注入", "cmdi": "命令注入", "log4j": "Log4j"}.get(vuln_type, vuln_type)
    prompt = _COMPRESS_PROMPT.format(
        vuln_type_zh=vuln_name,
        history_section=history_section,
        combined_cot=combined,
    )

    try:
        client = _get_client()
        resp = client.chat.completions.create(
            model=model,
            temperature=0.3,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.choices[0].message.content.strip()
        # 限制在 150 字以内（供 Prompt 注入，必须极简）
        if len(raw) > 150:
            raw = raw[:150]
        return raw
    except Exception:
        return ""
