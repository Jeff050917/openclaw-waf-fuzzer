# -*- coding: utf-8 -*-
"""
response_extractor.py  响应关键信息提取器（Token 压缩专用）

【核心职责】
1. 从 DVWA CMDI 响应包中提取 <pre> 标签内容（命令注入的唯一输出区域）。
2. 与干净基线做行级 diff，剔除页面自身框架内容。
3. 多层假阳性过滤（WAF拦截页/网络诊断/Shell报错/空输出）。
4. 输出紧凑摘要，供 LLM 审查时只传关键文本，大幅削减 Token 消耗。

【Token 压缩效果】
  典型 DVWA CMDI 响应包: 8000-15000 字符（完整 HTML）
  → 提取+diff后: 20-500 字符（仅增量 <pre> 内容）
  → 压缩比: 95%-99.8%

【用法】
  # 命令行：对比单个响应和基线
  python response_extractor.py baseline.html response.html

  # 命令行：批量对比（输出 JSON 摘要供 LLM 审查）
  python response_extractor.py --baseline baseline.html --responses r1.html r2.html r3.html

  # 作为模块：
  from response_extractor import extract_delta, batch_extract_for_llm
  delta = extract_delta(baseline_html, response_html)
  batch = batch_extract_for_llm(baseline_html, [r1_html, r2_html, r3_html])
"""

import html as _html_mod
import json
import os
import re
import sys

# ============================================================
# 假阳性过滤正则（与 inline_parser 保持一致）
# ============================================================

_WAF_BLOCKED = re.compile(
    r'access\s+denied|blocked|forbidden|被拦截|拦截页面|403\s+Forbidden|406\s+Not\s+Acceptable',
    re.IGNORECASE,
)

_NETWORK_DIAG = re.compile(
    r'PING\s+\S+|bytes\s+from\s+\d|icmp_seq=\d|ttl=\d|time=[\d.]+|'
    r'packets\s+transmitted|packet\s+loss|round-trip|'
    r'rtt\s+min/avg/max|traceroute\s+to|nslookup|Server:\s+\S+|Address:\s+\d',
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


# ============================================================
# 核心提取函数
# ============================================================

def extract_pre_blocks(html: str) -> str:
    """提取所有 <pre> 标签内的纯文本，剥离 HTML 标签并实体解码。"""
    if not html:
        return ""
    blocks = re.findall(r'<pre[^>]*>([\s\S]*?)</pre>', html, re.IGNORECASE)
    if not blocks:
        return ""
    text = "\n".join(blocks)
    text = re.sub(r'<[^>]*>', '', text)  # 剥离残留 HTML 标签
    text = _html_mod.unescape(text)
    return text.strip()


def _diff_lines(text: str, baseline_text: str) -> str:
    """行级集合差：从 text 中移除 baseline 已存在的行。"""
    if not baseline_text:
        return text
    base_lines = set(baseline_text.splitlines())
    new_lines = [l for l in text.splitlines() if l.strip() and l not in base_lines]
    return "\n".join(new_lines) if new_lines else ""


def _is_false_positive(text: str) -> bool:
    """多维度假阳性判定。"""
    if not text or not text.strip():
        return True
    if _EMPTY_OR_TRIVIAL.match(text.strip()):
        return True
    if _WAF_BLOCKED.search(text):
        return True
    if _NETWORK_DIAG.search(text):
        return True
    if _SHELL_ERRORS.search(text):
        return True
    return False


def extract_delta(baseline_html: str, response_html: str) -> dict:
    """提取响应包相对于基线的关键增量内容。

    Args:
        baseline_html: 干净基线响应（无注入）
        response_html: 待检测的响应包

    Returns:
        {
            "has_delta": bool,       # 是否有有效增量
            "delta_text": str,       # 增量文本（已过滤）
            "raw_pre": str,          # 原始 <pre> 内容（未过滤）
            "baseline_pre": str,     # 基线的 <pre> 内容
            "is_false_positive": bool,
            "false_positive_reason": str,
            "token_saved": int,      # 相比传完整 HTML 节省的字符数
        }
    """
    result = {
        "has_delta": False,
        "delta_text": "",
        "raw_pre": "",
        "baseline_pre": "",
        "is_false_positive": False,
        "false_positive_reason": "",
        "token_saved": 0,
    }

    response_len = len(response_html) if response_html else 0
    raw_pre = extract_pre_blocks(response_html)
    result["raw_pre"] = raw_pre

    if not raw_pre:
        result["token_saved"] = response_len
        return result

    baseline_pre = extract_pre_blocks(baseline_html) if baseline_html else ""
    result["baseline_pre"] = baseline_pre

    # 第一层假阳性检查
    if _WAF_BLOCKED.search(raw_pre):
        result["is_false_positive"] = True
        result["false_positive_reason"] = "WAF拦截页面"
        result["token_saved"] = response_len - len(raw_pre)
        return result

    # 行级 diff
    delta = _diff_lines(raw_pre, baseline_pre)

    if not delta:
        # 有 <pre> 但无增量（与基线完全一致）
        result["token_saved"] = response_len
        return result

    # 第二层假阳性检查（对增量内容）
    if _NETWORK_DIAG.search(delta):
        result["is_false_positive"] = True
        result["false_positive_reason"] = "网络诊断输出(ping/traceroute)"
        result["delta_text"] = delta
        result["token_saved"] = response_len - len(delta)
        return result

    if _SHELL_ERRORS.search(delta):
        result["is_false_positive"] = True
        result["false_positive_reason"] = "Shell命令报错"
        result["delta_text"] = delta
        result["token_saved"] = response_len - len(delta)
        return result

    if _EMPTY_OR_TRIVIAL.match(delta.strip()):
        result["is_false_positive"] = True
        result["false_positive_reason"] = "空/纯标点输出"
        result["token_saved"] = response_len
        return result

    # 通过所有检查
    result["has_delta"] = True
    result["delta_text"] = delta[:2000]  # 截断保护
    result["token_saved"] = response_len - len(delta)
    return result


# ============================================================
# 批量提取：为 LLM 审查准备紧凑摘要
# ============================================================

def batch_extract_for_llm(
    baseline_html: str,
    response_htmls: list[str],
    max_chars_per_entry: int = 600,
    max_entries: int = 10,
) -> dict:
    """批量提取多个响应包的增量内容，输出 LLM 审查就绪的紧凑格式。

    Args:
        baseline_html: 干净基线响应
        response_htmls: 待审查的响应包列表
        max_chars_per_entry: 每条增量内容的最大字符数（截断）
        max_entries: 最多返回多少条（取最近 N 条）

    Returns:
        {
            "summary": str,           # 可直接注入 LLM prompt 的编号文本块
            "entries": list[dict],    # 每条详情
            "total_original_chars": int,
            "total_extracted_chars": int,
            "compression_ratio": float,
        }
    """
    entries = []
    total_original = 0
    total_extracted = 0

    # 取最近 max_entries 条
    for i, resp_html in enumerate(response_htmls[-max_entries:]):
        total_original += len(resp_html) if resp_html else 0
        delta = extract_delta(baseline_html, resp_html)

        entry = {
            "index": i,
            "has_delta": delta["has_delta"],
            "is_false_positive": delta["is_false_positive"],
            "false_positive_reason": delta["false_positive_reason"],
            "delta_text": delta["delta_text"][:max_chars_per_entry],
            "raw_pre": delta["raw_pre"][:max_chars_per_entry],
            "chars_original": len(resp_html) if resp_html else 0,
            "chars_extracted": len(delta["delta_text"]),
        }
        entries.append(entry)
        total_extracted += len(delta["delta_text"])

    # 构建 LLM 审查就绪的编号文本
    summary_lines = []
    for e in entries:
        content = e["delta_text"] if e["has_delta"] else e["raw_pre"]
        tag = ""
        if e["is_false_positive"]:
            tag = f" [疑似假阳性: {e['false_positive_reason']}]"
        elif not e["has_delta"]:
            tag = " [无增量内容]"
        summary_lines.append(f"--- 条目 {e['index']} ---{tag}\n{content[:max_chars_per_entry]}")

    compression = 1 - (total_extracted / max(total_original, 1))

    return {
        "summary": "\n".join(summary_lines),
        "entries": entries,
        "total_original_chars": total_original,
        "total_extracted_chars": total_extracted,
        "compression_ratio": round(compression, 4),
    }


# ============================================================
# Token 估算
# ============================================================

def estimate_tokens(text: str) -> int:
    """粗略估算 Token 数（英文约 4 字符/Token，中文约 1.5 字符/Token）。"""
    if not text:
        return 0
    ascii_chars = sum(1 for c in text if ord(c) < 128)
    non_ascii_chars = len(text) - ascii_chars
    return int(ascii_chars / 4 + non_ascii_chars / 1.5)


# ============================================================
# 命令行入口
# ============================================================

def _main():
    import argparse

    parser = argparse.ArgumentParser(
        description="DVWA CMDI 响应关键信息提取器 — 压缩 Token 消耗",
    )
    sub = parser.add_subparsers(dest="command")

    # 单文件对比
    single = sub.add_parser("diff", help="对比单个响应和基线")
    single.add_argument("baseline", help="基线 HTML 文件路径")
    single.add_argument("response", help="响应 HTML 文件路径")
    single.add_argument("--json", action="store_true", help="JSON 输出")

    # 批量提取
    batch = sub.add_parser("batch", help="批量提取，输出 LLM 审查摘要")
    batch.add_argument("--baseline", required=True, help="基线 HTML 文件路径")
    batch.add_argument("--responses", nargs="+", required=True, help="响应 HTML 文件路径列表")
    batch.add_argument("--max-chars", type=int, default=600, help="每条最大字符数 (默认 600)")
    batch.add_argument("--json", action="store_true", help="JSON 输出")

    # 统计信息
    stats = sub.add_parser("stats", help="仅统计 Token 压缩效果")
    stats.add_argument("baseline", help="基线 HTML 文件路径")
    stats.add_argument("responses", nargs="+", help="响应 HTML 文件路径列表")

    args = parser.parse_args()

    if args.command == "diff":
        baseline_html = _read_file(args.baseline)
        response_html = _read_file(args.response)
        delta = extract_delta(baseline_html, response_html)

        if args.json:
            _print_json(delta)
        else:
            print(f"基线文件: {args.baseline} ({len(baseline_html)} 字符)")
            print(f"响应文件: {args.response} ({len(response_html)} 字符)")
            print(f"基线 <pre>: {delta['baseline_pre'][:200]}...")
            print(f"原始 <pre>: {delta['raw_pre'][:500]}")
            print(f"有效增量: {'是' if delta['has_delta'] else '否'}")
            if delta["is_false_positive"]:
                print(f"假阳性: {delta['false_positive_reason']}")
            if delta["delta_text"]:
                print(f"增量内容:\n{delta['delta_text']}")
            orig_tokens = estimate_tokens(response_html)
            delta_tokens = estimate_tokens(delta['delta_text'])
            compression = 1 - (delta_tokens / max(orig_tokens, 1))
            print(f"节省 Token: ~{orig_tokens} → ~{delta_tokens} (压缩 {compression:.1%})")

    elif args.command == "batch":
        baseline_html = _read_file(args.baseline)
        response_htmls = [_read_file(f) for f in args.responses]
        batch_result = batch_extract_for_llm(
            baseline_html, response_htmls,
            max_chars_per_entry=args.max_chars,
        )

        if args.json:
            _print_json(batch_result)
        else:
            print(f"基线: {args.baseline} ({len(baseline_html)} 字符)")
            print(f"响应: {len(args.responses)} 个文件")
            print(f"原始总字符: {batch_result['total_original_chars']:,}")
            print(f"提取总字符: {batch_result['total_extracted_chars']:,}")
            print(f"压缩比: {batch_result['compression_ratio']:.1%}")
            print(f"节省 Token 估算: "
                  f"{estimate_tokens('x' * batch_result['total_original_chars']):,} → "
                  f"{estimate_tokens('x' * batch_result['total_extracted_chars']):,}")
            print()
            print("=== LLM 审查摘要 ===")
            print(batch_result["summary"])

    elif args.command == "stats":
        baseline_html = _read_file(args.baseline)
        response_htmls = [_read_file(f) for f in args.responses]
        total_orig = sum(len(h) for h in response_htmls)
        total_extracted = 0
        valid_count = 0
        fp_count = 0

        for resp_html in response_htmls:
            delta = extract_delta(baseline_html, resp_html)
            total_extracted += len(delta["delta_text"])
            if delta["has_delta"]:
                valid_count += 1
            if delta["is_false_positive"]:
                fp_count += 1

        compression = 1 - (total_extracted / max(total_orig, 1))
        print(f"文件数: {len(response_htmls)}")
        print(f"原始总字符: {total_orig:,}")
        print(f"增量总字符: {total_extracted:,}")
        print(f"压缩比: {compression:.1%}")
        print(f"有效增量: {valid_count} 条")
        print(f"假阳性: {fp_count} 条")
        print(f"Token 估算: {estimate_tokens('x' * total_orig):,} → ~{estimate_tokens('x' * total_extracted):,}")
        print(f"每次 LLM 审查可节省约 {estimate_tokens('x' * (total_orig - total_extracted)):,} Token")

    else:
        parser.print_help()


def _read_file(path: str) -> str:
    """读取文件，文件不存在时返回空字符串并告警。"""
    if not os.path.isfile(path):
        print(f"[WARN] 文件不存在: {path}", file=sys.stderr)
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _print_json(obj: dict):
    """格式化 JSON 输出并处理不可序列化类型。"""
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    _main()
