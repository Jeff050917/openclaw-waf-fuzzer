# OpenClaw Skill: waf-fuzzer 架构与运作流程

## 1. 项目概述

基于 LLM 的 WAF 语义引擎绕过测试工具。覆盖命令注入（CMDI）、SQL 注入（SQLi）、Log4j 反序列化场景。

核心原则：**AI 只做推理和变异，机械劳动全部本地化、缓存化、短路化。**

---

## 2. 目录结构

```
waf-fuzzer/
├── package.json              # OpenClaw 技能注册
├── index.ts                  # TS 桥接入口（stub，未完成）
├── plan.md                   # 本文档
├── core/                     # 核心引擎 (Python)
│   ├── workflow.py           # 主调度（目标选择、循环控制、报告落盘、逐轮 KB 更新）
│   ├── baseliner.py          # 基线采集（采集 HTML 指纹 + Session 预热 + LLM 驱动通用登录）
│   ├── llm_engine.py         # LLM 交互（Payload 生成/变异 + CoT 分析 + 5 级 JSON 解析容错 + 通用登录分析 + SQLi 证据判定）
│   ├── requester.py          # HTTP 发包（Session 复用 + Cookie jar 管理 + Session 预热 + LLM 驱动通用登录）
│   ├── inline_parser.py      # 证据提取器（基线 diff + CMDI 硬编码正则 + SQLi LLM 判定）
│   ├── response_extractor.py # 独立响应提取工具（CLI + 库调用，<pre> 提取 + diff + 假阳性过滤）
│   ├── memory_compressor.py  # KB 管理（分层架构：base_rules 只读 + learned_rules 逐轮更新）
│   └── requirements.txt
├── config/
│   ├── target.yaml           # 靶场配置（LLM 密钥、目标 URL、漏洞类型，支持任意 Web 网站）
│   └── base_rules.json       # 人工维护的基础规则（agent 只读，代码中无写入函数）
└── output/
    ├── bypass_report.txt     # 分类文本报告（人类可读）
    └── learned_rules.json    # Agent 学习的 WAF 规则（每 vuln_type 一条，逐轮更新）
```

---

## 3. 整体数据流

```
config/base_rules.json（人工维护，agent 只读）──┐
                                                 │ load_base_rules()
                                                 ▼
target.yaml                              get_kb_context() ──► 拼接两层 ──► {kb_section}
    │                                          ▲
    ▼                                          │ load_kb()
workflow.py ──► baseliner.py ──► 基线 HTML      │
    │              │                    │       │
    │              │ Session预热+登录   │       │
    │   ┌──────────┘                    │       │
    │   ▼                               │       │
    │   llm_engine.py ◄── CoT 分析 ◄───┘       │
    │        │              │                   │
    │        ▼ (payloads)   │ (拦截总结)        │
    │   requester.py ──► inline_parser ──► 判定拦截/绕过
    │        │              │
    │    短路拦截      三级文本提取
    │   (403/406/      + baseline diff
    │    501/429)      + 假阳性过滤
    │                  + CMDI 硬编码正则
    │                  + SQLi LLM 判定
    │                     │
    │                  BYPASS → record_bypass()
    │                     │
    │                     ▼
    │                bypass_report.txt
    │
    ▼
memory_compressor ◄── 每轮 CoT + 拦截分析（每轮即时压缩，不等全部测完）
    │
    ▼
output/learned_rules.json（逐轮更新，只改这层，不动 base_rules.json）
```

---

## 4. 三大阶段

### 阶段零：初始化

1. 加载 `config/target.yaml`（LLM 配置、Fuzzing 参数、靶场列表）。
2. 初始化 OpenAI 兼容客户端，连接 DeepSeek。
3. 加载分层 WAF 规则知识库：`config/base_rules.json`（人工维护，只读）+ `output/learned_rules.json`（agent 学习），两层拼接后注入后续 Prompt。
4. 交互式目标选择：终端菜单选择单个或全部目标。

### 阶段一：基线采集（`baseliner.py`）

对每个目标 URL：
1. **Session 预热（LLM 驱动，通用化）**：调用 `warmup_session()` 完成初始化。**不再硬编码 DVWA 登录流程**，而是将目标 URL 和页面内容交给 LLM 分析，由 LLM 判断：
   - 该网站是否需要登录？登录入口在哪？登录表单的字段名是什么？
   - 是否有 CSRF token？从哪个页面/元素提取？
   - 登录成功后如何验证 session 有效性？
   - LLM 输出结构化指令（GET/POST 序列 + 字段名 + 预期响应特征），本地代码执行。
   - **失败重试机制**：若预热失败，将错误信息和页面响应反馈给 LLM，LLM 分析失败原因后调整策略重试。最多 3 次尝试，每次失败后 LLM 思考并修正方案。3 次均失败则输出失败原因（如：找不到登录表单、CSRF token 提取失败、认证被拦截等）。
   - 预热过的 `host:port` 记录到 `_WARMED_HOSTS`，同主机后续目标跳过预热。
2. 发送一次干净请求（`{{INJECT}}` 替换为空字符串），采集正常页面的 HTML 响应体。
3. 若失败则等待 5 秒/10 秒重试，最多 3 次尝试。
4. 采集到的 `baseline_html` 供后续 `inline_parser` 做行级 diff——这是整个证据提取流程的**第一步**，尽早排除页面自身框架内容。

### 阶段二~三：CoT 驱动 Fuzzing 循环（`workflow.py`）

每轮迭代：

**Step A — AI 生成/变异 Payload（`llm_engine.py`）**

- 第 1 轮：`generate_initial_payloads()` — LLM 按五步思维链产出 15 个 Payload。
  1. **第〇步：黑盒上下文推测**。LLM 根据 URL 路由结构、参数名、页面标题/提示文本，推断后端命令执行上下文。
     例如 DVWA CMDI 靶场 URL 为 `/vulnerabilities/exec/`，输入框提示 "Enter an IP address"，参数名 `ip`，
     LLM 应推断出：后端大概率执行 `ping <用户输入>` 或 `nslookup <用户输入>` 这类网络诊断命令，
     注入点前缀为 `ip=`（GET 参数），闭合符可能为 `;`、`|`、`&&`、`%0a`。
     这一步不靠硬编码，LLM 自行从 URL + 页面描述中推理。
  2. 第一步：漏洞与防御分析
  3. 第二步：绕过策略
  4. 第三步：生成 Payload（JSON 返回）
- 后续轮次：`mutate_payloads()` — 把上一轮全部被拦截的 Payload 列表 + **实时更新的 KB 上下文**注入 Prompt，分析拦截根因并变异。
- **变异后更新 WAF 拦截策略**：每次变异完成后，将本轮的拦截分析结论（拦截了什么、为什么拦截、用什么方式绕过）立即写入 `learned_rules.json`，确保下一轮 Prompt 注入的是最新的策略知识。变异不是盲目的，而是基于对 WAF 拦截规则的理解进行针对性绕过。
- 杀伤力强制要求：CMD 必须带闭合符+高危回显命令，SQL 必须 UNION SELECT 拖库，禁止无害探路 Payload。
- **闭合符规则（LLM 判断）**：严禁裸命令（如 `nl /etc/passwd`），每个 Payload 必须自带闭合/连接符（`;`、`|`、`||`、`&&`、`%0a`、反引号、`$()`），或使用 Polyglot 兼容多种上下文。但闭合符的使用不硬编码规则，**由 LLM 自行判断拼接后的 Payload 在语法上是否合法**——即闭合符与命令的组合不会导致 shell 解析错误或 SQL 语法错误。LLM 在生成 Payload 时自行验证拼接正确性。
- **CMDI 三类命令的验证策略**：
  - **读取类**（cat/tac/rev/base64 等）：检查回显是否含目标文件内容（root:等系统账户名、base64 串等）。优先推荐。
  - **创建类**（touch/echo/cat > file 等）：**自包含验证模式**——创建文件时同时写入 marker 内容，再读取该文件验证 marker 出现在回显中。格式：`echo 'fzcr_MARKER' > /tmp/fz_FILE && cat /tmp/fz_FILE`。Parser 检测回显中的 `fzcr_` marker 字符串。
  - **删除类**（rm 等）：**三步验证**——`rm -f /tmp/fz_FILE && ls -la /tmp/ | grep fz_`，确认文件从目录列表中消失。Parser 检测 ls -la 输出中**不含**该文件名（需配合 `_CMDI_LS_DELETE` 模式）。
  - 所有 marker 文件名必须带随机后缀（`fz_` + 4位随机字符），防止跨轮残留干扰。

- **SQLi 验证策略（LLM 判断为主）**：SQLi 的回显模式远比 CMDI 复杂，不能用固定正则覆盖：
  - **UNION SELECT**：回显是数据库内容（表名、列名、用户数据），但格式因数据库和页面模板而异，没有固定模式。
  - **盲注（sleep/benchmark）**：没有文本回显，成功标志是响应延时。本地代码可检测延时是否 ≥ 阈值（如 sleep(10) → 响应 ≥ 10s），但需结合 payload 语义判断。
  - **报错注入（extractvalue/updatexml）**：回显嵌套在 MySQL 错误信息中，格式不固定。
  - **因此 SQLi 判定交给 LLM**：将原始命令（如 `1' AND sleep(10)--`）、筛选的回显文本、响应延时一起提交给 LLM，由 LLM 综合判断是否注入成功。LLM 需要区分：回显内容是否与 payload 语义一致（如 sleep(10) 对应 ≥10s 延时）、回显是否是预期的数据库数据（而非随机噪声或时间戳）。

**Step B — 高频并发发包（`requester.py`）**

- `ThreadPoolExecutor` 并发发送（默认 5 线程）。
- **Session 预热**：`warmup_session()` 由 LLM 驱动完成通用登录流程（非硬编码 DVWA），为 WAF 获取新鲜 session cookie 并完成认证。
- **Cookie jar 管理**：所有 cookie 由 `requests.Session` 统一管理（`_prepare_headers()` 剥离原始 Cookie 头），杜绝过期 `sl-session` 导致 WAF 静默丢包（不发 RST、不发 HTTP 错误，TCP 连接直接 hang 到超时）。
- **Fallback Headers**：自动补充浏览器特征头（Accept/Accept-Language/Accept-Encoding/Cache-Control/Upgrade-Insecure-Requests），配合调用方传入的 UA 和 Cookie，防止 WAF 对无特征脚本静默丢包。
- **短路拦截**：状态码 403/406/501/429 → 直接标记 `blocked=True`，不读响应体。
- **Parser 内联管道**：状态码 200 时，响应到达后第一时间调用 `inline_parser.extract_evidence()` 提取证据。
- **POST body URL 编码**：`quote(payload, safe='%')` 转义特殊字符（`&&`、`|` 等），防止被当作参数分隔符截断；`safe='%'` 保留已编码序列（如 `%0a` 换行注入），防止双重编码。
- CMDI 每轮前清理上一轮残留标记文件（`rm -f /tmp/fz_* /tmp/fuzz_* /tmp/cmdi_* /tmp/waf_*` 等），best-effort 不阻塞主流程。

**Step C — 本地证据评估（`inline_parser.py` + LLM 二次判定）**

核心原则：**先 diff 再校验，CMDI 硬编码快速判定，SQLi 交给 LLM 综合判断。**

```
extract_evidence(html, baseline_html, payload, vuln_type, response_time)
  │
  ├── 1. _extract_text_blocks(html)  三级回退提取文本块：
  │      L1: <pre> → L2: <code>/<samp>/<output>/<div class="output">/<textarea readonly> → L3: <body> 纯文本
  │      剥离残留 HTML 标签 + html.unescape 实体解码
  │
  ├── 2. 基线 diff：对 baseline_html 同等提取 → set 行级差集 → 无增量返回 None
  │
  ├── 3. _filter_lines() 逐行过滤：WAF拦截关键词 / Shell报错 / 空行纯标点
  │
  ├── 4. 按 vuln_type 分流判定：
  │      │
  │      ├── CMDI（本地硬编码判定，零 Token）：
  │      │   _has_cmdi_evidence() 按命令类型区分校验：
  │      │   读取类：_CMDI_PASSWD_LINE (root:/daemon:等系统账户名+冒号)
  │      │        / _CMDI_BASE64 (≥60字符的 base64 串)
  │      │   创建类：_CMDI_CREATE_MARKER (回显中出现 fzcr_ + 4位随机字符的 marker 字符串)
  │      │   删除类：_CMDI_LS_BLINDSIGHT (ls -la 输出中含 fz_/fuzz_/cmdi_/waf_ 前缀文件)
  │      │   → 均不命中返回 None
  │      │
  │      └── SQLi（LLM 判定，需消耗 Token）：
  │          将以下信息提交给 LLM：
  │          - 原始 payload 语义（如 `1' AND sleep(10)--` 表示时间盲注）
  │          - diff 后的回显文本（筛选后，已过滤页面框架）
  │          - 响应延时（ms）
  │          LLM 综合判断：
  │          - 时间盲注：延时是否与 sleep() 参数一致？回显是否为空或无意义噪声？
  │          - UNION 注入：回显是否包含数据库结构/数据？是否与 SELECT 的列对应？
  │          - 报错注入：回显是否包含 MySQL 错误信息中嵌套的查询结果？
  │          - 排除假阳性：如回显是 `1772734`（时间戳），但 payload 是 `1' AND sleep(10)--`，
  │            预期回显应为空或延时数据，`1772734` 可能是页面原有动态内容的残留，判定为假阳性。
  │          → LLM 返回 JSON: {"bypass": true/false, "confidence": 0-1, "reason": "..."}
  │
  └── 5. 返回证据文本（截断 ≤2000 字符）
```

**判定逻辑**：
- CMDI：提取文本块 → 基线 diff → 有增量 → 过滤 → 真实证据命中 → 绕过。其他 → 拦截。
- SQLi：提取文本块 → 基线 diff → 有增量或有延时 → 提交 LLM → LLM 判定 → 绕过/拦截。

**为什么先 diff 再校验**：baseline_html 的 `<pre>` 通常为空（正常 ping 请求无 `<pre>` 输出）或仅含固定提示文本。
先 diff 能立即排除页面框架内容，此时残留文本量已经很小——通常只有几十到几百字符，后续的过滤和正则校验成本极低。

**关于假阳性的实际风险**：
- 经 baseline diff 后，页面框架、CSRF token、时间戳等动态内容已排除。
- 即使残留类似 `1772734` 的数字文本，也不会命中 `root:` 这类证据正则（CMDI 场景）。
- 但 SQLi 模块对多余数据更敏感——回显中出现与 payload 语义不匹配的数字（如时间戳），需 LLM 判断是否为假阳性。例如 `1772734` 结合 `1' AND sleep(10)--` 应该回显延时而非数字，故判定假阳性。
- ping 命令成功时的 `0.11ms` 回显不含 `root:` 等密码文件特征，不会误判为 CMDI 绕过。
- Shell 命令静默失败时无任何回显，增量内容为空，自然返回 None。
- 唯一需关注的假阳性：靶场反射命令字符串但不执行，且反射内容碰巧包含系统账户名+冒号（概率极低）。
  - 若出现，因 diff 后文本量极小（几十字符），可交 AI 做低成本二次判定。

**Step D — 循环控制**

- 统计每轮拦截率、绕过数、耗时。
- 连续 N 轮全拦截（默认 5）→ 提醒 LLM 换思路，重置计数器继续循环。
- 达最大轮次（默认 20）→ 终止。

### 逐轮记忆压缩（`memory_compressor.py`）

**分层架构**：`config/base_rules.json`（人工维护，agent 只读）+ `output/learned_rules.json`（agent 学习，逐轮更新）。注入 Prompt 时两层拼接，同 vuln_type 不做跨层合并。

**通用规则**：`vuln_type` 为 `"general"` 的条目描述跨漏洞类型的通用 WAF 绕过思路（如协议层混淆），在所有漏洞类型的 Prompt 中都会注入，不受 vuln_type 过滤限制。

**每轮结束后立即执行，不等全部测完**：

1. 收集本轮 CoT 分析 + 策略字符串。
2. 调用 `compress_cot_analyses()`：LLM 压缩本轮拦截规律为一段精炼文本（≤150 字符）。Prompt 中注入 base_rules + learned_rules 作为上下文，避免重复发现已知规律。
3. `consolidate_kb()`：仅在 `learned_rules.json` 上操作。若存在同 vuln_type 的旧记录，调用 `_merge_rules()` 将新旧规则合并为一条；若合并失败则直接使用新规则覆盖。**base_rules.json 永不被 agent 写入**。
4. 合并后的 `kb_context` 立即刷新，下一轮 Prompt 注入的是 **base_rules + 最新 learned_rules 的拼接**。
5. `/etc/passwd` 等具体拦截模式由 agent 自己从拦截数据中总结，**不硬编码**进 KB。

---

## 5. Token 优化策略

| 策略 | 实现 | 效果 |
|------|------|------|
| 状态码短路 | `requester.py` | 403/406/501/429 直接跳过，不读 Body |
| 基线 diff 优先 | `inline_parser.py` | 先排除页面框架，残留文本极小（十到几百字符） |
| CMDI 硬编码证据正则 | `inline_parser.py` | 零 Token 证据提取，CMDI 快速判定 |
| SQLi LLM 判定 | `inline_parser.py` + `llm_engine.py` | SQLi 回显复杂，交 LLM 综合判断，仅 SQLi 场景消耗 Token |
| Parser 内联管道 | `requester.py` + `inline_parser.py` | 下游只看到证据文本，不传完整 HTML |
| 极简拦截列表 | `llm_engine.py` | `failed_list` 纯文本数组，不传完整报错页 |
| 逐轮压缩整合 | `memory_compressor.py` | 多轮 CoT 合并为一条整合规则，每轮即时更新 |
| 独立提取工具 | `response_extractor.py` | CLI + 库调用，按需提取 <pre> 差量，压缩比 95%-99.8% |

---

## 6. LLM JSON 解析容错

LLM 返回的 JSON 可能因 `max_tokens` 不足被中途截断，导致 `json.loads` 失败。
`llm_engine.py._chat_json` 实现了五级容错：

**第 1 层 — 正常解析**
从响应中摘取 markdown 代码块 ` ```json ... ``` `，直接 `json.loads`。

**第 2 层 — 截断修复**
若解析失败且 `finish_reason == "length"`（说明输出被截断）：
- 统计文本中未闭合的 `{}` 和 `[]`（状态机，排除字符串内的括号）
- 补全未闭合的 JSON 字符串
- 补全缺失的 `]` 和 `}`
- 重试 `json.loads`

**第 3 层 — 自动扩容重试**
若 `finish_reason == "length"`，将 `max_tokens` 翻倍后重新请求一次。

**第 4 层 — 数组提取**
若修复后仍失败：用字符级状态机（非正则）按括号计数提取 payloads 数组，
兼容 payload 内容中嵌套的 `[]`（如 `echo [test]`）。
同时用正则从残缺 JSON 中提取 `analysis` 和 `strategy` 字符串值。

**第 5 层 — 终极回退**
若所有结构化解析失败：用正则从响应文本中捞出所有引号包裹的、长度 ≥5 的字符串，
排除长文本值（>300 字符），优先从 `"payloads"` 附近的区域提取，作为 payload 候选列表。

**各调用点的 max_tokens**：

| 调用 | max_tokens | 说明 |
|------|-----------|------|
| `generate_initial_payloads` | 8192 | 15 条 payload + CoT 分析（第 3 层重试时翻倍至 16384） |
| `mutate_payloads` | 8192 | 同上（第 3 层重试时翻倍至 16384） |
| `compress_round_summary` | 1024 | 压缩本轮拦截规律 ≤150 字 |
| `_merge_rules` | 1024 | 合并新旧 KB 规则 |
| `analyze_login_page` | 2048 | LLM 分析登录页面 → 输出结构化登录指令 |
| `analyze_warmup_failure` | 2048 | LLM 分析登录失败原因 → 输出新登录方案 |
| `judge_sqli_evidence` | 1024 | SQLi 回显 + 延时 + payload 语义 → LLM 判定是否绕过 |

---

## 7. 输出格式（bypass_report.txt）

纯文本格式，分类输出。CMDI / SQLi / Log4j 各自独立区块。

### 7.1 CMDI 输出格式

```
================================================================================
WAF-Fuzzer Bypass Report
生成时间: 2026-04-28  |  共 N 条记录
================================================================================

████ CMDI · http://target/vulnerabilities/exec/ ████████████████████████████████

── 绕过文件路径（通配符变形）─ 3条 ──
Payload                                              证据摘要
--------------------------------------------------  ------------------------------
;/bin/c?t /???/pass??                                root:x:0:0:root...
;/bin/c?t /???/shad?w                                root:$6$...:0:0:...
;nl /etc/passwd                                      1  root:x:0:0:root...

── 绕过命令（echo+cat 拼接）─ 2条 ──
Payload                                              证据摘要
--------------------------------------------------  ------------------------------
;echo `cat /etc/passwd`                              root:x:0:0:root...
;echo $(cat /etc/passwd)                             root:x:0:0:root...

── 绕过命令（编码绕过）─ 1条 ──
Payload                                              证据摘要
--------------------------------------------------  ------------------------------
;cat /etc/passwd | base64                            cm9vdDp4OjA6MDpyb290...

████ SQLi · http://target/vulnerabilities/sqli/ ██████████████████████████████████

── UNION注入 ─ N条 ──
...
```

**CMDI 分类维度**（由 `_categorize_payload()` 基于预编译正则自动识别）：
1. **读取类-绕过文件路径** — 路径含 `?` `*` `[]` 通配符，验证：`_CMDI_PASSWD_LINE` / `_CMDI_BASE64`
2. **读取类-绕过命令** — base64/xxd/od/hexdump 编码、`${IFS}`、引号拼接、echo+cat 拼接，验证：同上
3. **读取类-换行注入** — `%0a` / `%0d%0a` 绕过闭合符检测，验证：同上
4. **读取类-直接读取** — 无绕过手法（裸 cat /etc/passwd 直接成功）
5. **创建类命令** — payload 含写入+读取模式（`echo > file && cat file`），验证：回显含 `fzcr_` marker
6. **删除类命令** — payload 含删除+列表模式（`rm file && ls`），验证：ls 输出中目标文件消失

每个分类下的 payload 由 AI 生成一行摘要，描述绕过原理，格式：
```
Payload                                              证据摘要
--------------------------------------------------  ------------------------------
;{实际payload}                                       {AI总结的一句话绕过说明}
```

**证据输出原则**（由 `_format_evidence_summary()` 实现）：
- **CMDI**：输出有效回显的关键内容。如 `cat /etc/passwd` 的回显输出 `root:x:0:0:root...`；但固定的 `ping 127.0.0.1` 回显（如 `64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.11ms`）不输出，因为没有信息价值。
- **SQLi**：输出从数据库中提取到的关键数据。如 UNION SELECT 拖出的表名/列名/用户数据；时间盲注输出延时信息（如 `响应延时 10.2s，sleep(10) 成功`）；报错注入输出错误信息中嵌套的查询结果。
- **无意义回显不输出**：如纯数字时间戳、页面框架文本、WAF 拦截页等，即使在 diff 后残留也不作为证据展示。
- **过滤规则**：自动过滤 ping 回显（bytes from/icmp_seq/ttl/time=ms）和纯数字时间戳（≥6位纯数字）。

**SQLi 分类维度**（由 `_categorize_payload()` 基于预编译正则自动识别）：
UNION注入 / 报错注入（extractvalue/updatexml/floor/polygon） / 盲注（sleep/benchmark/waitfor/pg_sleep） / 堆叠查询 / 内联注释绕过（`/*!50000...*/`） / 编码绕过（0x十六进制/char/unhex） / 双写绕过（UNIUNIONON） / 宽字节注入（%df%27） / 空白符绕过（%0a/%0b/%0c/%0d） / 闭合绕过（`'--`/`'#`/`'--+`） / 直接注入（默认分类）。

### 7.2 分层知识库（base_rules.json + learned_rules.json）

**`config/base_rules.json`**（人工维护，agent 只读）：

```json
[
  {
    "vuln_type": "general",
    "rules": "通用 WAF 绕过思路：协议层混淆（改请求方法、改 MIME 类型、参数污染、重复字段）+ Payload 变形 + 利用前后端解析差异使 WAF 切换检测引擎。"
  },
  {
    "vuln_type": "cmdi",
    "rules": "WAF 拦截命令关键字和文件路径字面量两条线。绕过命令：变量拼接(c'a't)、通配符(c?t)、不常用命令(rev/od/tac)、管道传参。绕过路径：通配符/???/pass??、字符拼接、编码。验证方法按命令类型区分：读取类检查回显；创建类用不被拦截的读取命令确认文件存在；删除类确认原文件消失。"
  },
  {
    "vuln_type": "sqli",
    "rules": "（待填写）"
  }
]
```

`target` 和 `timestamp` 字段在 base_rules 中可选。

**`output/learned_rules.json`**（agent 学习，逐轮更新）：

```json
[
  {
    "vuln_type": "cmdi",
    "target": "http://...",
    "rules": "WAF对cat命令关键字实施正则拦截，c?t通配符和echo+cat拼接均可绕过；两手法组合使用成功率最高。",
    "timestamp": "2026-04-28 12:00:00"
  }
]
```

两层同 vuln_type 的条目在注入 Prompt 时直接拼两行，不做跨层合并。`_merge_rules()` 仅在 learned_rules 内部操作，永不触碰 base_rules。

---

## 8. 绕过技术自动分类

`_categorize_payload()` 根据 Payload 特征自动识别，用于报告分组。所有匹配正则预编译为模块级常量，避免每轮重复编译。

### CMDI 分类

| 分类 | 检测特征 | 验证方法 |
|------|---------|---------|
| 读取类-绕过文件路径 | 路径含 `?` `*` `[]` 或字符串拼接 | `_CMDI_PASSWD_LINE` / `_CMDI_BASE64` |
| 读取类-绕过命令 | `base64` / `xxd` / `${IFS}` / 引号拼接 / echo+cat | `_CMDI_PASSWD_LINE` / `_CMDI_BASE64` |
| 读取类-换行注入 | `%0a` / `%0d%0a` | `_CMDI_PASSWD_LINE` / `_CMDI_BASE64` |
| 读取类-直接读取 | 默认分类（无绕过手法） | `_CMDI_PASSWD_LINE` / `_CMDI_BASE64` |
| 创建类命令 | payload 含 `echo.*>.*&&.*cat` 或 `touch.*&&.*cat` 模式 | `_CMDI_CREATE_MARKER`：回显含 `fzcr_` marker |
| 删除类命令 | payload 含 `rm.*&&.*ls` 模式 | `_CMDI_LS_BLINDSIGHT`：ls 输出中含 fz_/fuzz_ 前缀文件 |

### SQLi 分类

| 分类 | 检测特征 |
|------|---------|
| UNION注入 | `union[\s/\*!]+select` 或 `/\*!.*union` |
| 报错注入 | `extractvalue` / `updatexml` / `floor(` / `exp~` / `polygon` |
| 盲注 | `sleep(` / `benchmark(` / `waitfor delay` / `pg_sleep(` |
| 堆叠查询 | `; insert` / `; update` / `; delete` / `; drop` / `; create` / `; alter` / `; truncate` |
| 内联注释绕过 | `/*!\d{3,6}` |
| 编码绕过 | `0x[0-9a-fA-F]{4,}` / `char(` / `unhex(` |
| 双写绕过 | `uniun` / `selsel` / `frofrom` / `whewhere` / `oror` / `anand` |
| 宽字节注入 | `%df` (大小写不敏感) |
| 空白符绕过 | `%0b` `%0c` 或 `%0a` + union 组合 |
| 闭合绕过 | `' --` / `' #` / `' --+` 等 |
| 直接注入 | 默认分类 |

---

## 9. 独立工具：response_extractor.py

位于 `core/response_extractor.py`，提供独立于主 fuzzing 流程的响应提取能力：

- **库调用**：`extract_delta(baseline_html, response_html)` 和 `batch_extract_for_llm(baseline_html, [r1, r2, ...])`
- **CLI 调用**：`diff`（单文件对比）、`batch`（批量提取 LLM 审查摘要）、`stats`（压缩效果统计）
- **假阳性过滤**：WAF 拦截页 / 网络诊断输出(ping/traceroute) / Shell 报错 / 空纯标点
- **与 inline_parser 的关系**：`response_extractor.py` 仅做 <pre> 提取+diff+过滤，不做证据校验（证据校验由 `inline_parser.py` 独占：CMDI 硬编码正则，SQLi LLM 判定）。两者假阳性过滤正则保持一致。

---

## 10. 安全约束

1. 证据提取：CMDI 由硬编码完成（0 Token）；SQLi 回显复杂，交 LLM 综合判定（消耗 Token），仅在有增量回显或延时时触发。
2. 所有 HTTP 请求不走系统代理（`trust_env=False`），不跟随重定向。
3. CMDI 盲注：每轮发包前 + 目标结束后清理 /tmp 残留文件（`rm -f /tmp/fz_* /tmp/fuzz_* /tmp/cmdi_* /tmp/waf_*`），防止 `ls` 假阳性。
4. AI 不硬编码任何 WAF 规则（包括 `/etc/passwd` 被正则拦截这类结论），全部由 agent 从拦截数据中自行总结。
