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
│   ├── baseliner.py          # 基线采集（采集 HTML 指纹 + Session 预热 + DVWA 自动登录）
│   ├── llm_engine.py         # LLM 交互（Payload 生成/变异 + CoT 分析 + 5 级 JSON 解析容错）
│   ├── requester.py          # HTTP 发包（Session 复用 + Cookie jar 管理 + Session 预热 + DVWA 自动登录）
│   ├── inline_parser.py      # 硬编码证据提取器（基线 diff 优先 + 证据正则校验）
│   ├── response_extractor.py # 独立响应提取工具（CLI + 库调用，<pre> 提取 + diff + 假阳性过滤）
│   ├── memory_compressor.py  # KB 管理（逐轮更新、同 vuln_type 整合去重）
│   └── requirements.txt
├── config/
│   └── target.yaml           # 靶场配置（LLM 密钥、目标 URL、漏洞类型）
└── output/
    ├── bypass_report.txt     # 分类文本报告（人类可读）
    └── waf_rules_kb.json     # 整合式 WAF 规则知识库（每 vuln_type 一条，逐轮更新）
```

---

## 3. 整体数据流

```
target.yaml
    │
    ▼
workflow.py ──► baseliner.py ──► 基线 HTML (baseline_html)
    │              │                    │
    │              │ Session预热+登录   │
    │   ┌──────────┘                    │
    │   ▼                               │
    │   llm_engine.py ◄── CoT 分析 ◄── 逐轮 KB 上下文
    │        │              │
    │        ▼ (payloads)   │ (拦截总结，每轮即时入库)
    │   requester.py ──► inline_parser ──► 判定拦截/绕过
    │        │              │
    │    短路拦截      三级文本提取
    │   (403/406/      + baseline diff
    │    501/429)      + 假阳性过滤
    │                  + 证据正则校验
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
waf_rules_kb.json（逐轮更新，下一轮 Prompt 立即注入最新规则）
```

---

## 4. 三大阶段

### 阶段零：初始化

1. 加载 `config/target.yaml`（LLM 配置、Fuzzing 参数、靶场列表）。
2. 初始化 OpenAI 兼容客户端，连接 DeepSeek。
3. 加载历史 WAF 规则知识库 `output/waf_rules_kb.json`，注入后续 Prompt。
4. 交互式目标选择：终端菜单选择单个或全部目标。

### 阶段一：基线采集（`baseliner.py`）

对每个目标 URL：
1. **Session 预热**：调用 `warmup_session()` 完成三步初始化：
   - GET `/` → WAF 分配新鲜 `sl-session` + DVWA 分配 `PHPSESSID`
   - GET `/login.php` → 提取 CSRF `user_token`
   - POST `/login.php` → 用 `admin/password` + `user_token` 登录认证
   - GET `/security.php?security=low` → 设置安全等级为 low
   - 预热过的 `host:port` 记录到 `_WARMED_HOSTS`，同主机后续目标跳过预热
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
- 杀伤力强制要求：CMD 必须带闭合符+高危回显命令，SQL 必须 UNION SELECT 拖库，禁止无害探路 Payload。
- **闭合符强制规则**：严禁裸命令（如 `nl /etc/passwd`），每个 Payload 必须自带闭合/连接符（`;`、`|`、`||`、`&&`、`%0a`、反引号、`$()`），或使用 Polyglot 兼容多种上下文。
- **文件盲注三步骤**：若必须文件操作（如写 webshell），必须自包含 `rm -f 清理 → touch 创建 → ls -la 验证`，且文件名带随机后缀防跨轮残留。

**Step B — 高频并发发包（`requester.py`）**

- `ThreadPoolExecutor` 并发发送（默认 5 线程）。
- **Session 预热**：`warmup_session()` 自动完成 GET `/` → 获取 CSRF token → POST 登录 → 设置 security=low，为 WAF 获取新鲜 `sl-session` 并认证 PHPSESSID。
- **Cookie jar 管理**：所有 cookie 由 `requests.Session` 统一管理（`_prepare_headers()` 剥离原始 Cookie 头），杜绝过期 `sl-session` 导致 WAF 静默丢包（不发 RST、不发 HTTP 错误，TCP 连接直接 hang 到超时）。
- **Fallback Headers**：自动补充浏览器特征头（Accept/Accept-Language/Accept-Encoding/Cache-Control/Upgrade-Insecure-Requests），配合调用方传入的 UA 和 Cookie，防止 WAF 对无特征脚本静默丢包。
- **短路拦截**：状态码 403/406/501/429 → 直接标记 `blocked=True`，不读响应体。
- **Parser 内联管道**：状态码 200 时，响应到达后第一时间调用 `inline_parser.extract_evidence()` 提取证据。
- **POST body URL 编码**：`quote(payload, safe='%')` 转义特殊字符（`&&`、`|` 等），防止被当作参数分隔符截断；`safe='%'` 保留已编码序列（如 `%0a` 换行注入），防止双重编码。
- CMDI 每轮前清理上一轮残留标记文件（`rm -f /tmp/fz_* /tmp/fuzz_* /tmp/cmdi_* /tmp/waf_*` 等），best-effort 不阻塞主流程。

**Step C — 本地证据评估（`inline_parser.py`）**

核心原则：**先 diff 再校验，流程极简，管道做减法。**

```
extract_evidence(html, baseline_html) → _hardcoded_extract()
  │
  ├── 1. _extract_text_blocks(html)  三级回退提取文本块：
  │      L1: <pre> → L2: <code>/<samp>/<output>/<div class="output">/<textarea readonly> → L3: <body> 纯文本
  │      剥离残留 HTML 标签 + html.unescape 实体解码
  │
  ├── 2. 基线 diff：对 baseline_html 同等提取 → set 行级差集 → 无增量返回 None
  │
  ├── 3. _filter_lines() 逐行过滤：WAF拦截关键词 / Shell报错 / 空行纯标点
  │
  ├── 4. _has_real_evidence() 收紧证据校验：
  │      - CMDI: root:/daemon:/bin:/sys:/nobody: 等系统账户名+冒号
  │      - CMDI: ls -la + fz_/fuzz_/cmdi_/waf_ 前缀随机文件名（文件盲注）
  │      - CMDI: 长 base64 串 (≥60字符)
  │      - SQLi: ASCII表格边框 / schema字段名 / 用户数据标签(First name/Surname/Password) / MD5哈希(32位hex)
  │      - Log4j: JNDI引用(Reference Class Name)
  │      → 均不命中返回 None
  │
  └── 5. 返回证据文本（截断 ≤2000 字符）
```

**判定逻辑是二元的**：提取文本块 → 基线 diff → 有增量 → 过滤 → 真实证据命中 → 绕过。其他一切情况 → 拦截。

**为什么先 diff 再校验**：baseline_html 的 `<pre>` 通常为空（正常 ping 请求无 `<pre>` 输出）或仅含固定提示文本。
先 diff 能立即排除页面框架内容，此时残留文本量已经很小——通常只有几十到几百字符，后续的过滤和正则校验成本极低。

**关于假阳性的实际风险**：
- 经 baseline diff 后，页面框架、CSRF token、时间戳等动态内容已排除。
- 即使残留类似 `1772734` 的数字文本，也不会命中 `root:` 这类证据正则。
- ping 命令成功时的 `0.11ms` 回显不含 `root:` 等密码文件特征，不会误判为 CMDI 绕过。
- Shell 命令静默失败时无任何回显，增量内容为空，自然返回 None。
- 唯一需关注的假阳性：靶场反射命令字符串但不执行，且反射内容碰巧包含系统账户名+冒号（概率极低）。
  - 若出现，因 diff 后文本量极小（几十字符），可交 AI 做低成本二次判定。

**Step D — 循环控制**

- 统计每轮拦截率、绕过数、耗时。
- 连续 N 轮全拦截（默认 3）→ 提前终止。
- 达最大轮次（默认 20）→ 终止。

### 逐轮记忆压缩（`memory_compressor.py`）

**每轮结束后立即执行，不等全部测完**：

1. 收集本轮 CoT 分析 + 策略字符串。
2. 调用 `compress_cot_analyses()`：LLM 压缩本轮拦截规律为一段精炼文本（≤150 字符），格式：
   > "WAF 对字面量 `/etc/passwd` 和 `cat ` 命令实施正则拦截（403），通配符 `/???/pass??` + `c?t` 可绕过文件路径检测，但 `cat` 关键字变形仍需配合命令混淆..."
3. 若 KB 中已有同 vuln_type 的历史记录，Prompt 中会注入历史规则，要求 LLM 与历史记录整合去重、统一矛盾推断。
4. `consolidate_kb()`：若存在同 vuln_type 的旧记录，调用 `_merge_rules()`（使用 `deepseek-v4-flash`，`max_tokens=1024`）将新旧规则合并为一条；若合并失败则直接使用新规则覆盖。合并后的单条规则写入 `waf_rules_kb.json`。
5. 合并后的 `kb_context` 立即刷新，下一轮 Prompt 注入的是**最新的整合规则**。
6. `/etc/passwd` 等具体拦截模式由 agent 自己从拦截数据中总结，**不硬编码**进 KB。

---

## 5. Token 优化策略

| 策略 | 实现 | 效果 |
|------|------|------|
| 状态码短路 | `requester.py` | 403/406/501/429 直接跳过，不读 Body |
| 基线 diff 优先 | `inline_parser.py` | 先排除页面框架，残留文本极小（十到几百字符） |
| 硬编码证据正则 | `inline_parser.py` | 零 Token 证据提取，无 AI 依赖 |
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
| `_merge_rules` | 1024 | 合并新旧 KB 规则（使用 deepseek-v4-flash） |

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
1. **绕过文件路径** — 路径含 `?` `*` `[]` 通配符
2. **绕过命令** — base64/xxd/od/hexdump 编码、`${IFS}`、引号拼接、echo+cat 拼接
3. **换行注入** — `%0a` / `%0d%0a` 绕过闭合符检测
4. **文件盲注** — touch/mkdir/rm -f/ls -la 三步验证，无直接文件回显
5. **直接读取** — 无绕过（裸 cat /etc/passwd 直接成功，WAF 未拦截）

每个分类下的 payload 由 AI 生成一行摘要，描述绕过原理，格式：
```
Payload                                              证据摘要
--------------------------------------------------  ------------------------------
;{实际payload}                                       {AI总结的一句话绕过说明}
```

**SQLi 分类维度**（由 `_categorize_payload()` 基于预编译正则自动识别）：
UNION注入 / 报错注入（extractvalue/updatexml/floor/polygon） / 盲注（sleep/benchmark/waitfor/pg_sleep） / 堆叠查询 / 内联注释绕过（`/*!50000...*/`） / 编码绕过（0x十六进制/char/unhex） / 双写绕过（UNIUNIONON） / 宽字节注入（%df%27） / 空白符绕过（%0a/%0b/%0c/%0d） / 闭合绕过（`'--`/`'#`/`'--+`） / 直接注入（默认分类）。

### 7.2 waf_rules_kb.json（整合式单条，逐轮更新）

```json
[
  {
    "vuln_type": "cmdi",
    "target": "http://...",
    "rules": "WAF对字面量/etc/passwd实施正则拦截(403)，通配符/???/pass??可绕过路径检测；WAF对cat命令关键字实施正则拦截，c?t通配符和echo+cat拼接均可绕过；两手法组合使用成功率最高。注意：WAF不拦截nl/base64等替代读取命令。",
    "timestamp": "2026-04-28 12:00:00"
  }
]
```

`rules` 字段是一段**整合后的完整段落**，不是多条碎片记录的列表。
每轮更新时 `_merge_rules()` 将新旧规则合并去重、统一矛盾推断，确保下次 Prompt 注入时 agent 拿到的是最完整、最自洽的拦截规律描述。

---

## 8. 绕过技术自动分类

`_categorize_payload()` 根据 Payload 特征自动识别，用于报告分组。所有匹配正则预编译为模块级常量，避免每轮重复编译。

### CMDI 分类

| 分类 | 检测特征 | 说明 |
|------|---------|------|
| 绕过文件路径 | 路径含 `?` `*` `[]` 或字符串拼接 | 绕过 `/etc/passwd` 等路径字面量正则 |
| 绕过命令 | `base64` / `xxd` / `${IFS}` / 引号拼接 / echo+cat | 绕过 `cat`/`id` 等命令关键字正则 |
| 换行注入 | `%0a` / `%0d%0a` | 绕过闭合符检测 |
| 文件盲注 | `touch ` / `mkdir ` / `rm -f` / `ls -la` / `ls -l ` | 无直接回显，通过文件创建确认注入 |
| 直接读取 | 默认分类 | 未检测到任何绕过手法 |

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
- **与 inline_parser 的关系**：`response_extractor.py` 仅做 <pre> 提取+diff+过滤，不做证据正则校验（证据校验由 `inline_parser.py` 独占）。两者假阳性过滤正则保持一致。

---

## 10. 已完成清理项

以下功能已移除：

### 10.1 AI 校验（`_run_calibration` → `review_bypasses`）✅ 已移除

### 10.2 信标（TSEC_FLAG_xxx）✅ 已移除
- `clean_payload()` 函数已删除
- LLM prompt 中 TSEC 信标指令已删除
- CMDI 分类中"信标辅助"已移除

### 10.3 pre 内容导出（`extract_pre_raw`）✅ 已移除

### 10.4 回退正则安全网（`_regex_fallback`）✅ 已移除
替换为 `_extract_text_blocks()` 三级容器回退（L1: `<pre>` → L2: `<code>`/`<samp>`/output容器 → L3: `<body>`纯文本），不再盲扫全页 HTML。

---

## 11. 安全约束

1. 证据提取由硬编码完成，0 Token 消耗。
2. 所有 HTTP 请求不走系统代理（`trust_env=False`），不跟随重定向。
3. CMDI 盲注：每轮发包前 + 目标结束后清理 /tmp 残留文件（`rm -f /tmp/fz_* /tmp/fuzz_* /tmp/cmdi_* /tmp/waf_*`），防止 `ls` 假阳性。
4. AI 不硬编码任何 WAF 规则（包括 `/etc/passwd` 被正则拦截这类结论），全部由 agent 从拦截数据中自行总结。
