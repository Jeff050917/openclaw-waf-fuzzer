"""WAF 指纹识别器：检测目标是否有 WAF 并识别厂商。"""
from __future__ import annotations

import json
import re
from pathlib import Path

import requests

# Note: agents/ is at project root, not under core/
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).parent.parent))
from agents.models import WAFProfile

_SIGNATURES_PATH = Path(__file__).parent.parent / "config" / "waf_signatures.json"

# 探测 payload（低强度，用于触发 WAF 拦截页）
_PROBE_PAYLOADS = {
    "sqli": "' OR 1=1 --",
    "xss": "<script>alert(1)</script>",
    "cmdi": "; id",
    "traversal": "../../../etc/passwd",
}


class WAFFingerprinter:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> list[dict]:
        if _SIGNATURES_PATH.exists():
            return json.loads(_SIGNATURES_PATH.read_text(encoding="utf-8"))
        return []

    def fingerprint(self, url: str, headers: dict | None = None) -> WAFProfile:
        """对目标 URL 进行 WAF 指纹识别。"""
        detection_methods: list[str] = []
        matched_waf: dict | None = None
        matched_signatures: dict = {}

        # Step 1: 正常请求，检查响应头/cookie
        try:
            clean_resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException:
            return WAFProfile(detected=False)

        # Step 2: 被动指纹匹配
        passive_match = self._match_passive(clean_resp)
        if passive_match:
            detection_methods.append("passive_headers")
            matched_waf = passive_match["waf"]
            matched_signatures.update(passive_match["matched"])

        # Step 3: 主动探测
        probe_results = self._send_probes(url, headers)
        active_match = self._match_active(probe_results, clean_resp)
        if active_match:
            detection_methods.append("active_probe")
            if not matched_waf:
                matched_waf = active_match["waf"]
            matched_signatures.update(active_match["matched"])

        # Step 4: 组装结果
        if matched_waf:
            return WAFProfile(
                detected=True,
                waf_name=matched_waf.get("name"),
                waf_vendor=matched_waf.get("vendor"),
                confidence=0.9 if len(detection_methods) >= 2 else 0.7,
                detection_methods=detection_methods,
                signatures=matched_signatures,
                bypass_tips=matched_waf.get("bypass_tips", []),
            )

        # 没有匹配已知 WAF，但探测有拦截行为 → LLM 辅助分析
        if any(r.get("blocked") for r in probe_results):
            llm_result = self._llm_analyze(clean_resp, probe_results)
            return llm_result

        return WAFProfile(detected=False)

    def _llm_analyze(
        self,
        clean_resp: requests.Response,
        probe_results: list[dict],
    ) -> WAFProfile:
        """指纹库未命中时，调用 LLM 从响应特征推断 WAF 类型。"""
        from llm_engine import _chat_json

        headers_summary = "\n".join(f"  {k}: {v}" for k, v in clean_resp.headers.items())
        probe_summary = "\n".join(
            f"  [{r['type']}] status={r['status_code']} body={r['body'][:200]}"
            for r in probe_results if r.get("blocked")
        )

        prompt = f"""你是 WAF 指纹分析专家。以下是一个被 WAF 拦截的响应，请推断可能的 WAF 类型。

正常请求响应头：
{headers_summary}

被拦截的探测响应：
{probe_summary}

已知 WAF 签名未匹配。请从响应特征推断：
1. 可能的 WAF 类型（自建 WAF、小众 WAF、云厂商定制 WAF）
2. 检测引擎类型（正则/语义/机器学习）
3. 建议的绕过方向

返回 JSON：{{
  "waf_name": "推断的 WAF 名称",
  "confidence": 0-1,
  "engine_type": "正则/语义/ML",
  "bypass_tips": ["建议1", "建议2"],
  "reasoning": "推断理由"
}}"""

        try:
            result = _chat_json(prompt, model=None, temperature=0.3, max_tokens=512)
            if isinstance(result, dict):
                return WAFProfile(
                    detected=True,
                    waf_name=result.get("waf_name", "Unknown (LLM)"),
                    waf_vendor=None,
                    confidence=result.get("confidence", 0.5),
                    detection_methods=["llm_analysis"],
                    signatures={},
                    bypass_tips=result.get("bypass_tips", []),
                )
        except Exception:
            pass

        return WAFProfile(
            detected=True,
            waf_name="Unknown",
            waf_vendor=None,
            confidence=0.3,
            detection_methods=["active_probe"],
            signatures={},
            bypass_tips=["未知 WAF，建议从语义层开始探测拦截模式"],
        )

    def _match_passive(self, resp: requests.Response) -> dict | None:
        """检查响应头/cookie 匹配已知 WAF 指纹。"""
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        resp_cookies = "; ".join(
            f"{c.name}={c.value}" for c in resp.cookies
        )
        all_header_values = " ".join(
            f"{k}: {v}" for k, v in resp_headers_lower.items()
        )
        combined = f"{all_header_values} {resp_cookies}".lower()

        for waf in self.signatures:
            matched: dict = {"headers": [], "cookies": []}
            for sig in waf.get("signatures", {}).get("headers", []):
                if sig.lower() in combined:
                    matched["headers"].append(sig)
            for sig in waf.get("signatures", {}).get("cookies", []):
                if sig.lower() in combined:
                    matched["cookies"].append(sig)

            if matched["headers"] or matched["cookies"]:
                return {"waf": waf, "matched": matched}

        return None

    def _send_probes(
        self, url: str, headers: dict | None
    ) -> list[dict]:
        """发送低强度探测 payload，收集响应。"""
        results = []
        for payload_type, payload in _PROBE_PAYLOADS.items():
            try:
                resp = self.session.get(
                    url,
                    params={"q": payload},
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                results.append({
                    "type": payload_type,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "body": resp.text[:2000],
                    "headers": dict(resp.headers),
                    "blocked": resp.status_code in (403, 406, 501, 429),
                })
            except requests.RequestException:
                continue
        return results

    def _match_active(
        self,
        probe_results: list[dict],
        clean_resp: requests.Response,
    ) -> dict | None:
        """从探测响应中匹配 WAF 拦截页特征。"""
        clean_body = clean_resp.text[:2000]

        for result in probe_results:
            if not result["blocked"]:
                # 对比响应体变化
                if result["body"] == clean_body:
                    continue

            combined_text = f"{result['body']} {' '.join(f'{k}: {v}' for k, v in result['headers'].items())}"

            for waf in self.signatures:
                for sig in waf.get("signatures", {}).get("block_page", []):
                    if re.search(sig, combined_text, re.IGNORECASE):
                        return {"waf": waf, "matched": {"block_page": sig}}

        return None
