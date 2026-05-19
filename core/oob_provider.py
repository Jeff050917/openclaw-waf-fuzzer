"""OOB Provider — 自动获取 dnslog 临时域名并轮询回调。

支持：
  - dnslog.cn（免费，无需注册）
  - 手动配置（兼容旧的 oob.server + oob.poll_api）
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

import requests


class OOBProvider(ABC):
    """OOB 提供者基类。"""

    @abstractmethod
    def get_domain(self) -> str:
        """返回 OOB 域名，用于 payload 注入（如 'xxxx.dnslog.cn'）。"""

    @abstractmethod
    def poll(self, token: str) -> bool:
        """检查 token 对应的子域名是否收到回调。"""


class DnslogProvider(OOBProvider):
    """dnslog.cn 免费 OOB 服务。"""

    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self._domain = self._fetch_domain()

    def _fetch_domain(self) -> str:
        resp = self.session.get("http://dnslog.cn/getdomain.php", timeout=10)
        resp.raise_for_status()
        domain = resp.text.strip()
        if not domain or "." not in domain:
            raise RuntimeError(f"dnslog.cn 返回的域名无效: {resp.text!r}")
        return domain

    def get_domain(self) -> str:
        return self._domain

    def poll(self, token: str) -> bool:
        try:
            resp = self.session.get(
                "http://dnslog.cn/recevied.php", timeout=10,
            )
            return token in resp.text
        except Exception:
            return False


class ManualProvider(OOBProvider):
    """手动配置的 OOB 提供者（兼容旧配置）。"""

    def __init__(self, server: str, poll_api: str):
        self._server = server
        self._poll_api = poll_api

    def get_domain(self) -> str:
        return self._server

    def poll(self, token: str) -> bool:
        try:
            resp = requests.get(
                f"{self._poll_api}?token={token}",
                timeout=5, trust_env=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("received", False)
        except Exception:
            pass
        return False


def create_oob_provider(config: dict) -> OOBProvider | None:
    """根据配置创建 OOB provider。"""
    oob_cfg = config.get("oob")
    if not oob_cfg:
        return None

    provider = oob_cfg.get("provider", "")
    if provider == "dnslog":
        return DnslogProvider()
    if provider == "ceye":
        # 预留 ceye.io 支持
        raise NotImplementedError("ceye.io provider 尚未实现")

    # 兼容旧配置：手动指定 server + poll_api
    server = oob_cfg.get("server", "")
    poll_api = oob_cfg.get("poll_api", "")
    if server and poll_api and server != "oob.example.com":
        return ManualProvider(server=server, poll_api=poll_api)

    return None
