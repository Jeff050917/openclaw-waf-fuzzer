# core/crawler.py
"""站点爬取器：从入口 URL 发现所有表单和参数，供注入点推断使用。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


@dataclass
class CandidateForm:
    url: str
    action: str
    method: str  # "GET" | "POST"
    inputs: dict[str, str]  # param_name → placeholder/label 文本
    page_title: str = ""
    page_text: str = ""  # 表单周围的上下文文本


class SiteCrawler:
    def __init__(self, timeout: int = 10, max_pages: int = 50):
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.trust_env = False
        self.visited: set[str] = set()

    def crawl(self, entry_url: str) -> list[CandidateForm]:
        """从入口 URL 爬取，返回所有发现的表单。"""
        candidates: list[CandidateForm] = []
        queue = [entry_url]

        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

            # 提取表单
            for form in soup.find_all("form"):
                candidate = self._parse_form(url, form, page_title)
                if candidate:
                    candidates.append(candidate)

            # 提取页面内链接，加入队列
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                parsed = urlparse(link)
                # 只爬同站链接
                if parsed.netloc == urlparse(entry_url).netloc and link not in self.visited:
                    queue.append(link)

        return candidates

    def _parse_form(self, page_url: str, form, page_title: str) -> CandidateForm | None:
        action = form.get("action", "")
        method = (form.get("method") or "GET").upper()
        action_url = urljoin(page_url, action) if action else page_url

        inputs: dict[str, str] = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            # 跳过 hidden/submit/button 类型（但保留有 value 的 hidden 用于 CSRF）
            inp_type = (inp.get("type") or "").lower()
            if inp_type in ("submit", "button", "reset"):
                continue
            label = self._find_label(inp, form)
            inputs[name] = label or inp.get("placeholder", "") or inp.get("value", "")

        if not inputs:
            return None

        # 提取表单周围的上下文文本
        context_text = ""
        parent = form.parent
        if parent:
            context_text = parent.get_text(separator=" ", strip=True)[:500]

        return CandidateForm(
            url=page_url,
            action=action_url,
            method=method,
            inputs=inputs,
            page_title=page_title,
            page_text=context_text,
        )

    def _find_label(self, inp, form) -> str:
        inp_id = inp.get("id")
        if inp_id:
            label = form.find("label", attrs={"for": inp_id})
            if label:
                return label.get_text(strip=True)
        # 尝试找最近的 label
        parent = inp.parent
        if parent and parent.name == "label":
            return parent.get_text(strip=True)
        return ""
