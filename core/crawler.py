# core/crawler.py
"""站点爬取器：从入口 URL 发现所有表单和参数，供注入点推断使用。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from llm_engine import _chat_json


@dataclass
class CandidateForm:
    url: str
    action: str
    method: str  # "GET" | "POST"
    inputs: dict[str, str]  # param_name → placeholder/label 文本
    page_title: str = ""
    page_text: str = ""  # 表单周围的上下文文本


def _find_label(inp, form) -> str:
    """尝试从 <label for="id"> 或父 <label> 获取字段标签文本。"""
    inp_id = inp.get("id")
    if inp_id:
        label = form.find("label", attrs={"for": inp_id})
        if label:
            return label.get_text(strip=True)
    parent = inp.parent
    if parent and parent.name == "label":
        return parent.get_text(strip=True)
    return ""


def parse_form_element(page_url: str, form, page_title: str) -> CandidateForm | None:
    """解析单个 BeautifulSoup form 元素为 CandidateForm。

    模块级函数，供 SiteCrawler 和 main.py 共用。
    """
    action = form.get("action", "")
    method = (form.get("method") or "GET").upper()
    # action="#" 或空表示提交到当前页面
    if not action or action.strip() == "#":
        action_url = page_url.split("#")[0].split("?")[0]
    else:
        action_url = urljoin(page_url, action) if action else page_url

    inputs: dict[str, str] = {}
    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        if not name:
            continue
        inp_type = (inp.get("type") or "").lower()
        if inp_type in ("submit", "button", "reset"):
            continue
        label = _find_label(inp, form)
        inputs[name] = label or inp.get("placeholder", "") or inp.get("value", "") or name

    if not inputs:
        return None

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


class SiteCrawler:
    def __init__(self, timeout: int = 10, max_pages: int = 50):
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.trust_env = False
        self.visited: set[str] = set()

    def crawl(self, entry_url: str) -> list[CandidateForm]:
        """从入口 URL 爬取，返回所有发现的表单。若遇到登录页则自动登录。"""
        candidates: list[CandidateForm] = []
        queue = [entry_url]
        login_attempted = False

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
            page_forms = []
            for form in soup.find_all("form"):
                candidate = self._parse_form(url, form, page_title)
                if candidate:
                    page_forms.append(candidate)

            # 检测登录表单并自动登录
            if not login_attempted:
                login_form = self._detect_login_form(page_forms)
                if login_form:
                    login_attempted = True
                    if self._auto_login(login_form, page_title):
                        # 登录成功，清空状态从 index 页面重新爬取
                        candidates.clear()
                        self.visited.clear()
                        parsed_entry = urlparse(entry_url)
                        index_url = f"{parsed_entry.scheme}://{parsed_entry.netloc}/index.php"
                        queue = [index_url]
                        continue

            candidates.extend(page_forms)

            # 提取页面内链接，加入队列
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                parsed = urlparse(link)
                # 只爬同站链接
                if parsed.netloc == urlparse(entry_url).netloc and link not in self.visited:
                    queue.append(link)

        return candidates

    def _detect_login_form(self, forms: list[CandidateForm]) -> CandidateForm | None:
        """检测是否有登录表单（含 password 字段）。"""
        for form in forms:
            for name, label in form.inputs.items():
                if "password" in name.lower() or "pass" in name.lower() or "密码" in label:
                    return form
        return None

    def _auto_login(self, login_form: CandidateForm, page_title: str) -> bool:
        """让 LLM 识别靶场类型并获取默认凭据，自动登录。"""
        # 识别表单字段
        field_names = list(login_form.inputs.keys())
        prompt = f"""你是一个 Web 安全专家。根据以下登录页面信息，识别靶场/应用类型并提供默认登录凭据。

页面标题: {page_title}
登录地址: {login_form.action}
表单字段: {field_names}

请返回 JSON：
{{"app_name": "应用名称", "username": "默认用户名", "password": "默认密码", "reasoning": "判断依据"}}

常见靶场默认凭据参考：
- DVWA: admin/password
- SQLi-labs: admin/password 或无认证
- Pikachu: admin/admin123
- WebGoat: guest/guest 或 webgoat/webgoat
- Mutillidae: admin/admin 或 blank/blank
- bWAPP: bee/bug
- sqli: admin/admin
"""

        try:
            result = _chat_json(prompt, temperature=0.3, max_tokens=512)
            if not isinstance(result, dict):
                return False

            username = result.get("username", "")
            password = result.get("password", "")
            app_name = result.get("app_name", "")
            if not username and not password:
                return False

            print(f"  [INFO] 识别到 {app_name}，尝试登录: {username}/{password}")

            # 提取 CSRF token（如有）
            login_url = login_form.url
            try:
                login_page = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
                soup = BeautifulSoup(login_page.text, "html.parser")
            except Exception:
                soup = None

            # 构造登录数据
            login_data = {}
            for name, label in login_form.inputs.items():
                name_lower = name.lower()
                # CSRF token 优先匹配（避免 user_token 被误匹配为 username）
                if "token" in name_lower or "csrf" in name_lower:
                    if soup:
                        hidden = soup.find("input", {"name": name})
                        if hidden:
                            login_data[name] = hidden.get("value", "")
                elif "pass" in name_lower or "pwd" in name_lower:
                    login_data[name] = password
                elif "user" in name_lower or "login" in name_lower or "account" in name_lower:
                    login_data[name] = username
                else:
                    login_data[name] = label  # 保留原值

            # 补充 submit 按钮（部分靶场需要）
            if soup:
                for inp in soup.find_all("input", {"type": "submit"}):
                    btn_name = inp.get("name")
                    btn_value = inp.get("value", "Login")
                    if btn_name and btn_name not in login_data:
                        login_data[btn_name] = btn_value

            # 提交登录
            resp = self.session.post(
                login_form.action, data=login_data,
                timeout=self.timeout, allow_redirects=True,
            )

            # 判断登录是否成功
            if resp.status_code in (200, 302):
                # 检查是否还在登录页
                resp_text = resp.text.lower()
                if "login" not in resp.url.lower() or "logout" in resp_text or "dashboard" in resp_text or "vulnerabilities" in resp_text:
                    print(f"  [OK] 登录成功: {app_name}")
                    return True
                # 有些靶场登录后仍在 login.php 但显示不同内容
                if "password" not in resp_text[:500]:
                    print(f"  [OK] 登录成功: {app_name}")
                    return True

            print(f"  [WARN] 登录失败 (HTTP {resp.status_code})")
            return False

        except Exception as e:
            print(f"  [WARN] 自动登录出错: {e}")
            return False

    def _parse_form(self, page_url: str, form, page_title: str) -> CandidateForm | None:
        return parse_form_element(page_url, form, page_title)
