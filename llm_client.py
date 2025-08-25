# -*- coding: utf-8 -*-
import os, json, time, requests, re
from typing import List, Dict, Any, Optional

class LLMClient:
    """
    关键变化：
    - 默认不做内部重试（retries=0），把重试/降载交给上层自适应队列处理；
    - 拆分 (connect_timeout, read_timeout)，确保单次 HTTP 调用最久不会超过 read_timeout；
    - 关闭 requests/urllib3 的隐式重试，避免 5xx 被悄悄重试拖时；
    - 保证至少执行 1 次请求（retries=0 时也会跑 1 次）。
    """
    def __init__(self,
                 api_url: str = None,
                 api_key: str = None,
                 model: str = None,
                 timeout: int = 120,              # 保留：总超时语义（可不用）
                 retries: int = 0,                # 默认 0：不在这里重试
                 backoff: float = 1.0,            # 保留参数，但我们不再内部指数退避
                 connect_timeout: int = 10,       # 新增：连接超时
                 read_timeout: int = 55):         # 新增：读取超时（建议 < 外层 _run_with_timeout）
        self.api_url = api_url or os.environ.get("API_URL")
        self.api_key = api_key or os.environ.get("API_KEY")
        self.model = model or os.environ.get("MODEL")
        self.timeout = timeout
        self.retries = int(retries)
        self.backoff = float(backoff)
        self.connect_timeout = int(connect_timeout)
        self.read_timeout = int(read_timeout)

        if not (self.api_url and self.api_key and self.model):
            raise RuntimeError("Missing API_URL/API_KEY/MODEL; set env vars or config.json")

        # ---- 使用 Session + 彻底关闭 urllib3 的自动重试 ----
        self._session = requests.Session()
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            retry = Retry(
                total=0, connect=0, read=0, redirect=0, status=0,
                backoff_factor=0.0, allowed_methods=False, raise_on_status=False
            )
            adapter = HTTPAdapter(max_retries=retry)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
        except Exception:
            # 某些精简环境没有 urllib3.retry，也无所谓
            pass

    # -------- helpers 保持不变（兼容多家返回结构） --------
    @staticmethod
    def _strip_noise_to_json(txt: str):
        if not isinstance(txt, str):
            return None
        i = txt.find('{')
        j = txt.rfind('}')
        if i != -1 and j != -1 and j > i:
            core = txt[i:j+1].strip()
            try:
                return json.loads(core)
            except Exception:
                return None
        return None

    @staticmethod
    def _looks_like_plaintext(txt: str):
        if not txt:
            return False
        t = txt.strip()
        if not t:
            return False
        if "<html" in t.lower() or "</html>" in t.lower():
            return False
        if len(t) > 100000:
            return False
        return True

    @staticmethod
    def _extract_content_from_json(data: dict):
        if isinstance(data, dict):
            if "choices" in data and data["choices"]:
                ch0 = data["choices"][0]
                if isinstance(ch0, dict):
                    if "message" in ch0 and ch0["message"] and "content" in ch0["message"]:
                        return ch0["message"]["content"]
                    if "text" in ch0 and isinstance(ch0["text"], str):
                        return ch0["text"]
            if "choice" in data and data["choice"]:
                ch0 = data["choice"][0]
                if "message" in ch0 and ch0["message"] and "content" in ch0["message"]:
                    return ch0["message"]["content"]
            if "text" in data and isinstance(data["text"], str):
                return data["text"]
            if "output" in data and isinstance(data["output"], str):
                return data["output"]
            if "outputs" in data and isinstance(data["outputs"], list) and data["outputs"]:
                out0 = data["outputs"][0]
                if isinstance(out0, dict):
                    if "text" in out0 and isinstance(out0["text"], str):
                        return out0["text"]
                    if "message" in out0 and "content" in out0["message"]:
                        return out0["message"]["content"]
            if "error" in data:
                err = data["error"]
                msg = err.get("message") if isinstance(err, dict) else str(err)
                raise RuntimeError(f"LLM server returned error: {msg}")
        return None

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.0,
             _retries: Optional[int] = None) -> str:
        """
        单次对话请求。
        - 不做 5xx 自动重试（除非显式传入 _retries>0，但仍建议保持 0）
        - 超时采用 (connect_timeout, read_timeout)
        """
        tries = max(1, int(self.retries if _retries is None else _retries))

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
        }
        payload = {
            "model": self.model,
            "temperature": float(temperature),
            "top_p": 1,
            "n": 1,
            "stream": False,
            "stop": None,
            "presence_penalty": 0,
            "frequency_penalty": 0,
            "messages": messages
        }

        last_err = None
        for attempt in range(1, tries + 1):
            try:
                r = self._session.post(
                    self.api_url,
                    headers=headers,
                    data=json.dumps(payload),
                    timeout=(self.connect_timeout, self.read_timeout)  # (connect, read)
                )

                # 非 2xx：直接抛给上层（不要在这里重试 5xx）
                if r.status_code < 200 or r.status_code >= 300:
                    body = (r.text or "")[:8000]
                    raise RuntimeError(f"HTTP {r.status_code} from LLM server. Body head:\n{body}")

                # JSON 或纯文本兜底
                try:
                    data = r.json()
                except Exception:
                    data = self._strip_noise_to_json(r.text)

                if data is not None:
                    content = self._extract_content_from_json(data)
                    if isinstance(content, str) and content.strip():
                        return content.strip()
                else:
                    if self._looks_like_plaintext(r.text):
                        return (r.text or "").strip()

                # 到这里说明没有拿到有效文本
                snippet = (r.text or "")[:8000]
                last_err = RuntimeError(f"LLM response unrecognized/empty. Snippet:\n{snippet}")

            except Exception as e:
                last_err = e

            # 明确不做指数退避；把“重试策略”交给外层自适应队列
            if attempt < tries:
                # 可选：轻微等待，避免瞬时的 429/网关波动（如需）
                time.sleep(0.1)

        raise RuntimeError(f"Bad LLM response after {tries} attempts: {last_err}")
