#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用法示例：
    python syz_kasan_scraper_full.py --max-bugs 1 --combine  
"""
import argparse
import json
import os
import re
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

BASE = "https://syzkaller.appspot.com"
FIXED = f"{BASE}/upstream/fixed"
UA = {"User-Agent": "ksan-scraper/2.0 (+research)"}

TEXT_PATH_RE = re.compile(r"/text\?tag=", re.I)
SKIP_DOMAINS = {"groups.google.com", "lore.kernel.org", "lkml.org"}

# -------------------- HTTP helpers --------------------
def http_get(url: str, timeout=30, retries=3) -> requests.Response:
    last = None
    for i in range(retries):
        try:
            r = requests.get(url, headers=UA, timeout=timeout)
            r.raise_for_status()
            return r
        except Exception as e:
            last = e
            time.sleep(2 ** i)
    raise RuntimeError(f"GET failed for {url}: {last}")

def html(url: str) -> BeautifulSoup:
    return BeautifulSoup(http_get(url).text, "html.parser")

def is_syzkaller_text_link(href_abs: str) -> bool:
    if not href_abs:
        return False
    p = urlparse(href_abs)
    if p.netloc and p.netloc != urlparse(BASE).netloc:
        return False
    return bool(TEXT_PATH_RE.search((p.path or "") + "?" + (p.query or "")))

# -------------------- parsing helpers --------------------
def ensure_all_view(url: str) -> str:
    """bug?extid=... -> bug?extid=...&all=1"""
    u = urlparse(url)
    q = parse_qs(u.query)
    q["all"] = ["1"]
    newq = "&".join(f"{k}={v[0]}" for k, v in q.items())
    return u._replace(query=newq).geturl()

def extract_extid(url: str) -> str:
    return (parse_qs(urlparse(url).query).get("extid") or ["unknown"])[0]

def extract_top_fields(soup: BeautifulSoup) -> Dict:
    """宽松解析顶部表格字段（取页面第一个 table）"""
    fields = {}
    t = soup.find("table")
    if not t:
        return fields
    for tr in t.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) >= 2:
            key = tds[0].get_text(" ", strip=True).rstrip(":")
            val = tds[1].get_text(" ", strip=True)
            fields[key] = val
    return fields

def find_crashes_table(soup: BeautifulSoup):
    t = soup.find("table", id="crashes")
    if t:
        return t
    # fallback: any table whose headers contain time/kernel/commit
    for cand in soup.find_all("table"):
        heads = [th.get_text(" ", strip=True).lower() for th in cand.find_all("th")]
        if heads and all(k in " ".join(heads) for k in ("time", "kernel", "commit")):
            return cand
    return None

def collect_global_text_links(soup: BeautifulSoup) -> List[Tuple[str, str]]:
    """页面上的 /text? 链接（只保留 syzkaller 域；跳过外站）"""
    out = []
    for a in soup.find_all("a", href=True):
        text = a.get_text(" ", strip=True) or a.get("title") or ""
        href_abs = urljoin(BASE, a["href"])
        host = urlparse(href_abs).netloc
        if host and any(host.endswith(d) for d in SKIP_DOMAINS):
            continue
        if is_syzkaller_text_link(href_abs):
            out.append((text, href_abs))
    return out

def build_crashes_skeleton(soup: BeautifulSoup) -> Tuple[List[Dict], List[Tuple[int, str, str]]]:
    """
    返回 (rows, pending_fetches)
    rows: 每行一个 dict，链接单元先放 {"text":..., "href":..., "content": None}
    pending_fetches: [(row_index, col_key, url), ...] 需要下载 content 的文本链接
    """
    rows = []
    pending = []
    table = find_crashes_table(soup)
    if not table:
        return rows, pending

    headers = [th.get_text(" ", strip=True) for th in table.find_all("th")]
    for tr in table.find_all("tr")[1:]:
        tds = tr.find_all("td")
        if not tds:
            continue
        row = {}
        for i, td in enumerate(tds):
            col = headers[i] if i < len(headers) else f"col{i}"
            a = td.find("a", href=True)
            if a:
                href_abs = urljoin(BASE, a["href"])
                cell = {"text": a.get_text(" ", strip=True), "href": href_abs, "content": None}
                row[col] = cell
                if is_syzkaller_text_link(href_abs):
                    pending.append((len(rows), col, href_abs))
            else:
                row[col] = td.get_text(" ", strip=True)
        rows.append(row)
    return rows, pending

# -------------------- per-bug pipeline with inner progress --------------------
def parse_bug_with_progress(url: str, verbose=False) -> Dict:
    """分阶段进度：抓HTML -> 解析字段/标题 -> 识别全局Report -> 逐条下载crashes中的文本资源"""
    # Stage 1: fetch HTML (all=1)
    url_all = ensure_all_view(url)
    with tqdm(total=1, desc="获取HTML", leave=False) as pbar:
        soup = html(url_all)
        pbar.update(1)

    # Title / fields
    with tqdm(total=2, desc="解析结构", leave=False) as pbar:
        h = soup.find(["h2", "h1"]) or soup.find("title")
        title = h.get_text(" ", strip=True) if h else "(no title)"
        pbar.update(1)

        fields = extract_top_fields(soup)
        pbar.update(1)

    # Collect global /text? links (to find a Report quickly)
    global_text_links = collect_global_text_links(soup)
    report_url_global = None
    for txt, href in global_text_links:
        if "report" in txt.lower():
            report_url_global = href
            break

    # Build crashes skeleton & pending list to fetch
    crashes, pending = build_crashes_skeleton(soup)

    # Build download plan: unique URLs to fetch (crashes cells + optional global report)
    unique_urls = []
    seen = set()
    if report_url_global and report_url_global not in seen:
        unique_urls.append(("__CRASH_REPORT__", "__global__", report_url_global))
        seen.add(report_url_global)
    for r_idx, col_key, href in pending:
        if href not in seen:
            unique_urls.append((r_idx, col_key, href))
            seen.add(href)

    # Download with inner progress
    crash_report = ""
    if unique_urls:
        with tqdm(total=len(unique_urls), desc="下载文本", leave=False) as pbar:
            for r_idx, col_key, href in unique_urls:
                try:
                    txt = http_get(href).text if is_syzkaller_text_link(href) else None
                except Exception as e:
                    txt = f"[DOWNLOAD ERROR] {e}"
                if r_idx == "__CRASH_REPORT__":
                    crash_report = txt or crash_report
                else:
                    # fill into crashes row cell
                    if isinstance(r_idx, int) and 0 <= r_idx < len(crashes):
                        cell = crashes[r_idx].get(col_key)
                        if isinstance(cell, dict):
                            cell["content"] = txt
                pbar.update(1)

    # Fallback: if crash_report still empty, try first row's Report
    if not crash_report and crashes:
        first = crashes[0]
        for k, v in first.items():
            if isinstance(v, dict) and "report" in k.lower():
                crash_report = v.get("content") or crash_report
                if crash_report:
                    break

    return {
        "url": url,
        "extid": extract_extid(url),
        "title": title,
        "fields": fields,
        "crash_report": crash_report or "",
        "crashes": crashes
    }

# -------------------- list page & IO --------------------
def list_fixed(filter_kw: str = "kasan") -> List[Dict]:
    soup = html(FIXED)
    items = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/bug?extid="):
            items.append({"title": a.get_text(" ", strip=True), "url": urljoin(BASE, href)})
    print(f"[+] fixed 列表共找到 {len(items)} 条漏洞")
    if not filter_kw:
        sel = items
    else:
        pat = re.compile(filter_kw, re.I)
        sel = [it for it in items if pat.search(it["title"])]
    print(f"[+] 筛选出 {len(sel)} 条匹配 “{filter_kw}” 的漏洞")
    return sel

def save_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

# 生成安全文件名：基于 title 命名，并附上 extid 保证唯一性
WINDOWS_RESERVED = {
    "CON","PRN","AUX","NUL",
    *(f"COM{i}" for i in range(1,10)),
    *(f"LPT{i}" for i in range(1,10)),
}
def safe_filename(name: str, max_len: int = 120) -> str:
    """将漏洞标题转换为可用的文件名"""
    # 去掉多余空格
    name = re.sub(r"\s+", " ", name.strip())
    # 替换 Windows 禁用字符
    name = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", name)
    # 去掉尾部的点和空格
    name = name.rstrip(" .")
    # 截断过长
    if len(name) > max_len:
        name = name[:max_len].rstrip(" .")
    return f"{name}.json"


# -------------------- main --------------------
def main():
    ap = argparse.ArgumentParser(description="Syzkaller KSAN scraper with inner progress")
    ap.add_argument("--filter", default="kasan", help="标题筛选关键字（默认 kasan；如 kcsan；为空不过滤）")
    ap.add_argument("--max-bugs", type=int, default=5, help="最多抓取多少条（默认5便于验证）")
    ap.add_argument("--sleep", type=float, default=0.5, help="每条之间休眠秒数")
    ap.add_argument("--outdir", default="./result/bug02", help="输出目录（单条JSON会写在这里）")
    ap.add_argument("--combine", action="store_true", help="同时输出合并的 bugs.json")
    args = ap.parse_args()

    items = list_fixed(args.filter)
    if args.max_bugs and args.max_bugs > 0:
        items = items[:args.max_bugs]

    all_out, index = [], []
    for i, it in enumerate(tqdm(items, desc="Bug级进度", unit="bug"), 1):
        print(f"\n[#{i}] {it['title']}")
        try:
            data = parse_bug_with_progress(it["url"])
            all_out.append(data)
            title = it["title"]  # 这里是 fixed 页面原来的标题
            fname = safe_filename(title)
            save_json([data], os.path.join(args.outdir, fname))
            index.append({"title": data.get("title", ""), "url": it["url"]})
        except Exception as e:
            print(f"[ERROR] {it['url']}: {e}")
        time.sleep(args.sleep)

    save_json(index, os.path.join(args.outdir, "index.json"))
    if args.combine:
        save_json(all_out, os.path.join(args.outdir, "bugs.json"))
    print(f"\n[DONE] wrote {len(all_out)} bugs to ./{args.outdir}/")

if __name__ == "__main__":
    main()
