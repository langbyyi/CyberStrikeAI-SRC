#!/usr/bin/env python3
"""Burp MCP preflight for WeChat mini program login-key leaks.

The script enumerates wildcard/root-domain history and forces sensitive
WeChat login keyword searches before deeper vulnerability triage.
"""

from __future__ import annotations

import argparse
import json
import queue
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict


DEFAULT_JAVA = r"C:\Program Files\JetBrains\PyCharm 2025.2.1.1\jbr\bin\java.exe"
DEFAULT_JAR = r"C:\Users\Administrator\Desktop\mcp-proxy.jar"
DEFAULT_SSE = "http://127.0.0.1:9876/"

SESSION_KEY_REGEX = (
    r"session[\s_-]?key|sess[\s_-]?key|wx[\s_-]?session[\s_-]?key|"
    r"wechat[\s_-]?session[\s_-]?key|weixin[\s_-]?session[\s_-]?key|"
    r"mini[\s_-]?session[\s_-]?key|user[\s_-]?session[\s_-]?key|"
    r"login[\s_-]?session[\s_-]?key|third[\s_-]?session[\s_-]?key|"
    r"3rd[\s_-]?session[\s_-]?key|raw[\s_-]?session[\s_-]?key|"
    r"decrypt[\s_-]?key|decryption[\s_-]?key|phone[\s_-]?decrypt[\s_-]?key|"
    r"open[\s_-]?data[\s_-]?key"
)
WEAK_SESSION_KEY_REGEX = r"\b(?:sk|skey)\b"
WECHAT_CONTEXT_REGEX = (
    r"jscode2session|code2session|wx\.login|openid|unionid|getphonenumber|"
    r"encrypteddata|api\.weixin\.qq\.com|appsecret|mini|wechat|weixin"
)
SENSITIVE_REGEX = (
    rf"{SESSION_KEY_REGEX}|{WEAK_SESSION_KEY_REGEX}|jscode2Session|jscode2session|"
    r"code2Session|openid|unionid|getPhoneNumber|encryptedData|appSecret|"
    r"api\.weixin\.qq\.com|getSecretPhone|getOpenId|getWxInfo|bindPhone|"
    r"phoneLogin|getPhone"
)

SESSION_KEY_RE = re.compile(SESSION_KEY_REGEX, re.IGNORECASE)
WEAK_SESSION_KEY_RE = re.compile(WEAK_SESSION_KEY_REGEX, re.IGNORECASE)
WECHAT_CONTEXT_RE = re.compile(WECHAT_CONTEXT_REGEX, re.IGNORECASE)
SENSITIVE_RE = re.compile(SENSITIVE_REGEX, re.IGNORECASE)


def mask(text: str) -> str:
    secret_name = rf"{SESSION_KEY_REGEX}|{WEAK_SESSION_KEY_REGEX}|openid|unionid|token|secret|authorization|cookie"
    text = re.sub(rf"(?i)({secret_name})([\"']?\s*[:=]\s*[\"']?)[^,\"'&\s}}\]]+", r"\1\2<redacted>", text)
    text = re.sub(r"(?i)(code=)[^&\s]+", r"\1<redacted>", text)
    text = re.sub(r"1[3-9]\d{9}", "<phone>", text)
    return text


class McpClient:
    def __init__(self, java: str, jar: str, sse_url: str):
        self.proc = subprocess.Popen(
            [java, "-jar", jar, "--sse-url", sse_url],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.qout: queue.Queue[str] = queue.Queue()
        self.qerr: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._reader, args=(self.proc.stdout, self.qout), daemon=True).start()
        threading.Thread(target=self._reader, args=(self.proc.stderr, self.qerr), daemon=True).start()
        self._id = 0

    @staticmethod
    def _reader(stream, q: queue.Queue[str]) -> None:
        for line in stream:
            q.put(line.rstrip("\n"))

    def send(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        return self.wait(self._id)

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def wait(self, msg_id: int, timeout: int = 60) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self.qout.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == msg_id:
                return msg
        errors: list[str] = []
        while not self.qerr.empty():
            errors.append(self.qerr.get_nowait())
        raise TimeoutError("\n".join(errors[-20:]))

    def initialize(self) -> None:
        self.send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "miniapp-burp-preflight", "version": "0.1"},
            },
        )
        self.notify("notifications/initialized", {})

    def call_tool(self, name: str, arguments: dict) -> str:
        result = self.send("tools/call", {"name": name, "arguments": arguments})
        if "error" in result:
            return json.dumps(result["error"], ensure_ascii=False)
        content = result.get("result", {}).get("content", [])
        return "\n".join(item.get("text", "") for item in content if item.get("type") == "text")

    def close(self) -> None:
        self.proc.terminate()


def extract_hosts(text: str, root: str) -> list[str]:
    hosts = set(re.findall(r"(?i)Host:\s*([^\s:\\]+)", text))
    hosts.update(re.findall(r"https?://([^/\s\"']*" + re.escape(root) + r")", text, flags=re.I))
    return sorted(h for h in hosts if h.lower().endswith(root.lower()))


def extract_host_from_line(line: str, root: str) -> str:
    host_match = re.search(r"(?i)Host:\s*([^\s:\\]+)", line)
    if host_match:
        return host_match.group(1)
    url_match = re.search(r"https?://([^/\s\"']*" + re.escape(root) + r")", line, flags=re.I)
    if url_match:
        return url_match.group(1)
    return "<unknown>"


def is_sensitive_line(line: str) -> bool:
    if SENSITIVE_RE.search(line):
        if WEAK_SESSION_KEY_RE.search(line) and not (SESSION_KEY_RE.search(line) or WECHAT_CONTEXT_RE.search(line)):
            return False
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Enumerate Burp hosts and WeChat mini program login-key leak indicators.")
    parser.add_argument("root_domain", help="Root domain such as anjia.com")
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--java", default=DEFAULT_JAVA)
    parser.add_argument("--jar", default=DEFAULT_JAR)
    parser.add_argument("--sse-url", default=DEFAULT_SSE)
    args = parser.parse_args()

    client = McpClient(args.java, args.jar, args.sse_url)
    try:
        client.initialize()
        broad = client.call_tool("get_proxy_http_history_regex", {"regex": re.escape(args.root_domain), "count": args.count, "offset": 0})
        combined_regex = f"(?i)({re.escape(args.root_domain)}|{SENSITIVE_REGEX})"
        sensitive = client.call_tool("get_proxy_http_history_regex", {"regex": combined_regex, "count": args.count, "offset": 0})
        hosts = sorted(set(extract_hosts(broad, args.root_domain)) | set(extract_hosts(sensitive, args.root_domain)))
        print("HOSTS")
        for host in hosts:
            print(f"- {host}")

        print("\nSENSITIVE_MATCHES")
        by_host: dict[str, list[str]] = defaultdict(list)
        variant_hits: dict[str, set[str]] = defaultdict(set)
        for line in sensitive.splitlines():
            if not is_sensitive_line(line):
                continue
            host = extract_host_from_line(line, args.root_domain)
            if host != "<unknown>" and not host.lower().endswith(args.root_domain.lower()):
                continue
            if host == "<unknown>" and args.root_domain.lower() not in line.lower():
                continue
            for match in SESSION_KEY_RE.finditer(line):
                variant_hits[host].add(match.group(0))
            if WEAK_SESSION_KEY_RE.search(line) and WECHAT_CONTEXT_RE.search(line):
                variant_hits[host].add(WEAK_SESSION_KEY_RE.search(line).group(0))
            by_host[host].append(mask(line[:1500]))

        print("\nSESSION_KEY_VARIANT_HITS")
        for host, variants in sorted(variant_hits.items()):
            print(f"- {host}: {', '.join(sorted(variants, key=str.lower))}")

        for host, lines in sorted(by_host.items()):
            print(f"\n## {host}")
            for line in lines[:5]:
                print(mask(line))
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
