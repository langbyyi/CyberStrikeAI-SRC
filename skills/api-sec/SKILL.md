---
name: api-sec
description: >-
  Entry P1 category router for API security. Use when choosing between API
  recon, authorization, token abuse, and hidden-parameter workflows before any
  deeper API topic skill.
---

# API Security Router — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: API security entry router. Use when you encounter REST, GraphQL, SOAP, or WebSocket APIs and need to triage: asset discovery (OpenAPI/Swagger/docs), authorization (BOLA/BFLA/IDOR), token abuse (JWT/OAuth), or hidden parameter exploitation. Routes to specialized skills for deep exploitation. Covers API recon, endpoint discovery, versioning drift, and hidden documentation exposure before handing off.

Use this skill first to determine whether the current API case is more about documentation/asset discovery, object authorization, token trust issues, or GraphQL/hidden parameters, then route to the appropriate specialized skill.

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| API endpoint found? | Check docs (Swagger/OpenAPI) | Discover full attack surface before testing |
| Docs exist? | Test auth on each endpoint | Many APIs lack consistent auth enforcement |
| Auth works? | Test BOLA/IDOR — swap object IDs | #1 API vulnerability class |
| ID swap works? | Check rate limiting | Brute-force and abuse potential |
| Rate limit missing? | Look for hidden parameters | Extra JSON fields, undocumented endpoints |

```bash
# Quick test — check Swagger + test auth
curl -s https://target/swagger.json | jq '.paths | keys'
curl -s -H "Authorization: Bearer $TOKEN" https://target/api/users/2/profile
```

---

## When to Use

- Target exposes REST API, mobile backend, or GraphQL interface
- You need to determine API testing order before diving into specific topics
- You want to separate object authorization, JWT, GraphQL, and hidden field testing into distinct tracks

## Skill Map

- This skill covers quick routing for API asset discovery (OpenAPI, Swagger, version drift, hidden docs)
- [API Authorization and BOLA](../idor/SKILL.md): BOLA, BFLA, method abuse, hidden writable fields
- [API Auth and JWT Abuse](../jwt-attacks/SKILL.md): Bearer token, Header trust, Claim abuse, rate limit bypass
- [GraphQL and Hidden Parameters](../graphql/SKILL.md): introspection, batching, undocumented fields, hidden parameters

## Quick Triage

| Observation | Route |
|---|---|
| Swagger or OpenAPI present | See Skill Map above |
| IDs appear in URL, JSON, Header, or GraphQL args | [api-authorization-and-bola](../idor/SKILL.md) |
| JWT token visible in traffic | [api-auth-and-jwt-abuse](../jwt-attacks/SKILL.md) |
| `/graphql` or batched JSON arrays present | [graphql](../graphql/SKILL.md) |
| Registration, login, profile update accepts extra fields | [api-authorization-and-bola](../idor/SKILL.md) then [api-auth-and-jwt-abuse](../jwt-attacks/SKILL.md) |

## Recommended Flow

1. First check API surface exposure and documentation assets
2. Then check object-level and function-level authorization
3. Then check tokens, Headers, signatures, and rate limit boundaries
4. If GraphQL or complex JSON is present, proceed to hidden fields and schema abuse

---

## API SURFACE DISCOVERY

### OpenAPI / Swagger Detection

```text
/swagger.json
/swagger/v1/swagger.json
/api-docs
/api-docs.json
/v1/api-docs
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/.well-known/openapi.json
/api/swagger
/api/swagger/ui
```

### Version Drift Testing

```text
# If v2 is current, check if v1 still exists:
/api/v1/users
/api/v2/users
# v1 may have weaker auth or missing rate limits
```

### Hidden API Documentation

```text
# JavaScript bundle mining for API endpoints:
grep -roh '"/api/[a-zA-Z0-9/_-]*"' app.js | sort -u
grep -roh "'/api/[a-zA-Z0-9/_-]*'" app.js | sort -u

# Common hidden API patterns:
/api/admin
/api/internal
/api/debug
/api/test
/api/config
/api/health
/api/metrics
```

### HTTP Method Enumeration

```text
# Test all methods on each endpoint:
OPTIONS /api/users
GET /api/users
POST /api/users
PUT /api/users
PATCH /api/users
DELETE /api/users
# Some methods may be unauthenticated or have weaker authorization
```

---

## COMMON API ANTI-PATTERNS

| Anti-Pattern | Test | Impact |
|---|---|---|
| Sequential IDs (`/users/1`) | Change to `/users/2` | IDOR / BOLA |
| UUID in response but accepts ID | Send both | Authorization gap |
| Missing rate limit on login | Send 100+ requests | Brute force |
| Verbose error messages | Send invalid JSON | Info disclosure |
| CORS allows any origin | Send `Origin: evil.com` | Token theft |
| Mass assignment | Add `{"role":"admin"}` | Privilege escalation |
| No pagination limit | Request `?limit=999999` | Data exposure |
| API key in URL | Check Referer/header logs | Key leakage |

## DECISION TREE

```
API endpoint discovered?
├── REST API (OpenAPI/Swagger docs visible)?
│   └── Route to [api-authorization-and-bola] for BOLA/BFLA testing
├── GraphQL endpoint (/graphql, introspection enabled)?
│   └── Route to [graphql] for schema abuse testing
├── SOAP/WSDL endpoint found?
│   └── Test XML parsing, SOAP injection, WSDL enumeration
├── WebSocket connection present?
│   └── Test authentication, message validation, origin enforcement
└── API type unclear?
    └── Run API surface discovery, then re-triage
```

## TESTING CHECKLIST

- [ ] Discover API surface: find OpenAPI/Swagger docs, GraphQL endpoints, hidden API routes
- [ ] Test authentication on every endpoint: unauthenticated access, expired tokens, missing Authorization header
- [ ] Test authorization (BOLA/IDOR): replace object IDs in URLs, JSON bodies, and headers with other users' IDs
- [ ] Test HTTP method abuse: try PUT/DELETE/PATCH on GET-only endpoints, and vice versa
- [ ] Test hidden writable fields: send extra JSON keys in POST/PUT requests (role, isAdmin, price, etc.)
- [ ] Test rate limiting: send repeated requests to login, password reset, and sensitive endpoints
- [ ] Test JWT/token issues: algorithm confusion, expired tokens, tampered claims, missing signature validation
- [ ] Test GraphQL-specific issues: introspection exposure, query depth abuse, batch query attacks, unauthorized mutations
- [ ] Test input validation: send unexpected types, oversized payloads, negative IDs, special characters
- [ ] Route to specialized skills based on findings (see Skill Map above)

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `api_fuzzer` | Fuzz API endpoints with parameter mutations, unexpected HTTP methods, and edge-case payloads to discover hidden endpoints and authorization flaws |
| `api_schema_analyzer` | Analyze OpenAPI/Swagger/GraphQL schemas to identify undocumented endpoints, excessive permissions, and security issues in API definitions |
| `http_framework_test` | Send crafted HTTP requests to test BOLA/BFLA authorization, token abuse, and hidden writable fields across API endpoints |
| `http_repeater` | Replay and modify API requests to test IDOR, privilege escalation, JWT claim manipulation, and rate-limit bypass scenarios |
| `graphql_scanner` | Test GraphQL endpoints for introspection exposure, query depth abuse, mutation security, and batching attack vectors |

## RELATED ROUTING

- [auth-sec](../authentication-bypass/SKILL.md)
- [business-logic-vuln](../business-logic/SKILL.md)
- [recon-for-sec](../recon-and-methodology/SKILL.md)
