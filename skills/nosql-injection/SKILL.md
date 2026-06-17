---
name: nosql-injection
description: "NoSQL injection / MongoDB operator injection triage. Use when parameters or JSON bodies may reach MongoDB, CouchDB, Elasticsearch-style query DSL, JSON query filters, $where JavaScript, GraphQL-to-NoSQL resolvers, or when HackSkills routes MongoDB/JSON query syntax exposure to NoSQL Injection."
---

# NoSQL Injection

## Core Rule

Use only in authorized testing. Prefer low-impact boolean, type-confusion, and error-differential checks. Do not dump data, brute-force secrets, or run destructive database operations.

## First-Pass Triage

1. Identify whether user-controlled JSON, query parameters, GraphQL filters, search DSL, or form fields are translated into a NoSQL query.
2. Look for operator injection surfaces: `$ne`, `$gt`, `$regex`, `$in`, `$where`, nested objects where a scalar is expected, duplicate keys, and array coercion.
3. Compare baseline with harmless negative/positive controls:
   - expected scalar vs object
   - valid ID vs impossible ID
   - regex that matches nothing vs exact normal value
4. Treat login, password reset, search, tenant filters, price/quantity fields, and admin list APIs as high-value candidates.
5. Confirm with differential evidence: status, result count, stable body markers, error text, or authorization boundary changes.

## Route To Related Skills

- Use `api-authorization-and-bola` when the issue is object ownership or tenant filtering.
- Use `business-logic-vulnerabilities` when NoSQL type confusion changes price, quantity, coupon, or workflow state.
- Use `graphql-and-hidden-parameters` when the query surface is GraphQL.
- Use `burp-mcp-vuln-check` for replay and response diffing from Burp history.
