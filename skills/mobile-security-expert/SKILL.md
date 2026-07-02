---
name: mobile-security-expert
description: Mobile security testing for Android and iOS applications. Use when decompiling APKs/IPAs, analyzing AndroidManifest.xml, testing exported components, bypassing certificate pinning, analyzing deeplinks, performing Frida hooking, or testing mobile API backends.
---

# Mobile Security Vulnerability Testing

> **AI LOAD INSTRUCTION**: Mobile security testing based on 100+ HackerOne public reports. Covers Android (APK decompilation, manifest analysis, exported components, Frida hooking, certificate pinning bypass, local storage extraction) and iOS (IPA analysis, URL scheme abuse, Keychain/UserDefaults data exposure, ATS bypass). Use when decompiling APKs/IPAs, testing mobile API backends, analyzing deeplinks, or performing runtime instrumentation with Frida/Drozer. Base models often treat mobile as web — mobile-specific sinks (SharedPreferences, Keychain, Content Providers, URL schemes) require distinct testing approaches.

## Task Objectives

- This skill provides mobile security vulnerability testing guidance based on HackerOne public reports
- Capabilities include:
  - Android vulnerability testing guidance (business logic flaws, component security, data storage, permission bypass, etc.)
  - iOS vulnerability testing guidance (URL schemes, deep links, data protection, API security, etc.)
  - Vulnerability case study analysis (real report technique summaries)
  - Code pattern recognition and vulnerability detection (comparison with known vulnerability patterns)
  - Tool usage guidance (Drozer, Frida, Burp Suite, etc.)
- Auto-trigger: prioritize this skill when Android/iOS/mobile projects or vulnerability scanning tasks are detected. Typical project fingerprints include APK/AAB/IPA, AndroidManifest.xml, build.gradle, Kotlin/Java Android source, Info.plist, .xcodeproj, .xcworkspace, Swift/Objective-C, React Native, Flutter, Cordova/Capacitor, Frida, Drozer, MobSF, Burp mobile interception, mobile API security testing, HackerOne mobile case analysis.

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| APK available? | `jadx -d output app.apk` or `apktool d app.apk` | Decompile to review manifest, source, and resources |
| Hardcoded credentials? | `grep -r "api_key\|password\|secret\|token" output/` | Keys in source = direct leakage |
| API endpoints found? | `grep -r "http://" output/` or `grep -r "https://" output/` | Map backend attack surface |
| Certificate pinning? | Check `NetworkSecurityConfig` / `Info.plist` ATS settings | No pinning = proxy intercept all API traffic |
| Insecure data storage? | Check SharedPreferences, SQLite DB, Keychain after usage | Sensitive data stored in cleartext = local extraction |

```bash
# Quick APK triage
jadx -d ./decompiled app.apk
grep -ri "api_key\|password\|secret\|Authorization" ./decompiled/
cat ./decompiled/AndroidManifest.xml | grep -i "exported\|permission\|deeplink"
```

## Testing Workflow

### Standard Process

1. **Requirement identification and scenario matching**
   - Determine target platform (Android/iOS) or cross-platform
   - Identify vulnerability type (business logic, component security, data protection, etc.)
   - Determine query intent (learning guidance, code audit, case reference)

2. **Knowledge retrieval**
   - Android: read [android.md](android.md), locate relevant cases by keyword
   - iOS: read [IOS.md](IOS.md), locate relevant cases by keyword
   - Extract three parts from each case: "testing techniques", "technical details", "vulnerable code patterns"

3. **Analysis and guidance**
   - **Technique guidance**: provide actionable testing workflows based on case study steps
   - **Technical explanation**: explain vulnerability root cause, exploitation method, and key technical points
   - **Code pattern recognition**: compare user-provided code against known vulnerability patterns, highlight risks
   - **Tool recommendations**: recommend and guide usage of relevant security testing tools

4. **Output organization**
   - Target answers to user questions, avoid stacking unrelated cases
   - Provide specific actionable steps and commands
   - Include real case links for deep reference
   - For code analysis, clearly identify vulnerability locations and remediation suggestions

### Typical Scenarios

**Scenario A: How to find specific vulnerability types**
- Query relevant documentation, extract cases for the vulnerability type
- Summarize general testing approach and key points for that category
- Provide detailed step-by-step guidance and tool usage methods

**Scenario B: Code audit and vulnerability detection**
- Read the "vulnerable code patterns" from documentation
- Compare against user code, identify similar patterns
- Provide specific vulnerability locations and remediation suggestions

**Scenario C: HackerOne case analysis**
- Locate the corresponding case in documentation by report URL or vulnerability name
- Summarize the core testing techniques and technical highlights
- Analyze reusability of techniques in other scenarios

**Scenario D: Learning mobile security**
- Provide systematic case index by platform and vulnerability type
- Recommend learning paths from simple to complex
- Emphasize practical experience and techniques

## Resource Index

### Core Reference Materials

- **Android Vulnerability Knowledge Base**: [android.md](android.md)
  - Content: Android vulnerability cases based on 100+ HackerOne reports
  - Usage: Android application vulnerability testing guidance, code pattern reference
  - Coverage: business logic flaws, component security, data storage, permission bypass, API security, etc.

- **iOS Vulnerability Knowledge Base**: [IOS.md](IOS.md)
  - Content: iOS vulnerability cases based on 100+ HackerOne reports
  - Usage: iOS application vulnerability testing guidance, code pattern reference
  - Coverage: URL scheme handling, deep link security, data protection, API security, etc.

### Reference Document Structure

Each case contains three core sections:
1. **Testing techniques**: specific steps for vulnerability discovery, tool usage, analysis methodology
2. **Technical details**: attack flow, payload construction, key technical points
3. **Vulnerable code patterns**: vulnerable code examples and remediation suggestions

## Usage Examples

### Example 1: Android Activity Authentication Bypass

**Purpose**: Learn how to find Activity authentication bypass vulnerabilities in Android apps
**Execution**: Agent analysis + document retrieval
**Key points**:
- Use Drozer to enumerate exported Activity components
- Test whether sensitive Activities require authentication
- Check AndroidManifest.xml configuration and code logic

### Example 2: iOS URL Scheme Vulnerability Analysis

**Purpose**: Analyze whether an iOS app's URL scheme handling has security vulnerabilities
**Execution**: Agent code analysis + document reference
**Key points**:
- Check URL schemes registered in Info.plist
- Analyze URL handling logic in AppDelegate/SceneDelegate
- Verify call origin and parameter validation

### Example 3: 2FA Logic Flaw Testing

**Purpose**: Guide how to discover 2FA implementation logic vulnerabilities in mobile apps
**Execution**: Agent workflow guidance + tool usage recommendations
**Key points**:
- Test rate limiting on SMS resend
- Verify authorization checks during phone number binding
- Use Burp Suite to intercept and analyze requests

## DECISION TREE

```
Mobile application (APK/IPA) in scope?
├── Static analysis possible (decompile APK/IPA)?
│   ├── AndroidManifest.xml / Info.plist review?
│   │   ├── Exported components found?
│   │   │   └── Test unauthorized Activity/Service/Provider access
│   │   └── URL schemes / deeplinks registered?
│   │       └── Test deeplink abuse and parameter injection
│   └── Source code review reveals hardcoded secrets?
│       └── Test API key/key/credential leakage
├── Dynamic analysis possible (runtime testing)?
│   ├── Certificate pinning enforced?
│   │   ├── Pinning can be bypassed (Frida/Objection)?
│   │   │   └── Intercept traffic and test API backend
│   │   └── Pinning blocks proxy?
│   │       └── Focus on local storage and client-side analysis
│   └── Local data storage insecure?
│       ├── SharedPreferences / Keychain / SQLite leaks?
│       │   └── Extract and document sensitive data exposure
│       └── Backup enabled (adb backup / iCloud)?
│           └── Test backup extraction of sensitive data
├── API backend accessible?
│   └── Test authentication bypass, IDOR, parameter tampering, session handling
├── WebView components used?
│   └── Test JavaScript bridge, file access, intent URL schemes
└── No mobile app access?
    └── Report scope limitation; recommend runtime environment setup
```

## TESTING CHECKLIST

- [ ] Perform static analysis: decompile APK/IPA, review AndroidManifest.xml / Info.plist
- [ ] Analyze exported components: Activities, Services, Receivers, Content Providers
- [ ] Test deeplink and URL scheme abuse: registered schemes, intent filters, parameter handling
- [ ] Test certificate pinning: attempt proxy interception, check for bypass possibilities
- [ ] Analyze local data storage: SharedPreferences, Keychain, SQLite databases, keystore/Keychain
- [ ] Test API backend security: authentication bypass, IDOR, parameter tampering, session handling
- [ ] Perform dynamic analysis with Frida: hook methods, bypass root detection, trace crypto
- [ ] Test insecure logging: sensitive data in Logcat / Console output
- [ ] Test clipboard and keyboard cache for sensitive data leakage
- [ ] Test backup functionality: adb backup, iCloud backup inclusion of sensitive data
- [ ] Test biometric authentication bypass: can sensitive actions skip biometric check
- [ ] Review WebView security: JavaScript enabled, file access, intent URL schemes
- [ ] Test push notification security: data exposure, action handling without auth

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted HTTP requests to mobile API backends to test authentication bypass, parameter tampering, and session handling vulnerabilities |
| `http_repeater` | Replay and modify mobile API requests to test IDOR, privilege escalation, and token abuse scenarios identified from HackerOne case patterns |
| `nuclei_scan` | Run mobile-API-focused Nuclei templates to automate detection of common mobile backend vulnerabilities (auth bypass, exposed APIs, misconfigurations) |
| `api_fuzzer` | Fuzz mobile API endpoints for hidden parameters, unsupported HTTP methods, and unexpected input handling that may lead to business logic flaws |
| `api_schema_analyzer` | Analyze OpenAPI/Swagger schemas of mobile backends to identify undocumented endpoints, excessive permissions, and schema inconsistencies |

## RELATED ROUTING

- [api-security](../api-security/SKILL.md) — mobile API backend testing overlaps with general API security methodology
- [authentication-bypass](../authentication-bypass/SKILL.md) — auth bypass techniques apply to mobile login and session flows
- [jwt-attacks](../jwt-attacks/SKILL.md) — token abuse in mobile OAuth/OIDC flows shares attack patterns
- [burp-mcp](../burp-mcp/SKILL.md) — proxy history analysis for mobile traffic interception findings
