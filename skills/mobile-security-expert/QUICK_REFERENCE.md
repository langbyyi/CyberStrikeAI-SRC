# Quick Reference Guide for Android Security Testing

## 1. Vulnerability Quick Checklist by Type
### Common Locations:  
- **SQL Injection:** 
  - User input fields, API endpoints  
- **Insecure Data Storage:** 
  - Shared Preferences, SQLite databases, External storage  
- **Insecure Communication:** 
  - HTTP endpoints, Inter-app communication  
- **Code Injection:** 
  - Dynamic code execution areas, Reflection  
- **Improper Authentication:** 
  - Login screens, Session management  

## 2. Top 20 Critical Code Patterns to Watch For
1. Hardcoded credentials  
2. Use of `eval()` or similar functions  
3. Insecure data storage in plaintext  
4. Unvalidated user input  
5. Excessive permissions requests  
6. Insecure use of WebView  
7. Inadequate encryption of sensitive data  
8. Misconfigured server API endpoints  
9. Using outdated libraries  
10. Failure to implement SSL pinning  
11. Improper use of `AsyncTask`  
12. Missing `proguard` rules  
13. Lack of security logging  
14. Ignored security exceptions  
15. Incorrectly implemented OAuth  
16. Use of insecure third-party libraries  
17. Uncaught exceptions leading to crashes  
18. Blocking access without proper user notifications  
19. Lack of input validation in intents  
20. Poorly managed API keys  

## 3. Essential Testing Workflow
1. **Reconnaissance:**  
   - Understand the app architecture, functionalities, and endpoints.  
2. **Static Analysis:**  
   - Review code for vulnerabilities using tools.  
3. **Dynamic Analysis:**  
   - Perform runtime testing on real devices/emulators.  
4. **Identify Vulnerabilities:**  
   - Use checklists and patterns to find weaknesses.  
5. **Exploit Vulnerabilities:**  
   - Attempt to leverage identified vulnerabilities.  
6. **Documentation:**  
   - Document findings and recommendations.  

## 4. Tools Command Cheatsheet
- **OWASP ZAP:** `zap.sh` to start the tool.  
- **Burp Suite:** Start with `burpsuite` command.  
- **MobSF:** `mobsf.py` for static analysis.  
- **Drozer:** `drozer console connect` to connect to the device.  
- **APKTool:** `apktool d <apk>` to decompile the APK.  

## 5. Payload Templates
- **XSS Payload:** `<script>alert('XSS');</script>`  
- **SQL Injection:** `' OR 1=1 --`  
- **Command Injection:** `; ls -al`  
- **XML Injection:** `<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>`  

## 6. Common Bypass Techniques
- **Parameter Pollution:** Manipulating URL parameters to bypass security controls.  
- **Session Fixation:** Using a known session ID to gain unauthorized access.  
- **Replay Attacks:** Replaying valid requests to bypass authentication checks.  
- **Cross-Site Request Forgery (CSRF):** Exploiting a user’s active session to perform actions without their consent.  

> **Note:** Always have permission before testing an application. Respect ethical guidelines and legal restrictions.