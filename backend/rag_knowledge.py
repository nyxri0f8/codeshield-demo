import re
from typing import List, Dict, Any

# RAG Security Knowledge Base
KNOWLEDGE_BASE = {
    "OWASP": {
        "A01:2021-Broken Access Control": (
            "Access control enforces policy such that users cannot act outside of their intended permissions. "
            "Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, "
            "or performing a business function outside the user's limits. Common vulnerabilities include IDOR, "
            "privilege escalation, bypassing access control checks, and CORS misconfigurations."
        ),
        "A02:2021-Cryptographic Failures": (
            "Focuses on failures related to cryptography (or lack thereof) which often leads to sensitive data exposure. "
            "Issues include transmitting cleartext sensitive data, using weak/deprecated cryptographic algorithms (e.g., MD5, SHA1), "
            "hardcoded cryptographic keys, and poor key management."
        ),
        "A03:2021-Injection": (
            "An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized by the application. "
            "Dynamic queries or non-parameterized calls without context-aware escaping are passed directly to the interpreter. "
            "Includes SQL Injection, Command Injection, LDAP Injection, and NoSQL Injection."
        ),
        "A04:2021-Insecure Design": (
            "Focuses on risks related to design flaws. If you have insecure design, you cannot fix it with a perfect implementation. "
            "Examples include lack of threat modeling, single points of failure, missing rate limits, and insecure business logic flows."
        ),
        "A05:2021-Security Misconfiguration": (
            "The application lacks proper security hardening. Examples include default accounts/passwords, directory listing enabled, "
            "unnecessary ports open, missing security headers (e.g., Content-Security-Policy, X-Frame-Options), and detailed error pages exposing stack traces."
        ),
        "A06:2021-Vulnerable and Outdated Components": (
            "Using client-side or server-side components (e.g., library, framework, module) that are outdated, unsupported, or contain known vulnerabilities."
        ),
        "A07:2021-Identification and Authentication Failures": (
            "Confirmation of the user's identity, assertion, and session management are critical. Vulnerabilities include "
            "weak password policies, permitting credential stuffing, session fixation, session hijacking, and missing Multi-Factor Authentication (MFA)."
        ),
        "A08:2021-Software and Data Integrity Failures": (
            "Focuses on code and infrastructure that does not protect against integrity violations. "
            "Examples include auto-update features without signature validation, untrusted deserialization (e.g., Python pickle, Java deserialization), "
            "and insecure CI/CD pipelines."
        ),
        "A09:2021-Security Logging and Monitoring Failures": (
            "Without logging and monitoring, security breaches cannot be detected, escalated, or responded to. "
            "Vulnerabilities include insufficient logging of high-value transactions, audit logs not stored securely, and lack of active monitoring/alerting."
        ),
        "A10:2021-Server-Side Request Forgery (SSRF)": (
            "Occurs when a web application fetches a remote resource without validating the user-supplied URL. "
            "Allows attackers to coerce the application to send crafted requests to internal services, metadata APIs (e.g., AWS IMDS), or loopback interfaces."
        )
    },
    "CWE": {
        "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'). Allows attackers to run arbitrary SQL statements.",
        "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting' / XSS). Allows execution of malicious scripts in target browser.",
        "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'). Allows access to files outside active directory.",
        "CWE-798": "Use of Hardcoded Credentials. Exposes passwords, API keys, or tokens in source code.",
        "CWE-352": "Cross-Site Request Forgery (CSRF). Forces user to execute unwanted actions on authenticated app.",
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor. Leads to data leaks.",
        "CWE-94": "Improper Control of Generation of Code ('Code Injection'). Leads to Remote Code Execution (RCE).",
        "CWE-287": "Improper Authentication. Allows bypassing of authentication checks.",
        "CWE-276": "Incorrect Default Permissions. Allows unauthorized reading/writing of files/resources."
    },
    "MITRE_ATTACK": {
        "T1190": "Exploit Public-Facing Application: Attackers exploit vulnerabilities to gain access or run commands.",
        "T1110": "Brute Force: Attempting multiple passwords/credentials to gain unauthorized access.",
        "T1552": "Unsecured Credentials: Finding hardcoded secrets in source files, config files, or repositories.",
        "T1059": "Command and Scripting Interpreter: Executing scripts/commands to run malicious code.",
        "T1133": "External Remote Services: Gaining access via VPNs, APIs, or interfaces without proper authentication."
    },
    "GUIDELINES": {
        "API_Security": "Always enforce rate limiting, use JWT with strong signing keys, validate authorization headers, use secure CORS policies, and avoid exposure of internal IDs (use UUIDs).",
        "Input_Validation": "Validate all inputs using strict allow-lists. Sanitize strings before rendering. Use parameterized queries for databases.",
        "Cloud_Security": "Never commit cloud provider keys. Rotate credentials frequently. Enforce least privilege IAM policies. Use HTTPS-only policies."
    }
}

def search_knowledge_base(query: str) -> str:
    """
    Search the RAG knowledge base for keywords related to the query and return context.
    """
    results = []
    query_lower = query.lower()
    
    # Simple semantic keyword matching
    for category, items in KNOWLEDGE_BASE.items():
        matched_items = []
        for name, desc in items.items():
            if any(word in name.lower() or word in desc.lower() for word in query_lower.split()):
                matched_items.append(f"- **{name}**: {desc}")
        if matched_items:
            results.append(f"### Relevant {category.replace('_', ' ')}\n" + "\n".join(matched_items))
            
    if not results:
        # Return standard secure coding guidelines if no specific match
        return (
            "### Secure Coding Guidelines\n"
            "- Always validate and sanitize user input.\n"
            "- Use parameterized queries / prepared statements.\n"
            "- Never hardcode API keys, credentials, or secrets.\n"
            "- Implement proper Role-Based Access Control (RBAC).\n"
            "- Enable standard security headers and secure cookie flags."
        )
        
    return "\n\n".join(results[:3])
