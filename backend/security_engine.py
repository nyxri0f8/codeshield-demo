import os
import re
import google.generativeai as genai
from typing import List, Dict, Any, Tuple
from backend.rag_knowledge import search_knowledge_base

# SAST regex rules for different languages
SAST_RULES = [
    {
        "id": "CS-001",
        "name": "Hardcoded Secret / API Key Exposure",
        "category": "Data Security",
        "cwe": "CWE-798",
        "owasp": "A02:2021-Cryptographic Failures",
        "severity": "Critical",
        "pattern": r"(?i)(api_key|secret|password|passwd|private_key|token|auth_token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.\+\/]{16,}['\"]",
        "description": "Exposing secrets or API keys in source code allows unauthorized access if the repository is leaked or compromised.",
        "fix_guidance": "Move secrets to environment variables or use a secret management service like HashiCorp Vault or AWS Secrets Manager."
    },
    {
        "id": "CS-002",
        "name": "SQL Injection vulnerability",
        "category": "Injection Attacks",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "severity": "High",
        "pattern": r"(?i)(execute|query|select|insert|update|delete).*?[\+\%]\s*\w+|f['\"].*?\{.*?\}.*?(from|select|where)",
        "description": "Building SQL queries by concatenating raw user input allows attackers to manipulate the query logic and view or delete data.",
        "fix_guidance": "Use parameterized queries or prepared statements (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))."
    },
    {
        "id": "CS-003",
        "name": "Cross-Site Scripting (XSS) via innerHTML",
        "category": "Cross-Site Attacks",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "severity": "High",
        "pattern": r"\.innerHTML\s*=\s*.*?(req|query|input|param|window\.location)",
        "description": "Assigning unvalidated user input directly to innerHTML can lead to execution of arbitrary HTML/JS inside the user's browser.",
        "fix_guidance": "Use textContent or innerText, or use a proper sanitization library like DOMPurify."
    },
    {
        "id": "CS-004",
        "name": "Remote Code Execution (RCE) via eval() or Command Injection",
        "category": "Injection Attacks",
        "cwe": "CWE-94",
        "owasp": "A03:2021-Injection",
        "severity": "Critical",
        "pattern": r"\beval\(|exec\(|subprocess\.(Popen|run|call)\(.*shell\s*=\s*True",
        "description": "Using eval(), exec(), or running OS commands with shell=True on unvalidated user input enables arbitrary system command execution.",
        "fix_guidance": "Avoid eval() entirely. For commands, run subprocesses with arguments as a list and shell=False."
    },
    {
        "id": "CS-005",
        "name": "Weak Cryptographic Hashing",
        "category": "Data Security",
        "cwe": "CWE-328",
        "owasp": "A02:2021-Cryptographic Failures",
        "severity": "Medium",
        "pattern": r"hashlib\.md5\(|hashlib\.sha1\(|\bmd5\(|\bsha1\(",
        "description": "MD5 and SHA-1 hashing algorithms are cryptographically broken and vulnerable to collision attacks.",
        "fix_guidance": "Use stronger hashing algorithms like SHA-256 or password-specific algorithms like bcrypt/argon2."
    },
    {
        "id": "CS-006",
        "name": "Unsafe Deserialization",
        "category": "Software Integrity",
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "severity": "High",
        "pattern": r"pickle\.loads\(|pickle\.load\(|yaml\.load\(",
        "description": "Deserializing untrusted data with pickle or unsafe yaml loader can lead to arbitrary code execution.",
        "fix_guidance": "Use safe loaders like json.loads() or yaml.safe_load()."
    },
    {
        "id": "CS-007",
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "SSRF Attacks",
        "cwe": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "pattern": r"requests\.(get|post|request)\(\s*(url|req|target|param|input)",
        "description": "Fetching remote resources using user-supplied parameters without whitelist validation allows Server-Side Request Forgery.",
        "fix_guidance": "Use a strict whitelist of permitted domains, resolve hostnames, and block internal IP ranges."
    },
    {
        "id": "CS-008",
        "name": "Wildcard CORS Policy with Credentials Enabled",
        "category": "Infrastructure Security",
        "cwe": "CWE-942",
        "owasp": "A05:2021-Security Misconfiguration",
        "severity": "Medium",
        "pattern": r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|CORS\(.*origin.*\*.*credentials.*True",
        "description": "Configuring CORS with allow_origins=['*'] alongside credentials enabled allows third-party sites to read sensitive authenticated responses.",
        "fix_guidance": "Specify explicit authorized origin domains rather than wildcard mappings when credentials are enabled."
    }
]

def scan_file_content(file_path: str, content: str) -> List[Dict[str, Any]]:
    """
    Run static analysis rule-based checks on a file's content.
    """
    findings = []
    lines = content.split('\n')
    
    for rule in SAST_RULES:
        # Check rule against full content or line by line
        matches = re.finditer(rule["pattern"], content)
        for match in matches:
            # Find the line number of the match
            char_idx = match.start()
            line_no = content[:char_idx].count('\n') + 1
            
            # Extract surrounding context
            start_line = max(0, line_no - 3)
            end_line = min(len(lines), line_no + 3)
            context_lines = lines[start_line:end_line]
            
            # Add line numbers to code context
            code_snippet = ""
            for idx, ln in enumerate(context_lines):
                curr_line_no = start_line + idx + 1
                prefix = ">> " if curr_line_no == line_no else "   "
                code_snippet += f"{prefix}{curr_line_no} | {ln}\n"
                
            findings.append({
                "id": rule["id"],
                "name": rule["name"],
                "category": rule["category"],
                "cwe": rule["cwe"],
                "owasp": rule["owasp"],
                "severity": rule["severity"],
                "file": file_path,
                "line": line_no,
                "description": rule["description"],
                "code_snippet": code_snippet,
                "vulnerable_code": lines[line_no - 1].strip(),
                "fix_guidance": rule["fix_guidance"]
            })
            
    return findings

def get_gemini_analysis(api_key: str, findings: List[Dict[str, Any]], chat_history: List[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Enrich static findings or answer questions using Gemini AI with security knowledge context.
    """
    if not api_key:
        return {"error": "API Key missing"}
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash') # fallback or base model
        
        # Prepare context based on findings
        context = ""
        for idx, f in enumerate(findings[:3]): # limit to avoid token blowout
            rag_info = search_knowledge_base(f["name"])
            context += (
                f"Finding #{idx+1}:\n"
                f"Name: {f['name']}\n"
                f"File: {f['file']}:{f['line']}\n"
                f"Code: {f['vulnerable_code']}\n"
                f"RAG Guidelines:\n{rag_info}\n"
                "------\n"
            )
            
        prompt = (
            "You are CodeShield AI, a premier enterprise cybersecurity audit agent.\n"
            "Analyze these code findings and provide a comprehensive security response in JSON format.\n"
            "The JSON must have the following structure:\n"
            "{\n"
            "  'overall_score': integer (0-100),\n"
            "  'score_breakdown': {'code_security': int, 'authentication': int, 'api_security': int, 'infrastructure': int, 'compliance': int},\n"
            "  'findings_enrichment': [\n"
            "     {\n"
            "       'file': string,\n"
            "       'line': integer,\n"
            "       'explanation': 'beginner-friendly explanation of why it is dangerous and real-world impact',\n"
            "       'secure_fix': 'drop-in corrected code codeblock'\n"
            "     }\n"
            "  ],\n"
            "  'threat_modeling': {\n"
            "     'attack_surface': 'description of attack surface',\n"
            "     'potential_threats': ['threat 1', 'threat 2'],\n"
            "     'risk_matrix': 'low/medium/high risk rating',\n"
            "     'exploitation_scenarios': ['scenario 1'],\n"
            "     'mitigation_plan': 'mitigation steps'\n"
            "  },\n"
            "  'hardening_recommendations': ['recommendation 1', 'recommendation 2']\n"
            "}\n\n"
            f"Findings context:\n{context}\n"
            "Return ONLY a clean JSON object, no wrapping markdown formatting tags except standard json."
        )
        
        response = model.generate_content(prompt)
        text = response.text.strip()
        
        # Strip markdown tags if any
        if text.startswith("```json"):
            text = text[7:]
        if text.endswith("```"):
            text = text[:-3]
            
        import json
        return json.loads(text.strip())
    except Exception as e:
        return {"error": str(e)}

def ai_chat_mentor(api_key: str, message: str, chat_history: List[Dict[str, str]] = None) -> str:
    """
    RAG chat mentor that answers security questions.
    """
    rag_context = search_knowledge_base(message)
    
    if not api_key:
        return (
            "**[Offline Mode]** Me Antigravity chatbot. You no supply Gemini API Key. "
            "Me search stone-table library instead!\n\n"
            f"{rag_context}\n\n"
            "Add Gemini key in top bar to get smart AI answers!"
        )
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = (
            "You are CodeShield AI Security Mentor, an expert cybersecurity specialist.\n"
            "Help the developer understand how to write secure code.\n"
            "Use the following knowledge base context to enrich your answer if applicable.\n"
            f"Knowledge Base Context:\n{rag_context}\n\n"
            f"User message: {message}\n"
            "Answer clearly with explanations and secure code fixes."
        )
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error talking to Gemini Spirit: {str(e)}"
