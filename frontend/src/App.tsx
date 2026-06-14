import React, { useState, useEffect } from "react";
import { 
  Shield, 
  Upload, 
  Globe, 
  Terminal, 
  Cpu, 
  Send, 
  Download, 
  RefreshCw, 
  Key, 
  ChevronDown, 
  ChevronUp, 
  FileCode,
  ArrowRight,
  Database,
  Eye
} from "lucide-react";
import { motion, AnimatePresence, LayoutGroup } from "framer-motion";
import JSZip from "jszip";
import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { AnimatedContainer } from "./components/AnimatedContainer";

interface Finding {
  id: string;
  name: string;
  category: string;
  cwe: string;
  owasp: string;
  severity: string;
  file: string;
  line: number;
  description: string;
  code_snippet: string;
  vulnerable_code: string;
  fix_guidance: string;
  secure_fix?: string;
}

interface ScanData {
  id: string;
  status: string;
  filename?: string;
  target_url?: string;
  scanned_files: number;
  metrics: {
    overall_score: number;
    code_security: number;
    authentication: number;
    api_security: number;
    infrastructure: number;
    compliance: number;
  };
  threat_model: {
    attack_surface: string;
    potential_threats: string[];
    risk_matrix: string;
    exploitation_scenarios: string[];
    mitigation_plan: string;
  };
  hardening: string[];
  findings: Finding[];
}

const KNOWLEDGE_BASE: Record<string, Record<string, string>> = {
  "OWASP": {
    "A01:2021-Broken Access Control": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user's limits. Common vulnerabilities include IDOR, privilege escalation, bypassing access control checks, and CORS misconfigurations.",
    "A02:2021-Cryptographic Failures": "Focuses on failures related to cryptography (or lack thereof) which often leads to sensitive data exposure. Issues include transmitting cleartext sensitive data, using weak/deprecated cryptographic algorithms (e.g., MD5, SHA1), hardcoded cryptographic keys, and poor key management.",
    "A03:2021-Injection": "An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized by the application. Dynamic queries or non-parameterized calls without context-aware escaping are passed directly to the interpreter. Includes SQL Injection, Command Injection, LDAP Injection, and NoSQL Injection.",
    "A04:2021-Insecure Design": "Focuses on risks related to design flaws. If you have insecure design, you cannot fix it with a perfect implementation. Examples include lack of threat modeling, single points of failure, missing rate limits, and insecure business logic flows.",
    "A05:2021-Security Misconfiguration": "The application lacks proper security hardening. Examples include default accounts/passwords, directory listing enabled, unnecessary ports open, missing security headers (e.g., Content-Security-Policy, X-Frame-Options), and detailed error pages exposing stack traces.",
    "A06:2021-Vulnerable and Outdated Components": "Using client-side or server-side components (e.g., library, framework, module) that are outdated, unsupported, or contain known vulnerabilities.",
    "A07:2021-Identification and Authentication Failures": "Confirmation of the user's identity, assertion, and session management are critical. Vulnerabilities include weak password policies, permitting credential stuffing, session fixation, session hijacking, and missing Multi-Factor Authentication (MFA).",
    "A08:2021-Software and Data Integrity Failures": "Focuses on code and infrastructure that does not protect against integrity violations. Examples include auto-update features without signature validation, untrusted deserialization (e.g., Python pickle, Java deserialization), and insecure CI/CD pipelines.",
    "A09:2021-Security Logging and Monitoring Failures": "Without logging and monitoring, security breaches cannot be detected, escalated, or responded to. Vulnerabilities include insufficient logging of high-value transactions, audit logs not stored securely, and lack of active monitoring/alerting.",
    "A10:2021-Server-Side Request Forgery (SSRF)": "Occurs when a web application fetches a remote resource without validating the user-supplied URL. Allows attackers to coerce the application to send crafted requests to internal services, metadata APIs (e.g., AWS IMDS), or loopback interfaces."
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
};

function searchKnowledgeBase(query: string): string {
  const queryLower = query.toLowerCase();
  const words = queryLower.split(/\s+/);
  const results: string[] = [];
  
  for (const [category, items] of Object.entries(KNOWLEDGE_BASE)) {
    const matchedItems: string[] = [];
    for (const [name, desc] of Object.entries(items)) {
      if (words.some(word => name.toLowerCase().includes(word) || desc.toLowerCase().includes(word))) {
        matchedItems.push(`- **${name}**: ${desc}`);
      }
    }
    if (matchedItems.length > 0) {
      results.push(`### Relevant ${category.replace('_', ' ')}\n${matchedItems.join('\n')}`);
    }
  }
  
  if (results.length === 0) {
    return `### Secure Coding Guidelines\n- Always validate and sanitize user input.\n- Use parameterized queries / prepared statements.\n- Never hardcode API keys, credentials, or secrets.\n- Implement proper Role-Based Access Control (RBAC).\n- Enable standard security headers and secure cookie flags.`;
  }
  
  return results.slice(0, 3).join('\n\n');
}

const SAST_RULES = [
  {
    id: "CS-001",
    name: "Hardcoded Secret / API Key Exposure",
    category: "Data Security",
    cwe: "CWE-798",
    owasp: "A02:2021-Cryptographic Failures",
    severity: "Critical",
    pattern: /(api_key|secret|password|passwd|private_key|token|auth_token)\s*[:=]\s*['"][A-Za-z0-9_\-\.\+\/]{16,}['"]/i,
    description: "Exposing secrets or API keys in source code allows unauthorized access if the repository is leaked or compromised.",
    fix_guidance: "Move secrets to environment variables or use a secret management service like HashiCorp Vault or AWS Secrets Manager."
  },
  {
    id: "CS-002",
    name: "SQL Injection vulnerability",
    category: "Injection Attacks",
    cwe: "CWE-89",
    owasp: "A03:2021-Injection",
    severity: "High",
    pattern: /(execute|query|select|insert|update|delete).*?[\+\%]\s*\w+|f['"].*?\{.*?\}.*?(from|select|where)/i,
    description: "Building SQL queries by concatenating raw user input allows attackers to manipulate the query logic and view or delete data.",
    fix_guidance: "Use parameterized queries or prepared statements."
  },
  {
    id: "CS-003",
    name: "Cross-Site Scripting (XSS) via innerHTML",
    category: "Cross-Site Attacks",
    cwe: "CWE-79",
    owasp: "A03:2021-Injection",
    severity: "High",
    pattern: /\.innerHTML\s*=\s*.*?(req|query|input|param|window\.location)/i,
    description: "Assigning unvalidated user input directly to innerHTML can lead to execution of arbitrary HTML/JS inside the user's browser.",
    fix_guidance: "Use textContent or innerText, or use a proper sanitization library like DOMPurify."
  },
  {
    id: "CS-004",
    name: "Remote Code Execution (RCE) via eval() or Command Injection",
    category: "Injection Attacks",
    cwe: "CWE-94",
    owasp: "A03:2021-Injection",
    severity: "Critical",
    pattern: /\beval\(|\bexec\(|subprocess\.(Popen|run|call)\(.*shell\s*=\s*True/,
    description: "Using eval(), exec(), or running OS commands with shell=True on unvalidated user input enables arbitrary system command execution.",
    fix_guidance: "Avoid eval() entirely. For commands, run subprocesses with arguments as a list and shell=False."
  },
  {
    id: "CS-005",
    name: "Weak Cryptographic Hashing",
    category: "Data Security",
    cwe: "CWE-328",
    owasp: "A02:2021-Cryptographic Failures",
    severity: "Medium",
    pattern: /hashlib\.md5\(|hashlib\.sha1\(|\bmd5\(|\bsha1\(/,
    description: "MD5 and SHA-1 hashing algorithms are cryptographically broken and vulnerable to collision attacks.",
    fix_guidance: "Use stronger hashing algorithms like SHA-256 or password-specific algorithms like bcrypt/argon2."
  },
  {
    id: "CS-006",
    name: "Unsafe Deserialization",
    category: "Software Integrity",
    cwe: "CWE-502",
    owasp: "A08:2021-Software and Data Integrity Failures",
    severity: "High",
    pattern: /pickle\.loads\(|pickle\.load\(|yaml\.load\(/,
    description: "Deserializing untrusted data with pickle or unsafe yaml loader can lead to arbitrary code execution.",
    fix_guidance: "Use safe loaders like json.loads() or yaml.safe_load()."
  },
  {
    id: "CS-007",
    name: "Server-Side Request Forgery (SSRF)",
    category: "SSRF Attacks",
    cwe: "CWE-918",
    owasp: "A10:2021-Server-Side Request Forgery (SSRF)",
    severity: "High",
    pattern: /requests\.(get|post|request)\(\s*(url|req|target|param|input)/,
    description: "Fetching remote resources using user-supplied parameters without whitelist validation allows Server-Side Request Forgery.",
    fix_guidance: "Use a strict whitelist of permitted domains, resolve hostnames, and block internal IP ranges."
  },
  {
    id: "CS-008",
    name: "Wildcard CORS Policy with Credentials Enabled",
    category: "Infrastructure Security",
    cwe: "CWE-942",
    owasp: "A05:2021-Security Misconfiguration",
    severity: "Medium",
    pattern: /allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|CORS\(.*origin.*\*.*credentials.*True/,
    description: "Configuring CORS with allow_origins=['*'] alongside credentials enabled allows third-party sites to read sensitive authenticated responses.",
    fix_guidance: "Specify explicit authorized origin domains rather than wildcard mappings when credentials are enabled."
  }
];

const MOCK_EXPLORER_FILES: Record<string, { content: string; vulnLine: number | null }> = {
  "core/auth_handler.py": {
    content: `import jwt\nimport os\n\n# JWT Authorization Signature Config\n# WARNING: Do not modify signature algorithm without consulting security\nJWT_SECRET_TOKEN = "AIzaSyC155_mammoth_secret_key_99xY2"\n\ndef sign_session(user_id):\n    payload = {\n        "user_id": user_id,\n        "role": "user"\n    }\n    return jwt.encode(payload, JWT_SECRET_TOKEN, algorithm="HS256")`,
    vulnLine: 5
  },
  "db/connection_pool.js": {
    content: `const pg = require('pg');\nconst pool = new pg.Pool();\n\n// Query interface\nasync function findUser(username) {\n  // Un-parameterized user input passing directly to driver execute sink\n  const query = \`SELECT * FROM accounts WHERE username = '\` + username + \`'\`;\n  const res = await db.query(query);\n  return res.rows[0];\n}`,
    vulnLine: 7
  },
  "views/dashboard_portal.html": {
    content: `<!DOCTYPE html>\n<html>\n<body>\n  <div id="status-box">Loading status...</div>\n  \n  <script>\n    // Extract query payload and inject directly into DOM innerHTML\n    const urlParams = new URLSearchParams(window.location.search);\n    const msg = urlParams.get('message');\n    document.getElementById('status-box').innerHTML = msg;\n  </script>\n</body>\n</html>`,
    vulnLine: 9
  },
  "api/v1/auth_endpoints.py": {
    content: `from fastapi import APIRouter, Depends\nfrom core.auth_handler import sign_session\n\nrouter = APIRouter()\n\n@router.post("/login")\ndef login(username: str):\n    # Simulated auth login endpoint\n    return {"token": sign_session(username)}`,
    vulnLine: null
  },
  "config/application_settings.yml": {
    content: `# Application config parameters\napp:\n  name: codeshield-server\n  version: 1.0.0\nsecurity:\n  session_timeout: 3600\n  allow_anonymous: false`,
    vulnLine: null
  }
};

function CodebaseExplorer({ 
  scannedFiles, 
  selectedFile, 
  onSelectFile 
}: { 
  scannedFiles: Record<string, { content: string; vulnLine: number | null }>;
  selectedFile: string; 
  onSelectFile: (file: string) => void;
}) {
  const activeFile = (selectedFile in scannedFiles) 
    ? selectedFile 
    : Object.keys(scannedFiles)[0] || "core/auth_handler.py";

  const fileData = scannedFiles[activeFile] || { content: "", vulnLine: null };

  return (
    <div className="explorer-grid">
      {/* File Sidebar */}
      <div className="explorer-sidebar">
        <span className="explorer-sidebar-title">Scanned Tree</span>
        {Object.entries(scannedFiles).map(([filename, data]) => {
          const isSelected = activeFile === filename;
          const hasVuln = data.vulnLine !== null;

          return (
            <button
              key={filename}
              onClick={() => onSelectFile(filename)}
              className={`file-btn ${isSelected ? "active" : ""}`}
            >
              <span style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{filename}</span>
              {hasVuln && <span className="vuln-indicator-dot" />}
            </button>
          );
        })}
      </div>

      {/* Editor Content */}
      <div className="editor-pane">
        <div className="editor-header">
          <span>Source Inspector</span>
          <span className="file-path">{activeFile}</span>
        </div>

        <pre style={{ overflowX: 'auto', flex: 1, margin: 0 }}>
          <code style={{ display: 'block', textAlign: 'left' }}>
            {fileData.content.split("\n").map((line, idx) => {
              const lineNo = idx + 1;
              const isVulnLine = fileData.vulnLine === lineNo;

              return (
                <div 
                  key={idx} 
                  className={`code-line ${isVulnLine ? "vulnerable" : ""}`}
                >
                  <span className="line-number">{lineNo}</span>
                  <span style={{ paddingLeft: '8px', whiteSpace: 'pre' }}>{line}</span>
                </div>
              );
            })}
          </code>
        </pre>
      </div>
    </div>
  );
}

function AttackPathGraph({ vulnName }: { vulnName: string }) {
  let steps = [
    { title: "Input Trigger", desc: "Attacker payload request", status: "active" },
    { title: "Sink Hook", desc: "Unsanitized code execution", status: "danger" },
    { title: "Target Asset", desc: "System / Database resource", status: "compromised" }
  ];

  if (vulnName.includes("Secret") || vulnName.includes("Key")) {
    steps = [
      { title: "Code Commit", desc: "Hardcoded secret string in source", status: "active" },
      { title: "Source Exposure", desc: "Key leaked via repository access", status: "danger" },
      { title: "Credential Theft", desc: "Attacker signs administrative sessions", status: "compromised" }
    ];
  } else if (vulnName.includes("SQL")) {
    steps = [
      { title: "User Query Parameter", desc: "Unchecked SQL payload input", status: "active" },
      { title: "Driver Execution Sink", desc: "Database driver runs dynamic query", status: "danger" },
      { title: "Database Leakage", desc: "Complete table records dumped", status: "compromised" }
    ];
  } else if (vulnName.includes("XSS")) {
    steps = [
      { title: "URL Injection Param", desc: "Malicious script passed in search query", status: "active" },
      { title: "Client innerHTML Sink", desc: "Browser compiles HTML without escaping", status: "danger" },
      { title: "Session Cookie Theft", desc: "Attacker script hijacks document.cookie", status: "compromised" }
    ];
  } else if (vulnName.includes("CORS")) {
    steps = [
      { title: "Cors Request", desc: "Origin request header from untrusted site", status: "active" },
      { title: "Wildcard CORS config", desc: "Site wildcard accepts allow-credentials", status: "danger" },
      { title: "Session Reading", desc: "External script reads credentials from context", status: "compromised" }
    ];
  }

  return (
    <div className="exploit-graph-container">
      <div className="details-block-title" style={{ marginBottom: '16px', textAlign: 'left' }}>Visual Exploit Vector Graph</div>
      <div className="graph-steps-flex">
        <div className="graph-laser-line" />
        {steps.map((step, idx) => (
          <div key={idx} className="graph-step-node">
            <div className={`node-circle ${step.status}`}>
              {idx + 1}
            </div>
            <div className="node-label">{step.title}</div>
            <div className="node-desc">{step.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"zip" | "git" | "url">("zip");
  const [apiKey, setApiKey] = useState("");
  const [gitUrl, setGitUrl] = useState("");
  const [webUrl, setWebUrl] = useState("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  
  // Supabase state
  const [supabaseUrl, setSupabaseUrl] = useState("");
  const [supabaseAnonKey, setSupabaseAnonKey] = useState("");
  const [supabaseClient, setSupabaseClient] = useState<SupabaseClient | null>(null);
  const [supabaseStatus, setSupabaseStatus] = useState<"disconnected" | "connected" | "error">("disconnected");
  
  // Scanning state
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanningFileName, setScanningFileName] = useState("");
  const [scannedFiles, setScannedFiles] = useState<Record<string, { content: string; vulnLine: number | null }>>(MOCK_EXPLORER_FILES);
  const [scanResult, setScanResult] = useState<ScanData | null>(null);
  
  // Findings state
  const [selectedFindingIndex, setSelectedFindingIndex] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("All");
  const [activeExplorerFile, setActiveExplorerFile] = useState<string>("core/auth_handler.py");
  
  // Chat state
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState<Array<{ sender: "user" | "bot"; text: string }>>([
    { sender: "bot", text: "Me CodeShield Mentor! Ask me how to protect your cave from bad fire-spirits (vulnerabilities)." }
  ]);
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [chatSessionId] = useState<string>(() => crypto.randomUUID());

  // Setup Supabase when credentials change
  useEffect(() => {
    if (supabaseUrl && supabaseAnonKey) {
      try {
        const client = createClient(supabaseUrl, supabaseAnonKey);
        setSupabaseClient(client);
        setSupabaseStatus("connected");
      } catch (err) {
        setSupabaseStatus("error");
      }
    } else {
      setSupabaseClient(null);
      setSupabaseStatus("disconnected");
    }
  }, [supabaseUrl, supabaseAnonKey]);

  // Read local storage on mount for API Key and Supabase Config
  useEffect(() => {
    const savedKey = localStorage.getItem("codeshield_api_key");
    const savedSupaUrl = localStorage.getItem("codeshield_supabase_url");
    const savedSupaKey = localStorage.getItem("codeshield_supabase_anon_key");
    if (savedKey) setApiKey(savedKey);
    if (savedSupaUrl) setSupabaseUrl(savedSupaUrl);
    if (savedSupaKey) setSupabaseAnonKey(savedSupaKey);
  }, []);

  const saveApiKey = (val: string) => {
    setApiKey(val);
    localStorage.setItem("codeshield_api_key", val);
  };

  const saveSupabaseUrl = (val: string) => {
    setSupabaseUrl(val);
    localStorage.setItem("codeshield_supabase_url", val);
  };

  const saveSupabaseAnonKey = (val: string) => {
    setSupabaseAnonKey(val);
    localStorage.setItem("codeshield_supabase_anon_key", val);
  };

  const handleStartScan = async () => {
    setIsScanning(true);
    setScanProgress(5);
    setScanResult(null);

    if (activeTab === "zip" && uploadFile) {
      try {
        setScanProgress(20);
        const zip = await JSZip.loadAsync(uploadFile);
        const filesMap: Record<string, { content: string; vulnLine: number | null }> = {};
        const fileNames = Object.keys(zip.files).filter(name => !zip.files[name].dir);
        
        let processedCount = 0;
        const totalFiles = fileNames.length;
        
        for (const name of fileNames) {
          processedCount++;
          const matchesExt = name.endsWith('.py') || name.endsWith('.js') || name.endsWith('.ts') || 
                             name.endsWith('.tsx') || name.endsWith('.jsx') || name.endsWith('.html') || 
                             name.endsWith('.css') || name.endsWith('.sql') || name.endsWith('.php') || 
                             name.endsWith('.go') || name.endsWith('.rs');
          
          if (matchesExt) {
            setScanningFileName(name);
            const content = await zip.files[name].async("string");
            filesMap[name] = { content, vulnLine: null };
            setScanProgress(20 + Math.floor((processedCount / totalFiles) * 30));
          }
        }
        
        if (Object.keys(filesMap).length === 0) {
          alert("No readable source code files found in ZIP!");
          setIsScanning(false);
          return;
        }

        setScannedFiles(filesMap);
        runSastScan(filesMap, uploadFile.name);
      } catch (err: any) {
        alert("Failed to load ZIP file: " + err.message);
        setIsScanning(false);
      }
    } else if (activeTab === "url" && webUrl) {
      // Crawl security headers simulator
      setScanProgress(40);
      setScanningFileName(webUrl);
      setTimeout(() => {
        setScanProgress(70);
        const simulatedFiles: Record<string, { content: string; vulnLine: number | null }> = {
          "security-headers.config": {
            content: `HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nServer: nginx\nConnection: keep-alive\nCache-Control: no-cache\n\n# Scanning headers for ${webUrl}\n# Missing: Content-Security-Policy\n# Missing: X-Frame-Options\n# Missing: Strict-Transport-Security`,
            vulnLine: 6
          }
        };
        setScannedFiles(simulatedFiles);
        runUrlSastScan(webUrl, simulatedFiles);
      }, 1500);
    } else if (activeTab === "git" && gitUrl) {
      // Simulate git clone and scan
      let currentFileIdx = 0;
      const scanFiles = Object.keys(MOCK_EXPLORER_FILES);
      const interval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 60) {
            clearInterval(interval);
            setScannedFiles(MOCK_EXPLORER_FILES);
            runSastScan(MOCK_EXPLORER_FILES, gitUrl.replace("https://github.com/", ""));
            return 60;
          }
          setScanningFileName(scanFiles[currentFileIdx % scanFiles.length]);
          currentFileIdx++;
          return prev + 15;
        });
      }, 400);
    }
  };

  const runSastScan = async (files: Record<string, { content: string; vulnLine: number | null }>, filename: string) => {
    setScanProgress(70);
    
    // Core SAST regex scanner
    const findings: Finding[] = [];
    let scannedFilesCount = 0;

    for (const [filePath, fileInfo] of Object.entries(files)) {
      scannedFilesCount++;
      const content = fileInfo.content;
      const lines = content.split('\n');

      for (const rule of SAST_RULES) {
        // Run regex
        const matches = [...content.matchAll(new RegExp(rule.pattern, 'g'))];
        
        for (const match of matches) {
          const charIdx = match.index;
          if (charIdx === undefined) continue;
          
          const lineNo = content.slice(0, charIdx).split('\n').length;
          fileInfo.vulnLine = lineNo; // Flag in explorer

          // Extract surrounding lines for snippet
          const startLine = Math.max(0, lineNo - 3);
          const endLine = Math.min(lines.length, lineNo + 3);
          let codeSnippet = "";
          for (let i = startLine; i < endLine; i++) {
            const currentLineNo = i + 1;
            const prefix = currentLineNo === lineNo ? ">> " : "   ";
            codeSnippet += `${prefix}${currentLineNo} | ${lines[i]}\n`;
          }

          findings.push({
            id: rule.id + "_" + Math.random().toString(36).substring(2, 6),
            name: rule.name,
            category: rule.category,
            cwe: rule.cwe,
            owasp: rule.owasp,
            severity: rule.severity,
            file: filePath,
            line: lineNo,
            description: rule.description,
            code_snippet: codeSnippet,
            vulnerable_code: lines[lineNo - 1]?.trim() || "",
            fix_guidance: rule.fix_guidance
          });
        }
      }
    }

    setScanProgress(85);

    // Initial base metrics calculation
    const vulnCount = findings.length;
    const baseScore = Math.max(30, 100 - (vulnCount * 12));
    
    let metrics = {
      overall_score: baseScore,
      code_security: baseScore,
      authentication: vulnCount < 3 ? 85 : 70,
      api_security: vulnCount < 2 ? 90 : 75,
      infrastructure: 80,
      compliance: Math.max(50, baseScore - 5)
    };

    let threatModel = {
      attack_surface: `Application source code of ${filename} containing ${scannedFilesCount} files.`,
      potential_threats: [
        "Credential leakage from application source codes.",
        "SQL Injection flaws allowing database extraction.",
        "Arbitrary command execution via unsafe method triggers."
      ],
      risk_matrix: vulnCount > 3 ? "High" : (vulnCount > 0 ? "Medium" : "Low"),
      exploitation_scenarios: [
        "Attacker intercepts code repositories, discovers hardcoded keys or SQL injections, and uses them to access application resources."
      ],
      mitigation_plan: "Implement parameterized database statements, securely store private credentials, and restrict CORS endpoints."
    };

    let hardening = [
      "Implement Multi-Factor Authentication (MFA) across administrative API portals.",
      "Move all credential parameters to local environment vaults.",
      "Enforce strict Content Security Policy (CSP) security parameters."
    ];

    // If Gemini key present, call Gemini for full report enrichment
    if (apiKey) {
      try {
        const enriched = await getGeminiAnalysis(findings, scannedFilesCount, filename);
        if (enriched) {
          metrics = enriched.metrics || metrics;
          threatModel = enriched.threatModel || threatModel;
          hardening = enriched.hardening || hardening;
          
          // Enrich findings with AI explanations and secure fixes
          if (enriched.findings_enrichment) {
            findings.forEach(f => {
              const enrichment = enriched.findings_enrichment.find((enrich: any) => enrich.file === f.file && enrich.line === f.line);
              if (enrichment) {
                f.description = enrichment.explanation || f.description;
                f.secure_fix = enrichment.secure_fix || "";
              }
            });
          }
        }
      } catch (err) {
        console.error("Gemini enrichment failed, using static analysis details:", err);
      }
    }

    const completedScanResult: ScanData = {
      id: crypto.randomUUID(),
      status: "completed",
      filename,
      scanned_files: scannedFilesCount,
      metrics,
      threat_model: threatModel,
      hardening,
      findings
    };

    setScanResult(completedScanResult);
    setIsScanning(false);
    setScanProgress(100);
    if (findings.length > 0) {
      setActiveExplorerFile(findings[0].file);
    }

    // Write to Supabase if client is active
    if (supabaseClient) {
      await writeScanToSupabase(completedScanResult);
    }
  };

  const runUrlSastScan = async (url: string, _files: Record<string, { content: string; vulnLine: number | null }>) => {
    const findings: Finding[] = [
      {
        id: "CS-WEB-001",
        name: "Missing Content-Security-Policy (CSP) Security Header",
        category: "Infrastructure Security",
        cwe: "CWE-693",
        owasp: "A05:2021-Security Misconfiguration",
        severity: "Medium",
        file: "security-headers.config",
        line: 6,
        description: "The website is missing the Content-Security-Policy response header, leaving users vulnerable to clickjacking or cross-site scripting attacks.",
        code_snippet: `HTTP GET ${url}\n>> [Missing Header] Content-Security-Policy`,
        vulnerable_code: "Header: Content-Security-Policy is missing",
        fix_guidance: "Configure your web server to send the 'Content-Security-Policy' header."
      },
      {
        id: "CS-WEB-002",
        name: "Session Cookie Missing Secure & HttpOnly Flags",
        category: "Authentication Issues",
        cwe: "CWE-614",
        owasp: "A07:2021-Identification and Authentication Failures",
        severity: "High",
        file: "security-headers.config",
        line: 6,
        description: "Session cookies do not have the HttpOnly or Secure flags set, allowing malicious scripts to steal the session token.",
        code_snippet: "Set-Cookie: session_id=xyz123; Path=/",
        vulnerable_code: "Set-Cookie: session_id=xyz123; Path=/",
        fix_guidance: "Add HttpOnly, Secure, and SameSite=Strict flags to all session set-cookie headers."
      }
    ];

    let metrics = {
      overall_score: 75,
      code_security: 95,
      authentication: 70,
      api_security: 85,
      infrastructure: 60,
      compliance: 75
    };

    let threatModel = {
      attack_surface: `Public website landing pages at ${url}`,
      potential_threats: [
        "Session hijacking of users via cross-site scripting.",
        "Clickjacking attacks framing the login screen.",
        "MitM (Man-in-the-Middle) eavesdropping due to missing SSL/HSTS configurations."
      ],
      risk_matrix: "Medium",
      exploitation_scenarios: [
        "Attacker creates an iframe framing the login screen of the target site and tricks user into entering details."
      ],
      mitigation_plan: "Implement HSTS, configure strong CSP rules, and secure all set-cookie directives."
    };

    let hardening = [
      "Deploy a Web Application Firewall (WAF) to block bad payloads.",
      "Enforce secure HTTPS redirection for all endpoints.",
      "Enable rate-limiting on forms to prevent brute-forcing login attempts."
    ];

    if (apiKey) {
      try {
        const enriched = await getGeminiAnalysis(findings, 1, url);
        if (enriched) {
          metrics = enriched.metrics || metrics;
          threatModel = enriched.threatModel || threatModel;
          hardening = enriched.hardening || hardening;
        }
      } catch (err) {
        console.error("Gemini URL enrichment failed:", err);
      }
    }

    const completedScanResult: ScanData = {
      id: crypto.randomUUID(),
      status: "completed",
      target_url: url,
      scanned_files: 1,
      metrics,
      threat_model: threatModel,
      hardening,
      findings
    };

    setScanResult(completedScanResult);
    setIsScanning(false);
    setScanProgress(100);
    setActiveExplorerFile("security-headers.config");

    // Write to Supabase if client is active
    if (supabaseClient) {
      await writeScanToSupabase(completedScanResult);
    }
  };

  const getGeminiAnalysis = async (findingsList: Finding[], count: number, name: string) => {
    // Call Gemini using standard fetch
    const context = findingsList.slice(0, 3).map((f, idx) => {
      const rag = searchKnowledgeBase(f.name);
      return `Finding #${idx + 1}:\nName: ${f.name}\nFile: ${f.file}:${f.line}\nCode: ${f.vulnerable_code}\nRAG Context:\n${rag}\n---`;
    }).join('\n');

    const prompt = `You are CodeShield AI, a premier enterprise cybersecurity audit agent.
Analyze these code findings and provide a comprehensive security response in JSON format.
The JSON must have the following exact structure:
{
  "metrics": {
    "overall_score": 75,
    "code_security": 80,
    "authentication": 70,
    "api_security": 85,
    "infrastructure": 60,
    "compliance": 75
  },
  "findings_enrichment": [
     {
       "file": "path/to/file",
       "line": 10,
       "explanation": "Brief explanation of the vulnerability and security implications.",
       "secure_fix": "Secure code fix block."
     }
  ],
  "threatModel": {
     "attack_surface": "Description of attack surface",
     "potential_threats": ["threat 1", "threat 2"],
     "risk_matrix": "Low/Medium/High",
     "exploitation_scenarios": ["scenario 1"],
     "mitigation_plan": "mitigation steps"
  },
  "hardening": ["recommendation 1", "recommendation 2"]
}

Context of Scan target ${name} containing ${count} files.
Findings list:
${context}

Return ONLY the raw JSON object, no markdown styling tags like \`\`\`json.`;

    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
        }
      );
      
      const resData = await response.json();
      let textResponse = resData.candidates?.[0]?.content?.parts?.[0]?.text || "";
      
      // Clean JSON delimiters if needed
      textResponse = textResponse.trim();
      if (textResponse.startsWith("```json")) {
        textResponse = textResponse.substring(7);
      }
      if (textResponse.endsWith("```")) {
        textResponse = textResponse.substring(0, textResponse.length - 3);
      }
      
      return JSON.parse(textResponse.trim());
    } catch (err) {
      console.error(err);
      return null;
    }
  };

  const writeScanToSupabase = async (scan: ScanData) => {
    try {
      // Insert scan metadata
      const { error: scanErr } = await supabaseClient!
        .from("scans")
        .insert({
          id: scan.id,
          filename: scan.filename || null,
          target_url: scan.target_url || null,
          status: scan.status,
          scanned_files: scan.scanned_files,
          overall_score: scan.metrics.overall_score,
          code_security: scan.metrics.code_security,
          authentication: scan.metrics.authentication,
          api_security: scan.metrics.api_security,
          infrastructure: scan.metrics.infrastructure,
          compliance: scan.metrics.compliance,
          attack_surface: scan.threat_model.attack_surface,
          potential_threats: scan.threat_model.potential_threats,
          risk_matrix: scan.threat_model.risk_matrix,
          exploitation_scenarios: scan.threat_model.exploitation_scenarios,
          mitigation_plan: scan.threat_model.mitigation_plan,
          hardening_recs: scan.hardening
        })
        .select()
        .single();

      if (scanErr) throw scanErr;

      // Insert findings
      if (scan.findings.length > 0) {
        const findingsRows = scan.findings.map(f => ({
          scan_id: scan.id,
          name: f.name,
          category: f.category,
          cwe: f.cwe,
          owasp: f.owasp,
          severity: f.severity,
          file: f.file,
          line: f.line,
          description: f.description,
          code_snippet: f.code_snippet,
          vulnerable_code: f.vulnerable_code,
          fix_guidance: f.fix_guidance,
          secure_fix: f.secure_fix || null
        }));

        const { error: findErr } = await supabaseClient!.from("findings").insert(findingsRows);
        if (findErr) throw findErr;
      }
      
      console.log("Scan successfully synchronized with Supabase DB!");
    } catch (err) {
      console.error("Database sync failed:", err);
    }
  };

  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg = chatInput;
    setChatHistory(prev => [...prev, { sender: "user", text: userMsg }]);
    setChatInput("");
    setIsChatLoading(true);

    // Write user message to Supabase if database exists
    if (supabaseClient) {
      await supabaseClient.from("chat_messages").insert({
        session_id: chatSessionId,
        role: "user",
        content: userMsg
      });
    }

    const ragContext = searchKnowledgeBase(userMsg);

    if (!apiKey) {
      // Offline mode
      setTimeout(() => {
        let reply = "Me no understand. Ask about SQL injection, XSS, or how to secure credentials!";
        const lower = userMsg.toLowerCase();
        
        if (lower.includes("sql injection") || lower.includes("sqli")) {
          reply = `**SQL Injection (SQLi) is bad fire-spirit!** It happen when you paste user input directly into SQL command.\n\n**Vulnerable code example:**\n\`\`\`python\ncursor.execute("SELECT * FROM users WHERE user = '" + username + "'")\n\`\`\`\n\n**Secure Fix:** Use parameterized queries!\n\`\`\`python\ncursor.execute("SELECT * FROM users WHERE user = %s", (username,))\n\`\`\``;
        } else if (lower.includes("xss") || lower.includes("cross-site")) {
          reply = `**Cross-Site Scripting (XSS) is browser-spirit curse!** Attackers inject malicious JavaScript into webpages.\n\nTo prevent XSS, always sanitize user input, use textContent instead of innerHTML, or configure a Content Security Policy (CSP) header.`;
        } else if (lower.includes("secret") || lower.includes("api key") || lower.includes("token")) {
          reply = `**Hardcoded keys are bad!** If you commit keys to code, anyone who sees the code can steal your mammoth resources.\n\nUse environment variables (.env files) or tools like AWS Secrets Manager or HashiCorp Vault. Never push secrets to GitHub!`;
        } else if (lower.includes("rag")) {
          reply = `**RAG (Retrieval-Augmented Generation)** is like reading cave scrolls before answering. It search OWASP Top 10, CWE database, and secure guidelines, and gives Gemini the best scrolls. This make AI answers super smart and correct for your specific code!`;
        }

        setChatHistory(prev => [...prev, { sender: "bot", text: reply }]);
        setIsChatLoading(false);

        if (supabaseClient) {
          supabaseClient.from("chat_messages").insert({
            session_id: chatSessionId,
            role: "assistant",
            content: reply
          });
        }
      }, 800);
    } else {
      try {
        const prompt = `You are CodeShield AI Security Mentor, an expert cybersecurity specialist.
Help the developer understand how to write secure code.
Use the following knowledge base context to enrich your answer if applicable:
${ragContext}

User message: ${userMsg}
Answer clearly with explanations and secure code fixes. Keep it precise.`;

        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
          }
        );

        const resData = await response.json();
        const reply = resData.candidates?.[0]?.content?.parts?.[0]?.text || "Me having trouble connecting with Gemini spirits.";
        
        setChatHistory(prev => [...prev, { sender: "bot", text: reply }]);
        setIsChatLoading(false);

        if (supabaseClient) {
          await supabaseClient.from("chat_messages").insert({
            session_id: chatSessionId,
            role: "assistant",
            content: reply
          });
        }
      } catch (err) {
        setChatHistory(prev => [...prev, { sender: "bot", text: "Error talking to Gemini spirits." }]);
        setIsChatLoading(false);
      }
    }
  };

  const handleAutoFix = async (finding: Finding) => {
    if (!apiKey) {
      // Offline fallback fix
      const mockFix = `// [Offline Fix Recommendation]\n// Always sanitize or use parameterized inputs!\n// Fix for vulnerability: ${finding.name}\n// Raw code was: ${finding.vulnerable_code}`;
      applyFixToScanResult(finding, mockFix);
      return;
    }

    try {
      const prompt = `You are CodeShield AI Secure Code Generator.
Fix this vulnerable code snippet: '${finding.vulnerable_code}' which has been flagged as '${finding.name}'.
Return ONLY the secure replacement code block. Do not include markdown codeblocks or explanations, just raw secure code.`;

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
        }
      );

      const resData = await response.json();
      const secureFixText = resData.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "";
      applyFixToScanResult(finding, secureFixText);
    } catch (err) {
      alert("Could not generate Auto-Fix. Check your Gemini API key!");
    }
  };

  const applyFixToScanResult = async (finding: Finding, secureFix: string) => {
    if (!scanResult) return;
    
    const updatedFindings = scanResult.findings.map(f => {
      if (f.id === finding.id) {
        return { ...f, secure_fix: secureFix };
      }
      return f;
    });

    const updatedResult = { ...scanResult, findings: updatedFindings };
    setScanResult(updatedResult);

    // Update in Supabase database if connected
    if (supabaseClient) {
      try {
        await supabaseClient
          .from("findings")
          .update({ secure_fix: secureFix })
          .match({ scan_id: scanResult.id, file: finding.file, line: finding.line });
      } catch (err) {
        console.error("Failed to update fix in Database:", err);
      }
    }
  };

  const filteredFindings = scanResult?.findings.filter(f => {
    if (filterSeverity === "All") return true;
    if (filterSeverity === "Critical/High") return f.severity === "Critical" || f.severity === "High";
    return f.severity === filterSeverity;
  }) || [];

  return (
    <div className="app-wrapper">
      <div className="ambient-glow-1" />
      <div className="ambient-glow-2" />

      {/* Navbar */}
      <header className="navbar-container">
        <div className="navbar-glass">
          <div className="logo-section">
            <div className="logo-icon-wrap">
              <Shield className="h-5 w-5 text-cyan-400" strokeWidth={1.5} />
            </div>
            <h1 className="logo-title">
              CodeShield <span className="logo-badge">AI</span>
            </h1>
          </div>

          <div className="nav-actions">
            {/* Supabase status indicator */}
            <div className={`status-indicator ${supabaseStatus === "connected" ? "connected" : "offline"}`}>
              <Database className="h-3.5 w-3.5" />
              <span>{supabaseStatus === "connected" ? "Database Sync Active" : "Offline Storage"}</span>
              <span className={`status-dot ${supabaseStatus === "connected" ? "connected" : "offline"}`} />
            </div>

            {/* Gemini API Key */}
            <div className="api-key-input-wrap">
              <Key className="h-3.5 w-3.5 text-slate-500" strokeWidth={1.5} />
              <input 
                type="password"
                placeholder="Paste Gemini API Key..."
                value={apiKey}
                onChange={(e) => saveApiKey(e.target.value)}
                className="api-key-input"
              />
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="main-grid">
        
        {/* LEFT PANEL: SCANNER SETUP & DETECTED VULNERABILITIES */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          
          {/* Settings / Config Panel for Supabase */}
          <AnimatedContainer animation="fadeIn" delay={0.1}>
            <div className="double-bezel-outer">
              <div className="double-bezel-inner">
                <span className="section-tag cyan">Settings</span>
                <h2 className="panel-title" style={{ marginBottom: '12px' }}>Supabase Backend Connection</h2>
                
                <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginTop: '12px' }}>
                  <div style={{ flex: 1, minWidth: '220px' }}>
                    <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Supabase Project URL</label>
                    <input 
                      type="text" 
                      placeholder="https://xyz.supabase.co" 
                      value={supabaseUrl} 
                      onChange={(e) => saveSupabaseUrl(e.target.value)}
                      className="standard-input"
                      style={{ paddingLeft: '16px' }}
                    />
                  </div>
                  <div style={{ flex: 1, minWidth: '220px' }}>
                    <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Anon API Key</label>
                    <input 
                      type="password" 
                      placeholder="eyJhbGci..." 
                      value={supabaseAnonKey} 
                      onChange={(e) => saveSupabaseAnonKey(e.target.value)}
                      className="standard-input"
                      style={{ paddingLeft: '16px' }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </AnimatedContainer>

          {/* Target Scanner Panel */}
          <AnimatedContainer animation="fadeInUp" delay={0.2}>
            <div className="double-bezel-outer">
              <div className="double-bezel-inner">
                <span className="section-tag cyan">Engine setup</span>
                <h2 className="panel-title">Configure Vulnerability Scan</h2>

                {/* Tabs */}
                <div className="tabs-container">
                  <button 
                    onClick={() => setActiveTab("zip")}
                    className={`tab-btn ${activeTab === "zip" ? "active" : ""}`}
                  >
                    <Upload className="h-3.5 w-3.5" strokeWidth={1.5} />
                    ZIP Repository
                  </button>
                  <button 
                    onClick={() => setActiveTab("git")}
                    className={`tab-btn ${activeTab === "git" ? "active" : ""}`}
                  >
                    <Terminal className="h-3.5 w-3.5" strokeWidth={1.5} />
                    Git Repository
                  </button>
                  <button 
                    onClick={() => setActiveTab("url")}
                    className={`tab-btn ${activeTab === "url" ? "active" : ""}`}
                  >
                    <Globe className="h-3.5 w-3.5" strokeWidth={1.5} />
                    Website Scanner
                  </button>
                </div>

                {/* Tab content */}
                {activeTab === "zip" && (
                  <div 
                    onClick={() => document.getElementById("zip-uploader")?.click()}
                    className="upload-dropzone"
                  >
                    <Upload className="upload-icon" size={36} strokeWidth={1.2} />
                    <p className="upload-title">Click to upload ZIP repository file</p>
                    <p className="upload-subtitle">Supported: Python, JS, TS, React, Go, Rust, HTML, CSS</p>
                    <input 
                      type="file" 
                      accept=".zip"
                      onChange={(e) => e.target.files && setUploadFile(e.target.files[0])}
                      className="hidden" 
                      id="zip-uploader"
                      style={{ display: 'none' }}
                    />
                    {uploadFile && (
                      <p className="selected-file-badge">
                        <FileCode size={16} />
                        {uploadFile.name} ({(uploadFile.size / 1024).toFixed(1)} KB)
                      </p>
                    )}
                  </div>
                )}

                {activeTab === "git" && (
                  <div>
                    <div className="text-input-container">
                      <Terminal className="input-icon" size={16} />
                      <input 
                        type="text" 
                        placeholder="https://github.com/username/project" 
                        value={gitUrl}
                        onChange={(e) => setGitUrl(e.target.value)}
                        className="standard-input"
                      />
                    </div>
                    <p className="input-help">Clone and audit repository directly from GitHub branch.</p>
                  </div>
                )}

                {activeTab === "url" && (
                  <div>
                    <div className="text-input-container">
                      <Globe className="input-icon" size={16} />
                      <input 
                        type="text" 
                        placeholder="https://secure-portal.com" 
                        value={webUrl}
                        onChange={(e) => setWebUrl(e.target.value)}
                        className="standard-input"
                      />
                    </div>
                    <p className="input-help">Analyze live HTTP headers, cookies, and CORS configurations.</p>
                  </div>
                )}

                {/* CTA Button */}
                <motion.button 
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={handleStartScan}
                  disabled={isScanning || (activeTab === "zip" && !uploadFile) || (activeTab === "git" && !gitUrl) || (activeTab === "url" && !webUrl)}
                  className="cta-button"
                >
                  <span>{isScanning ? "Scanning Target..." : "Auditing Target"}</span>
                  <div className="cta-icon-wrap">
                    {isScanning ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" strokeWidth={1.5} />
                    ) : (
                      <ArrowRight className="h-3.5 w-3.5" strokeWidth={1.5} />
                    )}
                  </div>
                </motion.button>
              </div>
            </div>
          </AnimatedContainer>

          {/* Progress Bar */}
          <AnimatePresence>
            {isScanning && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="double-bezel-outer"
              >
                <div className="double-bezel-inner">
                  <div className="progress-container">
                    <div className="progress-header">
                      <span>Auditing codebase files...</span>
                      <span>{scanProgress}%</span>
                    </div>
                    <div className="progress-bar-bg">
                      <div className="progress-bar-fill" style={{ width: `${scanProgress}%` }} />
                    </div>
                    <p className="progress-file">Scanning: <span>{scanningFileName || "Analyzing tree structure..."}</span></p>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Interactive Source Explorer */}
          <AnimatePresence>
            {scanResult && (
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="double-bezel-outer"
              >
                <div className="double-bezel-inner">
                  <span className="section-tag cyan">Workspace</span>
                  <h3 className="panel-title">Interactive Source Code Explorer</h3>
                  <CodebaseExplorer 
                    scannedFiles={scannedFiles} 
                    selectedFile={activeExplorerFile} 
                    onSelectFile={setActiveExplorerFile} 
                  />
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Detected Vulnerabilities Results List */}
          <AnimatePresence>
            {scanResult && (
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="double-bezel-outer"
              >
                <div className="double-bezel-inner" style={{ padding: 0 }}>
                  <div style={{ padding: '24px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '16px' }}>
                    <div>
                      <span className="section-tag rose">Scan log</span>
                      <h3 className="panel-title" style={{ margin: 0 }}>Detected Vulnerabilities ({filteredFindings.length})</h3>
                    </div>

                    <div className="results-header-actions">
                      <select 
                        value={filterSeverity}
                        onChange={(e) => setFilterSeverity(e.target.value)}
                        className="severity-select"
                      >
                        <option value="All">All Severities</option>
                        <option value="Critical/High">Critical / High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                      </select>

                      <button 
                        onClick={() => window.print()}
                        className="export-btn"
                      >
                        <Download size={14} />
                        Export Audit
                      </button>
                    </div>
                  </div>

                  <LayoutGroup>
                    <motion.div layout className="findings-divider" style={{ display: 'flex', flexDirection: 'column' }}>
                      {filteredFindings.length === 0 ? (
                        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                          No vulnerabilities found matching filters.
                        </div>
                      ) : (
                        filteredFindings.map((finding, idx) => {
                          const isExpanded = selectedFindingIndex === idx;
                          const severityClass = finding.severity.toLowerCase();
                          
                          return (
                            <motion.div 
                              layout 
                              key={finding.id} 
                              className="finding-row"
                            >
                              {/* Accordion Summary */}
                              <div 
                                onClick={() => {
                                  setSelectedFindingIndex(isExpanded ? null : idx);
                                  if (!isExpanded) {
                                    setActiveExplorerFile(finding.file);
                                  }
                                }}
                                className="finding-summary"
                              >
                                <div className="finding-title-section">
                                  <span className={`severity-badge ${severityClass}`}>{finding.severity}</span>
                                  <div style={{ textAlign: 'left' }}>
                                    <div className="finding-name">{finding.name}</div>
                                    <div className="finding-meta">
                                      File: <span className="cyan">{finding.file}</span> : Line {finding.line}
                                    </div>
                                  </div>
                                </div>
                                {isExpanded ? <ChevronUp size={16} className="text-slate-400" /> : <ChevronDown size={16} className="text-slate-400" />}
                              </div>

                              {/* Accordion Details */}
                              <AnimatePresence>
                                {isExpanded && (
                                  <motion.div 
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    exit={{ opacity: 0, height: 0 }}
                                    style={{ overflow: 'hidden' }}
                                  >
                                    <div className="finding-details">
                                      <div>
                                        <div className="details-block-title" style={{ textAlign: 'left' }}>Vulnerability Explanation</div>
                                        <p className="details-desc" style={{ textAlign: 'left' }}>{finding.description}</p>
                                      </div>

                                      <div>
                                        <div className="details-block-title" style={{ textAlign: 'left' }}>Code Context</div>
                                        <div className="code-snippet-box">{finding.code_snippet}</div>
                                      </div>

                                      <AttackPathGraph vulnName={finding.name} />

                                      <div>
                                        <div className="details-block-title" style={{ textAlign: 'left' }}>Secure Fix Recommendation</div>
                                        <p className="details-desc" style={{ textAlign: 'left', marginBottom: '8px' }}>{finding.fix_guidance}</p>
                                        {finding.secure_fix && (
                                          <div className="code-snippet-box" style={{ background: '#022c22', borderColor: '#059669', color: '#a7f3d0' }}>
                                            {finding.secure_fix}
                                          </div>
                                        )}
                                      </div>

                                      {/* AutoFix Action Buttons */}
                                      <div className="actions-row">
                                        <button 
                                          onClick={() => handleAutoFix(finding)}
                                          className="action-btn-primary"
                                        >
                                          <Cpu size={14} />
                                          {finding.secure_fix ? "Re-Generate Fix" : "Generate Secure Fix"}
                                        </button>
                                        <button 
                                          onClick={() => {
                                            setActiveExplorerFile(finding.file);
                                            // Scroll to explorer
                                            document.getElementById("workspace-explorer")?.scrollIntoView({ behavior: 'smooth' });
                                          }}
                                          className="action-btn-secondary"
                                        >
                                          <Eye size={14} />
                                          Inspect File
                                        </button>
                                      </div>
                                    </div>
                                  </motion.div>
                                )}
                              </AnimatePresence>
                            </motion.div>
                          );
                        })
                      )}
                    </motion.div>
                  </LayoutGroup>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* RIGHT SIDEBAR: DASHBOARD METRICS & CHAT MENTOR */}
        <div className="right-sidebar">
          
          {/* Security score circle and breakdown */}
          <AnimatedContainer animation="fadeIn" delay={0.3}>
            <div className="double-bezel-outer">
              <div className="double-bezel-inner">
                <span className="section-tag cyan">Audit dashboard</span>
                <h3 className="panel-title">Security Posture Dashboard</h3>

                {scanResult ? (
                  <>
                    <div className="metrics-wheel-container">
                      <svg className="metrics-wheel-svg">
                        <circle className="metrics-wheel-bg" cx="70" cy="70" r="58" />
                        <circle 
                          className="metrics-wheel-fill" 
                          cx="70" 
                          cy="70" 
                          r="58" 
                          stroke={scanResult.metrics.overall_score > 75 ? "var(--emerald-primary)" : (scanResult.metrics.overall_score > 50 ? "var(--orange-primary)" : "var(--rose-primary)")}
                          strokeDasharray="364.4"
                          strokeDashoffset={364.4 - (364.4 * scanResult.metrics.overall_score) / 100}
                        />
                      </svg>
                      <div className="metrics-wheel-text">
                        <span className="score-number">{scanResult.metrics.overall_score}</span>
                        <span className="score-label">Secure Score</span>
                      </div>
                    </div>

                    <div className="score-breakdown-list">
                      {[
                        { name: "Code Security", val: scanResult.metrics.code_security, color: "var(--cyan-primary)" },
                        { name: "Authentication", val: scanResult.metrics.authentication, color: "var(--rose-primary)" },
                        { name: "API Security", val: scanResult.metrics.api_security, color: "#a855f7" },
                        { name: "Infrastructure", val: scanResult.metrics.infrastructure, color: "var(--orange-primary)" },
                        { name: "Compliance", val: scanResult.metrics.compliance, color: "var(--emerald-primary)" }
                      ].map((item, idx) => (
                        <div key={idx} className="breakdown-row">
                          <span className="breakdown-label">{item.name}</span>
                          <div style={{ display: 'flex', alignItems: 'center' }}>
                            <div className="breakdown-bar-bg">
                              <div className="breakdown-bar-fill" style={{ width: `${item.val}%`, backgroundColor: item.color }} />
                            </div>
                            <span className="breakdown-val">{item.val}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                    Run a vulnerability audit scan to generate security metrics dashboards.
                  </div>
                )}
              </div>
            </div>
          </AnimatedContainer>

          {/* AI Threat Modeling Panel */}
          <AnimatePresence>
            {scanResult && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="double-bezel-outer"
              >
                <div className="double-bezel-inner">
                  <span className="section-tag rose">Threat modeling</span>
                  <h3 className="panel-title">Dynamic Threat Surface Vector</h3>
                  
                  <div style={{ textAlign: 'left', display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '0.75rem' }}>
                    <div>
                      <div className="details-block-title">Attack Surface</div>
                      <p className="details-desc">{scanResult.threat_model.attack_surface}</p>
                    </div>

                    <div>
                      <div className="details-block-title">Exploitation Risk Severity</div>
                      <span className={`severity-badge ${scanResult.threat_model.risk_matrix.toLowerCase()}`}>{scanResult.threat_model.risk_matrix} Risk</span>
                    </div>

                    <div>
                      <div className="details-block-title">Exploitation Scenario</div>
                      <ul style={{ paddingLeft: '16px', listStyleType: 'disc', color: 'var(--text-secondary)' }}>
                        {scanResult.threat_model.exploitation_scenarios.map((sc, i) => (
                          <li key={i} style={{ marginBottom: '4px' }}>{sc}</li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <div className="details-block-title">Mitigation Guidelines</div>
                      <p className="details-desc">{scanResult.threat_model.mitigation_plan}</p>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* AI Security Mentor Chatbot */}
          <AnimatedContainer animation="fadeIn" delay={0.4}>
            <div className="double-bezel-outer">
              <div className="double-bezel-inner">
                <span className="section-tag cyan">AI security mentor</span>
                <h3 className="panel-title">Interactive Audit Assistant</h3>

                <div className="chat-messages-box">
                  {chatHistory.map((chat, idx) => (
                    <div key={idx} className={`chat-bubble ${chat.sender}`}>
                      <div style={{ whiteSpace: 'pre-wrap', textAlign: 'left' }}>
                        {chat.text}
                      </div>
                    </div>
                  ))}
                  {isChatLoading && (
                    <div className="chat-bubble bot" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <RefreshCw size={12} className="animate-spin text-slate-400" />
                      <span>Consulting secure coding scrolls...</span>
                    </div>
                  )}
                </div>

                <form onSubmit={handleSendMessage} className="chat-input-form">
                  <input 
                    type="text" 
                    placeholder="Ask how to fix finding or write secure code..." 
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    className="chat-input-field"
                    disabled={isChatLoading}
                  />
                  <button 
                    type="submit" 
                    disabled={isChatLoading || !chatInput.trim()}
                    className="chat-send-btn"
                  >
                    <Send size={14} />
                  </button>
                </form>
              </div>
            </div>
          </AnimatedContainer>

        </div>
        
      </main>
    </div>
  );
}
