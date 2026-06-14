"use client";

import React, { useState, useEffect } from "react";
import { 
  Shield, 
  Upload, 
  Globe, 
  Terminal, 
  AlertTriangle, 
  CheckCircle, 
  Cpu, 
  Send, 
  Download, 
  RefreshCw, 
  Lock, 
  Key, 
  ChevronDown, 
  ChevronUp, 
  HelpCircle,
  FileCode,
  Layers,
  ArrowRight
} from "lucide-react";

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

const MOCK_EXPLORER_FILES = {
  "core/auth_handler.py": {
    content: `import jwt
import os

# JWT Authorization Signature Config
# WARNING: Do not modify signature algorithm without consulting security
JWT_SECRET_TOKEN = "AIzaSyC155_mammoth_secret_key_99xY2"

def sign_session(user_id):
    payload = {
        "user_id": user_id,
        "role": "user"
    }
    return jwt.encode(payload, JWT_SECRET_TOKEN, algorithm="HS256")`,
    vulnLine: 6
  },
  "db/connection_pool.js": {
    content: `const pg = require('pg');
const pool = new pg.Pool();

// Query interface
async function findUser(username) {
  // Un-parameterized user input passing directly to driver execute sink
  const query = \`SELECT * FROM accounts WHERE username = '\` + username + \`'\`;
  const res = await db.query(query);
  return res.rows[0];
}`,
    vulnLine: 7
  },
  "views/dashboard_portal.html": {
    content: `<!DOCTYPE html>
<html>
<body>
  <div id="status-box">Loading status...</div>
  
  <script>
    // Extract query payload and inject directly into DOM innerHTML
    const urlParams = new URLSearchParams(window.location.search);
    const msg = urlParams.get('message');
    document.getElementById('status-box').innerHTML = msg;
  </script>
</body>
</html>`,
    vulnLine: 10
  },
  "api/v1/auth_endpoints.py": {
    content: `from fastapi import APIRouter, Depends
from core.auth_handler import sign_session

router = APIRouter()

@router.post("/login")
def login(username: str):
    # Simulated auth login endpoint
    return {"token": sign_session(username)}`,
    vulnLine: null
  },
  "config/application_settings.yml": {
    content: `# Application config parameters
app:
  name: codeshield-server
  version: 1.0.0
security:
  session_timeout: 3600
  allow_anonymous: false`,
    vulnLine: null
  }
};

interface CodebaseExplorerProps {
  selectedFile: string;
  onSelectFile: (file: string) => void;
}

function CodebaseExplorer({ selectedFile, onSelectFile }: CodebaseExplorerProps) {
  const activeFile = (selectedFile in MOCK_EXPLORER_FILES) 
    ? (selectedFile as keyof typeof MOCK_EXPLORER_FILES) 
    : "core/auth_handler.py";

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-[340px] bg-[#070708]/30 border border-white/5 rounded-[1.75rem] overflow-hidden">
      
      {/* File Sidebar list */}
      <div className="col-span-1 border-r border-white/5 p-4 flex flex-col gap-1 overflow-y-auto">
        <span className="text-[10px] uppercase font-bold tracking-widest text-gray-500 mb-2 pl-2">Scanned Tree</span>
        
        {Object.entries(MOCK_EXPLORER_FILES).map(([filename, fileData]) => {
          const isSelected = activeFile === filename;
          const hasVuln = fileData.vulnLine !== null;

          return (
            <button
              key={filename}
              onClick={() => onSelectFile(filename)}
              className={`w-full text-left py-2 px-3.5 rounded-full text-xs font-mono transition-spring flex items-center justify-between border ${
                isSelected 
                  ? "bg-white/5 text-white border-white/10" 
                  : "text-gray-500 hover:text-gray-300 border-transparent"
              }`}
            >
              <span className="truncate">{filename}</span>
              {hasVuln && (
                <span className="w-1.5 h-1.5 rounded-full bg-rose-450 shadow-[0_0_8px_rgba(244,63,94,0.5)] shrink-0" />
              )}
            </button>
          );
        })}
      </div>

      {/* Editor Content pane */}
      <div className="col-span-2 p-5 bg-[#050505] overflow-y-auto flex flex-col font-mono text-[11px]">
        <div className="border-b border-white/5 pb-2 mb-4 flex items-center justify-between text-[10px] text-gray-500 uppercase tracking-widest font-sans">
          <span>Source Inspector</span>
          <span className="font-mono text-cyan-400">{activeFile}</span>
        </div>

        <pre className="flex-1 overflow-x-auto text-gray-300 leading-relaxed scrollbar-thin text-left">
          <code>
            {MOCK_EXPLORER_FILES[activeFile].content.split("\n").map((line, idx) => {
              const lineNo = idx + 1;
              const isVulnLine = MOCK_EXPLORER_FILES[activeFile].vulnLine === lineNo;

              return (
                <div 
                  key={idx} 
                  className={`flex items-start px-2 py-0.5 rounded ${
                    isVulnLine ? "bg-rose-500/10 text-rose-300 border-l-2 border-rose-500" : ""
                  }`}
                >
                  <span className="text-gray-650 select-none w-8 text-right pr-3">{lineNo}</span>
                  <span>{line}</span>
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

  if (vulnName.includes("Secret")) {
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
  }

  return (
    <div className="bg-[#050505] border border-white/5 rounded-[1.25rem] p-6 space-y-6 text-left">
      <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2">Visual Exploit Vector Graph</h5>
      
      <div className="flex flex-col md:flex-row items-center justify-between gap-6 relative">
        <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-zinc-900 -translate-y-1/2 hidden md:block z-0 overflow-hidden">
          <div className="h-full bg-cyan-400 w-1/3 animate-[laser-line_2s_linear_infinite]" />
        </div>

        {steps.map((step, idx) => (
          <div key={idx} className="flex flex-col items-center text-center z-10 w-full md:w-1/3 relative">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center border transition-spring ${
              step.status === "active" 
                ? "bg-cyan-500/10 border-cyan-400/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.1)]"
                : (step.status === "danger" ? "bg-orange-500/10 border-orange-400/30 text-orange-400 shadow-[0_0_15px_rgba(249,115,22,0.1)]" : "bg-rose-500/10 border-rose-400/30 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.1)]")
            }`}>
              <span className="font-mono text-xs font-bold">{idx + 1}</span>
            </div>
            
            <h6 className="text-xs font-semibold text-white mt-3">{step.title}</h6>
            <p className="text-[10px] text-gray-500 mt-1 max-w-[155px] leading-normal">{step.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<"zip" | "git" | "url">("zip");
  const [apiKey, setApiKey] = useState("");
  const [gitUrl, setGitUrl] = useState("");
  const [webUrl, setWebUrl] = useState("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  
  // Scanning state
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanningFileName, setScanningFileName] = useState("");
  const [scanResult, setScanResult] = useState<ScanData | null>(null);
  const [selectedFindingIndex, setSelectedFindingIndex] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("All");
  const [activeExplorerFile, setActiveExplorerFile] = useState<string>("core/auth_handler.py");
  
  // Chat state
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState<Array<{ sender: "user" | "bot"; text: string }>>([
    { sender: "bot", text: "Me CodeShield Mentor! Ask me how to protect your cave from bad fire-spirits (vulnerabilities)." }
  ]);
  const [isChatLoading, setIsChatLoading] = useState(false);
  
  // Backend connectivity status
  const [backendAlive, setBackendAlive] = useState(false);
  const API_BASE = "http://127.0.0.1:8000";

  // Check backend health
  useEffect(() => {
    fetch(`${API_BASE}/api/health`)
      .then(res => res.json())
      .then(() => setBackendAlive(true))
      .catch(() => setBackendAlive(false));
  }, []);

  // Check scan status if running in backend
  const checkScanStatus = (scanId: string) => {
    const interval = setInterval(() => {
      fetch(`${API_BASE}/api/scan/${scanId}`)
        .then(res => res.json())
        .then(data => {
          if (data.status === "completed") {
            setScanResult(data);
            setIsScanning(false);
            clearInterval(interval);
          } else if (data.status === "failed") {
            alert("Scan failed: " + data.error);
            setIsScanning(false);
            clearInterval(interval);
          }
        })
        .catch(() => {
          clearInterval(interval);
          setIsScanning(false);
        });
    }, 2000);
  };

  const handleStartScan = async () => {
    setIsScanning(true);
    setScanProgress(10);
    setScanResult(null);

    if (backendAlive) {
      try {
        if (activeTab === "zip" && uploadFile) {
          const formData = new FormData();
          formData.append("file", uploadFile);
          if (apiKey) formData.append("apiKey", apiKey);

          const res = await fetch(`${API_BASE}/api/scan/zip`, {
            method: "POST",
            body: formData,
          });
          const data = await res.json();
          if (data.scan_id) {
            setScanProgress(50);
            checkScanStatus(data.scan_id);
          } else {
            throw new Error(data.detail || "ZIP scan upload failed");
          }
        } else if (activeTab === "url" && webUrl) {
          const res = await fetch(`${API_BASE}/api/scan/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: webUrl, apiKey }),
          });
          const data = await res.json();
          if (data.scan_id) {
            setScanProgress(60);
            checkScanStatus(data.scan_id);
          } else {
            throw new Error(data.detail || "URL scan failed");
          }
        } else {
          runMockScan();
        }
      } catch (err: any) {
        alert("Scan connection error: " + err.message + ". Running in mock mode!");
        runMockScan();
      }
    } else {
      runMockScan();
    }
  };

  const runMockScan = () => {
    const scanFiles = [
      "core/auth_handler.py",
      "db/connection_pool.js",
      "api/v1/auth_endpoints.py",
      "views/dashboard_portal.html",
      "config/application_settings.yml",
      "utils/secure_upload.ts"
    ];
    
    let currentFileIdx = 0;
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          setIsScanning(false);
          setScanResult(getMockScanData());
          return 100;
        }
        setScanningFileName(scanFiles[currentFileIdx % scanFiles.length]);
        currentFileIdx++;
        return prev + 15;
      });
    }, 450);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setUploadFile(e.dataTransfer.files[0]);
    }
  };

  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg = chatInput;
    setChatHistory(prev => [...prev, { sender: "user", text: userMsg }]);
    setChatInput("");
    setIsChatLoading(true);

    if (backendAlive) {
      try {
        const res = await fetch(`${API_BASE}/api/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: userMsg, apiKey }),
        });
        const data = await res.json();
        setChatHistory(prev => [...prev, { sender: "bot", text: data.response }]);
      } catch {
        simulateBotResponse(userMsg);
      } finally {
        setIsChatLoading(false);
      }
    } else {
      setTimeout(() => {
        simulateBotResponse(userMsg);
        setIsChatLoading(false);
      }, 800);
    }
  };

  const simulateBotResponse = (msg: string) => {
    const lower = msg.toLowerCase();
    let reply = "Me no understand. Ask about SQL injection, XSS, or how to secure credentials!";
    
    if (lower.includes("sql injection") || lower.includes("sqli")) {
      reply = `**SQL Injection (SQLi) is bad fire-spirit!** It happen when you paste user input directly into SQL command.

**Vulnerable code example:**
\`\`\`python
cursor.execute("SELECT * FROM users WHERE user = '" + username + "'")
\`\`\`

**Secure Fix:** Use parameterized queries!
\`\`\`python
cursor.execute("SELECT * FROM users WHERE user = %s", (username,))
\`\`\``;
    } else if (lower.includes("xss") || lower.includes("cross-site")) {
      reply = `**Cross-Site Scripting (XSS) is browser-spirit curse!** Attackers inject malicious JavaScript into webpages.

To prevent XSS, always sanitize user input, use textContent instead of innerHTML, or configure a Content Security Policy (CSP) header.`;
    } else if (lower.includes("secret") || lower.includes("api key") || lower.includes("token")) {
      reply = `**Hardcoded keys are bad!** If you commit keys to code, anyone who sees the code can steal your mammoth resources.

Use environment variables (.env files) or tools like AWS Secrets Manager or HashiCorp Vault. Never push secrets to GitHub!`;
    } else if (lower.includes("rag")) {
      reply = `**RAG (Retrieval-Augmented Generation)** is like reading cave scrolls before answering. It search OWASP Top 10, CWE database, and secure guidelines, and gives Gemini the best scrolls. This make AI answers super smart and correct for your specific code!`;
    }
    
    setChatHistory(prev => [...prev, { sender: "bot", text: reply }]);
  };

  const handleAutoFix = async (finding: Finding) => {
    if (backendAlive) {
      try {
        const res = await fetch(`${API_BASE}/api/autofix`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            vulnerable_code: finding.vulnerable_code,
            vuln_name: finding.name,
            apiKey
          }),
        });
        const data = await res.json();
        
        if (scanResult) {
          const updatedFindings = scanResult.findings.map(f => {
            if (f.id === finding.id && f.file === finding.file && f.line === finding.line) {
              return { ...f, secure_fix: data.secure_fix };
            }
            return f;
          });
          setScanResult({ ...scanResult, findings: updatedFindings });
        }
      } catch {
        alert("Could not generate Auto-Fix. Check if Gemini key is set!");
      }
    } else {
      if (scanResult) {
        const mockFix = getMockFix(finding.name, finding.vulnerable_code);
        const updatedFindings = scanResult.findings.map(f => {
          if (f.id === finding.id && f.file === finding.file && f.line === finding.line) {
            return { ...f, secure_fix: mockFix };
          }
          return f;
        });
        setScanResult({ ...scanResult, findings: updatedFindings });
      }
    }
  };

  const filteredFindings = scanResult?.findings.filter(f => {
    if (filterSeverity === "All") return true;
    if (filterSeverity === "Critical/High") return f.severity === "Critical" || f.severity === "High";
    return f.severity === filterSeverity;
  }) || [];

  return (
    <div className="flex-1 flex flex-col min-h-[100dvh] bg-[#050505] pb-24 relative">
      {/* Background ambient light */}
      <div className="ambient-glow" />

      {/* Floating Island Navbar */}
      <header className="mt-6 mx-auto w-full max-w-7xl px-4 z-10 animate-waterfall" style={{ animationDelay: "0ms" }}>
        <div className="bg-zinc-950/70 backdrop-blur-md border border-white/5 rounded-full px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-cyan-500/10 p-2 rounded-full border border-cyan-500/20">
              <Shield className="h-5 w-5 text-cyan-400" strokeWidth={1.2} />
            </div>
            <div>
              <h1 className="text-md font-bold tracking-tight text-white flex items-center gap-2">
                CodeShield <span className="text-[10px] text-cyan-400 border border-cyan-400/20 px-2 py-0.5 rounded-full bg-cyan-400/5 font-mono">AI</span>
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 bg-[#0d0d0d] border border-white/5 rounded-full px-3 py-1.5">
              <Key className="h-3.5 w-3.5 text-gray-500" strokeWidth={1.2} />
              <input 
                type="password"
                placeholder="Paste Gemini API Key..."
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="bg-transparent text-xs text-white placeholder-gray-600 outline-none w-40 font-sans"
              />
            </div>

            <div className="flex items-center gap-3 text-xs">
              <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-medium ${
                backendAlive ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
              }`}>
                <span className={`h-1.5 w-1.5 rounded-full ${backendAlive ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
                {backendAlive ? "Connected" : "Offline Mode"}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Asymmetric Grid Layout */}
      <main className="max-w-7xl mx-auto w-full px-4 mt-12 grid grid-cols-1 lg:grid-cols-3 gap-8 z-10 flex-1">
        
        {/* LEFT COLUMN: 65% - Scan and Primary Results */}
        <section className="lg:col-span-2 space-y-8">
          
          {/* Target Scanner Panel: Double-Bezel Nested Architecture */}
          <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "100ms" }}>
            <div className="double-bezel-inner relative overflow-hidden">
              <div className="laser-line absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-10 pointer-events-none" />
              
              <div className="mb-6">
                <span className="rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.2em] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 w-fit block mb-3">
                  Engine setup
                </span>
                <h2 className="text-xl font-bold text-white tracking-tight">Configure Vulnerability Scan</h2>
              </div>

              {/* Tabs */}
              <div className="flex gap-2 p-1 bg-[#0d0d0d] border border-white/5 rounded-full mb-6">
                <button 
                  onClick={() => setActiveTab("zip")}
                  className={`flex-1 py-2 rounded-full text-xs font-medium transition-spring flex items-center justify-center gap-2 ${
                    activeTab === "zip" ? "bg-white/5 text-white border border-white/10" : "text-gray-500 hover:text-white"
                  }`}
                >
                  <Upload className="h-3.5 w-3.5" strokeWidth={1.2} />
                  ZIP Repository
                </button>
                <button 
                  onClick={() => setActiveTab("git")}
                  className={`flex-1 py-2 rounded-full text-xs font-medium transition-spring flex items-center justify-center gap-2 ${
                    activeTab === "git" ? "bg-white/5 text-white border border-white/10" : "text-gray-500 hover:text-white"
                  }`}
                >
                  <Terminal className="h-3.5 w-3.5" strokeWidth={1.2} />
                  Git Repository
                </button>
                <button 
                  onClick={() => setActiveTab("url")}
                  className={`flex-1 py-2 rounded-full text-xs font-medium transition-spring flex items-center justify-center gap-2 ${
                    activeTab === "url" ? "bg-white/5 text-white border border-white/10" : "text-gray-500 hover:text-white"
                  }`}
                >
                  <Globe className="h-3.5 w-3.5" strokeWidth={1.2} />
                  Website Scanner
                </button>
              </div>

              {/* Tab Content */}
              {activeTab === "zip" && (
                <div 
                  onDragOver={handleDragOver}
                  onDrop={handleDrop}
                  className="border border-dashed border-white/5 hover:border-cyan-500/30 transition-spring rounded-[1.75rem] p-10 text-center bg-[#070708]/50"
                >
                  <Upload className="h-8 w-8 mx-auto text-gray-650 mb-3" strokeWidth={1.2} />
                  <p className="text-sm text-gray-300 font-medium">Drag and drop ZIP repository file here</p>
                  <p className="text-xs text-gray-500 mt-1.5">Supported: Python, JS, TS, React, Go, Rust, Java, HTML/CSS</p>
                  <input 
                    type="file" 
                    accept=".zip"
                    onChange={(e) => e.target.files && setUploadFile(e.target.files[0])}
                    className="hidden" 
                    id="zip-uploader"
                  />
                  <label 
                    htmlFor="zip-uploader"
                    className="mt-4 inline-flex items-center text-xs bg-zinc-900 border border-white/5 hover:bg-zinc-850 px-4 py-2 rounded-full text-white cursor-pointer transition-spring"
                  >
                    Select File
                  </label>
                  {uploadFile && (
                    <p className="text-xs text-cyan-400 mt-3 font-medium flex items-center justify-center gap-1.5 font-mono">
                      <FileCode className="h-3.5 w-3.5" strokeWidth={1.2} />
                      {uploadFile.name} ({(uploadFile.size / 1024).toFixed(1)} KB)
                    </p>
                  )}
                </div>
              )}

              {activeTab === "git" && (
                <div className="space-y-4">
                  <div className="relative">
                    <Terminal className="absolute left-4 top-3.5 h-4 w-4 text-gray-600" strokeWidth={1.2} />
                    <input 
                      type="text" 
                      placeholder="https://github.com/username/project" 
                      value={gitUrl}
                      onChange={(e) => setGitUrl(e.target.value)}
                      className="w-full bg-[#0d0d0d] border border-white/5 rounded-full py-3.5 pl-12 pr-4 text-xs text-white focus:border-cyan-500/30 outline-none transition-spring font-mono"
                    />
                  </div>
                  <p className="text-[11px] text-gray-500">Clone and crawl source tree dynamically for static analysis review.</p>
                </div>
              )}

              {activeTab === "url" && (
                <div className="space-y-4">
                  <div className="relative">
                    <Globe className="absolute left-4 top-3.5 h-4 w-4 text-gray-600" strokeWidth={1.2} />
                    <input 
                      type="text" 
                      placeholder="https://secure-portal.com" 
                      value={webUrl}
                      onChange={(e) => setWebUrl(e.target.value)}
                      className="w-full bg-[#0d0d0d] border border-white/5 rounded-full py-3.5 pl-12 pr-4 text-xs text-white focus:border-cyan-500/30 outline-none transition-spring font-mono"
                    />
                  </div>
                  <p className="text-[11px] text-gray-500">Crawl live endpoints, extract security headers, session parameters, and exposed cookies.</p>
                </div>
              )}

              {/* Action Button: Button-in-Button CTA Architecture */}
              <div className="mt-8 flex justify-end">
                <button 
                  onClick={handleStartScan}
                  disabled={isScanning || (activeTab === "zip" && !uploadFile) || (activeTab === "git" && !gitUrl) || (activeTab === "url" && !webUrl)}
                  className={`pl-5 pr-2 py-2 rounded-full font-bold text-xs uppercase tracking-wider transition-spring flex items-center gap-4 group active:scale-[0.98] ${
                    isScanning 
                      ? "bg-zinc-900 text-gray-600 border border-white/5 cursor-not-allowed" 
                      : "bg-white text-black hover:bg-gray-200 cursor-pointer shadow-[0_10px_30px_rgba(255,255,255,0.05)]"
                  }`}
                >
                  <span>{isScanning ? "Scanning Target..." : "Auditing Target"}</span>
                  <div className="w-8 h-8 rounded-full bg-black/5 dark:bg-white/10 flex items-center justify-center group-hover:translate-x-1 transition-spring">
                    {isScanning ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin text-gray-400" strokeWidth={1.2} />
                    ) : (
                      <ArrowRight className="h-3.5 w-3.5 text-black" strokeWidth={1.2} />
                    )}
                  </div>
                </button>
              </div>
            </div>
          </div>

          {/* Scanning Status Loader */}
          {isScanning && (
            <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "50ms" }}>
              <div className="double-bezel-inner">
                <div className="flex items-center justify-between text-xs mb-3">
                  <span className="font-semibold text-cyan-400 flex items-center gap-2">
                    <Terminal className="h-4 w-4 animate-pulse text-cyan-400" strokeWidth={1.2} />
                    Analyzing source files...
                  </span>
                  <span className="text-gray-400 font-mono">{scanProgress}%</span>
                </div>
                <div className="w-full bg-[#0d0d0d] border border-white/5 rounded-full h-1 overflow-hidden">
                  <div 
                    className="bg-cyan-400 h-full transition-spring" 
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
                <div className="mt-3 text-[11px] text-gray-500 font-mono">
                  Current file: <span className="text-gray-300">{scanningFileName || "initializing static tree..."}</span>
                </div>
              </div>
            </div>
          )}

          {/* Codebase Explorer: Double-Bezel */}
          {scanResult && (
            <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "180ms" }}>
              <div className="double-bezel-inner">
                <div className="mb-6">
                  <span className="rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.2em] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 w-fit block mb-3">
                    Codebase Inspector
                  </span>
                  <h3 className="text-xl font-bold text-white tracking-tight">Interactive Source Explorer</h3>
                </div>
                <CodebaseExplorer selectedFile={activeExplorerFile} onSelectFile={setActiveExplorerFile} />
              </div>
            </div>
          )}

          {/* Results Table: Double-Bezel */}
          {scanResult && (
            <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "200ms" }}>
              <div className="double-bezel-inner !p-0">
                <div className="p-6 border-b border-white/5 flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <span className="rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.2em] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20 w-fit block mb-2">
                      Scan log
                    </span>
                    <h3 className="text-md font-bold text-white tracking-tight">
                      Detected Vulnerabilities ({scanResult.findings.length})
                    </h3>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    <select 
                      value={filterSeverity}
                      onChange={(e) => setFilterSeverity(e.target.value)}
                      className="bg-[#0d0d0d] border border-white/5 text-xs text-white rounded-full px-4 py-2 outline-none focus:border-cyan-500/30 font-sans"
                    >
                      <option value="All">All Severities</option>
                      <option value="Critical/High">Critical / High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>

                    <a 
                      href={backendAlive ? `${API_BASE}/api/scan/${scanResult.id}/report` : "#"}
                      target="_blank"
                      rel="noreferrer"
                      onClick={(e) => {
                        if (!backendAlive) {
                          e.preventDefault();
                          window.print();
                        }
                      }}
                      className="bg-[#0d0d0d] border border-white/5 hover:border-white/10 hover:bg-zinc-900 text-xs px-4 py-2 rounded-full flex items-center gap-1.5 text-gray-300 transition-spring font-medium"
                    >
                      <Download className="h-3.5 w-3.5" strokeWidth={1.2} />
                      Export Audit
                    </a>
                  </div>
                </div>

                <div className="divide-y divide-white/5">
                  {filteredFindings.length === 0 ? (
                    <div className="p-8 text-center text-xs text-gray-500 font-sans">
                      No matching findings found.
                    </div>
                  ) : (
                    filteredFindings.map((finding, idx) => {
                      const isExpanded = selectedFindingIndex === idx;
                      const sevColor = finding.severity === "Critical" 
                        ? "bg-rose-500/10 text-rose-400 border-rose-500/20" 
                        : (finding.severity === "High" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" : "bg-yellow-500/10 text-yellow-400 border-yellow-500/20");
                      
                      return (
                        <div key={idx} className="bg-transparent hover:bg-white/[0.01] transition-spring">
                          
                          <div 
                            onClick={() => {
                              setSelectedFindingIndex(isExpanded ? null : idx);
                              if (!isExpanded) {
                                setActiveExplorerFile(finding.file);
                              }
                            }}
                            className="p-6 flex items-center justify-between cursor-pointer"
                          >
                            <div className="flex items-center gap-4">
                              <span className={`text-[10px] uppercase font-bold tracking-widest px-2.5 py-1 rounded-full border ${sevColor} font-mono`}>
                                {finding.severity}
                              </span>
                              <div>
                                <h4 className="text-sm font-semibold text-white tracking-tight">{finding.name}</h4>
                                <p className="text-xs text-gray-500 font-mono mt-1 flex items-center gap-1.5">
                                  <FileCode className="h-3 w-3 text-gray-600" strokeWidth={1.2} />
                                  {finding.file} {finding.line > 0 && `: L${finding.line}`}
                                </p>
                              </div>
                            </div>
                            
                            <div className="flex items-center gap-3">
                              <span className="text-[10px] text-gray-400 font-mono bg-[#0d0d0d] border border-white/5 px-2.5 py-0.5 rounded-full">
                                {finding.cwe}
                              </span>
                              {isExpanded ? <ChevronUp className="h-4 w-4 text-gray-500" strokeWidth={1.2} /> : <ChevronDown className="h-4 w-4 text-gray-500" strokeWidth={1.2} />}
                            </div>
                          </div>

                          {isExpanded && (
                            <div className="px-6 pb-8 border-t border-white/5 pt-6 space-y-6">
                              <div>
                                <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1.5">Risk Summary</h5>
                                <p className="text-xs text-gray-400 leading-relaxed max-w-[65ch]">{finding.description}</p>
                              </div>

                              <div>
                                <h5 className="text-[10px] font-bold text-rose-400 uppercase tracking-widest mb-2">Vulnerable Code block</h5>
                                <pre className="bg-[#050505] border border-white/5 rounded-[1.25rem] p-5 font-mono text-[11px] overflow-x-auto text-gray-300 scrollbar-thin">
                                  <code>{finding.code_snippet}</code>
                                </pre>
                              </div>

                              <AttackPathGraph vulnName={finding.name} />

                              <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                  <h5 className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest">Remediation Script</h5>
                                  <button 
                                    onClick={() => handleAutoFix(finding)}
                                    className="bg-emerald-500/5 hover:bg-emerald-500/10 border border-emerald-500/10 text-[10px] px-3.5 py-1.5 rounded-full text-emerald-400 transition-spring flex items-center gap-1.5 cursor-pointer font-medium"
                                  >
                                    <Cpu className="h-3 w-3" strokeWidth={1.2} />
                                    Generate AI Fix
                                  </button>
                                </div>

                                {finding.secure_fix ? (
                                  <pre className="bg-emerald-950/5 border border-emerald-500/10 rounded-[1.25rem] p-5 font-mono text-[11px] overflow-x-auto text-emerald-400 scrollbar-thin">
                                    <code>{finding.secure_fix}</code>
                                  </pre>
                                ) : (
                                  <div className="bg-[#050505] border border-white/5 rounded-[1.25rem] p-5 text-xs text-gray-400 leading-relaxed font-sans">
                                    <p className="font-semibold text-gray-350 mb-1">Standard Secure Path:</p>
                                    <p>{finding.fix_guidance}</p>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}

                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Threat Modeling: Double-Bezel */}
          {scanResult && (
            <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "300ms" }}>
              <div className="double-bezel-inner">
                <div className="mb-6">
                  <span className="rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.2em] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 w-fit block mb-3">
                    Threat surface
                  </span>
                  <h3 className="text-xl font-bold text-white tracking-tight">AI Threat Modeling Analysis</h3>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="space-y-4">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase font-semibold block tracking-wider">Attack Surface Scope</span>
                      <p className="text-xs text-gray-400 mt-1 leading-relaxed">{scanResult.threat_model.attack_surface}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase font-semibold block tracking-wider">Exploitation Scenario</span>
                      <p className="text-xs text-gray-450 mt-1.5 leading-relaxed bg-[#050505] border border-white/5 p-4 rounded-[1.25rem] font-mono">
                        {scanResult.threat_model.exploitation_scenarios[0]}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase font-semibold block tracking-wider">Threat Level Index</span>
                      <p className="text-xs text-rose-450 mt-1 font-bold font-mono">{scanResult.threat_model.risk_matrix}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase font-semibold block tracking-wider">Mitigation Plan</span>
                      <p className="text-xs text-gray-400 mt-1 leading-relaxed">{scanResult.threat_model.mitigation_plan}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

        </section>

        {/* RIGHT COLUMN: 35% - Score & Security Mentor */}
        <section className="lg:col-span-1 space-y-8">
          
          {/* Circular Security Score Panel: Double-Bezel */}
          {scanResult && (
            <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "150ms" }}>
              <div className="double-bezel-inner flex flex-col items-center justify-center text-center">
                <span className="rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.2em] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 w-fit block mb-6">
                  Security Rating
                </span>

                <div className="relative w-36 h-36 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="72" cy="72" r="62" className="stroke-zinc-900" strokeWidth="4" fill="transparent" />
                    <circle 
                      cx="72" 
                      cy="72" 
                      r="62" 
                      className={
                        scanResult.metrics.overall_score > 75 
                          ? "stroke-emerald-400" 
                          : (scanResult.metrics.overall_score > 50 ? "stroke-amber-400" : "stroke-rose-400")
                      } 
                      strokeWidth="5" 
                      fill="transparent" 
                      strokeDasharray={389.56}
                      strokeDashoffset={389.56 - (389.56 * scanResult.metrics.overall_score) / 100}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute text-center">
                    <span className="text-4xl font-extrabold text-white font-mono">{scanResult.metrics.overall_score}</span>
                    <span className="text-gray-500 text-[10px] block uppercase tracking-wider font-medium">Score</span>
                  </div>
                </div>

                <div className="mt-8 w-full space-y-3 text-left">
                  {[
                    { label: "Code Integrity", val: scanResult.metrics.code_security },
                    { label: "Auth Mechanisms", val: scanResult.metrics.authentication },
                    { label: "API Protection", val: scanResult.metrics.api_security }
                  ].map((m, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between text-[11px] font-medium">
                        <span className="text-gray-400">{m.label}</span>
                        <span className="text-white font-mono">{m.val}%</span>
                      </div>
                      <div className="w-full bg-[#0d0d0d] border border-white/5 h-1 rounded-full overflow-hidden">
                        <div className="bg-cyan-400 h-full" style={{ width: `${m.val}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* AI Security Mentor: Double-Bezel */}
          <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "250ms" }}>
            <div className="double-bezel-inner !p-0 flex flex-col h-[580px]">
              
              {/* Chat Header */}
              <div className="p-5 bg-zinc-950/80 border-b border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  <div>
                    <h3 className="text-xs font-bold text-white tracking-widest uppercase">Security Mentor</h3>
                    <p className="text-[9px] text-gray-500 font-mono">Gemini RAG scrolls active</p>
                  </div>
                </div>
              </div>

              {/* Chat Messages */}
              <div className="flex-1 p-5 overflow-y-auto space-y-4 text-xs scrollbar-thin">
                {chatHistory.map((msg, idx) => (
                  <div 
                    key={idx} 
                    className={`flex ${msg.sender === "user" ? "justify-end" : "justify-start"}`}
                  >
                    <div className={`max-w-[90%] rounded-[1.25rem] p-4 leading-relaxed border ${
                      msg.sender === "user" 
                        ? "bg-cyan-500/5 text-cyan-300 border-cyan-500/10" 
                        : "bg-[#0d0d0d] text-gray-300 border-white/5"
                    }`}>
                      {msg.text.split("\n").map((line, lIdx) => {
                        if (line.startsWith("```")) return null;
                        if (line.startsWith("**") && line.endsWith("**")) {
                          return <p key={lIdx} className="font-bold text-white mb-1.5">{line.replace(/\*\*/g, "")}</p>;
                        }
                        return <p key={lIdx} className="mb-2 last:mb-0">{line}</p>;
                      })}
                    </div>
                  </div>
                ))}
                {isChatLoading && (
                  <div className="flex justify-start">
                    <div className="bg-[#0d0d0d] border border-white/5 rounded-[1.25rem] p-4 text-gray-500 flex items-center gap-2">
                      <RefreshCw className="h-3 w-3 animate-spin text-cyan-400" strokeWidth={1.2} />
                      Consulting local scrolls...
                    </div>
                  </div>
                )}
              </div>

              {/* Quick Query pills */}
              <div className="px-5 py-3 border-t border-white/5 bg-[#070708]/50 flex flex-wrap gap-2">
                {[
                  { label: "Fix SQLi", query: "How do I prevent SQL Injection?" },
                  { label: "Explain XSS", query: "Explain DOM XSS vulnerabilities" },
                  { label: "Protect Keys", query: "Best practices for API keys" }
                ].map((btn, bIdx) => (
                  <button
                    key={bIdx}
                    onClick={() => setChatInput(btn.query)}
                    className="bg-[#0d0d0d] hover:bg-zinc-900 border border-white/5 text-[10px] px-3.5 py-1.5 rounded-full text-gray-400 hover:text-white transition-spring cursor-pointer font-medium"
                  >
                    {btn.label}
                  </button>
                ))}
              </div>

              {/* Chat Input form */}
              <form onSubmit={handleSendMessage} className="p-3 border-t border-white/5 bg-[#0c0c0d] flex gap-2">
                <input 
                  type="text" 
                  placeholder="Ask secure coding questions..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  className="flex-1 bg-[#050505] border border-white/5 rounded-full px-4 py-2.5 text-xs text-white placeholder-gray-600 outline-none focus:border-cyan-500/30 font-sans transition-spring"
                />
                <button 
                  type="submit" 
                  className="bg-white hover:bg-gray-200 text-black w-9 h-9 rounded-full flex items-center justify-center transition-spring cursor-pointer shrink-0"
                >
                  <Send className="h-3.5 w-3.5" strokeWidth={1.2} />
                </button>
              </form>

            </div>
          </div>

          {/* Hardening Checklist Panel: Double-Bezel */}
          {scanResult && (
            <div className="double-bezel-outer animate-waterfall" style={{ animationDelay: "350ms" }}>
              <div className="double-bezel-inner">
                <div className="mb-4">
                  <span className="rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.2em] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 w-fit block mb-3">
                    Hardening recommendations
                  </span>
                  <h3 className="text-md font-bold text-white tracking-tight">Security Checklist</h3>
                </div>

                <ul className="space-y-3.5">
                  {scanResult.hardening.map((rec, idx) => (
                    <li key={idx} className="flex gap-2.5 text-xs text-gray-450 leading-relaxed align-top">
                      <CheckCircle className="h-4.5 w-4.5 text-emerald-400 shrink-0 mt-0.5" strokeWidth={1.2} />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

        </section>

      </main>
    </div>
  );
}

// ==========================================
// MOCK DATA GENERATION FUNCTIONS
// ==========================================

function getMockScanData(): ScanData {
  return {
    id: "scan-session-987654",
    status: "completed",
    filename: "codeshield_core_audit.zip",
    scanned_files: 8,
    metrics: {
      overall_score: 54,
      code_security: 42,
      authentication: 70,
      api_security: 60,
      infrastructure: 80,
      compliance: 48
    },
    threat_model: {
      attack_surface: "The application exposes administrative web portals, API endpoints containing customer profiles, and a database link running un-parameterized queries.",
      potential_threats: [
        "Unauthorized database access via SQL injection on the user login screen.",
        "Exfiltration of sensitive JWT signature secret keys committed inside git codebase.",
        "Session hijacking of users via Cross-Site Scripting (XSS) due to unsafe HTML injections."
      ],
      risk_matrix: "Critical Risk (Score: 54/100)",
      exploitation_scenarios: [
        "An external attacker detects the exposed 'JWT_SECRET_TOKEN' in jwt_handler.py. Using it, they forge administrative session signatures, bypassing token signature logic, and extract customer accounts via database injection."
      ],
      mitigation_plan: "1. Parameterize all SQL connection cursors. 2. Remove hardcoded JWT sign strings. 3. Sanitize HTML DOM element injections."
    },
    hardening: [
      "Configure Content Security Policy (CSP) header values to block inline scripts.",
      "Activate Secure and HttpOnly flags on session credentials.",
      "Restrict Cross-Origin Resource Sharing (CORS) header policies to absolute hosts.",
      "Run dependency validation to patch nested package directory vulnerabilities."
    ],
    findings: [
      {
        id: "CS-001",
        name: "Hardcoded Secret / API Key Exposure",
        category: "Data Security",
        cwe: "CWE-798",
        owasp: "A02:2021-Cryptographic Failures",
        severity: "Critical",
        file: "core/auth_handler.py",
        line: 8,
        description: "Exposing secrets or API keys in source code allows unauthorized access if the repository is leaked or compromised.",
        code_snippet: "   6 | import jwt\n   7 | \n>> 8 | JWT_SECRET_TOKEN = \"AIzaSyC155_mammoth_secret_key_99xY2\"\n   9 | \n  10 | def sign_session(user_id):",
        vulnerable_code: "JWT_SECRET_TOKEN = \"AIzaSyC155_mammoth_secret_key_99xY2\"",
        fix_guidance: "Move secrets to environment variables (e.g., os.environ.get('JWT_SECRET_TOKEN')) or use a secure cloud configuration vault."
      },
      {
        id: "CS-002",
        name: "SQL Injection Vulnerability",
        category: "Injection Attacks",
        cwe: "CWE-89",
        owasp: "A03:2021-Injection",
        severity: "High",
        file: "db/connection_pool.js",
        line: 14,
        description: "Building SQL queries by concatenating raw user input allows attackers to manipulate the query logic and view or delete data.",
        code_snippet: "  12 | async function findUser(username) {\n  13 |   const query = `SELECT * FROM accounts WHERE username = '` + username + `'`;\n>> 14 |   const res = await db.query(query);\n  15 |   return res.rows[0];",
        vulnerable_code: "const query = `SELECT * FROM accounts WHERE username = '` + username + `'`;",
        fix_guidance: "Use parameterized queries or prepared statements (e.g., db.query('SELECT * FROM accounts WHERE username = $1', [username]))."
      },
      {
        id: "CS-003",
        name: "Cross-Site Scripting (XSS) via innerHTML",
        category: "Cross-Site Attacks",
        cwe: "CWE-79",
        owasp: "A03:2021-Injection",
        severity: "High",
        file: "views/dashboard_portal.html",
        line: 42,
        description: "Assigning unvalidated user input directly to innerHTML can lead to execution of arbitrary HTML/JS inside the user's browser.",
        code_snippet: "  40 |   const urlParams = new URLSearchParams(window.location.search);\n  41 |   const msg = urlParams.get('message');\n>> 42 |   document.getElementById('status-box').innerHTML = msg;\n  43 | </script>",
        vulnerable_code: "document.getElementById('status-box').innerHTML = msg;",
        fix_guidance: "Use textContent or innerText, or use a proper sanitization library like DOMPurify."
      }
    ]
  };
}

function getMockFix(vulnName: string, vulnerableCode: string): string {
  if (vulnName.includes("Secret")) {
    return `// [Auto-Fix Applied]
import os
JWT_SECRET_TOKEN = os.environ.get("JWT_SECRET_TOKEN") # Loaded securely from environment variables`;
  }
  if (vulnName.includes("SQL")) {
    return `// [Auto-Fix Applied]
async function findUser(username) {
  const query = 'SELECT * FROM accounts WHERE username = $1';
  const res = await db.query(query, [username]);
  return res.rows[0];
}`;
  }
  if (vulnName.includes("XSS")) {
    return `// [Auto-Fix Applied]
document.getElementById('status-box').textContent = msg;`;
  }
  return "// Remediation: Sanitize or parameterize inputs before execution.";
}
