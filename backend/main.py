import os
import zipfile
import shutil
import urllib.request
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import tempfile
import uuid
import json

from backend.security_engine import scan_file_content, get_gemini_analysis, ai_chat_mentor
from backend.report_generator import generate_html_report

app = FastAPI(title="CodeShield AI Backend", version="1.0.0")

# Enable CORS for next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store (simulating Redis/DB storage)
SCANS_DB: Dict[str, Dict[str, Any]] = {}

class ChatRequest(BaseModel):
    message: str
    apiKey: Optional[str] = None

class AutoFixRequest(BaseModel):
    vulnerable_code: str
    vuln_name: str
    apiKey: Optional[str] = None

class UrlScanRequest(BaseModel):
    url: str
    apiKey: Optional[str] = None

@app.get("/api/health")
def health_check():
    return {"status": "ok", "message": "CodeShield AI Backend is alive like mammoth!"}

def run_background_code_scan(scan_id: str, files_data: Dict[str, str], api_key: Optional[str]):
    """
    Background worker to scan repository files and optionally enrich with Gemini.
    """
    try:
        SCANS_DB[scan_id]["status"] = "scanning"
        all_findings = []
        scanned_files_count = 0
        
        for file_path, content in files_data.items():
            scanned_files_count += 1
            findings = scan_file_content(file_path, content)
            all_findings.extend(findings)
            
        SCANS_DB[scan_id]["scanned_files"] = scanned_files_count
        SCANS_DB[scan_id]["findings"] = all_findings
        
        # Calculate base score metrics
        vuln_count = len(all_findings)
        code_score = max(30, 100 - (vuln_count * 12))
        
        metrics = {
            "overall_score": code_score,
            "code_security": code_score,
            "authentication": 85 if vuln_count < 3 else 70,
            "api_security": 90 if vuln_count < 2 else 75,
            "infrastructure": 80,
            "compliance": max(50, code_score - 5)
        }
        
        threat_model = {
            "attack_surface": "Application source code contains multiple entrypoints and parameters.",
            "potential_threats": [
                "Credential leakage from configuration files.",
                "SQL injection in user databases leading to data theft.",
                "Unsafe code execution on backend worker nodes."
            ],
            "risk_matrix": "High" if vuln_count > 3 else "Medium",
            "exploitation_scenarios": [
                "Attacker finds SQL injection, bypasses login, extracts all secret API keys, and steals database records."
            ],
            "mitigation_plan": "Sanitize input, implement proper access control, and replace hardcoded keys with vault configs."
        }
        
        hardening_recs = [
            "Enable strict Content Security Policy (CSP) headers.",
            "Implement multi-factor authentication (MFA) for administrative routes.",
            "Integrate SAST scanning in your CI/CD pipeline."
        ]
        
        # If Gemini API key is present, enrich the scan report
        if api_key:
            gemini_res = get_gemini_analysis(api_key, all_findings)
            if "error" not in gemini_res:
                metrics = gemini_res.get("score_breakdown", metrics)
                metrics["overall_score"] = gemini_res.get("overall_score", metrics["overall_score"])
                threat_model = gemini_res.get("threat_modeling", threat_model)
                hardening_recs = gemini_res.get("hardening_recommendations", hardening_recs)
                
                # Merge AI explanation and fixes back to findings
                enriched_findings = gemini_res.get("findings_enrichment", [])
                enrich_map = {(f["file"], f["line"]): f for f in enriched_findings}
                
                for f in all_findings:
                    key = (f["file"], f["line"])
                    if key in enrich_map:
                        f["description"] = enrich_map[key].get("explanation", f["description"])
                        f["secure_fix"] = enrich_map[key].get("secure_fix", "")
        
        # Save results
        SCANS_DB[scan_id].update({
            "status": "completed",
            "metrics": metrics,
            "threat_model": threat_model,
            "hardening": hardening_recs,
            "findings": all_findings
        })
        
    except Exception as e:
        SCANS_DB[scan_id].update({
            "status": "failed",
            "error": str(e)
        })

@app.post("/api/scan/zip")
async def scan_zip(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    apiKey: Optional[str] = Form(None)
):
    """
    Endpoint to upload and scan ZIP repositories.
    """
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported like real mammoth hide!")
        
    scan_id = str(uuid.uuid4())
    SCANS_DB[scan_id] = {
        "id": scan_id,
        "filename": file.filename,
        "status": "uploading",
        "findings": [],
        "scanned_files": 0
    }
    
    # Read ZIP content to memory
    files_data = {}
    temp_dir = tempfile.mkdtemp()
    
    try:
        zip_path = os.path.join(temp_dir, file.filename)
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
            
        # Parse files
        for root, _, filenames in os.walk(temp_dir):
            for filename in filenames:
                # Filter useful source files
                if filename.endswith(('.py', '.js', '.ts', '.tsx', '.jsx', '.html', '.css', '.sql', '.php', '.go', '.rs')):
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            files_data[rel_path] = f.read()
                    except Exception:
                        pass
    finally:
        shutil.rmtree(temp_dir)
        
    if not files_data:
        raise HTTPException(status_code=400, detail="No readable source code files found in ZIP!")
        
    background_tasks.add_task(run_background_code_scan, scan_id, files_data, apiKey)
    return {"scan_id": scan_id, "status": "queued"}

@app.post("/api/scan/url")
async def scan_url(
    request: UrlScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Endpoint to scan website URLs.
    """
    scan_id = str(uuid.uuid4())
    SCANS_DB[scan_id] = {
        "id": scan_id,
        "target_url": request.url,
        "status": "queued",
        "findings": [],
        "scanned_files": 1
    }
    
    # Run mock crawling & web vulnerability checks in background
    def run_url_scan():
        SCANS_DB[scan_id]["status"] = "scanning"
        findings = []
        
        # Attempt to grab security headers
        headers_found = {}
        try:
            req = urllib.request.Request(
                request.url, 
                headers={'User-Agent': 'CodeShieldSecurityScanner/1.0'}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                headers_found = {k.lower(): v for k, v in response.getheaders()}
        except Exception:
            # Fallback to simulation if server is offline
            pass
            
        # Standard security checks
        missing_headers = []
        if 'content-security-policy' not in headers_found:
            missing_headers.append(("Content-Security-Policy (CSP)", "A05:2021-Security Misconfiguration"))
        if 'x-frame-options' not in headers_found:
            missing_headers.append(("X-Frame-Options", "A05:2021-Security Misconfiguration"))
        if 'strict-transport-security' not in headers_found:
            missing_headers.append(("Strict-Transport-Security (HSTS)", "A02:2021-Cryptographic Failures"))
            
        for header_name, category in missing_headers:
            findings.append({
                "id": "CS-WEB-001",
                "name": f"Missing {header_name} Security Header",
                "category": "Infrastructure Security",
                "cwe": "CWE-693",
                "owasp": category,
                "severity": "Medium",
                "file": request.url,
                "line": 0,
                "description": f"The website is missing the {header_name} response header, leaving users vulnerable to clickjacking or cross-site scripting attacks.",
                "code_snippet": f"HTTP GET {request.url}\n>> [Missing Header] {header_name}",
                "vulnerable_code": f"Header: {header_name} is missing",
                "fix_guidance": f"Configure your web server (Nginx, Apache, or cloud CDN) to send the '{header_name}' header in response headers."
            })
            
        # Add a simulated form autocomplete or cookie missing secure flag
        findings.append({
            "id": "CS-WEB-002",
            "name": "Session Cookie Missing Secure & HttpOnly Flags",
            "category": "Authentication Issues",
            "cwe": "CWE-614",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "severity": "High",
            "file": request.url + "/login",
            "line": 0,
            "description": "Session cookies do not have the HttpOnly or Secure flags set, allowing malicious scripts to steal the session token.",
            "code_snippet": "Set-Cookie: session_id=xyz123; Path=/",
            "vulnerable_code": "Set-Cookie: session_id=xyz123; Path=/",
            "fix_guidance": "Add HttpOnly, Secure, and SameSite=Strict flags to all session set-cookie headers."
        })
        
        # Basic URL scanning metrics
        metrics = {
            "overall_score": 78,
            "code_security": 95,
            "authentication": 70,
            "api_security": 85,
            "infrastructure": 60,
            "compliance": 75
        }
        
        threat_model = {
            "attack_surface": f"Public website landing and login pages at {request.url}",
            "potential_threats": [
                "Session hijacking of users via cross-site scripting.",
                "Clickjacking attacks framing the login screen.",
                "MitM (Man-in-the-Middle) snooping due to missing HTTPS/HSTS configuration."
            ],
            "risk_matrix": "Medium",
            "exploitation_scenarios": [
                "Attacker creates an iframe framing the login screen of the target url and tricks user into entering details."
            ],
            "mitigation_plan": "Implement HSTS, configure strong CSP rules, and secure all set-cookie directives."
        }
        
        hardening_recs = [
            "Deploy a Web Application Firewall (WAF) to block bad payloads.",
            "Enforce secure HTTPS redirection for all endpoints.",
            "Enable rate-limiting on forms to prevent brute-forcing login attempts."
        ]
        
        # If Gemini key exists, enrich URL scan details
        if request.apiKey:
            gemini_res = get_gemini_analysis(request.apiKey, findings)
            if "error" not in gemini_res:
                metrics = gemini_res.get("score_breakdown", metrics)
                metrics["overall_score"] = gemini_res.get("overall_score", metrics["overall_score"])
                threat_model = gemini_res.get("threat_modeling", threat_model)
                hardening_recs = gemini_res.get("hardening_recommendations", hardening_recs)
                
                # Merge AI explanation and fixes back to findings
                enriched_findings = gemini_res.get("findings_enrichment", [])
                enrich_map = {(f["file"], f["line"]): f for f in enriched_findings}
                for f in findings:
                    key = (f["file"], f["line"])
                    if key in enrich_map:
                        f["description"] = enrich_map[key].get("explanation", f["description"])
                        f["secure_fix"] = enrich_map[key].get("secure_fix", "")
                        
        SCANS_DB[scan_id].update({
            "status": "completed",
            "metrics": metrics,
            "threat_model": threat_model,
            "hardening": hardening_recs,
            "findings": findings
        })
        
    background_tasks.add_task(run_url_scan)
    return {"scan_id": scan_id, "status": "queued"}

@app.get("/api/scan/{scan_id}")
def get_scan_status(scan_id: str):
    """
    Get the status and findings of a scan.
    """
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan not found!")
    return SCANS_DB[scan_id]

@app.post("/api/chat")
def chat_mentor(request: ChatRequest):
    """
    Chat with the AI Security Mentor.
    """
    response_text = ai_chat_mentor(request.apiKey, request.message)
    return {"response": response_text}

@app.post("/api/autofix")
def generate_autofix(request: AutoFixRequest):
    """
    Generate a secure code fix for the given vulnerable code using Gemini.
    """
    if not request.apiKey:
        # Static mock fix generator fallback
        return {
            "secure_fix": (
                "// [Offline Fix Recommendation]\n"
                "// Always sanitize or use parameterized inputs!\n"
                f"// Fix for vulnerability: {request.vuln_name}\n"
                "// Raw code was: " + request.vulnerable_code
            )
        }
        
    try:
        genai.configure(api_key=request.apiKey)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = (
            f"You are CodeShield AI Secure Code Generator.\n"
            f"Fix this vulnerable code snippet: '{request.vulnerable_code}' which has been flagged as '{request.vuln_name}'.\n"
            "Return ONLY the secure replacement code block. Do not include markdown codeblocks or explanations, just raw secure code."
        )
        
        response = model.generate_content(prompt)
        return {"secure_fix": response.text.strip()}
    except Exception as e:
        return {"secure_fix": f"// Error generating fix: {str(e)}"}

@app.get("/api/scan/{scan_id}/report", response_class=HTMLResponse)
def get_pdf_report(scan_id: str):
    """
    Generate and serve HTML print-friendly report.
    """
    if scan_id not in SCANS_DB or SCANS_DB[scan_id]["status"] != "completed":
        raise HTTPException(status_code=404, detail="Scan not complete or not found!")
        
    scan_data = SCANS_DB[scan_id]
    report_html = generate_html_report(
        scan_data["findings"], 
        scan_data["metrics"], 
        scan_data["threat_model"]
    )
    return report_html
