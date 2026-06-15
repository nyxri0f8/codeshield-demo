import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import JSZip from 'jszip';
import { HelpCircle, Send, ArrowLeft, RefreshCw, Folder, FileCode, Cpu } from 'lucide-react';
import { supabase } from '../lib/supabase';
import type { Finding, IdorEndpoint, ComplianceFlag, Scan } from '../types';
import { Sidebar } from '../components/Sidebar';
import { HealthScoreRing } from '../components/HealthScoreRing';
import { FindingCard } from '../components/FindingCard';
import { IDORTable } from '../components/IDORTable';
import { ComplianceBadge } from '../components/ComplianceBadge';
import { OWASPChart } from '../components/OWASPChart';
import { AttackNarrativeCard } from '../components/AttackNarrativeCard';
import { talkToGemini, checkRateLimit } from '../lib/gemini';
import { useAuth } from '../hooks/useAuth';
import { useGeminiKey } from '../hooks/useGeminiKey';

// Helper to parse concatenated code into individual files
function parseRawCode(rawCode: string | undefined): { [path: string]: string } {
  if (!rawCode) return {};
  const lines = rawCode.split('\n');
  const files: { [path: string]: string } = {};
  
  let currentFile = '';
  let currentContent: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = line.match(/^\/\/ FILE:\s*(.+)$/);
    if (match) {
      if (currentFile) {
        files[currentFile] = currentContent.join('\n');
      }
      currentFile = match[1].trim();
      currentContent = [];
    } else {
      if (!currentFile && line.trim() !== '') {
        currentFile = 'main.js';
      }
      if (currentFile) {
        currentContent.push(line);
      }
    }
  }
  
  if (currentFile) {
    files[currentFile] = currentContent.join('\n');
  }
  
  return files;
}

interface FileTreeNode {
  name: string;
  path: string;
  isDir: boolean;
  children?: FileTreeNode[];
}

function buildFileTree(paths: string[]): FileTreeNode[] {
  const root: FileTreeNode[] = [];
  for (const path of paths) {
    const parts = path.split('/');
    let currentLevel = root;
    let accumulatedPath = '';
    
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      accumulatedPath = accumulatedPath ? `${accumulatedPath}/${part}` : part;
      const isLast = i === parts.length - 1;
      
      let existingNode = currentLevel.find(node => node.name === part && node.isDir === !isLast);
      if (!existingNode) {
        existingNode = {
          name: part,
          path: accumulatedPath,
          isDir: !isLast,
          children: isLast ? undefined : []
        };
        currentLevel.push(existingNode);
      }
      if (!isLast && existingNode.children) {
        currentLevel = existingNode.children;
      }
    }
  }
  
  const sortNodes = (nodes: FileTreeNode[]) => {
    nodes.sort((a, b) => {
      if (a.isDir && !b.isDir) return -1;
      if (!a.isDir && b.isDir) return 1;
      return a.name.localeCompare(b.name);
    });
    nodes.forEach(node => {
      if (node.children) sortNodes(node.children);
    });
  };
  sortNodes(root);
  return root;
}

function applyFixToRawCode(
  rawCode: string | undefined,
  filePath: string,
  vulnerableSnippet: string,
  secureFix: string
): string {
  if (!rawCode) return '';
  const files = parseRawCode(rawCode);
  
  if (files[filePath]) {
    const originalContent = files[filePath];
    if (originalContent.includes(vulnerableSnippet)) {
      files[filePath] = originalContent.replace(vulnerableSnippet, secureFix);
    } else {
      const fileLines = originalContent.split('\n');
      const snippetLines = vulnerableSnippet.split('\n').map(l => l.trim()).filter(Boolean);
      
      let matchIdx = -1;
      if (snippetLines.length > 0) {
        for (let i = 0; i < fileLines.length; i++) {
          if (fileLines[i].trim().includes(snippetLines[0])) {
            let allMatch = true;
            for (let j = 0; j < snippetLines.length; j++) {
              if (i + j >= fileLines.length || !fileLines[i + j].trim().includes(snippetLines[j])) {
                allMatch = false;
                break;
              }
            }
            if (allMatch) {
              matchIdx = i;
              break;
            }
          }
        }
      }
      
      if (matchIdx !== -1) {
        fileLines.splice(matchIdx, snippetLines.length, secureFix);
        files[filePath] = fileLines.join('\n');
      } else {
        files[filePath] = originalContent.replace(vulnerableSnippet.trim(), secureFix);
      }
    }
  }
  
  const recompiled: string[] = [];
  const filePaths = Object.keys(files);
  for (let i = 0; i < filePaths.length; i++) {
    const path = filePaths[i];
    if (path === 'main.js' && filePaths.length === 1 && !rawCode.includes('// FILE:')) {
      recompiled.push(files[path]);
    } else {
      recompiled.push(`// FILE: ${path}`);
      recompiled.push(files[path]);
    }
  }
  return recompiled.join('\n');
}

export default function ScanResultPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const { geminiKey } = useGeminiKey(user?.id);

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [idorEndpoints, setIdorEndpoints] = useState<IdorEndpoint[]>([]);
  const [complianceFlags, setComplianceFlags] = useState<ComplianceFlag[]>([]);
  const [loading, setLoading] = useState(true);

  // Remediation loading states
  const [fixingId, setFixingId] = useState<string | null>(null);

  // Code Explorer state
  const [selectedFile, setSelectedFile] = useState<string>('');
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});
  const [isRescanning, setIsRescanning] = useState(false);

  // Tabs state
  const [activeTab, setActiveTab] = useState<'findings' | 'idor' | 'compliance' | 'charts'>('findings');

  // Chat state
  const [chatInput, setChatInput] = useState('');
  const [chatHistory, setChatHistory] = useState<Array<{ sender: 'user' | 'bot'; text: string }>>([
    { sender: 'bot', text: 'Me CodeShield Security Mentor! Ask me questions about these vulnerabilities or how to apply parameterized remediation blocks.' }
  ]);
  const [isChatLoading, setIsChatLoading] = useState(false);

  useEffect(() => {
    async function loadScanData() {
      if (!id) return;
      try {
        setLoading(true);

        // Demo mode: load from localStorage instead of Supabase
        if (id.startsWith('demo-result-')) {
          const stored = localStorage.getItem(`demo_scan_${id}`);
          if (stored) {
            const { scan: s, findings: f, idor_endpoints: e, compliance_flags: c } = JSON.parse(stored);
            setScan(s);
            setFindings(f);
            setIdorEndpoints(e);
            setComplianceFlags(c);
            
            if (s && s.raw_code) {
              const parsed = parseRawCode(s.raw_code);
              const keys = Object.keys(parsed);
              if (keys.length > 0) setSelectedFile(keys[0]);
            }
          }
          setLoading(false);
          return;
        }

        const [scanRes, findingsRes, idorRes, complianceRes] = await Promise.all([
          supabase.from('scans').select('*').eq('id', id).single(),
          supabase.from('findings').select('*').eq('scan_id', id).order('cvss_score', { ascending: false }),
          supabase.from('idor_endpoints').select('*').eq('scan_id', id),
          supabase.from('compliance_flags').select('*').eq('scan_id', id),
        ]);

        if (scanRes.data) {
          setScan(scanRes.data);
          if (scanRes.data.raw_code) {
            const parsed = parseRawCode(scanRes.data.raw_code);
            const keys = Object.keys(parsed);
            if (keys.length > 0) setSelectedFile(keys[0]);
          }
        }
        if (findingsRes.data) setFindings(findingsRes.data);
        if (idorRes.data) setIdorEndpoints(idorRes.data);
        if (complianceRes.data) setComplianceFlags(complianceRes.data);
      } catch (err) {
        console.error("Failed to load scan details:", err);
      } finally {
        setLoading(false);
      }
    }

    loadScanData();
  }, [id]);

  const handleAutoFix = async (finding: Finding) => {
    if (fixingId) return;

    // Check rate limit
    if (geminiKey) {
      const rateLimit = checkRateLimit();
      if (!rateLimit.allowed) {
        alert(`Rate limit exceeded. Please wait ${rateLimit.waitTimeSec} seconds before requesting a fix.`);
        return;
      }
    }

    setFixingId(finding.id);

    try {
      const prompt = `You are CodeShield AI Secure Code Generator.
Fix this vulnerable code snippet: '${finding.vulnerable_snippet}' which has been flagged as '${finding.title}' in the file '${finding.file_path}'.
Return ONLY the secure replacement code block. Do not include markdown codeblocks or explanations, just raw secure code.`;

      let secureFixText = '';
      if (geminiKey) {
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
          }
        );
        const data = await response.json();
        secureFixText = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "";
      } else {
        // Mock fallback
        secureFixText = `// [Remediated Code Fix]\n// Parameterized database inputs enforce safety filter\n`;
        if (finding.title.includes('Secret')) {
          secureFixText = `const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);`;
        } else if (finding.title.includes('SQL')) {
          secureFixText = `const query = 'SELECT * FROM users WHERE username = $1 AND password = $2';\nconst user = await db.query(query, [username, password]);`;
        } else if (finding.title.includes('IDOR')) {
          secureFixText = `const order = await db.query('SELECT * FROM orders WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);`;
        }
      }

      // Update in Supabase (skip for demo scans)
      if (id && !id.startsWith('demo-result-')) {
        const updatedRawCode = applyFixToRawCode(scan?.raw_code, finding.file_path || 'unknown', finding.vulnerable_snippet || '', secureFixText);

        const { error: findErr } = await supabase
          .from('findings')
          .update({ secure_fix: secureFixText, is_fixed: true })
          .eq('id', finding.id);
        if (findErr) throw findErr;

        const { error: scanErr } = await supabase
          .from('scans')
          .update({ raw_code: updatedRawCode })
          .eq('id', scan?.id);
        if (scanErr) throw scanErr;

        setScan(prev => prev ? { ...prev, raw_code: updatedRawCode } : null);
      } else if (id) {
        // Demo: persist fix and raw_code back to localStorage
        const stored = localStorage.getItem(`demo_scan_${id}`);
        if (stored) {
          const data = JSON.parse(stored);
          data.findings = data.findings.map((f: any) =>
            f.id === finding.id ? { ...f, secure_fix: secureFixText, is_fixed: true } : f
          );
          
          const updatedRawCode = applyFixToRawCode(data.scan.raw_code, finding.file_path || 'unknown', finding.vulnerable_snippet || '', secureFixText);
          data.scan.raw_code = updatedRawCode;

          localStorage.setItem(`demo_scan_${id}`, JSON.stringify(data));
          setScan(data.scan);
        }
      }

      // Update in local state
      setFindings((prev) => 
        prev.map((f) => (f.id === finding.id ? { ...f, secure_fix: secureFixText, is_fixed: true } : f))
      );
    } catch (err: any) {
      alert("Failed to apply secure fix: " + err.message);
    } finally {
      setFixingId(null);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || isChatLoading) return;

    const userMsg = chatInput;
    setChatInput('');
    setChatHistory((prev) => [...prev, { sender: 'user', text: userMsg }]);
    setIsChatLoading(true);

    try {
      let botReply = '';
      if (geminiKey) {
        botReply = await talkToGemini(userMsg, geminiKey, findings);
      } else {
        // Fallback local mock answers
        await new Promise((r) => setTimeout(r, 600));
        const lower = userMsg.toLowerCase();
        if (lower.includes('sql') || lower.includes('injection')) {
          botReply = `**SQL Injection** occurs when unsanitized input is parsed as code. Parameterize your statements like this:\n\n\`\`\`javascript\ndb.query('SELECT * FROM users WHERE id = $1', [userId]);\n\`\`\``;
        } else if (lower.includes('secret') || lower.includes('stripe')) {
          botReply = `**Hardcoded credentials** leak access tokens. Inject variables via system environments:\n\n\`\`\`javascript\nconst key = process.env.API_KEY;\n\`\`\``;
        } else {
          botReply = `Me smart caveman security bot! Ask me about XSS, credentials leakage, or IDOR. Add Gemini key to settings for expert responses.`;
        }
      }

      setChatHistory((prev) => [...prev, { sender: 'bot', text: botReply }]);
    } catch (err) {
      setChatHistory((prev) => [...prev, { sender: 'bot', text: 'Connection to AI mentor failed.' }]);
    } finally {
      setIsChatLoading(false);
    }
  };

  const inspectSource = (file: string, line?: number) => {
    setSelectedFile(file);
    if (line !== undefined) {
      setHighlightedLine(line);
    } else {
      setHighlightedLine(null);
    }
  };

  useEffect(() => {
    if (highlightedLine !== null) {
      const timer = setTimeout(() => {
        const element = document.getElementById(`code-line-${highlightedLine}`);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [highlightedLine, selectedFile]);

  const toggleDirectory = (path: string) => {
    setExpandedPaths(prev => ({ ...prev, [path]: !prev[path] }));
  };

  const renderNode = (node: FileTreeNode, depth = 0) => {
    const isExpanded = expandedPaths[node.path] ?? true;
    
    if (node.isDir) {
      return (
        <div key={node.path} style={{ marginLeft: `${depth * 8}px` }}>
          <div 
            onClick={() => toggleDirectory(node.path)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 6px',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.75rem',
              color: 'var(--text-secondary)',
              userSelect: 'none'
            }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            <span style={{
              fontSize: '0.55rem',
              transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
              transition: 'transform 0.15s',
              marginRight: '2px',
              color: 'var(--text-muted)'
            }}>▶</span>
            <Folder size={12} className="text-cyan-500" style={{ flexShrink: 0 }} />
            <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.name}</span>
          </div>
          {isExpanded && node.children?.map(child => renderNode(child, depth + 1))}
        </div>
      );
    } else {
      const isSelected = selectedFile === node.path;
      return (
        <div 
          key={node.path}
          onClick={() => {
            setSelectedFile(node.path);
            setHighlightedLine(null);
          }}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 6px',
            marginLeft: `${depth * 8 + 10}px`,
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '0.75rem',
            color: isSelected ? 'var(--cyan-primary)' : 'var(--text-secondary)',
            background: isSelected ? 'rgba(6, 182, 212, 0.08)' : 'transparent',
            borderLeft: isSelected ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            userSelect: 'none'
          }}
          onMouseEnter={(e) => {
            if (!isSelected) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
          }}
          onMouseLeave={(e) => {
            if (!isSelected) e.currentTarget.style.background = 'transparent';
          }}
        >
          <FileCode size={12} className={isSelected ? 'text-cyan-400' : 'text-slate-400'} style={{ flexShrink: 0 }} />
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.name}</span>
        </div>
      );
    }
  };

  const handleFixAndRescan = async () => {
    if (isRescanning || !scan || findings.length === 0) return;
    setIsRescanning(true);

    try {
      // 1. Generate fixes for all findings
      let updatedRawCode = scan.raw_code || '';
      
      const findingsWithFixes = findings.map((f) => {
        if (f.secure_fix) return f;
        
        let fixText = `// [Remediated Code Fix]\n`;
        if (f.title.includes('Secret')) {
          fixText = `const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);`;
        } else if (f.title.includes('SQL')) {
          fixText = `const query = 'SELECT * FROM users WHERE username = $1 AND password = $2';\nconst user = await db.query(query, [username, password]);`;
        } else if (f.title.includes('IDOR')) {
          fixText = `const order = await db.query('SELECT * FROM orders WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);`;
        } else if (f.title.includes('eval')) {
          fixText = `// Remediated: Avoid eval/exec\n// const result = safeEval(code);`;
        } else if (f.title.includes('Console')) {
          fixText = `console.info('Operation successfully authenticated.');`;
        } else if (f.title.includes('Catch')) {
          fixText = `catch (err) {\n  console.error('Operation failed:', err);\n  res.status(500).send('Internal server error');\n}`;
        } else if (f.title.includes('Limit')) {
          fixText = `const rateLimit = require('express-rate-limit');\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });\nrouter.post('/login', loginLimiter, loginHandler);`;
        } else {
          fixText = `// Remediated: Secure boundary filters implemented\n`;
        }
        return { ...f, secure_fix: fixText };
      });

      // Apply all fixes to the raw code
      for (const f of findingsWithFixes) {
        updatedRawCode = applyFixToRawCode(updatedRawCode, f.file_path || 'unknown', f.vulnerable_snippet || '', f.secure_fix || '');
      }

      // 2. Re-run analysis on the updated raw code
      const { runStaticAnalysis: analyzeFn, generateStaticResult: resultFn } = await import('../lib/analyzer');
      const newStaticFindings = analyzeFn(updatedRawCode);
      
      let geminiResult;
      if (geminiKey) {
        try {
          const { analyzeWithGemini } = await import('../lib/gemini');
          geminiResult = await analyzeWithGemini(updatedRawCode, geminiKey, newStaticFindings);
        } catch {
          geminiResult = resultFn(newStaticFindings, updatedRawCode);
        }
      } else {
        geminiResult = resultFn(newStaticFindings, updatedRawCode);
      }

      const { calculateScore, calculateProjectedScore } = await import('../lib/scoreCalc');
      const { score, grade } = calculateScore(geminiResult.findings || []);
      const { score: projectedScore } = calculateProjectedScore(geminiResult.findings || []);

      // 3. Save the updated scan and findings
      if (id && !id.startsWith('demo-result-')) {
        await Promise.all([
          supabase.from('findings').delete().eq('scan_id', id),
          supabase.from('idor_endpoints').delete().eq('scan_id', id),
          supabase.from('compliance_flags').delete().eq('scan_id', id)
        ]);

        if (geminiResult.findings?.length) {
          const findingsRows = geminiResult.findings.map((f: any) => ({
            scan_id: id,
            title: f.title,
            description: f.description,
            severity: f.severity,
            cvss_score: f.cvss_score,
            owasp_category: f.owasp_category,
            cwe_id: f.cwe_id,
            vulnerable_snippet: f.vulnerable_snippet,
            secure_fix: f.secure_fix,
            fix_recommendation: f.fix_recommendation,
            impact_analysis: f.impact_analysis,
            attack_narrative: f.attack_narrative,
            file_path: f.file_path || 'unknown',
            line_number: f.line_number || 1,
            is_ai_smell: f.is_ai_smell || false,
            is_fixed: false
          }));
          await supabase.from('findings').insert(findingsRows);
        }

        if (geminiResult.idor_endpoints?.length) {
          const idorRows = geminiResult.idor_endpoints.map((e: any) => ({
            scan_id: id,
            endpoint: e.endpoint,
            method: e.method,
            risk_level: e.risk_level,
            has_auth_check: e.has_auth_check,
            has_ownership_check: e.has_ownership_check,
            reasoning: e.reasoning,
            line_number: e.line_number || 1
          }));
          await supabase.from('idor_endpoints').insert(idorRows);
        }

        if (geminiResult.compliance_flags?.length) {
          const compRows = geminiResult.compliance_flags.map((c: any) => ({
            scan_id: id,
            framework: c.framework,
            risk_level: c.risk_level,
            reason: c.reason
          }));
          await supabase.from('compliance_flags').insert(compRows);
        }

        await supabase
          .from('scans')
          .update({
            raw_code: updatedRawCode,
            overall_score: score,
            projected_score: projectedScore,
            grade
          })
          .eq('id', id);

        const [scanRes, findingsRes, idorRes, complianceRes] = await Promise.all([
          supabase.from('scans').select('*').eq('id', id).single(),
          supabase.from('findings').select('*').eq('scan_id', id).order('cvss_score', { ascending: false }),
          supabase.from('idor_endpoints').select('*').eq('scan_id', id),
          supabase.from('compliance_flags').select('*').eq('scan_id', id),
        ]);

        if (scanRes.data) setScan(scanRes.data);
        if (findingsRes.data) setFindings(findingsRes.data);
        if (idorRes.data) setIdorEndpoints(idorRes.data);
        if (complianceRes.data) setComplianceFlags(complianceRes.data);
      } else if (id) {
        const demoScanData = {
          scan: {
            id,
            user_id: 'demo-123',
            project_name: scan.project_name,
            source_type: scan.source_type,
            status: 'done' as const,
            overall_score: score,
            projected_score: projectedScore,
            grade,
            raw_code: updatedRawCode,
            created_at: scan.created_at,
          } as Scan,
          findings: (geminiResult.findings || []).map((f: any, i: number) => ({ ...f, id: f.id || `df-${i}`, scan_id: id, is_fixed: false })),
          idor_endpoints: (geminiResult.idor_endpoints || []).map((e: any, i: number) => ({ ...e, id: e.id || `de-${i}`, scan_id: id })),
          compliance_flags: (geminiResult.compliance_flags || []).map((c: any, i: number) => ({ ...c, id: c.id || `dc-${i}`, scan_id: id })),
        };

        localStorage.setItem(`demo_scan_${id}`, JSON.stringify(demoScanData));
        setScan(demoScanData.scan);
        setFindings(demoScanData.findings);
        setIdorEndpoints(demoScanData.idor_endpoints);
        setComplianceFlags(demoScanData.compliance_flags);
      }

      alert("Vulnerabilities fixed and code rescanned successfully!");
    } catch (err: any) {
      alert("Failed to fix and rescan: " + err.message);
    } finally {
      setIsRescanning(false);
    }
  };

  const handleDownloadZip = async () => {
    if (!scan || !scan.raw_code) return;
    
    try {
      const zip = new JSZip();
      const files = parseRawCode(scan.raw_code);
      const filePaths = Object.keys(files);
      
      if (filePaths.length === 0) {
        alert("No files found to package.");
        return;
      }
      
      for (const path of filePaths) {
        zip.file(path, files[path]);
      }
      
      const content = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(content);
      
      const link = document.createElement('a');
      link.href = url;
      const sanitizedName = scan.project_name.toLowerCase().replace(/\s+/g, '_');
      link.download = `${sanitizedName}_fixed_code.zip`;
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert("Failed to generate ZIP archive: " + err.message);
    }
  };

  const handleExportReport = () => {
    if (!scan) return;
    
    // Replace </script> with <\/script> to prevent breaking the generated HTML script block
    const findingsJson = JSON.stringify(findings).replace(/<\/script>/g, '<\\/script>');
    const idorJson = JSON.stringify(idorEndpoints).replace(/<\/script>/g, '<\\/script>');
    const complianceJson = JSON.stringify(complianceFlags).replace(/<\/script>/g, '<\\/script>');
    
    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeShield Security Audit Report: ${scan.project_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
        
        :root {
            --bg-main: #030305;
            --bg-card: rgba(8, 8, 12, 0.75);
            --border-glass: rgba(255, 255, 255, 0.06);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #475569;
            --cyan-primary: #06b6d4;
            --cyan-light: rgba(6, 182, 212, 0.08);
            --rose-primary: #f43f5e;
            --rose-light: rgba(244, 63, 94, 0.08);
            --orange-primary: #f97316;
            --orange-light: rgba(249, 115, 22, 0.08);
            --emerald-primary: #10b981;
            --emerald-light: rgba(16, 185, 129, 0.08);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            background-color: var(--bg-main);
            color: var(--text-primary);
            font-family: 'Plus Jakarta Sans', sans-serif;
            padding: 40px;
            line-height: 1.5;
            position: relative;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .ambient-glow-1 {
            position: absolute;
            top: -10%;
            left: -10%;
            width: 600px;
            height: 600px;
            background: radial-gradient(circle, rgba(6, 182, 212, 0.05) 0%, transparent 70%);
            z-index: -1;
            pointer-events: none;
        }
        .ambient-glow-2 {
            position: absolute;
            bottom: -10%;
            right: -10%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(244, 63, 94, 0.03) 0%, transparent 70%);
            z-index: -1;
            pointer-events: none;
        }
        
        .container {
            max-width: 1300px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-glass);
            padding-bottom: 24px;
            margin-bottom: 36px;
        }
        
        .header-title h1 {
            font-size: 2.2rem;
            font-weight: 800;
            letter-spacing: -0.03em;
        }
        
        .header-title p {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-top: 4px;
        }
        
        .badge {
            background: var(--cyan-light);
            color: var(--cyan-primary);
            border: 1px solid rgba(6, 182, 212, 0.2);
            font-size: 0.65rem;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 99px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            display: inline-block;
        }
        
        .outer-card {
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.01) 100%);
            padding: 1px;
            border-radius: 20px;
            box-shadow: 0 16px 40px rgba(0,0,0,0.5);
            margin-bottom: 24px;
        }
        
        .inner-card {
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 19px;
            padding: 24px;
            backdrop-filter: blur(20px);
        }
        
        .kpi-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 28px;
        }
        
        @media (max-width: 900px) {
            .kpi-row {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        @media (max-width: 550px) {
            .kpi-row {
                grid-template-columns: 1fr;
            }
        }
        
        .kpi-label {
            font-size: 0.65rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
            font-weight: 700;
        }
        
        .kpi-value {
            font-size: 2.2rem;
            font-weight: 800;
            margin-top: 6px;
            letter-spacing: -0.02em;
        }
        
        .kpi-sub {
            font-size: 0.7rem;
            color: var(--text-muted);
            margin-top: 4px;
        }

        .chart-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }
        
        @media (max-width: 800px) {
            .chart-row {
                grid-template-columns: 1fr;
            }
        }

        .chart-card-inner {
            height: 320px;
            display: flex;
            flex-direction: column;
        }
        
        .chart-card-inner h3 {
            font-size: 0.85rem;
            font-weight: 700;
            margin-bottom: 20px;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .chart-container {
            flex: 1;
            position: relative;
        }

        .compliance-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }

        .compliance-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-glass);
            border-radius: 12px;
            padding: 16px;
        }

        .compliance-info h4 {
            font-size: 0.85rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .compliance-info p {
            font-size: 0.7rem;
            color: var(--text-secondary);
            margin-top: 4px;
        }
        
        .filters-bar {
            display: flex;
            gap: 16px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-glass);
            padding: 16px 24px;
            border-radius: 16px;
            margin-bottom: 24px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .filter-group label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .filter-group select, .filter-group input {
            background: rgba(5, 5, 8, 0.8);
            border: 1px solid var(--border-glass);
            color: var(--text-primary);
            padding: 8px 16px;
            border-radius: 99px;
            font-size: 0.75rem;
            outline: none;
            cursor: pointer;
        }
        
        .table-card {
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }
        
        th {
            padding: 14px 24px;
            font-size: 0.65rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            font-weight: 700;
            border-bottom: 2px solid var(--border-glass);
            cursor: pointer;
            user-select: none;
        }
        
        th:hover {
            color: var(--text-primary);
        }
        
        td {
            padding: 16px 24px;
            font-size: 0.8rem;
            border-bottom: 1px solid var(--border-glass);
            color: var(--text-secondary);
        }

        .finding-row {
            cursor: pointer;
            transition: background 0.2s;
        }

        .finding-row:hover td {
            background: rgba(255, 255, 255, 0.015);
        }

        .finding-row.expanded td {
            border-bottom: none;
            background: rgba(255, 255, 255, 0.01);
        }
        
        .sev-badge {
            font-size: 0.6rem;
            font-weight: 700;
            padding: 3px 10px;
            border-radius: 99px;
            text-transform: uppercase;
            display: inline-block;
            letter-spacing: 0.05em;
        }
        .sev-badge.critical { background: var(--rose-light); color: var(--rose-primary); border: 1px solid rgba(244,63,94,0.15); }
        .sev-badge.high { background: var(--orange-light); color: var(--orange-primary); border: 1px solid rgba(249,115,22,0.15); }
        .sev-badge.medium { background: rgba(234, 179, 8, 0.08); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.15); }
        .sev-badge.low { background: var(--cyan-light); color: var(--cyan-primary); border: 1px solid rgba(6,182,212,0.15); }
        .sev-badge.informational { background: rgba(255, 255, 255, 0.05); color: var(--text-secondary); border: 1px solid rgba(255,255,255,0.1); }

        .detail-expanded-row td {
            padding: 0 24px 24px;
            background: rgba(255, 255, 255, 0.01);
            animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .detail-wrapper {
            background: rgba(3, 3, 5, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 16px;
            padding: 24px;
            display: grid;
            grid-template-columns: 1.2fr 1fr;
            gap: 24px;
        }

        @media (max-width: 900px) {
            .detail-wrapper {
                grid-template-columns: 1fr;
            }
        }

        .detail-info {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .detail-section-title {
            font-size: 0.62rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
            font-weight: 800;
            margin-bottom: 4px;
        }

        .detail-text {
            font-size: 0.78rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        .code-container {
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .code-block-wrap h5 {
            font-size: 0.65rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 6px;
        }
        .code-block-wrap.vulnerable h5 { color: var(--rose-primary); }
        .code-block-wrap.secure h5 { color: var(--emerald-primary); }

        .code-box {
            font-family: 'JetBrains Mono', monospace;
            background: #030305;
            padding: 14px;
            border-radius: 10px;
            font-size: 0.72rem;
            white-space: pre-wrap;
            border: 1px solid rgba(255, 255, 255, 0.03);
            overflow-x: auto;
            line-height: 1.4;
            max-height: 200px;
            overflow-y: auto;
        }
        .code-box.vulnerable {
            border-left: 2px solid var(--rose-primary);
            color: #fca5a5;
        }
        .code-box.secure {
            border-left: 2px solid var(--emerald-primary);
            color: #a7f3d0;
        }
    </style>
</head>
<body>
    <div class="ambient-glow-1"></div>
    <div class="ambient-glow-2"></div>

    <div class="container">
        <header>
            <div class="header-title">
                <span class="badge">Security Posture Report</span>
                <h1 style="margin-top: 8px;">${scan.project_name}</h1>
                <p>AI-assisted codebase auditing powered by CodeShield X | Generated ${new Date().toLocaleString()}</p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 2.6rem; font-weight: 800; color: var(--cyan-primary); line-height: 1.1;">${scan.overall_score}%</div>
                <div style="font-size: 0.65rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; margin-top: 4px;">Health Grade: ${scan.grade}</div>
            </div>
        </header>

        <section class="kpi-row">
            <div class="outer-card">
                <div class="inner-card">
                    <div class="kpi-label">Health Rating</div>
                    <div class="kpi-value" id="kpi-score" style="color: var(--cyan-primary);">${scan.overall_score}%</div>
                    <div class="kpi-sub">Overall security index</div>
                </div>
            </div>
            <div class="outer-card">
                <div class="inner-card">
                    <div class="kpi-label">Remediated Target</div>
                    <div class="kpi-value" id="kpi-projected" style="color: var(--emerald-primary);">${scan.projected_score || scan.overall_score}%</div>
                    <div class="kpi-sub">Score after fixing criticals</div>
                </div>
            </div>
            <div class="outer-card">
                <div class="inner-card">
                    <div class="kpi-label">Active Findings</div>
                    <div class="kpi-value" id="kpi-findings">0</div>
                    <div class="kpi-sub">Vulnerabilities remaining</div>
                </div>
            </div>
            <div class="outer-card">
                <div class="inner-card">
                    <div class="kpi-label">High-Risk Threats</div>
                    <div class="kpi-value" id="kpi-threats" style="color: var(--rose-primary);">0</div>
                    <div class="kpi-sub">Critical & high severity</div>
                </div>
            </div>
        </section>

        <section class="chart-row">
            <div class="outer-card">
                <div class="inner-card chart-card-inner">
                    <h3>Vulnerabilities by Severity</h3>
                    <div class="chart-container">
                        <canvas id="severity-chart"></canvas>
                    </div>
                </div>
            </div>
            <div class="outer-card">
                <div class="inner-card chart-card-inner">
                    <h3>Distribution by OWASP Category</h3>
                    <div class="chart-container">
                        <canvas id="category-chart"></canvas>
                    </div>
                </div>
            </div>
        </section>

        <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.08em;">Compliance Posture</h3>
        <section class="compliance-grid" id="compliance-container">
        </section>

        <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.08em;">Detailed Vulnerabilities Registry</h3>
        
        <div class="filters-bar">
            <div class="filter-group">
                <label for="filter-severity">Severity</label>
                <select id="filter-severity" onchange="applyFilters()">
                    <option value="all">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Informational">Informational</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="filter-owasp">OWASP Category</label>
                <select id="filter-owasp" onchange="applyFilters()">
                    <option value="all">All Categories</option>
                </select>
            </div>
            <div class="filter-group" style="margin-left: auto;">
                <input type="text" id="filter-search" placeholder="Search vulnerabilities..." oninput="applyFilters()" style="width: 200px; padding: 8px 16px;" />
            </div>
        </div>

        <div class="outer-card table-card">
            <div class="inner-card" style="padding: 0;">
                <table id="findings-table">
                    <thead>
                        <tr>
                            <th onclick="sortTable('severity')" style="width: 15%;">Severity</th>
                            <th onclick="sortTable('title')" style="width: 45%;">Vulnerability Title</th>
                            <th onclick="sortTable('file_path')" style="width: 25%;">File Path</th>
                            <th onclick="sortTable('line_number')" style="width: 8%;">Line</th>
                            <th onclick="sortTable('cvss_score')" style="width: 7%;">CVSS</th>
                        </tr>
                    </thead>
                    <tbody id="table-body">
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const FINDINGS = ${findingsJson};
        const IDOR = ${idorJson};
        const COMPLIANCE = ${complianceJson};

        document.getElementById('kpi-findings').textContent = FINDINGS.length;
        
        const threatsCount = FINDINGS.filter(f => f.severity === 'Critical' || f.severity === 'High').length;
        document.getElementById('kpi-threats').textContent = threatsCount;

        const compContainer = document.getElementById('compliance-container');
        if (COMPLIANCE.length === 0) {
            compContainer.innerHTML = '<div class="compliance-item" style="grid-column: 1/-1; justify-content: center; color: var(--text-secondary);">No compliance flags recorded.</div>';
        } else {
            COMPLIANCE.forEach(c => {
                const badgeColor = c.risk_level === 'Critical' ? 'var(--rose-primary)' : c.risk_level === 'High' ? 'var(--orange-primary)' : '#eab308';
                compContainer.innerHTML += \`
                    <div class="compliance-item">
                        <div class="compliance-info">
                            <h4>\${c.framework || 'Framework Evaluation'}</h4>
                            <p>\${c.reason || 'No compliance violations observed.'}</p>
                        </div>
                        <span class="sev-badge" style="background: rgba(255,255,255,0.03); color: \${badgeColor}; border: 1px solid \${badgeColor}50;">
                            \${c.risk_level} Risk
                        </span>
                    </div>
                \`;
            });
        }

        const owaspSelect = document.getElementById('filter-owasp');
        const uniqueOwasp = [...new Set(FINDINGS.map(f => f.owasp_category).filter(Boolean))].sort();
        uniqueOwasp.forEach(cat => {
            const opt = document.createElement('option');
            opt.value = cat;
            opt.textContent = cat;
            owaspSelect.appendChild(opt);
        });

        let severityChart, categoryChart;

        function initCharts(data) {
            const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
            const catCounts = {};

            data.forEach(f => {
                if (f.severity in sevCounts) sevCounts[f.severity]++;
                if (f.owasp_category) {
                    catCounts[f.owasp_category] = (catCounts[f.owasp_category] || 0) + 1;
                }
            });

            const sevCtx = document.getElementById('severity-chart').getContext('2d');
            severityChart = new Chart(sevCtx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(sevCounts),
                    datasets: [{
                        data: Object.values(sevCounts),
                        backgroundColor: ['#f43f5e', '#f97316', '#eab308', '#06b6d4', '#64748b'],
                        borderColor: '#030305',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { 
                            position: 'right', 
                            labels: { color: '#f8fafc', font: { family: 'Plus Jakarta Sans', size: 11 } } 
                        }
                    }
                }
            });

            const catCtx = document.getElementById('category-chart').getContext('2d');
            categoryChart = new Chart(catCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(catCounts),
                    datasets: [{
                        data: Object.values(catCounts),
                        backgroundColor: 'rgba(6, 182, 212, 0.4)',
                        borderColor: '#06b6d4',
                        borderWidth: 1.5,
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { 
                            beginAtZero: true,
                            grid: { color: 'rgba(255,255,255,0.04)' },
                            ticks: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 10 } } 
                        },
                        x: { 
                            grid: { display: false },
                            ticks: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 10 } } 
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        let filteredFindings = [...FINDINGS];
        let expandedFindingId = null;

        function renderTable(data) {
            const tbody = document.getElementById('table-body');
            tbody.innerHTML = '';
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 40px; color:#64748b;">No matching findings found.</td></tr>';
                return;
            }

            data.forEach(f => {
                const isExpanded = expandedFindingId === f.id;
                const tr = document.createElement('tr');
                tr.className = 'finding-row' + (isExpanded ? ' expanded' : '');
                tr.onclick = (e) => {
                    if (e.target.closest('.code-box') || e.target.closest('a')) return;
                    toggleRow(f.id);
                };
                
                tr.innerHTML = \`
                    <td><span class="sev-badge \${f.severity.toLowerCase()}">\${f.severity}</span></td>
                    <td style="font-weight: 600; color: #f8fafc;">
                        \${f.title}
                        <div style="font-size:0.75rem; color:#94a3b8; font-weight:400; margin-top:2px;">\${f.owasp_category || 'General Security'}</div>
                    </td>
                    <td style="font-family:'JetBrains Mono', monospace; color:#06b6d4; font-size:0.75rem;">\${f.file_path || 'unknown'}</td>
                    <td style="font-family:'JetBrains Mono', monospace;">\${f.line_number || 1}</td>
                    <td style="font-weight:700; color: \${getScoreColor(f.cvss_score || 0)};">\${f.cvss_score !== undefined ? f.cvss_score.toFixed(1) : '0.0'}</td>
                \`;
                tbody.appendChild(tr);

                if (isExpanded) {
                    const expandTr = document.createElement('tr');
                    expandTr.className = 'detail-expanded-row';
                    
                    const parseNarrative = (text) => {
                        const plainText = text || '';
                        const partsArray = [];
                        
                        const attackMatch = plainText.match(/\\\[Attack Performed\\\]\\s*([^\\\[]+)/);
                        const changeMatch = plainText.match(/\\\[System Change\\\]\\s*([^\\\[]+)/);
                        const accessMatch = plainText.match(/\\\[Access Gained\\\]\\s*([^\\\[]+)/);
                        const recMatch = plainText.match(/\\\[Recommendation\\\]\\s*([^\\\[]+)/);

                        if (attackMatch) partsArray.push({ label: 'Attack Performed', content: attackMatch[1].trim() });
                        if (changeMatch) partsArray.push({ label: 'System Change', content: changeMatch[1].trim() });
                        if (accessMatch) partsArray.push({ label: 'Access Gained', content: accessMatch[1].trim() });
                        if (recMatch) partsArray.push({ label: 'Recommendation', content: recMatch[1].trim() });

                        if (partsArray.length === 0) {
                            return [{ label: 'Threat Narrative', content: plainText }];
                        }
                        return partsArray;
                    };

                    const narrativeHtml = parseNarrative(f.attack_narrative).map(part => \`
                        <div style="margin-top: 6px;">
                            <span style="color: var(--rose-primary); font-weight: 700; text-transform: uppercase; font-size: 0.58rem; letter-spacing: 0.05em; display: inline-block; min-width: 120px;">\${part.label}</span>
                            <span style="color: var(--text-secondary); font-size: 0.75rem;">\${part.content}</span>
                        </div>
                    \`).join('');

                    expandTr.innerHTML = \`
                        <td colspan="5">
                            <div class="detail-wrapper">
                                <div class="detail-info">
                                    <div>
                                        <div class="detail-section-title">Description</div>
                                        <div class="detail-text">\${f.description || 'No descriptive context recorded.'}</div>
                                    </div>
                                    <div>
                                        <div class="detail-section-title">Impact Analysis</div>
                                        <div class="detail-text">\${f.impact_analysis || 'Exploiting this flaw could compromise system integrity and user access levels.'}</div>
                                    </div>
                                    \${f.attack_narrative ? \`
                                    <div>
                                        <div class="detail-section-title">Breach Narrative Simulation</div>
                                        <div style="background: rgba(244, 63, 94, 0.02); padding: 12px; border-radius: 8px; border: 1px solid rgba(244,63,94,0.08);">
                                            \${narrativeHtml}
                                        </div>
                                    </div>
                                    \` : ''}
                                    <div>
                                        <div class="detail-section-title">Remediation Steps</div>
                                        <div class="detail-text" style="color: var(--text-primary); font-weight: 500;">\${f.fix_recommendation || 'Apply parameterized inputs and perform boundary validation reviews.'}</div>
                                    </div>
                                </div>
                                <div class="code-container">
                                    \${f.vulnerable_snippet ? \`
                                    <div class="code-block-wrap vulnerable">
                                        <h5>Vulnerable Code Snippet</h5>
                                        <div class="code-box vulnerable">\${escapeHtml(f.vulnerable_snippet)}</div>
                                    </div>
                                    \` : ''}
                                    
                                    \${f.secure_fix ? \`
                                    <div class="code-block-wrap secure">
                                        <h5>Remediated Secure Code</h5>
                                        <div class="code-box secure">\${escapeHtml(f.secure_fix)}</div>
                                    </div>
                                    \` : ''}
                                </div>
                            </div>
                        </td>
                    \`;
                    tbody.appendChild(expandTr);
                }
            });
        }

        function escapeHtml(string) {
            return String(string).replace(/[&<>"']/g, function (s) {
                return {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#39;'
                }[s];
            });
        }

        function toggleRow(id) {
            if (expandedFindingId === id) {
                expandedFindingId = null;
            } else {
                expandedFindingId = id;
            }
            renderTable(filteredFindings);
        }

        function getScoreColor(cvss) {
            if (cvss >= 8.0) return 'var(--rose-primary)';
            if (cvss >= 5.0) return 'var(--orange-primary)';
            if (cvss >= 3.0) return '#eab308';
            return 'var(--cyan-primary)';
        }

        function applyFilters() {
            const sev = document.getElementById('filter-severity').value;
            const cat = document.getElementById('filter-owasp').value;
            const query = document.getElementById('filter-search').value.toLowerCase().trim();

            filteredFindings = FINDINGS.filter(f => {
                if (sev !== 'all' && f.severity !== sev) return false;
                if (cat !== 'all' && f.owasp_category !== cat) return false;
                if (query) {
                    const matchTitle = f.title.toLowerCase().includes(query);
                    const matchDesc = (f.description || '').toLowerCase().includes(query);
                    const matchFile = (f.file_path || '').toLowerCase().includes(query);
                    if (!matchTitle && !matchDesc && !matchFile) return false;
                }
                return true;
            });

            expandedFindingId = null;
            renderTable(filteredFindings);

            const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
            const catCounts = {};
            filteredFindings.forEach(f => {
                if (f.severity in sevCounts) sevCounts[f.severity]++;
                if (f.owasp_category) {
                    catCounts[f.owasp_category] = (catCounts[f.owasp_category] || 0) + 1;
                }
            });

            severityChart.data.datasets[0].data = Object.values(sevCounts);
            severityChart.update();

            categoryChart.data.labels = Object.keys(catCounts);
            categoryChart.data.datasets[0].data = Object.values(catCounts);
            categoryChart.update();
        }

        let sortCol = 'cvss_score';
        let sortAsc = false;
        function sortTable(field) {
            if (sortCol === field) {
                sortAsc = !sortAsc;
            } else {
                sortCol = field;
                sortAsc = true;
            }

            const sorted = [...filteredFindings].sort((a, b) => {
                let aVal = a[field] || '';
                let bVal = b[field] || '';
                
                if (field === 'cvss_score' || field === 'line_number') {
                    aVal = parseFloat(aVal) || 0;
                    bVal = parseFloat(bVal) || 0;
                }
                
                if (aVal < bVal) return sortAsc ? -1 : 1;
                if (aVal > bVal) return sortAsc ? 1 : -1;
                return 0;
            });
            renderTable(sorted);
        }

        initCharts(FINDINGS);
        renderTable(FINDINGS);
    </script>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${scan.project_name.toLowerCase().replace(/\s+/g, '_')}_security_report.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', minHeight: '100vh', background: '#050508' }}>
        <Sidebar />
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#050508' }}>
      <Sidebar />

      <main style={{ flex: 1, padding: '40px', overflowY: 'auto' }}>
        
        {/* Header Breadcrumb */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '24px', textAlign: 'left' }}>
          <Link to="/dashboard" style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none', fontSize: '0.8rem' }}>
            <ArrowLeft size={14} /> Back to Dashboard
          </Link>
        </div>

        {/* Audit Details */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px', marginBottom: '32px', textAlign: 'left' }}>
          <div>
            <h1 className="logo-title" style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Audit Report: {scan?.project_name}
            </h1>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Source type: <span style={{ color: 'var(--cyan-primary)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>{scan?.source_type}</span> | Scanned on: {scan?.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
            </p>
            <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
              <button
                onClick={handleExportReport}
                style={{
                  background: 'rgba(255, 255, 255, 0.04)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  color: 'var(--text-primary)',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  padding: '8px 16px',
                  borderRadius: '99px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  transition: 'background 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)'}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
                </svg>
                Export Interactive Dashboard
              </button>

              <button
                onClick={handleFixAndRescan}
                disabled={findings.length === 0 || isRescanning}
                style={{
                  background: 'linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)',
                  border: 'none',
                  color: '#000',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  padding: '8px 20px',
                  borderRadius: '99px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  opacity: findings.length === 0 || isRescanning ? 0.6 : 1,
                  transition: 'opacity 0.2s'
                }}
              >
                <Cpu size={14} className={isRescanning ? 'animate-spin' : ''} />
                {isRescanning ? 'Fixing & Rescanning...' : 'One-Click Fix & Rescan'}
              </button>

              <button
                onClick={handleDownloadZip}
                disabled={!scan?.raw_code}
                style={{
                  background: 'rgba(255, 255, 255, 0.04)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  color: 'var(--text-primary)',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  padding: '8px 16px',
                  borderRadius: '99px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  transition: 'background 0.2s',
                  opacity: !scan?.raw_code ? 0.5 : 1
                }}
                onMouseEnter={(e) => !(!scan?.raw_code) && (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)')}
                onMouseLeave={(e) => !(!scan?.raw_code) && (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)')}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
                </svg>
                Download Fixed ZIP
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
            {scan?.overall_score !== undefined && scan?.grade && (
              <HealthScoreRing score={scan.overall_score} grade={scan.grade} size={110} strokeWidth={8} />
            )}
          </div>
        </div>

        {/* Interactive Recharts visual matrix */}
        <div style={{ marginBottom: '32px' }}>
          <OWASPChart findings={findings} />
        </div>

        {/* Narrative Threat Simulator */}
        <div style={{ marginBottom: '32px' }}>
          <AttackNarrativeCard findings={findings} />
        </div>

        {/* Split workspace for Code Explorer & Detailed Findings */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '24px', alignItems: 'stretch', marginBottom: '32px' }}>
          {/* Left Column: Code Explorer */}
          <div className="double-bezel-outer" style={{ display: 'flex', flexDirection: 'column' }}>
            <div className="double-bezel-inner" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px', minHeight: '550px' }}>
              <span className="section-tag cyan">Code explorer</span>
              <h2 className="panel-title" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', textAlign: 'left' }}>
                <Folder size={18} className="text-cyan-400" /> Source Workspace
              </h2>
              
              <div style={{ display: 'flex', gap: '20px', flex: 1, height: '100%' }}>
                {/* File Tree Column */}
                <div style={{
                  width: '180px',
                  borderRight: '1px solid var(--border-glass)',
                  paddingRight: '12px',
                  overflowY: 'auto',
                  maxHeight: '450px',
                  textAlign: 'left'
                }}>
                  {Object.keys(parseRawCode(scan?.raw_code)).length === 0 ? (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>No source files found.</div>
                  ) : (
                    buildFileTree(Object.keys(parseRawCode(scan?.raw_code))).map(node => renderNode(node))
                  )}
                </div>

                {/* Code Viewer Column */}
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                  <div style={{
                    fontSize: '0.7rem',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--cyan-primary)',
                    background: 'rgba(6, 182, 212, 0.05)',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    marginBottom: '10px',
                    border: '1px solid rgba(6, 182, 212, 0.1)',
                    textOverflow: 'ellipsis',
                    overflow: 'hidden',
                    whiteSpace: 'nowrap',
                    textAlign: 'left'
                  }}>
                    {selectedFile || 'Select a file to view code'}
                  </div>

                  <div style={{
                    flex: 1,
                    background: '#010103',
                    border: '1px solid var(--border-glass)',
                    borderRadius: '12px',
                    overflow: 'auto',
                    maxHeight: '400px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem',
                    padding: '16px 0',
                    position: 'relative',
                    textAlign: 'left'
                  }}>
                    {selectedFile ? (
                      (parseRawCode(scan?.raw_code)[selectedFile] || '').split('\n').map((lineText, idx) => {
                        const lineNum = idx + 1;
                        const isHighlighted = highlightedLine === lineNum;
                        
                        return (
                          <div 
                            key={lineNum}
                            id={`code-line-${lineNum}`}
                            style={{
                              display: 'flex',
                              background: isHighlighted ? 'rgba(244, 63, 94, 0.12)' : 'transparent',
                              borderLeft: isHighlighted ? '3px solid #f43f5e' : '3px solid transparent',
                              padding: '2px 16px 2px 8px',
                              alignItems: 'center'
                            }}
                          >
                            <span style={{
                              width: '28px',
                              color: isHighlighted ? '#f43f5e' : '#475569',
                              textAlign: 'right',
                              marginRight: '12px',
                              userSelect: 'none',
                              fontSize: '0.7rem'
                            }}>
                              {lineNum}
                            </span>
                            <pre style={{ margin: 0, color: isHighlighted ? '#fda4af' : '#e2e8f0', whiteSpace: 'pre' }}>
                              {lineText || ' '}
                            </pre>
                          </div>
                        );
                      })
                    ) : (
                      <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                        No code selected
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Findings Tabs & Chatbot */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', minWidth: 0 }}>
            {/* Detailed Findings Tabs */}
            <div className="double-bezel-outer" style={{ flex: 1 }}>
              <div className="double-bezel-inner" style={{ padding: 0, height: '100%', display: 'flex', flexDirection: 'column' }}>
                {/* Tab selection */}
                <div style={{ padding: '20px 24px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', display: 'flex', gap: '8px' }}>
                  <button 
                    onClick={() => setActiveTab('findings')}
                    className={`tab-btn ${activeTab === 'findings' ? 'active' : ''}`}
                    style={{ flex: 'none', padding: '8px 20px' }}
                  >
                    Vulnerabilities ({findings.length})
                  </button>
                  <button 
                    onClick={() => setActiveTab('idor')}
                    className={`tab-btn ${activeTab === 'idor' ? 'active' : ''}`}
                    style={{ flex: 'none', padding: '8px 20px' }}
                  >
                    IDOR Routes ({idorEndpoints.length})
                  </button>
                  <button 
                    onClick={() => setActiveTab('compliance')}
                    className={`tab-btn ${activeTab === 'compliance' ? 'active' : ''}`}
                    style={{ flex: 'none', padding: '8px 20px' }}
                  >
                    Compliance Check
                  </button>
                </div>

                {/* Tab content renders */}
                <div style={{ flex: 1, overflowY: 'auto', maxHeight: '450px' }}>
                  {activeTab === 'findings' && (
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      {findings.length === 0 ? (
                        <div style={{ padding: '40px', color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center' }}>No vulnerabilities detected.</div>
                      ) : (
                        findings.map((f) => (
                          <FindingCard 
                            key={f.id} 
                            finding={f} 
                            onAutoFix={handleAutoFix} 
                            onInspectFile={inspectSource}
                            isFixing={fixingId === f.id}
                          />
                        ))
                      )}
                    </div>
                  )}

                  {activeTab === 'idor' && (
                    <div style={{ padding: '24px' }}>
                      <IDORTable endpoints={idorEndpoints} />
                    </div>
                  )}

                  {activeTab === 'compliance' && (
                    <div style={{ padding: '24px' }}>
                      <ComplianceBadge flags={complianceFlags} />
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* AI Security Mentor Chatbot */}
            <div className="double-bezel-outer" style={{ textAlign: 'left' }}>
              <div className="double-bezel-inner">
                <span className="section-tag cyan">AI security mentor</span>
                <h3 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <HelpCircle size={18} className="text-cyan-400" />
                  Interactive Audit Assistant
                </h3>

                <div className="chat-messages-box" style={{ height: '180px' }}>
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
                    placeholder="Ask secure fix details..." 
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
          </div>
        </div>

      </main>
    </div>
  );
}
