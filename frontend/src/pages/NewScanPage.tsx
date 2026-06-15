import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Upload, Terminal, Globe, Code, ArrowRight, FileCode } from 'lucide-react';
import JSZip from 'jszip';
import { useAuth } from '../hooks/useAuth';
import { useGeminiKey } from '../hooks/useGeminiKey';
import { supabase } from '../lib/supabase';
import { runStaticAnalysis, generateStaticResult } from '../lib/analyzer';
import { analyzeWithGemini } from '../lib/gemini';
import { calculateScore, calculateProjectedScore } from '../lib/scoreCalc';
import { Sidebar } from '../components/Sidebar';
import { ScanProgress } from '../components/ScanProgress';

export default function NewScanPage() {
  const { user } = useAuth();
  const { geminiKey } = useGeminiKey(user?.id);
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<'paste' | 'zip' | 'github' | 'website'>('paste');
  const [projectName, setProjectName] = useState('');
  const [code, setCode] = useState('');
  const [gitUrl, setGitUrl] = useState('');
  const [gitToken, setGitToken] = useState(() => localStorage.getItem('codeshield_github_pat') || '');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [websiteUrl, setWebsiteUrl] = useState('');

  // Scanning progress state
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState('');
  const [scanProgress, setScanProgress] = useState(0);

  const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  const isDemo = user?.id === 'demo-123';

  const handleScan = async () => {
    let sourceCode = code;
    let type: 'paste' | 'zip' | 'github' | 'website' = activeTab;

    if (activeTab === 'paste' && !code.trim()) return;
    if (activeTab === 'zip' && !uploadFile) return;
    if (activeTab === 'github' && !gitUrl) return;
    if (activeTab === 'website' && !websiteUrl) return;

    setIsScanning(true);
    setScanProgress(5);
    setScanStage('Parsing repository code structure...');

    try {
      // If ZIP, parse files first to compile one big code block for static scan
      if (activeTab === 'zip' && uploadFile) {
        setScanStage('Extracting ZIP package elements...');
        setScanProgress(15);
        const zip = await JSZip.loadAsync(uploadFile);
        let extractedCode = '';
        const fileNames = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
        
        for (const name of fileNames) {
          const matches = name.endsWith('.js') || name.endsWith('.ts') || name.endsWith('.py') || name.endsWith('.pyw');
          if (matches) {
            const content = await zip.files[name].async('string');
            extractedCode += `\n// FILE: ${name}\n${content}\n`;
          }
        }
        sourceCode = extractedCode || '// No js/py files found in ZIP archive.';
      } else if (activeTab === 'github' && gitUrl) {
        setScanStage('Cloning GitHub source code tree...');
        setScanProgress(15);
        
        // Check if it's a single file link
        const fileMatch = gitUrl.match(/github\.com\/([^/]+)\/([^/]+)\/blob\/([^/]+)\/(.+)$/);
        
        if (fileMatch) {
          const owner = fileMatch[1];
          const repo = fileMatch[2];
          const branch = fileMatch[3];
          const filePath = fileMatch[4];
          
          setScanStage(`Fetching single file: ${filePath}...`);
          setScanProgress(50);
          
          const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;
          const headers: HeadersInit = {};
          if (gitToken.trim()) {
            headers['Authorization'] = `token ${gitToken.trim()}`;
          }
          
          const fileRes = await fetch(rawUrl, { headers });
          if (!fileRes.ok) {
            throw new Error(`Failed to fetch file from raw GitHub content (${fileRes.status})`);
          }
          const fileText = await fileRes.text();
          sourceCode = `\n// FILE: ${filePath}\n${fileText}\n`;
        } else {
          const match = gitUrl.match(/github\.com\/([^/]+)\/([^/&#?]+)/);
          if (!match) throw new Error("Invalid GitHub URL. Must be like: https://github.com/owner/repo or https://github.com/owner/repo/blob/branch/path/to/file");
          const owner = match[1];
          let repo = match[2].split('/')[0];
          if (repo.endsWith('.git')) repo = repo.substring(0, repo.length - 4);

          const headers: HeadersInit = {};
          if (gitToken.trim()) {
            headers['Authorization'] = `token ${gitToken.trim()}`;
          }

          // Fetch repo info
          const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
          if (!repoRes.ok) {
            const errData = await repoRes.json().catch(() => ({}));
            throw new Error(`GitHub API Error (${repoRes.status}): ${errData.message || repoRes.statusText}`);
          }
          const repoData = await repoRes.json();
          const branch = repoData.default_branch || 'main';

          // Fetch recursive tree
          const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, { headers });
          if (!treeRes.ok) {
            const errData = await treeRes.json().catch(() => ({}));
            throw new Error(`GitHub API Error (${treeRes.status}): ${errData.message || treeRes.statusText}`);
          }
          const treeData = await treeRes.json();
          
          const extensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java', '.cpp', '.c', '.cs', '.rb', '.php'];
          const files = (treeData.tree || []).filter((item: any) => 
            item.type === 'blob' && extensions.some(ext => item.path.endsWith(ext))
          ).slice(0, 15); // fetch max 15 files

          let fetchedCode = '';
          for (const file of files) {
            try {
              // Try raw.githubusercontent.com first (bypasses API rate limit!)
              const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file.path}`;
              const rawRes = await fetch(rawUrl, { headers });
              if (rawRes.ok) {
                const txt = await rawRes.text();
                fetchedCode += `\n// FILE: ${file.path}\n${txt}\n`;
              } else {
                // Fallback to API if private repo
                const contentRes = await fetch(file.url, { headers });
                if (contentRes.ok) {
                  const blobData = await contentRes.json();
                  if (blobData && blobData.content) {
                    const base64 = blobData.content.replace(/\s/g, '');
                    let txt = '';
                    try {
                      txt = decodeURIComponent(escape(atob(base64)));
                    } catch {
                      txt = atob(base64);
                    }
                    fetchedCode += `\n// FILE: ${file.path}\n${txt}\n`;
                  }
                }
              }
            } catch (fileErr) {
              console.warn(`Failed to retrieve file: ${file.path}`, fileErr);
            }
          }
          sourceCode = fetchedCode || '// No matching source code files found in github repository branch.';
        }
      } else if (activeTab === 'website' && websiteUrl) {
        setScanStage('Fetching website document...');
        setScanProgress(15);
        
        let targetUrl = websiteUrl.trim();
        if (!/^https?:\/\//i.test(targetUrl)) {
          targetUrl = 'https://' + targetUrl;
        }

        const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(targetUrl)}`;
        const res = await fetch(proxyUrl);
        if (!res.ok) {
          throw new Error(`Failed to fetch website contents (${res.status})`);
        }
        const text = await res.text();
        sourceCode = `\n// FILE: index.html\n// SOURCE URL: ${targetUrl}\n${text}\n`;
      }

      // Demo mode: run static analysis + mock/static Gemini, store in localStorage, no Supabase
      if (isDemo) {
        setScanStage('Running local static regex SAST engine...');
        setScanProgress(40);
        await delay(600);

        const staticFindings = runStaticAnalysis(sourceCode);

        setScanStage('AI Security Enrichment via Gemini...');
        setScanProgress(75);
        await delay(700);

        let geminiResult;
        if (geminiKey) {
          try { geminiResult = await analyzeWithGemini(sourceCode, geminiKey, staticFindings); }
          catch { geminiResult = generateStaticResult(staticFindings, sourceCode); }
        } else {
          geminiResult = generateStaticResult(staticFindings, sourceCode);
        }

        setScanStage('Computing posture scores and metrics...');
        setScanProgress(90);
        await delay(400);

        const { score, grade } = calculateScore(geminiResult.findings || []);
        const { score: projectedScore } = calculateProjectedScore(geminiResult.findings || []);

        const demoScanId = `demo-result-${Date.now()}`;
        const demoScanData = {
          scan: {
            id: demoScanId,
            user_id: 'demo-123',
            project_name: projectName || (activeTab === 'zip' ? uploadFile?.name : activeTab === 'github' ? 'GitHub Project' : 'Untitled Snippet'),
            source_type: type,
            status: 'done',
            overall_score: score,
            projected_score: projectedScore,
            grade,
            raw_code: sourceCode,
            created_at: new Date().toISOString(),
          },
          findings: (geminiResult.findings || []).map((f: any, i: number) => ({ ...f, id: f.id || `df-${i}`, scan_id: demoScanId, is_fixed: false })),
          idor_endpoints: (geminiResult.idor_endpoints || []).map((e: any, i: number) => ({ ...e, id: e.id || `de-${i}`, scan_id: demoScanId })),
          compliance_flags: (geminiResult.compliance_flags || []).map((c: any, i: number) => ({ ...c, id: c.id || `dc-${i}`, scan_id: demoScanId })),
        };

        localStorage.setItem(`demo_scan_${demoScanId}`, JSON.stringify(demoScanData));

        setScanProgress(100);
        setScanStage('Audit complete!');
        await delay(200);
        setIsScanning(false);
        navigate(`/scan/${demoScanId}`);
        return;
      }

      setScanStage('Initializing scan in database...');
      setScanProgress(25);
      await delay(300);

      // 1. Create scan entry
      const { data: scan, error: scanErr } = await supabase
        .from('scans')
        .insert({
          user_id: user?.id,
          project_name: projectName || (activeTab === 'zip' ? uploadFile?.name : activeTab === 'github' ? 'GitHub Project' : 'Untitled Snippet'),
          source_type: type,
          status: 'scanning',
          raw_code: sourceCode
        })
        .select()
        .single();

      if (scanErr) throw scanErr;

      setScanStage('Running local static regex SAST engine...');
      setScanProgress(45);
      await delay(500);

      const staticFindings = runStaticAnalysis(sourceCode);

      setScanStage('AI Security Enrichment via Gemini...');
      setScanProgress(75);
      await delay(500);

      let geminiResult;
      if (geminiKey) {
        try {
          geminiResult = await analyzeWithGemini(sourceCode, geminiKey, staticFindings);
        } catch (e) {
          console.error("Gemini failed, using fallback static results:", e);
          geminiResult = generateStaticResult(staticFindings, sourceCode);
        }
      } else {
        // Fallback to static results
        geminiResult = generateStaticResult(staticFindings, sourceCode);
      }

      setScanStage('Computing posture scores and metrics...');
      setScanProgress(90);
      await delay(400);

      const { score, grade } = calculateScore(geminiResult.findings || []);
      const { score: projectedScore } = calculateProjectedScore(geminiResult.findings || []);

      // 2. Insert Findings
      if (geminiResult.findings?.length) {
        const findingsRows = geminiResult.findings.map((f: any) => ({
          scan_id: scan.id,
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

        const { error: findErr } = await supabase.from('findings').insert(findingsRows);
        if (findErr) throw findErr;
      }

      // 3. Insert IDOR routes
      if (geminiResult.idor_endpoints?.length) {
        const idorRows = geminiResult.idor_endpoints.map((e: any) => ({
          scan_id: scan.id,
          endpoint: e.endpoint,
          method: e.method,
          risk_level: e.risk_level,
          has_auth_check: e.has_auth_check,
          has_ownership_check: e.has_ownership_check,
          reasoning: e.reasoning,
          line_number: e.line_number || 1
        }));

        const { error: idorErr } = await supabase.from('idor_endpoints').insert(idorRows);
        if (idorErr) throw idorErr;
      }

      // 4. Insert Compliance
      if (geminiResult.compliance_flags?.length) {
        const compRows = geminiResult.compliance_flags.map((c: any) => ({
          scan_id: scan.id,
          framework: c.framework,
          risk_level: c.risk_level,
          reason: c.reason
        }));

        const { error: compErr } = await supabase.from('compliance_flags').insert(compRows);
        if (compErr) throw compErr;
      }

      // 5. Update Scan Status
      const { error: upErr } = await supabase
        .from('scans')
        .update({
          status: 'done',
          overall_score: score,
          projected_score: projectedScore,
          grade
        })
        .eq('id', scan.id);

      if (upErr) throw upErr;

      setScanProgress(100);
      setScanStage('Audit complete!');
      await delay(200);
      setIsScanning(false);
      navigate(`/scan/${scan.id}`);

    } catch (err: any) {
      alert("Audit execution failed: " + err.message);
      setIsScanning(false);
    }
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#050508' }}>
      <Sidebar />
      <ScanProgress isOpen={isScanning} stage={scanStage} progress={scanProgress} />
      
      <main style={{ flex: 1, padding: '40px', maxWidth: '800px', margin: '0 auto', textAlign: 'left' }}>
        <h1 className="logo-title" style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
          New Vulnerability Audit
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '36px' }}>
          Select target code source format to initialize security scan.
        </p>

        <div className="double-bezel-outer">
          <div className="double-bezel-inner">
            <span className="section-tag cyan">Repository audit</span>
            <h2 className="panel-title" style={{ marginBottom: '20px' }}>Audit Target Setup</h2>

            {/* Project Name */}
            <div style={{ marginBottom: '24px' }}>
              <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', fontWeight: 750 }}>Project Name</label>
              <input 
                type="text" 
                placeholder="E.g., payment-service" 
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="standard-input"
                style={{ paddingLeft: '16px' }}
              />
            </div>

            {/* Tabs */}
            <div className="tabs-container">
              <button 
                onClick={() => setActiveTab('paste')}
                className={`tab-btn ${activeTab === 'paste' ? 'active' : ''}`}
              >
                <Code className="h-3.5 w-3.5" strokeWidth={1.5} />
                Paste Code
              </button>
              <button 
                onClick={() => setActiveTab('zip')}
                className={`tab-btn ${activeTab === 'zip' ? 'active' : ''}`}
              >
                <Upload className="h-3.5 w-3.5" strokeWidth={1.5} />
                ZIP Archive
              </button>
              <button 
                onClick={() => setActiveTab('github')}
                className={`tab-btn ${activeTab === 'github' ? 'active' : ''}`}
              >
                <Terminal className="h-3.5 w-3.5" strokeWidth={1.5} />
                GitHub Link
              </button>
              <button 
                onClick={() => setActiveTab('website')}
                className={`tab-btn ${activeTab === 'website' ? 'active' : ''}`}
              >
                <Globe className="h-3.5 w-3.5" strokeWidth={1.5} />
                Website Link
              </button>
            </div>

            {/* Content pane */}
            {activeTab === 'paste' && (
              <div style={{ marginBottom: '20px' }}>
                <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', fontWeight: 750 }}>Source Code Snippet</label>
                <textarea
                  placeholder="Paste JavaScript, Python, or SQL code block here..."
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  style={{
                    width: '100%',
                    height: '240px',
                    background: 'rgba(0, 0, 0, 0.4)',
                    border: '1px solid var(--border-glass)',
                    borderRadius: '16px',
                    padding: '16px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem',
                    color: 'var(--text-primary)',
                    outline: 'none',
                    resize: 'none'
                  }}
                />
              </div>
            )}

            {activeTab === 'zip' && (
              <div 
                onClick={() => document.getElementById('new-zip-uploader')?.click()}
                className="upload-dropzone"
                style={{ marginBottom: '24px' }}
              >
                <Upload className="upload-icon" size={32} />
                <p className="upload-title">Click to upload ZIP source package</p>
                <p className="upload-subtitle">Checks python, javascript files recursively</p>
                <input 
                  type="file" 
                  accept=".zip"
                  onChange={(e) => e.target.files && setUploadFile(e.target.files[0])}
                  id="new-zip-uploader"
                  style={{ display: 'none' }}
                />
                {uploadFile && (
                  <p className="selected-file-badge">
                    <FileCode size={14} />
                    {uploadFile.name} ({(uploadFile.size / 1024).toFixed(1)} KB)
                  </p>
                )}
              </div>
            )}

            {activeTab === 'github' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
                <div>
                  <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', fontWeight: 750 }}>GitHub Repository Link</label>
                  <div className="text-input-container">
                    <Globe className="input-icon" size={16} />
                    <input 
                      type="text" 
                      placeholder="https://github.com/owner/repository" 
                      value={gitUrl}
                      onChange={(e) => setGitUrl(e.target.value)}
                      className="standard-input"
                    />
                  </div>
                  <p className="input-help">Supports both public and private repositories.</p>
                </div>
                <div>
                  <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', fontWeight: 750 }}>GitHub Personal Access Token (Optional)</label>
                  <div className="text-input-container">
                    <Terminal className="input-icon" size={16} />
                    <input 
                      type="password" 
                      placeholder="ghp_... (Saved in browser local storage)" 
                      value={gitToken}
                      onChange={(e) => {
                        setGitToken(e.target.value);
                        localStorage.setItem('codeshield_github_pat', e.target.value);
                      }}
                      className="standard-input"
                    />
                  </div>
                  <p className="input-help">Bypasses API rate limit (60 req/hr) and enables private repository scans.</p>
                </div>
              </div>
            )}

            {activeTab === 'website' && (
              <div style={{ marginBottom: '24px' }}>
                <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', fontWeight: 750 }}>Website URL Link</label>
                <div className="text-input-container">
                  <Globe className="input-icon" size={16} />
                  <input 
                    type="text" 
                    placeholder="https://example.com" 
                    value={websiteUrl}
                    onChange={(e) => setWebsiteUrl(e.target.value)}
                    className="standard-input"
                  />
                </div>
                <p className="input-help">Fetches web page document source code using client-side CORS bypass proxy.</p>
              </div>
            )}

            {/* Audit button */}
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={handleScan}
              className="cta-button"
              style={{ marginTop: '12px' }}
            >
              <span>Audit Application</span>
              <div className="cta-icon-wrap">
                <ArrowRight size={14} />
              </div>
            </motion.button>
          </div>
        </div>
      </main>
    </div>
  );
}
