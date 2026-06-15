export interface StaticFinding {
  ruleId: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  line: number;
  snippet: string;
  isAiSmell: boolean;
  file_path: string;
  line_number: number;
}

const RULES = [
  {
    id: 'hardcoded-secret',
    pattern: /(password|secret|api_key|token|stripe)\s*[=:]\s*["'][^"']{6,}["']/gi,
    title: 'Hardcoded Secret Detected',
    severity: 'Critical' as const,
    isAiSmell: false,
  },
  {
    id: 'sql-injection',
    pattern: /["'`]\s*\+\s*(req\.|user|input|\$\{)|`[^`]*\$\{[^}]*(req\.|params|query|body)/g,
    title: 'SQL Injection via String Interpolation',
    severity: 'Critical' as const,
    isAiSmell: false,
  },
  {
    id: 'eval-exec',
    pattern: /\beval\s*\(|\bexec\s*\(/g,
    title: 'Dangerous eval / exec Usage',
    severity: 'High' as const,
    isAiSmell: false,
  },
  {
    id: 'idor-route',
    pattern: /router\.(get|put|delete|patch)\s*\(['"`][^'"`]*:(id|userId|fileId|orderId)/gi,
    title: 'ID Parameter Route — Potential IDOR',
    severity: 'High' as const,
    isAiSmell: false,
  },
  {
    id: 'ai-todo-auth',
    pattern: /\/\/\s*TODO:?\s*(add\s*auth|validate|check\s*(user|auth)|implement|fix)/gi,
    title: 'AI Smell — Unimplemented Auth TODO',
    severity: 'Medium' as const,
    isAiSmell: true,
  },
  {
    id: 'console-secret',
    pattern: /console\.(log|warn|info)\s*\([^)]*?(token|password|secret|key|auth)/gi,
    title: 'AI Smell — Secret Logged to Console',
    severity: 'High' as const,
    isAiSmell: true,
  },
  {
    id: 'empty-catch',
    pattern: /catch\s*\([^)]*\)\s*\{\s*\}/g,
    title: 'AI Smell — Empty Catch Block',
    severity: 'Medium' as const,
    isAiSmell: true,
  },
  {
    id: 'missing-rate-limit',
    pattern: /router\.(post)\s*\(['"`]\/(login|signin|auth|register)/gi,
    title: 'Missing Rate Limiting on Auth Endpoint',
    severity: 'Medium' as const,
    isAiSmell: true,
  },
];

export function runStaticAnalysis(code: string): StaticFinding[] {
  const lines = code.split('\n');
  const findings: StaticFinding[] = [];

  let currentFile = 'main.js';
  let currentFileLine = 0;
  const lineDetails = lines.map((line) => {
    const match = line.match(/^\/\/ FILE:\s*(.+)$/);
    if (match) {
      currentFile = match[1].trim();
      currentFileLine = 0;
      return { file_path: currentFile, line_number: 0, isHeader: true };
    } else {
      currentFileLine++;
      return { file_path: currentFile, line_number: currentFileLine, isHeader: false };
    }
  });

  for (const rule of RULES) {
    lines.forEach((line, i) => {
      if (lineDetails[i].isHeader) return;
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          line: i + 1,
          snippet: line.trim(),
          isAiSmell: rule.isAiSmell,
          file_path: lineDetails[i].file_path,
          line_number: lineDetails[i].line_number,
        });
      }
    });
  }

  return findings;
}

export function generateStaticResult(staticFindings: StaticFinding[], sourceCode: string) {
  const findings = staticFindings.map((f, idx) => {
    let secure_fix = '';
    if (f.ruleId === 'sql-injection') {
      secure_fix = `// Remediated: Use parameterized queries to prevent SQL Injection\nconst query = 'SELECT * FROM users WHERE username = $1 AND password = $2';\nconst user = await db.query(query, [username, password]);`;
    } else if (f.ruleId === 'hardcoded-secret') {
      secure_fix = `// Remediated: Retrieve secret key from environment variables\nconst stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);`;
    } else if (f.ruleId === 'eval-exec') {
      secure_fix = `// Remediated: Avoid eval/exec. Use safe parsing or structure logic instead\n// const result = safeEval(code);`;
    } else if (f.ruleId === 'idor-route') {
      secure_fix = `// Remediated: Verify active user session checks ownership of the requested resource ID\nconst resource = await db.query('SELECT * FROM resources WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);`;
    } else if (f.ruleId === 'ai-todo-auth') {
      secure_fix = `// Remediated: Implemented auth middleware protection\nrouter.get('/data', checkUserAuth, async (req, res) => { ... });`;
    } else if (f.ruleId === 'console-secret') {
      secure_fix = `// Remediated: Remove credentials logging to console\nconsole.info('Operation successfully authenticated.');`;
    } else if (f.ruleId === 'empty-catch') {
      secure_fix = `// Remediated: Properly log and handle errors\ncatch (err) {\n  console.error('Operation failed:', err);\n  res.status(500).send('Internal server error');\n}`;
    } else if (f.ruleId === 'missing-rate-limit') {
      secure_fix = `// Remediated: Apply rate limiter middleware on login\nconst rateLimit = require('express-rate-limit');\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });\nrouter.post('/login', loginLimiter, loginHandler);`;
    } else {
      secure_fix = `// Apply appropriate secure practices to prevent vulnerabilities.`;
    }

    return {
      id: `df-${idx}`,
      title: f.title,
      description: `A potential ${f.title.toLowerCase()} vulnerability was identified during static code analysis. This pattern is often associated with security posture weaknesses.`,
      severity: f.severity,
      cvss_score: f.severity === 'Critical' ? 9.0 : f.severity === 'High' ? 7.5 : f.severity === 'Medium' ? 5.0 : 2.5,
      owasp_category: f.ruleId === 'sql-injection' ? 'A03:2021-Injection' : f.ruleId === 'hardcoded-secret' ? 'A02:2021-Cryptographic Failures' : 'A01:2021-Broken Access Control',
      cwe_id: f.ruleId === 'sql-injection' ? 'CWE-89' : f.ruleId === 'hardcoded-secret' ? 'CWE-798' : 'CWE-284',
      vulnerable_snippet: f.snippet,
      secure_fix,
      fix_recommendation: `Review and refactor code line ${f.line_number} in file ${f.file_path}. Avoid dangerous constructs and enforce boundary security checks.`,
      impact_analysis: `Exploiting this vulnerability could enable attackers to extract sensitive database files, compromise user sessions, or manipulate application controls.`,
      attack_narrative: f.severity === 'Critical' || f.severity === 'High'
        ? (() => {
            if (f.ruleId === 'sql-injection') {
              return `[Attack Performed] Injected malicious inputs into database query paths. [System Change] Bypassed query validation filters. [Access Gained] Direct read/write access to administrative database records. [Recommendation] Implement parameterized queries.`;
            } else if (f.ruleId === 'hardcoded-secret') {
              return `[Attack Performed] Harvested plaintext secret credentials. [System Change] Compromised integrated api environment parameters. [Access Gained] External service privileges. [Recommendation] Store secrets in environment variables.`;
            } else if (f.ruleId === 'eval-exec') {
              return `[Attack Performed] Injected runtime instructions via input fields. [System Change] Ran shell code in server context. [Access Gained] Remote Code Execution (RCE) privileges. [Recommendation] Avoid eval and exec entirely.`;
            } else if (f.ruleId === 'idor-route') {
              return `[Attack Performed] Manipulated resource ID route variables. [System Change] Bypassed user access boundaries. [Access Gained] Unauthorized read/write permissions for other users' resources. [Recommendation] Enforce session-based ownership checks.`;
            }
            return `[Attack Performed] Targeted structural logic flaws in file ${f.file_path} at line ${f.line_number}. [System Change] Bypassed code integrity checks. [Access Gained] Escalated execution privileges. [Recommendation] Refactor code to apply strict input sanitization.`;
          })()
        : undefined,
      file_path: f.file_path,
      line_number: f.line_number,
      is_ai_smell: f.isAiSmell,
      is_fixed: false
    };
  });

  const lines = sourceCode.split('\n');
  const idor_endpoints: any[] = [];
  let currentFileLine = 0;

  lines.forEach((line) => {
    const fileMatch = line.match(/^\/\/ FILE:\s*(.+)$/);
    if (fileMatch) {
      currentFileLine = 0;
      return;
    }
    currentFileLine++;

    const idorRegex = /router\.(get|put|delete|patch)\s*\(['"`]([^'"`]*:(id|userId|fileId|orderId)[^'"`]*)/gi;
    let match;
    while ((match = idorRegex.exec(line)) !== null) {
      idor_endpoints.push({
        id: `de-${idor_endpoints.length}`,
        endpoint: match[2],
        method: match[1].toUpperCase(),
        risk_level: 'High',
        has_auth_check: line.toLowerCase().includes('auth') || line.toLowerCase().includes('protect'),
        has_ownership_check: false,
        reasoning: `Route parameter contains dynamic resource identifier '${match[3]}' which lacks verified access control check.`,
        line_number: currentFileLine
      });
    }
  });

  const compliance_flags = [
    {
      id: 'dc-0',
      framework: 'OWASP ASVS' as const,
      risk_level: findings.some(f => f.severity === 'Critical') ? 'Critical' : 'High' as const,
      reason: 'Application source code exposes patterns violating fundamental input and query parameterization standards.'
    },
    {
      id: 'dc-1',
      framework: 'SOC2' as const,
      risk_level: 'Medium' as const,
      reason: 'Lack of systematic input filters and secure storage of authorization parameters represents compliance risk.'
    }
  ];

  return { findings, idor_endpoints, compliance_flags };
}
