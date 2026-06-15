import type { StaticFinding } from './analyzer';

const MODEL = 'gemini-2.5-flash';
const ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;

// Rate Limiter: Max 5 requests per minute
const LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS = 5;
const requestTimestamps: number[] = [];

export function checkRateLimit(): { allowed: boolean; waitTimeSec?: number } {
  const now = Date.now();
  while (requestTimestamps.length > 0 && requestTimestamps[0] < now - LIMIT_WINDOW_MS) {
    requestTimestamps.shift();
  }
  
  if (requestTimestamps.length >= MAX_REQUESTS) {
    const oldestInWindow = requestTimestamps[0];
    const waitTimeMs = LIMIT_WINDOW_MS - (now - oldestInWindow);
    return { allowed: false, waitTimeSec: Math.ceil(waitTimeMs / 1000) };
  }
  
  requestTimestamps.push(now);
  return { allowed: true };
}

export async function analyzeWithGemini(
  code: string,
  apiKey: string,
  staticFindings: StaticFinding[]
): Promise<any> {
  const rateLimit = checkRateLimit();
  if (!rateLimit.allowed) {
    throw new Error(`Rate limit exceeded. Please wait ${rateLimit.waitTimeSec} seconds before scanning again.`);
  }

  const prompt = `
You are a senior application security engineer performing a full code audit.

Analyze the code and static pre-scan findings below. For EACH finding, return a JSON object with ALL these fields:
- title (string)
- description (string, 2-3 sentences)
- severity ("Critical" | "High" | "Medium" | "Low" | "Informational")
- cvss_score (number 0.0–10.0, one decimal)
- owasp_category (e.g. "A03:2021 Injection")
- cwe_id (e.g. "CWE-89")
- vulnerable_snippet (exact code lines)
- secure_fix (corrected code)
- fix_recommendation (1–2 sentences)
- impact_analysis (1–2 sentences)
- is_ai_smell (boolean — true if this is a typical AI-generated code mistake like TODO auth, console.log of secrets, empty catch)
- attack_narrative (2–3 sentence first-person attacker story — ONLY for Critical and High)
- file_path ("unknown" if not determinable)
- line_number (integer)

Also detect IDOR endpoints: routes with :id, :userId, :fileId etc. For each return:
- endpoint (string)
- method ("GET"|"POST"|"PUT"|"DELETE"|"PATCH")
- risk_level ("High"|"Medium"|"Low")
- has_auth_check (boolean)
- has_ownership_check (boolean)
- reasoning (1 sentence)
- line_number (integer)

Also generate compliance flags based on the findings:
- framework ("GDPR"|"PCI-DSS"|"SOC2"|"OWASP ASVS")
- risk_level ("Critical"|"High"|"Medium")
- reason (1 sentence)

Static findings from regex analyzer:
${JSON.stringify(staticFindings, null, 2)}

Code to audit:
\`\`\`
${code.slice(0, 7000)}
\`\`\`

Respond ONLY with a valid JSON object like this (no markdown, no backticks, no explanation):
{
  "findings": [...],
  "idor_endpoints": [...],
  "compliance_flags": [...]
}
`;

  const res = await fetch(`${ENDPOINT}?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.15, maxOutputTokens: 8192 },
    }),
  });

  if (!res.ok) throw new Error(`Gemini API error: ${res.status}`);

  const data = await res.json();
  const text = data.candidates?.[0]?.content?.parts?.[0]?.text ?? '{}';
  const clean = text.replace(/```json|```/g, '').trim();
  return JSON.parse(clean);
}

// AI Chat function
export async function talkToGemini(
  message: string,
  apiKey: string,
  contextFindings: any[]
): Promise<string> {
  const rateLimit = checkRateLimit();
  if (!rateLimit.allowed) {
    return `Me rate limit exceeded. Please wait ${rateLimit.waitTimeSec} seconds before asking again.`;
  }

  const context = contextFindings.slice(0, 3).map((f, i) => 
    `Finding #${i+1}: ${f.title}\nSeverity: ${f.severity}\nCode: ${f.vulnerable_snippet}`
  ).join('\n---\n');

  const prompt = `You are CodeShield AI Security Mentor, an expert application security engineer.
Help the developer write secure code or answer their security question.
${context ? `Here is the current scan context:\n${context}` : ''}

Developer message: ${message}

Answer clearly, including code fixes where appropriate. Keep explanations focused and professional.`;

  const res = await fetch(`${ENDPOINT}?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }]
    })
  });

  if (!res.ok) throw new Error(`Gemini API error: ${res.status}`);
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text ?? 'Me had problem communicating with Gemini spirit.';
}
