export function calculateScore(findings: any[]): { score: number; grade: string } {
  const deductions: Record<string, number> = {
    Critical: 20,
    High: 10,
    Medium: 5,
    Low: 2,
    Informational: 0,
  };

  const total = findings.reduce(
    (acc, f) => acc - (deductions[f.severity] ?? 0), 100
  );
  const score = Math.max(0, Math.min(100, total));

  const grade =
    score >= 90 ? 'A+' :
    score >= 80 ? 'A' :
    score >= 70 ? 'B' :
    score >= 55 ? 'C' :
    score >= 40 ? 'D' : 'F';

  return { score, grade };
}

export function calculateProjectedScore(findings: any[]): { score: number; grade: string } {
  // projected = score if all Critical + High are fixed
  const filtered = findings.filter(
    (f) => f.severity !== 'Critical' && f.severity !== 'High'
  );
  return calculateScore(filtered);
}
