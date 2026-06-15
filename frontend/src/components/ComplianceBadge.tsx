import { CheckCircle2, AlertTriangle, ShieldCheck } from 'lucide-react';
import type { ComplianceFlag } from '../types';

interface ComplianceBadgeProps {
  flags: ComplianceFlag[];
}

export function ComplianceBadge({ flags }: ComplianceBadgeProps) {
  const frameworks = [
    { name: 'GDPR', fullName: 'General Data Protection Regulation' },
    { name: 'PCI-DSS', fullName: 'Payment Card Industry Data Security Standard' },
    { name: 'SOC2', fullName: 'System and Organization Controls 2' },
    { name: 'OWASP ASVS', fullName: 'Application Security Verification Standard' }
  ];

  return (
    <div className="double-bezel-outer">
      <div className="double-bezel-inner">
        <span className="section-tag cyan">Regulatory</span>
        <h3 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldCheck size={18} className="text-cyan-400" />
          Regulatory Compliance Matrix
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginTop: '16px' }}>
          {frameworks.map((fw) => {
            const violation = flags.find((f) => f.framework === fw.name);
            const isCompliant = !violation;

            return (
              <div 
                key={fw.name}
                style={{
                  background: 'rgba(0, 0, 0, 0.2)',
                  border: '1px solid var(--border-glass)',
                  borderRadius: '16px',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  textAlign: 'left'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>{fw.name}</span>
                  {isCompliant ? (
                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.65rem', color: 'var(--emerald-primary)', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '99px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                      <CheckCircle2 size={12} /> Compliant
                    </span>
                  ) : (
                    <span className="severity-badge critical" style={{ fontSize: '0.6rem', padding: '2px 8px' }}>
                      Violated
                    </span>
                  )}
                </div>
                
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{fw.fullName}</span>
                
                {!isCompliant && (
                  <p style={{ fontSize: '0.7rem', color: '#fda4af', lineHeight: 1.4, borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '6px', marginTop: '4px' }}>
                    <AlertTriangle size={10} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'middle' }} />
                    {violation.reason}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
