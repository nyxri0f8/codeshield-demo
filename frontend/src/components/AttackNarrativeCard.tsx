import { Terminal } from 'lucide-react';
import type { Finding } from '../types';

interface AttackNarrativeCardProps {
  findings: Finding[];
}

export function AttackNarrativeCard({ findings }: AttackNarrativeCardProps) {
  const narrativeFindings = findings.filter(
    (f) => (f.severity === 'Critical' || f.severity === 'High') && f.attack_narrative
  );

  if (narrativeFindings.length === 0) {
    return (
      <div className="double-bezel-outer">
        <div className="double-bezel-inner" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
          No critical or high severity attack vectors detected for narrative threat mapping.
        </div>
      </div>
    );
  }

  return (
    <div className="double-bezel-outer">
      <div className="double-bezel-inner">
        <span className="section-tag rose">Attack Narrative</span>
        <h3 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Terminal size={18} className="text-rose-400" />
          Sequential Breach Vector Simulation
        </h3>
        
        <p className="details-desc" style={{ textAlign: 'left', marginBottom: '24px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          Based on detected vulnerabilities, this timeline simulates how a threat actor would chain exploits in a real-world attack:
        </p>

        <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', gap: '24px', paddingLeft: '24px' }}>
          {/* Vertical timeline connector line */}
          <div 
            style={{ 
              position: 'absolute', 
              left: '7px', 
              top: '8px', 
              bottom: '8px', 
              width: '2px', 
              background: 'linear-gradient(to bottom, var(--rose-primary), rgba(244, 63, 94, 0.1))' 
            }} 
          />

          {narrativeFindings.map((f, i) => (
            <div key={f.id} style={{ position: 'relative', textAlign: 'left' }}>
              {/* Timeline indicator node */}
              <div 
                style={{ 
                  position: 'absolute', 
                  left: '-23px', 
                  top: '4px', 
                  width: '12px', 
                  height: '12px', 
                  borderRadius: '50%', 
                  background: 'var(--bg-main)',
                  border: '3px solid var(--rose-primary)',
                  boxShadow: '0 0 8px var(--rose-primary)'
                }} 
              />
              
              <div>
                <span style={{ fontSize: '0.6rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
                  Exploit Vector #{i + 1} — {f.title} ({f.severity})
                </span>
                <p 
                  style={{ 
                    fontSize: '0.75rem', 
                    color: '#fca5a5', 
                    marginTop: '4px',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: 1.5,
                    background: 'rgba(244, 63, 94, 0.05)',
                    padding: '12px',
                    borderRadius: '8px',
                    border: '1px solid rgba(244, 63, 94, 0.1)'
                  }}
                >
                  "{f.attack_narrative}"
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
