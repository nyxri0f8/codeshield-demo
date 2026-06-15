import { AlertTriangle, Check, X } from 'lucide-react';
import type { IdorEndpoint } from '../types';

interface IDORTableProps {
  endpoints: IdorEndpoint[];
}

export function IDORTable({ endpoints }: IDORTableProps) {
  if (endpoints.length === 0) {
    return (
      <div className="double-bezel-outer">
        <div className="double-bezel-inner" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
          No dynamic route parameters matching IDOR threat criteria detected.
        </div>
      </div>
    );
  }

  return (
    <div className="double-bezel-outer">
      <div className="double-bezel-inner" style={{ padding: 0 }}>
        <div style={{ padding: '24px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', textAlign: 'left' }}>
          <span className="section-tag cyan">Access Validation</span>
          <h3 className="panel-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={18} className="text-cyan-400" />
            Detected IDOR Attack Vectors
          </h3>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid rgba(255, 255, 255, 0.08)' }}>
                <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Method</th>
                <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Route Endpoint</th>
                <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk</th>
                <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'center' }}>Auth Check</th>
                <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'center' }}>Owner Check</th>
                <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Parameter Reasoning</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e) => (
                <tr key={e.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  {/* Method */}
                  <td style={{ padding: '16px 24px', fontFamily: 'var(--font-mono)' }}>
                    <span 
                      style={{ 
                        padding: '2px 8px', 
                        borderRadius: '4px',
                        fontWeight: 700,
                        background: e.method === 'DELETE' ? 'var(--rose-light)' : 'var(--cyan-light)',
                        color: e.method === 'DELETE' ? 'var(--rose-primary)' : 'var(--cyan-primary)'
                      }}
                    >
                      {e.method || 'GET'}
                    </span>
                  </td>
                  {/* Endpoint */}
                  <td style={{ padding: '16px 24px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{e.endpoint}</td>
                  {/* Risk */}
                  <td style={{ padding: '16px 24px' }}>
                    <span 
                      className={`severity-badge ${e.risk_level.toLowerCase()}`}
                    >
                      {e.risk_level}
                    </span>
                  </td>
                  {/* Auth Check */}
                  <td style={{ padding: '16px 24px', textAlign: 'center' }}>
                    {e.has_auth_check ? (
                      <Check className="text-emerald-400 mx-auto" size={16} />
                    ) : (
                      <X className="text-rose-400 mx-auto" size={16} />
                    )}
                  </td>
                  {/* Ownership Check */}
                  <td style={{ padding: '16px 24px', textAlign: 'center' }}>
                    {e.has_ownership_check ? (
                      <Check className="text-emerald-400 mx-auto" size={16} />
                    ) : (
                      <X className="text-rose-400 mx-auto" size={16} />
                    )}
                  </td>
                  {/* Reasoning */}
                  <td style={{ padding: '16px 24px', color: 'var(--text-muted)' }}>{e.reasoning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
