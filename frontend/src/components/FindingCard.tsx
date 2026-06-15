import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, ChevronUp, Cpu, Eye } from 'lucide-react';
import type { Finding } from '../types';

interface FindingCardProps {
  finding: Finding;
  onAutoFix: (finding: Finding) => Promise<void>;
  onInspectFile: (filePath: string, lineNumber?: number) => void;
  isFixing?: boolean;
}

export function FindingCard({
  finding,
  onAutoFix,
  onInspectFile,
  isFixing = false,
}: FindingCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const getSeverityBadge = () => {
    switch (finding.severity) {
      case 'Critical':
        return <span className="severity-badge critical">Critical</span>;
      case 'High':
        return <span className="severity-badge high">High</span>;
      case 'Medium':
        return <span className="severity-badge medium">Medium</span>;
      default:
        return <span className="severity-badge low" style={{ background: 'rgba(59,130,246,0.1)', color: 'var(--cyan-primary)', border: '1px solid rgba(59,130,246,0.2)' }}>{finding.severity}</span>;
    }
  };

  return (
    <div className="finding-row" style={{ listStyleType: 'none', background: 'transparent' }}>
      {/* Header Accordion summary */}
      <div 
        onClick={() => setIsExpanded(!isExpanded)}
        className="finding-summary"
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px 24px', cursor: 'pointer' }}
      >
        <div className="finding-title-section" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {getSeverityBadge()}
          <div style={{ textAlign: 'left' }}>
            <span className="finding-name" style={{ fontSize: '0.9rem', fontWeight: 600 }}>{finding.title}</span>
            <div className="finding-meta" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              File: <span className="cyan">{finding.file_path}</span> : Line {finding.line_number} {finding.is_ai_smell && <span style={{ color: 'var(--orange-primary)', background: 'var(--orange-light)', padding: '1px 6px', borderRadius: '99px', fontSize: '0.55rem', fontWeight: 600, marginLeft: '6px' }}>AI Smell</span>}
            </div>
          </div>
        </div>
        {isExpanded ? <ChevronUp size={16} className="text-slate-400" /> : <ChevronDown size={16} className="text-slate-400" />}
      </div>

      {/* Expanded body details */}
      <AnimatePresence initial={false}>
        {isExpanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3, ease: 'easeInOut' }}
            style={{ overflow: 'hidden' }}
          >
            <div className="finding-details" style={{ padding: '0 24px 24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Description */}
              <div>
                <div className="details-block-title" style={{ textAlign: 'left', fontWeight: 700, fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Description</div>
                <p className="details-desc" style={{ textAlign: 'left', fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginTop: '4px' }}>{finding.description}</p>
              </div>

              {/* Code Snippet */}
              {finding.vulnerable_snippet && (
                <div>
                  <div className="details-block-title" style={{ textAlign: 'left', fontWeight: 700, fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Vulnerable Code Snippet</div>
                  <div className="code-snippet-box" style={{ background: '#030305', border: '1px solid rgba(255, 255, 255, 0.04)', padding: '16px', borderRadius: '12px', overflowX: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '4px', textAlign: 'left' }}>
                    <code style={{ whiteSpace: 'pre-wrap' }}>
                      {`   ${finding.line_number} | ${finding.vulnerable_snippet}`}
                    </code>
                  </div>
                </div>
              )}

              {/* Fix Recommendation */}
              {finding.fix_recommendation && (
                <div>
                  <div className="details-block-title" style={{ textAlign: 'left', fontWeight: 700, fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Fix Recommendation</div>
                  <p className="details-desc" style={{ textAlign: 'left', fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginTop: '4px' }}>{finding.fix_recommendation}</p>
                </div>
              )}

              {/* Secure Fix Code block */}
              {finding.secure_fix && (
                <div>
                  <div className="details-block-title" style={{ textAlign: 'left', fontWeight: 700, fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>AI Remediated Safe Fix</div>
                  <div className="code-snippet-box" style={{ background: '#022c22', border: '1px solid #059669', padding: '16px', borderRadius: '12px', overflowX: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: '#a7f3d0', marginTop: '4px', textAlign: 'left' }}>
                    <code style={{ whiteSpace: 'pre-wrap' }}>{finding.secure_fix}</code>
                  </div>
                </div>
              )}

              {/* Attack Narrative */}
              {finding.attack_narrative && (
                <div>
                  <div className="details-block-title" style={{ textAlign: 'left', fontWeight: 700, fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Attacker Exploitation Narrative</div>
                  <p className="details-desc" style={{ textAlign: 'left', fontSize: '0.75rem', color: 'var(--rose-primary)', background: 'var(--rose-light)', border: '1px solid rgba(244, 63, 94, 0.15)', padding: '12px 16px', borderRadius: '12px', lineHeight: 1.6, marginTop: '4px' }}>
                    <strong>Attacker:</strong> "{finding.attack_narrative}"
                  </p>
                </div>
              )}

              {/* Action Buttons */}
              <div className="actions-row" style={{ display: 'flex', gap: '12px', marginTop: '8px' }}>
                <button 
                  onClick={() => onAutoFix(finding)}
                  disabled={isFixing}
                  className="action-btn-primary"
                  style={{ cursor: 'pointer', padding: '8px 18px', display: 'flex', alignItems: 'center', gap: '8px', border: 'none', borderRadius: '99px', background: 'var(--cyan-primary)', color: '#000', fontWeight: 700 }}
                >
                  <Cpu size={14} />
                  {finding.secure_fix ? 'Re-Remediate' : isFixing ? 'Fixing...' : 'Remediate Code'}
                </button>
                {finding.file_path && finding.file_path !== 'unknown' && (
                  <button 
                    onClick={() => onInspectFile(finding.file_path!, finding.line_number)}
                    className="action-btn-secondary"
                    style={{ cursor: 'pointer', padding: '8px 18px', display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255,255,255,0.05)', color: 'var(--text-primary)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '99px', fontWeight: 600 }}
                  >
                    <Eye size={14} />
                    Inspect Source
                  </button>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
