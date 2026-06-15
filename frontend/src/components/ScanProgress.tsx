import { motion, AnimatePresence } from 'framer-motion';
import { RefreshCw } from 'lucide-react';

interface ScanProgressProps {
  isOpen: boolean;
  stage: string;
  progress: number;
}

export function ScanProgress({ isOpen, stage, progress }: ScanProgressProps) {
  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop blur */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(5, 5, 8, 0.85)',
              backdropFilter: 'blur(12px)',
              zIndex: 999,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            {/* Modal Body */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              transition={{ type: 'spring', damping: 25, stiffness: 350 }}
              style={{
                width: '100%',
                maxWidth: '400px',
                padding: '1px',
                borderRadius: '24px',
                background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.2) 0%, rgba(255, 255, 255, 0.02) 100%)'
              }}
            >
              <div 
                style={{
                  background: 'var(--bg-glass)',
                  padding: '36px',
                  borderRadius: '23px',
                  textAlign: 'center',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '24px'
                }}
              >
                {/* Rotating gear/icon wrapper */}
                <div 
                  style={{ 
                    position: 'relative',
                    width: '64px',
                    height: '64px',
                    borderRadius: '50%',
                    background: 'var(--cyan-light)',
                    border: '1px solid rgba(6, 182, 212, 0.2)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}
                >
                  <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" strokeWidth={1.5} />
                </div>

                <div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Auditing Application Code
                  </h3>
                  <p style={{ fontSize: '0.75rem', color: 'var(--cyan-primary)', fontWeight: 600, marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
                    {stage}
                  </p>
                </div>

                {/* Progress bar fill */}
                <div style={{ width: '100%' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: 600 }}>
                    <span>Static SAST + Gemini AI</span>
                    <span>{progress}%</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.05)', borderRadius: '99px', overflow: 'hidden' }}>
                    <motion.div 
                      style={{ height: '100%', background: 'var(--cyan-primary)', boxShadow: '0 0 12px var(--cyan-primary)' }}
                      initial={{ width: 0 }}
                      animate={{ width: `${progress}%` }}
                      transition={{ duration: 0.3 }}
                    />
                  </div>
                </div>

                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                  Extracting parameters, checking tokens, building threat vectors...
                </span>
              </div>
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
