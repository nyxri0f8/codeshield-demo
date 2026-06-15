import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Key, Eye, EyeOff, Check } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useGeminiKey } from '../hooks/useGeminiKey';
import { Sidebar } from '../components/Sidebar';

export default function SettingsPage() {
  const { user } = useAuth();
  const { geminiKey, saveKey, saving } = useGeminiKey(user?.id);
  const [inputKey, setInputKey] = useState('');
  const [show, setShow] = useState(false);
  const [saved, setSaved] = useState(false);

  // Sync inputs when loaded
  useEffect(() => {
    if (geminiKey) {
      setInputKey(geminiKey);
    }
  }, [geminiKey]);

  const handleSave = async () => {
    if (!inputKey.trim()) return;
    await saveKey(inputKey);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#050508' }}>
      <Sidebar />
      
      <main style={{ flex: 1, padding: '40px', maxWidth: '800px', margin: '0 auto', textAlign: 'left' }}>
        <h1 className="logo-title" style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
          Account Settings
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '36px' }}>
          Manage credentials and security integration parameter models.
        </p>

        {/* Gemini Key Config Card */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="double-bezel-outer"
        >
          <div className="double-bezel-inner" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div 
                style={{ 
                  width: '36px', 
                  height: '36px', 
                  borderRadius: '10px', 
                  background: 'var(--cyan-light)', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center' 
                }}
              >
                <Key className="w-4 h-4 text-cyan-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  Google Gemini API Configuration
                </h3>
                <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', margin: 0, marginTop: '2px' }}>
                  {geminiKey ? 'API Key Active (●●●●' + geminiKey.slice(-4) + ')' : 'No key configured. Running in offline fallback mode.'}
                </p>
              </div>
              {geminiKey && (
                <span 
                  style={{ 
                    marginLeft: 'auto', 
                    fontSize: '0.65rem', 
                    color: 'var(--emerald-primary)', 
                    background: 'rgba(16, 185, 129, 0.1)', 
                    padding: '2px 8px', 
                    borderRadius: '99px',
                    border: '1px solid rgba(16, 185, 129, 0.2)'
                  }}
                >
                  Connected
                </span>
              )}
            </div>

            {/* Input wrap */}
            <div style={{ position: 'relative' }}>
              <input
                type={show ? 'text' : 'password'}
                placeholder="AIzaSy... (Paste Gemini API key from AI Studio)"
                value={inputKey}
                onChange={(e) => setInputKey(e.target.value)}
                className="standard-input"
                style={{ paddingLeft: '16px', paddingRight: '48px' }}
              />
              <button
                onClick={() => setShow(!show)}
                style={{
                  position: 'absolute',
                  right: '16px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer'
                }}
              >
                {show ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>

            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: 1.4, margin: 0 }}>
              The key is saved inside your private profile. It is used at runtime solely to contact the Gemini LLM endpoint directly from your browser. Get your API key at <a href="https://aistudio.google.com" target="_blank" rel="noreferrer" style={{ color: 'var(--cyan-primary)', textDecoration: 'none' }}>aistudio.google.com</a>.
            </p>

            <motion.button
              onClick={handleSave}
              disabled={saving || !inputKey.trim()}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.97 }}
              className="action-btn-primary"
              style={{
                alignSelf: 'flex-start',
                cursor: 'pointer',
                padding: '10px 20px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                border: 'none',
                borderRadius: '12px',
                background: 'var(--cyan-primary)',
                color: '#000',
                fontWeight: 700,
                fontSize: '0.8rem',
                minWidth: '120px',
                justifyContent: 'center'
              }}
            >
              {saved ? <Check size={16} /> : <Key size={16} />}
              <span>{saved ? 'Saved!' : saving ? 'Saving...' : 'Save Config'}</span>
            </motion.button>
          </div>
        </motion.div>
      </main>
    </div>
  );
}
