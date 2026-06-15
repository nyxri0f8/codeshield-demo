import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Mail, Lock, AlertTriangle } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export default function LoginPage() {
  const { signInWithGoogle, signInWithEmail, signUpWithEmail, signInAsDemo } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSignUp, setIsSignUp] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleGoogle = async () => {
    try {
      setLoading(true);
      await signInWithGoogle();
    } catch (err: any) {
      setError(err.message || 'Google OAuth failed.');
      setLoading(false);
    }
  };

  const handleEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) return;

    setError('');
    setLoading(true);
    
    try {
      const { error: authErr } = isSignUp
        ? await signUpWithEmail(email, password)
        : await signInWithEmail(email, password);

      if (authErr) {
        setError(authErr.message);
      } else {
        navigate('/dashboard');
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemo = () => {
    signInAsDemo();
    navigate('/dashboard');
  };

  return (
    <div 
      style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        background: '#050508',
        fontFamily: 'var(--font-sans)',
      }}
    >
      {/* Left Panel: Branding & Product Info (Hidden on mobile) */}
      <div 
        style={{
          flex: 1.2,
          position: 'relative',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '60px',
          background: 'radial-gradient(circle at 10% 20%, rgba(6, 182, 212, 0.1), transparent 60%), radial-gradient(circle at 90% 80%, rgba(244, 63, 94, 0.05), transparent 60%), #080C14',
          borderRight: '1px solid var(--border-glass)',
          overflow: 'hidden'
        }}
        className="login-left-panel"
      >
        {/* Decorative Grid */}
        <div style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: 'radial-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 0)',
          backgroundSize: '24px 24px',
          pointerEvents: 'none'
        }} />

        {/* Brand Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', zIndex: 2 }}>
          <div 
            style={{ 
              width: '44px', 
              height: '44px', 
              borderRadius: '14px', 
              background: 'var(--cyan-light)', 
              border: '1px solid rgba(6, 182, 212, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '8px' }}>
              CodeShield <span className="logo-badge">X</span>
            </h1>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', margin: 0, fontWeight: 500, textAlign: 'left' }}>
              AI Application Security Auditing
            </p>
          </div>
        </div>

        {/* Center Tagline */}
        <div style={{ maxWidth: '480px', margin: 'auto 0', zIndex: 2, textAlign: 'left' }}>
          <motion.h2 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.8 }}
            style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.1, letterSpacing: '-0.03em', marginBottom: '20px' }}
          >
            Securing codebases at the speed of thought.
          </motion.h2>
          <motion.p 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.8 }}
            style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '0' }}
          >
            Connect repositories or paste your code. CodeShield X performs immediate hybrid pre-scans and leverages Google Gemini AI to find logic flaws, IDOR points, hardcoded secrets, and compliance drift.
          </motion.p>
        </div>

        {/* Left Panel Footer */}
        <div style={{ display: 'flex', gap: '24px', zIndex: 2, textAlign: 'left' }}>
          <div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--cyan-primary)' }}>&lt; 5s</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '2px' }}>Static Pre-Scan</div>
          </div>
          <div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)' }}>Gemini 1.5</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '2px' }}>Vulnerability Enrichment</div>
          </div>
          <div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--emerald-primary)' }}>100%</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '2px' }}>Auto-Remediation</div>
          </div>
        </div>
      </div>

      {/* Right Panel: Auth Form */}
      <div 
        style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '40px',
          position: 'relative'
        }}
      >
        {/* Glow behind the form */}
        <div style={{
          position: 'absolute',
          width: '300px',
          height: '300px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(6, 182, 212, 0.08) 0%, transparent 70%)',
          pointerEvents: 'none'
        }} />

        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
          style={{
            width: '100%',
            maxWidth: '400px',
            background: 'var(--bg-glass)',
            border: '1px solid var(--border-glass)',
            borderRadius: '24px',
            backdropFilter: 'blur(20px)',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.06)',
            padding: '40px',
          }}
        >
          {/* Logo on small screens (Hidden on desktop) */}
          <div className="login-mobile-logo" style={{ display: 'none', alignItems: 'center', gap: '10px', marginBottom: '24px' }}>
            <Shield className="w-5 h-5 text-cyan-400" />
            <span style={{ fontSize: '1.1rem', fontWeight: 800 }}>CodeShield X</span>
          </div>

          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px', textAlign: 'left' }}>
            {isSignUp ? 'Create account' : 'Welcome back'}
          </h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '28px', textAlign: 'left' }}>
            {isSignUp ? 'Start auditing your code for vulnerabilities.' : 'Sign in to your security dashboard.'}
          </p>

          {/* Google OAuth Button with inline Google SVG logo */}
          <motion.button
            onClick={handleGoogle}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
            disabled={loading}
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '12px',
              padding: '14px',
              borderRadius: '16px',
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'background 0.2s',
              marginBottom: '20px'
            }}
          >
            <svg viewBox="0 0 24 24" width="16" height="16" style={{ marginRight: '2px' }}>
              <path fill="#EA4335" d="M12 5.04c1.66 0 3.2.57 4.38 1.69l3.27-3.27C17.67 1.54 14.98 0 12 0 7.35 0 3.37 2.67 1.46 6.56l3.86 3c.9-2.69 3.42-4.52 6.68-4.52z"/>
              <path fill="#4285F4" d="M23.49 12.27c0-.81-.07-1.59-.2-2.36H12v4.51h6.46c-.29 1.48-1.14 2.73-2.4 3.58l3.76 2.91c2.2-2.02 3.67-5 3.67-8.64z"/>
              <path fill="#FBBC05" d="M5.32 14.42c-.22-.66-.35-1.37-.35-2.1s1.3-1.44.35-2.1l-3.86-3C.56 9.07 0 10.48 0 12s.56 2.93 1.46 4.78l3.86-3z"/>
              <path fill="#34A853" d="M12 24c3.24 0 5.97-1.07 7.96-2.91l-3.76-2.91c-1.1.74-2.52 1.18-4.2 1.18-3.26 0-5.78-1.83-6.68-4.52H1.46v3C3.37 21.33 7.35 24 12 24z"/>
            </svg>
            Continue with Google
          </motion.button>

          {/* Divider */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
            <div style={{ flex: 1, height: '1px', background: 'rgba(255, 255, 255, 0.08)' }} />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>or use email</span>
            <div style={{ flex: 1, height: '1px', background: 'rgba(255, 255, 255, 0.08)' }} />
          </div>

          {/* Form */}
          <form onSubmit={handleEmail} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="text-input-container">
              <Mail className="input-icon" size={16} />
              <input
                type="email"
                placeholder="Email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="standard-input"
                required
                disabled={loading}
              />
            </div>
            <div className="text-input-container">
              <Lock className="input-icon" size={16} />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="standard-input"
                required
                disabled={loading}
              />
            </div>

            {error && (
              <p style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--rose-primary)', fontSize: '0.75rem', textAlign: 'left', padding: '0 4px', margin: 0 }}>
                <AlertTriangle size={12} />
                {error}
              </p>
            )}

            {/* Submit */}
            <motion.button
              type="submit"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.97 }}
              disabled={loading}
              style={{
                width: '100%',
                padding: '14px',
                borderRadius: '16px',
                background: 'var(--cyan-primary)',
                border: 'none',
                color: '#000',
                fontWeight: 700,
                fontSize: '0.85rem',
                cursor: 'pointer',
                marginTop: '10px'
              }}
            >
              {loading ? 'Authenticating...' : isSignUp ? 'Create Account' : 'Sign In'} →
            </motion.button>
          </form>

          <p style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '24px', margin: '24px 0 0' }}>
            {isSignUp ? 'Already have an account? ' : "Don't have an account? "}
            <button
              onClick={() => {
                setIsSignUp(!isSignUp);
                setError('');
              }}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--cyan-primary)',
                fontWeight: 600,
                cursor: 'pointer',
                padding: 0
              }}
            >
              {isSignUp ? 'Sign in' : 'Sign up'}
            </button>
          </p>

          {/* Demo Access */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '20px' }}>
            <div style={{ flex: 1, height: '1px', background: 'rgba(255, 255, 255, 0.06)' }} />
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>dev access</span>
            <div style={{ flex: 1, height: '1px', background: 'rgba(255, 255, 255, 0.06)' }} />
          </div>

          <motion.button
            onClick={handleDemo}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
            style={{
              marginTop: '12px',
              width: '100%',
              padding: '12px',
              borderRadius: '16px',
              background: 'transparent',
              border: '1px dashed rgba(6, 182, 212, 0.3)',
              color: 'var(--cyan-primary)',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              transition: 'background 0.2s, border-color 0.2s'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'rgba(6, 182, 212, 0.06)';
              e.currentTarget.style.borderColor = 'rgba(6, 182, 212, 0.6)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.borderColor = 'rgba(6, 182, 212, 0.3)';
            }}
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
            </svg>
            Continue as Demo User
          </motion.button>
        </motion.div>
      </div>
    </div>
  );
}
