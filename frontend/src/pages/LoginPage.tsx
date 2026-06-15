import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Mail, Lock, AlertTriangle, User, Key, Sparkles, CheckCircle, ArrowRight } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { supabase } from '../lib/supabase';

export default function LoginPage() {
  const { signInWithGoogle, signInWithEmail, signUpWithEmail, signInAsDemo } = useAuth();
  const navigate = useNavigate();
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [geminiKey, setGeminiKey] = useState('');
  
  const [isSignUp, setIsSignUp] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
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
    setError('');
    setSuccessMsg('');

    if (!email.trim() || !password.trim()) {
      setError('Please fill in all required fields.');
      return;
    }
    if (isSignUp && !fullName.trim()) {
      setError('Please enter your name.');
      return;
    }

    setLoading(true);
    
    try {
      if (isSignUp) {
        const { data, error: authErr } = await signUpWithEmail(email, password, fullName);
        if (authErr) {
          setError(authErr.message);
        } else {
          const session = data?.session;
          const user = data?.user;

          // If session exists, store Gemini Key in profile table immediately
          if (geminiKey.trim() && user && session) {
            const { error: profileErr } = await supabase
              .from('profiles')
              .update({ gemini_api_key: geminiKey.trim() })
              .eq('id', user.id);
            if (profileErr) {
              console.warn("Could not save Gemini Key to profile:", profileErr.message);
            }
          }

          if (session) {
            navigate('/dashboard');
          } else {
            setSuccessMsg('Account created! Please check your email to confirm your account and sign in.');
            setIsSignUp(false);
            setPassword('');
            setFullName('');
            setGeminiKey('');
          }
        }
      } else {
        const { error: authErr } = await signInWithEmail(email, password);
        if (authErr) {
          setError(authErr.message);
        } else {
          navigate('/dashboard');
        }
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
        minHeight: '100dvh', 
        display: 'flex', 
        background: '#030305',
        fontFamily: 'var(--font-sans)',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      {/* Background Mesh Gradients */}
      <div 
        style={{ 
          top: '-10%', 
          left: '-10%', 
          width: '600px', 
          height: '600px', 
          background: 'radial-gradient(circle, rgba(6, 182, 212, 0.08) 0%, transparent 70%)', 
          position: 'absolute', 
          pointerEvents: 'none' 
        }} 
      />
      <div 
        style={{ 
          bottom: '-10%', 
          right: '-10%', 
          width: '500px', 
          height: '500px', 
          background: 'radial-gradient(circle, rgba(244, 63, 94, 0.04) 0%, transparent 70%)', 
          position: 'absolute', 
          pointerEvents: 'none' 
        }} 
      />

      {/* Left Panel: Branding & Product Info (Hidden on mobile) */}
      <div 
        style={{
          flex: 1.2,
          position: 'relative',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '60px',
          background: 'radial-gradient(circle at 10% 20%, rgba(6, 182, 212, 0.06), transparent 60%), #050508',
          borderRight: '1px solid var(--border-glass)',
          overflow: 'hidden'
        }}
        className="login-left-panel"
      >
        {/* Decorative Grid */}
        <div style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: 'radial-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 0)',
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
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '8px' }}>
              CodeShield <span className="logo-badge">X</span>
            </h1>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', margin: 0, fontWeight: 500, textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              AI Application Security Auditing
            </p>
          </div>
        </div>

        {/* Center Tagline */}
        <div style={{ maxWidth: '460px', margin: 'auto 0', zIndex: 2, textAlign: 'left' }}>
          <span className="section-tag cyan" style={{ marginBottom: '16px' }}>Vanguard Auditing</span>
          <motion.h2 
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
            style={{ fontSize: '2.4rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.15, letterSpacing: '-0.03em', marginBottom: '20px' }}
          >
            Securing codebases at the speed of thought.
          </motion.h2>
          <motion.p 
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
            style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '0' }}
          >
            Connect repositories or paste your code. CodeShield X performs immediate hybrid pre-scans and leverages Google Gemini AI to find logic flaws, IDOR endpoints, hardcoded secrets, and compliance drift.
          </motion.p>
        </div>

        {/* Left Panel Footer Placeholder to Balance Spacing */}
        <div style={{ height: '24px', zIndex: 2 }} />
      </div>

      {/* Right Panel: Auth Form */}
      <div 
        style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '40px',
          position: 'relative',
          zIndex: 2
        }}
      >
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          style={{
            width: '100%',
            maxWidth: '420px',
            background: 'rgba(8, 8, 12, 0.65)',
            border: '1px solid rgba(255, 255, 255, 0.07)',
            borderRadius: '28px',
            backdropFilter: 'blur(30px)',
            boxShadow: '0 24px 64px rgba(0,0,0,0.6), inset 0 1px 1px rgba(255,255,255,0.08)',
            padding: '40px',
          }}
        >
          {/* Logo on small screens (Hidden on desktop) */}
          <div className="login-mobile-logo" style={{ display: 'none', alignItems: 'center', gap: '10px', marginBottom: '24px' }}>
            <Shield className="w-5 h-5 text-cyan-400" />
            <span style={{ fontSize: '1.1rem', fontWeight: 800 }}>CodeShield X</span>
          </div>

          <h2 style={{ fontSize: '1.45rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px', textAlign: 'left', letterSpacing: '-0.01em' }}>
            {isSignUp ? 'Create account' : 'Welcome back'}
          </h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '28px', textAlign: 'left', lineHeight: '1.4' }}>
            {isSignUp ? 'Start auditing your code for vulnerabilities.' : 'Sign in to your security dashboard.'}
          </p>

          {/* Success Banner */}
          {successMsg && (
            <div style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              color: 'var(--emerald-primary)',
              background: 'rgba(16, 185, 129, 0.06)',
              border: '1px solid rgba(16, 185, 129, 0.2)',
              padding: '12px 16px',
              borderRadius: '14px',
              fontSize: '0.8rem',
              textAlign: 'left',
              marginBottom: '20px'
            }}>
              <CheckCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              color: 'var(--rose-primary)',
              background: 'rgba(244, 63, 94, 0.06)',
              border: '1px solid rgba(244, 63, 94, 0.2)',
              padding: '12px 16px',
              borderRadius: '14px',
              fontSize: '0.8rem',
              textAlign: 'left',
              marginBottom: '20px'
            }}>
              <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
              <span>{error}</span>
            </div>
          )}

          {/* Google OAuth Button */}
          {!isSignUp && (
            <>
              <motion.button
                onClick={handleGoogle}
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.98 }}
                disabled={loading}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '12px',
                  padding: '14px',
                  borderRadius: '16px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
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
            </>
          )}

          {/* Form */}
          <form onSubmit={handleEmail} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            
            {/* Full Name (Sign Up only) */}
            {isSignUp && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', textAlign: 'left' }}>
                <label style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700 }}>
                  Full Name
                </label>
                {/* Double Bezel Input */}
                <div style={{
                  padding: '1px',
                  background: 'linear-gradient(180deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%)',
                  borderRadius: '16px',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                  boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.02), 0 4px 12px rgba(0,0,0,0.2)'
                }}>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    background: 'rgba(5, 5, 8, 0.7)',
                    borderRadius: '15px',
                    padding: '4px 14px',
                    border: '1px solid rgba(0,0,0,0.3)'
                  }}>
                    <User className="w-4 h-4 text-cyan-400/60" style={{ marginRight: '10px' }} />
                    <input
                      type="text"
                      placeholder="Jane Doe"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        outline: 'none',
                        color: 'var(--text-primary)',
                        fontSize: '0.8rem',
                        padding: '10px 0 10px 4px',
                        width: '100%',
                        fontFamily: 'var(--font-sans)',
                      }}
                      required
                      disabled={loading}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Email Address */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', textAlign: 'left' }}>
              <label style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700 }}>
                Email Address
              </label>
              <div style={{
                padding: '1px',
                background: 'linear-gradient(180deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%)',
                borderRadius: '16px',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.02), 0 4px 12px rgba(0,0,0,0.2)'
              }}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  background: 'rgba(5, 5, 8, 0.7)',
                  borderRadius: '15px',
                  padding: '4px 14px',
                  border: '1px solid rgba(0,0,0,0.3)'
                }}>
                  <Mail className="w-4 h-4 text-cyan-400/60" style={{ marginRight: '10px' }} />
                  <input
                    type="email"
                    placeholder="email@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      outline: 'none',
                      color: 'var(--text-primary)',
                      fontSize: '0.8rem',
                      padding: '10px 0 10px 4px',
                      width: '100%',
                      fontFamily: 'var(--font-sans)',
                    }}
                    required
                    disabled={loading}
                  />
                </div>
              </div>
            </div>

            {/* Password */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', textAlign: 'left' }}>
              <label style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700 }}>
                Password
              </label>
              <div style={{
                padding: '1px',
                background: 'linear-gradient(180deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%)',
                borderRadius: '16px',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.02), 0 4px 12px rgba(0,0,0,0.2)'
              }}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  background: 'rgba(5, 5, 8, 0.7)',
                  borderRadius: '15px',
                  padding: '4px 14px',
                  border: '1px solid rgba(0,0,0,0.3)'
                }}>
                  <Lock className="w-4 h-4 text-cyan-400/60" style={{ marginRight: '10px' }} />
                  <input
                    type="password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      outline: 'none',
                      color: 'var(--text-primary)',
                      fontSize: '0.8rem',
                      padding: '10px 0 10px 4px',
                      width: '100%',
                      fontFamily: 'var(--font-sans)',
                    }}
                    required
                    disabled={loading}
                  />
                </div>
              </div>
            </div>

            {/* Gemini API Key (Sign Up only) */}
            {isSignUp && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', textAlign: 'left' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Sparkles className="w-3 h-3 text-cyan-400" /> Gemini API Key <span style={{ color: 'rgba(255,255,255,0.3)', textTransform: 'lowercase', fontWeight: 400 }}>(optional)</span>
                  </label>
                </div>
                <div style={{
                  padding: '1px',
                  background: 'linear-gradient(180deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%)',
                  borderRadius: '16px',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                  boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.02), 0 4px 12px rgba(0,0,0,0.2)'
                }}>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    background: 'rgba(5, 5, 8, 0.7)',
                    borderRadius: '15px',
                    padding: '4px 14px',
                    border: '1px solid rgba(0,0,0,0.3)'
                  }}>
                    <Key className="w-4 h-4 text-cyan-400/60" style={{ marginRight: '10px' }} />
                    <input
                      type="password"
                      placeholder="AI_..."
                      value={geminiKey}
                      onChange={(e) => setGeminiKey(e.target.value)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        outline: 'none',
                        color: 'var(--text-primary)',
                        fontSize: '0.8rem',
                        padding: '10px 0 10px 4px',
                        width: '100%',
                        fontFamily: 'var(--font-mono)',
                      }}
                      disabled={loading}
                    />
                  </div>
                </div>
                <span style={{ fontSize: '0.6rem', color: 'rgba(255,255,255,0.3)', paddingLeft: '4px', lineHeight: '1.3' }}>
                  Stored securely to enable deep AI vulnerability reviews.
                </span>
              </div>
            )}

            {/* Submit Button */}
            <motion.button
              type="submit"
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.98 }}
              disabled={loading}
              style={{
                width: '100%',
                padding: '6px 6px 6px 20px',
                borderRadius: '99px',
                background: 'var(--cyan-primary)',
                border: 'none',
                color: '#000',
                fontWeight: 700,
                fontSize: '0.85rem',
                cursor: 'pointer',
                marginTop: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                transition: 'all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275)',
                boxShadow: '0 8px 24px rgba(6, 182, 212, 0.25)'
              }}
            >
              <span style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {loading ? 'Processing...' : isSignUp ? 'Create Account' : 'Sign In'}
              </span>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '99px',
                background: 'rgba(0, 0, 0, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <ArrowRight size={14} />
              </div>
            </motion.button>
          </form>

          {/* Toggle Login/Signup */}
          <p style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '24px', margin: '24px 0 0' }}>
            {isSignUp ? 'Already have an account? ' : "Don't have an account? "}
            <button
              onClick={() => {
                setIsSignUp(!isSignUp);
                setError('');
                setSuccessMsg('');
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '24px' }}>
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
