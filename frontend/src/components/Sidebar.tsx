import { NavLink, useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, SearchCode, Settings, LogOut } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export function Sidebar() {
  const { signOut, user } = useAuth();
  const navigate = useNavigate();

  const handleSignOut = async () => {
    await signOut();
    navigate('/login');
  };

  return (
    <aside 
      style={{
        width: '240px',
        background: 'rgba(10, 10, 15, 0.7)',
        backdropFilter: 'blur(16px)',
        borderRight: '1px solid var(--border-glass)',
        display: 'flex',
        flexDirection: 'column',
        padding: '24px 16px',
        height: '100vh',
        position: 'sticky',
        top: 0
      }}
    >
      {/* Brand Header */}
      <div className="logo-section" style={{ marginBottom: '32px', paddingLeft: '8px' }}>
        <div className="logo-icon-wrap" style={{ background: 'var(--cyan-light)' }}>
          <Shield className="h-5 w-5 text-cyan-400" strokeWidth={1.5} />
        </div>
        <span className="logo-title" style={{ fontSize: '1rem', fontWeight: 700 }}>
          CodeShield <span className="logo-badge">X</span>
        </span>
      </div>

      {/* Nav List */}
      <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1 }}>
        <NavLink 
          to="/dashboard" 
          className={({ isActive }) => `file-btn ${isActive ? 'active' : ''}`}
          style={{ textDecoration: 'none', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: '12px' }}
        >
          <LayoutDashboard size={16} />
          <span>Dashboard</span>
        </NavLink>

        <NavLink 
          to="/scan/new" 
          className={({ isActive }) => `file-btn ${isActive ? 'active' : ''}`}
          style={{ textDecoration: 'none', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: '12px' }}
        >
          <SearchCode size={16} />
          <span>New Audit</span>
        </NavLink>

        <NavLink 
          to="/settings" 
          className={({ isActive }) => `file-btn ${isActive ? 'active' : ''}`}
          style={{ textDecoration: 'none', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: '12px' }}
        >
          <Settings size={16} />
          <span>Settings</span>
        </NavLink>
      </nav>

      {/* Profile/Footer */}
      <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', paddingLeft: '8px' }}>
          <div 
            style={{ 
              width: '32px', 
              height: '32px', 
              borderRadius: '50%', 
              background: 'var(--cyan-light)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--cyan-primary)',
              fontSize: '0.8rem',
              fontWeight: 700
            }}
          >
            {user?.email?.charAt(0).toUpperCase() || 'U'}
          </div>
          <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '140px' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {user?.email?.split('@')[0]}
            </div>
            <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>
              {user?.email}
            </div>
          </div>
        </div>

        <button 
          onClick={handleSignOut}
          className="file-btn" 
          style={{ border: 'none', background: 'transparent', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer', color: 'var(--rose-primary)' }}
        >
          <LogOut size={16} />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}
