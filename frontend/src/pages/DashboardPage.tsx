import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { SearchCode, RefreshCw } from 'lucide-react';
import { supabase } from '../lib/supabase';
import type { Scan } from '../types';
import { Sidebar } from '../components/Sidebar';
import { useAuth } from '../hooks/useAuth';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';

const DEMO_SCANS: Scan[] = [
  { id: 'demo-scan-1', user_id: 'demo-123', project_name: 'checkout-api', source_type: 'paste', status: 'done', overall_score: 42, projected_score: 78, grade: 'D', created_at: new Date(Date.now() - 86400000 * 2).toISOString() },
  { id: 'demo-scan-2', user_id: 'demo-123', project_name: 'user-service', source_type: 'github', status: 'done', overall_score: 67, projected_score: 88, grade: 'C', created_at: new Date(Date.now() - 86400000).toISOString() },
  { id: 'demo-scan-3', user_id: 'demo-123', project_name: 'payment-gateway', source_type: 'zip', status: 'done', overall_score: 81, projected_score: 95, grade: 'A', created_at: new Date().toISOString() },
];

export default function DashboardPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const isDemo = user?.id === 'demo-123';
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  // Aggregated KPI Stats
  const [stats, setStats] = useState({
    totalScans: 0,
    avgScore: 100,
    criticalHighCount: 0
  });

  useEffect(() => {
    if (isDemo) {
      setScans(DEMO_SCANS);
      setStats({ totalScans: 3, avgScore: 63, criticalHighCount: 5 });
      setLoading(false);
      return;
    }

    async function loadScans() {
      try {
        setLoading(true);
        const { data, error } = await supabase
          .from('scans')
          .select('*')
          .order('created_at', { ascending: false });

        if (error) throw error;

        if (data) {
          setScans(data);

          const total = data.length;
          let sumScore = 0;
          let doneScansCount = 0;
          data.forEach(s => {
            if (s.status === 'done' && s.overall_score !== undefined) {
              sumScore += s.overall_score;
              doneScansCount++;
            }
          });
          const avg = doneScansCount > 0 ? Math.round(sumScore / doneScansCount) : 100;

          const { data: findings } = await supabase
            .from('findings')
            .select('severity, is_fixed');

          let criticalHigh = 0;
          if (findings) {
            findings.forEach(f => {
              if ((f.severity === 'Critical' || f.severity === 'High') && !f.is_fixed) {
                criticalHigh++;
              }
            });
          }

          setStats({
            totalScans: total,
            avgScore: avg,
            criticalHighCount: criticalHigh
          });
        }
      } catch (err) {
        console.error("Failed to load scans dashboard data:", err);
      } finally {
        setLoading(false);
      }
    }

    loadScans();
  }, [isDemo]);

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'var(--emerald-primary)';
    if (score >= 55) return 'var(--orange-primary)';
    return 'var(--rose-primary)';
  };

  const trendData = [...scans]
    .filter(s => s.status === 'done' && s.overall_score !== undefined)
    .reverse()
    .map((s, idx) => ({
      name: `Audit ${idx + 1}`,
      score: s.overall_score
    }));

  if (loading) {
    return (
      <div style={{ display: 'flex', minHeight: '100vh', background: '#050508' }}>
        <Sidebar />
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#050508' }}>
      <Sidebar />

      <main style={{ flex: 1, padding: '40px', overflowY: 'auto' }}>

        {/* Title Bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '36px', textAlign: 'left' }}>
          <div>
            <h1 className="logo-title" style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Security Overview
            </h1>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Clean tracking of your project security health indices.
            </p>
          </div>

          <Link
            to="/scan/new"
            className="cta-button"
            style={{ textDecoration: 'none', margin: 0, padding: '10px 24px' }}
          >
            <span>Run New Audit</span>
            <div className="cta-icon-wrap" style={{ width: '24px', height: '24px' }}>
              <SearchCode size={12} style={{ color: '#000' }} />
            </div>
          </Link>
        </div>

        {/* KPI Row (Simplified to 3 metrics) */}
        <div className="kpi-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '32px' }}>
          {/* Average Score */}
          <div className="double-bezel-outer">
            <div className="double-bezel-inner" style={{ padding: '20px', textAlign: 'left' }}>
              <div className="kpi-label">Average Health Rating</div>
              <div className="kpi-value" style={{ color: getScoreColor(stats.avgScore) }}>{stats.avgScore}%</div>
              <div className="kpi-change" style={{ color: getScoreColor(stats.avgScore) }}>Overall code security posture</div>
            </div>
          </div>

          {/* Active Threats */}
          <div className="double-bezel-outer">
            <div className="double-bezel-inner" style={{ padding: '20px', textAlign: 'left' }}>
              <div className="kpi-label">Active Threats</div>
              <div className="kpi-value" style={{ color: stats.criticalHighCount > 0 ? 'var(--rose-primary)' : 'var(--emerald-primary)' }}>
                {stats.criticalHighCount}
              </div>
              <div className="kpi-change" style={{ color: stats.criticalHighCount > 0 ? 'var(--rose-primary)' : 'var(--emerald-primary)' }}>
                Vulnerabilities requiring fix
              </div>
            </div>
          </div>

          {/* Total Scans */}
          <div className="double-bezel-outer">
            <div className="double-bezel-inner" style={{ padding: '20px', textAlign: 'left' }}>
              <div className="kpi-label">Total Audits</div>
              <div className="kpi-value">{stats.totalScans}</div>
              <div className="kpi-change positive">Project repositories analyzed</div>
            </div>
          </div>
        </div>

        {/* Historical Trend Line (Simplified) */}
        {trendData.length > 0 && (
          <div className="double-bezel-outer" style={{ marginBottom: '32px' }}>
            <div className="double-bezel-inner" style={{ textAlign: 'left' }}>
              <span className="section-tag cyan">Timeline</span>
              <h3 className="panel-title" style={{ marginBottom: '20px' }}>Security Rating History</h3>
              <div style={{ width: '100%', height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--cyan-primary)" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="var(--cyan-primary)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                    <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} domain={[0, 100]} />
                    <Tooltip
                      contentStyle={{
                        background: 'rgba(10, 10, 15, 0.9)',
                        border: '1px solid var(--border-glass)',
                        borderRadius: '8px',
                        fontSize: '11px',
                        color: 'var(--text-primary)'
                      }}
                    />
                    <Area type="monotone" dataKey="score" stroke="var(--cyan-primary)" fillOpacity={1} fill="url(#colorScore)" strokeWidth={2.5} name="Security Score" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {/* Scan Log Table (Simplified columns) */}
        <div className="double-bezel-outer">
          <div className="double-bezel-inner" style={{ padding: 0, textAlign: 'left' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <span className="section-tag rose">Registry</span>
              <h3 className="panel-title" style={{ margin: 0 }}>Audit History Registry</h3>
            </div>

            <div style={{ overflowX: 'auto' }}>
              {scans.length === 0 ? (
                <div style={{ padding: '40px', color: 'var(--text-muted)', fontSize: '0.80rem', textAlign: 'center' }}>
                  No security audits logged. Run an audit to view history.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid rgba(255, 255, 255, 0.08)' }}>
                      <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'left' }}>Project Name</th>
                      <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'center' }}>Secure Score</th>
                      <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'center' }}>Grade</th>
                      <th style={{ padding: '12px 24px', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'right' }}>Scanned Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((s) => (
                      <tr
                        key={s.id}
                        onClick={() => s.status === 'done' && navigate(`/scan/${s.id}`)}
                        style={{
                          borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                          fontSize: '0.75rem',
                          color: 'var(--text-secondary)',
                          cursor: s.status === 'done' ? 'pointer' : 'default',
                          transition: 'background 0.2s'
                        }}
                        onMouseEnter={(e) => s.status === 'done' && (e.currentTarget.style.background = 'rgba(255,255,255,0.01)')}
                        onMouseLeave={(e) => s.status === 'done' && (e.currentTarget.style.background = 'transparent')}
                      >
                        {/* Project Name */}
                        <td style={{ padding: '16px 24px', color: 'var(--text-primary)', fontWeight: 600, textAlign: 'left' }}>
                          {s.project_name}
                          <span style={{
                            marginLeft: '8px',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            fontSize: '0.55rem',
                            fontFamily: 'var(--font-mono)',
                            background: s.status === 'done' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)',
                            color: s.status === 'done' ? 'var(--emerald-primary)' : 'var(--rose-primary)'
                          }}>
                            {s.source_type}
                          </span>
                        </td>
                        {/* Secure Score */}
                        <td style={{ padding: '16px 24px', textAlign: 'center', fontWeight: 700, color: s.overall_score ? getScoreColor(s.overall_score) : 'var(--text-muted)' }}>
                          {s.overall_score !== undefined ? `${s.overall_score}%` : 'N/A'}
                        </td>
                        {/* Grade */}
                        <td style={{ padding: '16px 24px', textAlign: 'center', fontWeight: 700, color: s.overall_score ? getScoreColor(s.overall_score) : 'var(--text-muted)' }}>
                          {s.grade || 'N/A'}
                        </td>
                        {/* Created Date */}
                        <td style={{ padding: '16px 24px', color: 'var(--text-muted)', textAlign: 'right' }}>
                          {s.created_at ? new Date(s.created_at).toLocaleDateString() : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
