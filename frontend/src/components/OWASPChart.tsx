import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';
import type { Finding } from '../types';

interface OWASPChartProps {
  findings: Finding[];
}

export function OWASPChart({ findings }: OWASPChartProps) {
  // Aggregate findings by OWASP category
  const categories: Record<string, number> = {};
  const severities: Record<string, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0
  };

  findings.forEach((f) => {
    // Severity aggregation
    if (f.severity in severities) {
      severities[f.severity]++;
    }

    // OWASP category aggregation
    const owasp = f.owasp_category || 'Other / General';
    const categoryKey = owasp.split(':')[0] || owasp; // e.g., A03:2021 -> A03
    categories[categoryKey] = (categories[categoryKey] || 0) + 1;
  });

  // Convert categories to array
  const owaspData = Object.entries(categories).map(([name, count]) => ({
    name,
    count
  })).sort((a, b) => b.count - a.count);

  // Convert severities to array
  const severityData = Object.entries(severities)
    .filter(([_, count]) => count > 0)
    .map(([name, value]) => ({
      name,
      value
    }));

  const SEVERITY_COLORS: Record<string, string> = {
    Critical: 'var(--rose-primary)',
    High: 'var(--orange-primary)',
    Medium: '#eab308',
    Low: 'var(--cyan-primary)',
    Informational: 'var(--text-muted)'
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '24px' }}>
      
      {/* OWASP Category Bar Chart */}
      <div className="double-bezel-outer">
        <div className="double-bezel-inner">
          <span className="section-tag cyan">Distribution</span>
          <h3 className="panel-title" style={{ margin: 0, marginBottom: '20px' }}>Vulnerabilities by OWASP Category</h3>
          
          <div style={{ width: '100%', height: 220 }}>
            {owaspData.length === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                No findings data.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={owaspData} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                  <XAxis 
                    dataKey="name" 
                    stroke="var(--text-muted)" 
                    fontSize={10} 
                    tickLine={false} 
                    axisLine={false}
                  />
                  <YAxis 
                    stroke="var(--text-muted)" 
                    fontSize={10} 
                    tickLine={false} 
                    axisLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip 
                    contentStyle={{ 
                      background: 'rgba(10, 10, 15, 0.9)', 
                      border: '1px solid var(--border-glass)', 
                      borderRadius: '8px',
                      fontSize: '11px',
                      color: 'var(--text-primary)'
                    }}
                    cursor={{ fill: 'rgba(255, 255, 255, 0.02)' }}
                  />
                  <Bar dataKey="count" fill="var(--cyan-primary)" radius={[4, 4, 0, 0]}>
                    {owaspData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={index === 0 ? 'var(--cyan-primary)' : 'rgba(6, 182, 212, 0.6)'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Severity Breakdown Pie Chart */}
      <div className="double-bezel-outer">
        <div className="double-bezel-inner">
          <span className="section-tag rose">Aggregates</span>
          <h3 className="panel-title" style={{ margin: 0, marginBottom: '20px' }}>Findings by Severity Level</h3>
          
          <div style={{ width: '100%', height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {severityData.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                No findings data.
              </div>
            ) : (
              <>
                <div style={{ width: '50%', height: '100%' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || 'var(--text-muted)'} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          background: 'rgba(10, 10, 15, 0.9)', 
                          border: '1px solid var(--border-glass)', 
                          borderRadius: '8px',
                          fontSize: '11px',
                          color: 'var(--text-primary)'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                
                {/* Custom Legend */}
                <div style={{ width: '50%', paddingLeft: '12px', display: 'flex', flexDirection: 'column', gap: '8px', textAlign: 'left' }}>
                  {severityData.map((entry) => (
                    <div key={entry.name} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.75rem' }}>
                      <span 
                        style={{ 
                          width: '8px', 
                          height: '8px', 
                          borderRadius: '50%', 
                          background: SEVERITY_COLORS[entry.name],
                          display: 'inline-block' 
                        }} 
                      />
                      <span style={{ color: 'var(--text-secondary)' }}>{entry.name}:</span>
                      <strong style={{ color: 'var(--text-primary)' }}>{entry.value}</strong>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

    </div>
  );
}
