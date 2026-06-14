from typing import List, Dict, Any

def generate_html_report(findings: List[Dict[str, Any]], metrics: Dict[str, Any], threat_model: Dict[str, Any]) -> str:
    """
    Generate clean, printable HTML report of the security scan.
    """
    score = metrics.get("overall_score", 70)
    score_color = "#ef4444" if score < 50 else ("#eab308" if score < 80 else "#22c55e")
    
    findings_html = ""
    for f in findings:
        findings_html += f"""
        <div class="card severity-{f['severity'].lower()}">
            <div class="card-header">
                <span class="badge badge-{f['severity'].lower()}">{f['severity']}</span>
                <strong>{f['name']}</strong> ({f['cwe']} | {f['owasp']})
            </div>
            <div class="card-body">
                <p><strong>File:</strong> <code>{f['file']}</code> (Line {f['line']})</p>
                <p><strong>Description:</strong> {f['description']}</p>
                <pre><code>{f['code_snippet']}</code></pre>
                <p><strong>Remediation:</strong> {f['fix_guidance']}</p>
            </div>
        </div>
        """
        
    threats_html = ""
    for threat in threat_model.get("potential_threats", []):
        threats_html += f"<li>{threat}</li>"
        
    mitigation_html = threat_model.get("mitigation_plan", "No specific mitigation plan available.")
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CodeShield AI - Security Audit Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                color: #1f2937;
                background-color: #f9fafb;
                margin: 0;
                padding: 40px 20px;
            }}
            .container {{
                max-width: 900px;
                margin: 0 auto;
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            }}
            .header {{
                border-bottom: 2px solid #e5e7eb;
                padding-bottom: 20px;
                margin-bottom: 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .title-area h1 {{
                margin: 0;
                color: #111827;
                font-size: 28px;
            }}
            .title-area p {{
                margin: 5px 0 0 0;
                color: #6b7280;
            }}
            .score-circle {{
                width: 80px;
                height: 80px;
                border-radius: 50%;
                border: 6px solid {score_color};
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 24px;
                font-weight: bold;
                color: {score_color};
            }}
            .section-title {{
                border-left: 4px solid #3b82f6;
                padding-left: 10px;
                margin-top: 40px;
                margin-bottom: 20px;
                font-size: 20px;
                color: #111827;
            }}
            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .metric-box {{
                background: #f3f4f6;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
            }}
            .metric-val {{
                font-size: 24px;
                font-weight: bold;
                color: #1f2937;
            }}
            .metric-label {{
                font-size: 12px;
                color: #6b7280;
                margin-top: 5px;
                text-transform: uppercase;
            }}
            .card {{
                background: white;
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                margin-bottom: 20px;
                overflow: hidden;
            }}
            .card-header {{
                background: #f9fafb;
                padding: 12px 20px;
                border-bottom: 1px solid #e5e7eb;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .card-body {{
                padding: 20px;
            }}
            .badge {{
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                text-transform: uppercase;
            }}
            .badge-critical {{ background: #fee2e2; color: #991b1b; }}
            .badge-high {{ background: #ffedd5; color: #9a3412; }}
            .badge-medium {{ background: #fef9c3; color: #854d0e; }}
            .badge-low {{ background: #f0fdf4; color: #166534; }}
            .severity-critical {{ border-left: 4px solid #dc2626; }}
            .severity-high {{ border-left: 4px solid #ea580c; }}
            .severity-medium {{ border-left: 4px solid #ca8a04; }}
            .severity-low {{ border-left: 4px solid #16a34a; }}
            pre {{
                background: #1f2937;
                color: #f9fafb;
                padding: 15px;
                border-radius: 6px;
                overflow-x: auto;
                font-size: 13px;
                margin: 15px 0;
            }}
            code {{
                font-family: Consolas, Monaco, monospace;
            }}
            @media print {{
                body {{ background: white; padding: 0; }}
                .container {{ box-shadow: none; padding: 0; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="title-area">
                    <h1>CodeShield AI Security Audit</h1>
                    <p>Automated Vulnerability Detection and Threat Modeling Report</p>
                </div>
                <div class="score-circle">
                    {score}
                </div>
            </div>
            
            <div class="grid">
                <div class="metric-box">
                    <div class="metric-val">{metrics.get('code_security', 80)}</div>
                    <div class="metric-label">Code Security</div>
                </div>
                <div class="metric-box">
                    <div class="metric-val">{metrics.get('authentication', 75)}</div>
                    <div class="metric-label">Authentication</div>
                </div>
                <div class="metric-box">
                    <div class="metric-val">{metrics.get('api_security', 80)}</div>
                    <div class="metric-label">API Security</div>
                </div>
                <div class="metric-box">
                    <div class="metric-val">{metrics.get('compliance', 70)}</div>
                    <div class="metric-label">Compliance Check</div>
                </div>
            </div>
            
            <h2 class="section-title">Security Threat Modeling</h2>
            <p><strong>Attack Surface:</strong> {threat_model.get('attack_surface', 'Standard web application layers.')}</p>
            <h3>Potential Threats Identifed</h3>
            <ul>
                {threats_html if threats_html else "<li>None explicitly analyzed. Run deep scan.</li>"}
            </ul>
            <p><strong>Mitigation Strategy:</strong> {mitigation_html}</p>
            
            <h2 class="section-title">Vulnerability Findings ({len(findings)})</h2>
            {findings_html if findings_html else "<p>No critical or high vulnerabilities detected in static pass.</p>"}
            
            <div style="margin-top: 50px; text-align: center; font-size: 12px; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 20px;">
                Generated by CodeShield AI Security Auditor. Secure your cave.
            </div>
        </div>
    </body>
    </html>
    """
    return html
