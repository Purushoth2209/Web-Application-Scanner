from pathlib import Path
from jinja2 import Template
from typing import Dict, Any
from datetime import datetime
import json
import os


def combine_reports(root: Path, results: dict):
    """Enhanced report combination with professional styling and clear content"""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    try:
        # Generate enhanced professional report
        target_url = results.get('url', 'Unknown')
        html_content = generate_professional_report(root, results, target_url)
        
        idx = root / "index.html"
        idx.write_text(html_content, encoding="utf-8")
        
        return {
            "html": str(idx),
            "web_html": f"/reports/{root.name}/index.html"
        }
    except Exception as e:
        print(f"[!] Enhanced report generation failed: {e}")
        # Fallback to original implementation
        return combine_reports_fallback(root, results)


def generate_professional_report(root: Path, results: dict, target_url: str):
    """Generate a professional, clear, and comprehensive security report"""
    
    # Extract scan metadata
    metadata = results.get('scan_metadata', {})
    scan_time = metadata.get('start_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    scan_duration = metadata.get('total_duration', 0)
    
    # Process scanner results
    scanner_results = []
    total_vulnerabilities = 0
    overall_risk_level = "LOW"
    
    scanners_info = {
        'broken_access': {
            'name': 'Access Control',
            'description': 'Tests for unauthorized access to restricted resources and functionalities',
            'category': 'Authorization'
        },
        'csrf': {
            'name': 'CSRF Protection',
            'description': 'Validates Cross-Site Request Forgery prevention mechanisms',
            'category': 'Session Security'
        },
        'sqli': {
            'name': 'SQL Injection',
            'description': 'Examines database security against injection attacks',
            'category': 'Input Validation'
        },
        'xss': {
            'name': 'XSS Prevention',
            'description': 'Tests protection against Cross-Site Scripting vulnerabilities',
            'category': 'Output Encoding'
        }
    }
    
    for scanner_key, output in results.get('outputs', {}).items():
        if scanner_key == 'combined':
            continue
            
        scanner_info = scanners_info.get(scanner_key, {
            'name': scanner_key.replace('_', ' ').title(),
            'description': f'{scanner_key} security assessment',
            'category': 'Security'
        })
        
        error = results.get('errors', {}).get(scanner_key)
        
        if error:
            scanner_results.append({
                'key': scanner_key,
                'name': scanner_info['name'],
                'description': scanner_info['description'],
                'category': scanner_info['category'],
                'status': 'ERROR',
                'status_class': 'status-error',
                'vulnerabilities': 0,
                'links_crawled': 0,
                'forms_found': 0,
                'duration': 0,
                'error_message': error,
                'report_link': None,
                'summary': 'Scanner encountered an error during execution'
            })
        elif output and isinstance(output, dict):
            vulns = output.get('vulnerabilities_found', 0)
            total_vulnerabilities += vulns
            
            # Determine status based on vulnerabilities
            if vulns == 0:
                status = 'SECURE'
                status_class = 'status-secure'
                summary = 'No vulnerabilities detected. Security measures appear effective.'
            elif vulns <= 2:
                status = 'LOW RISK'
                status_class = 'status-low'
                summary = f'Found {vulns} minor issue{"s" if vulns > 1 else ""}. Consider reviewing for improvements.'
                if overall_risk_level == "LOW":
                    overall_risk_level = "MEDIUM"
            elif vulns <= 5:
                status = 'MEDIUM RISK'
                status_class = 'status-medium'
                summary = f'Identified {vulns} vulnerabilities requiring attention.'
                overall_risk_level = "MEDIUM"
            else:
                status = 'HIGH RISK'
                status_class = 'status-high'
                summary = f'Critical: {vulns} significant vulnerabilities found. Immediate action required.'
                overall_risk_level = "HIGH"
            
            # Get report link
            report_link = None
            if output.get('html'):
                try:
                    html_path = Path(output['html'])
                    rel_path = html_path.resolve().relative_to(root.resolve())
                    report_link = str(rel_path).replace("\\", "/")
                except:
                    report_link = output.get('html')
            
            scanner_results.append({
                'key': scanner_key,
                'name': scanner_info['name'],
                'description': scanner_info['description'],
                'category': scanner_info['category'],
                'status': status,
                'status_class': status_class,
                'vulnerabilities': vulns,
                'links_crawled': output.get('links_crawled', 0),
                'forms_found': output.get('forms_found', 0),
                'duration': output.get('scan_duration', 0),
                'error_message': None,
                'report_link': report_link,
                'summary': summary
            })
        else:
            scanner_results.append({
                'key': scanner_key,
                'name': scanner_info['name'],
                'description': scanner_info['description'],
                'category': scanner_info['category'],
                'status': 'NO DATA',
                'status_class': 'status-warning',
                'vulnerabilities': 0,
                'links_crawled': 0,
                'forms_found': 0,
                'duration': 0,
                'error_message': None,
                'report_link': None,
                'summary': 'No data available from this scanner'
            })
    
    # Generate recommendations based on findings
    recommendations = generate_security_recommendations(scanner_results, overall_risk_level)
    
    template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 15px;
            margin-bottom: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            text-align: center;
        }
        
        .header p {
            text-align: center;
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .scan-info {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            border-left: 4px solid #667eea;
        }
        
        .scan-info h2 {
            color: #667eea;
            margin-bottom: 1rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid #eee;
        }
        
        .info-label {
            font-weight: 600;
            color: #555;
        }
        
        .info-value {
            color: #333;
            font-family: 'Courier New', monospace;
        }
        
        .overview {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        
        .overview h2 {
            color: #333;
            margin-bottom: 1.5rem;
            text-align: center;
        }
        
        .risk-indicator {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .risk-level {
            display: inline-block;
            padding: 1rem 2rem;
            border-radius: 50px;
            font-weight: bold;
            font-size: 1.2rem;
            text-transform: uppercase;
        }
        
        .risk-low { background: #d4edda; color: #155724; }
        .risk-medium { background: #fff3cd; color: #856404; }
        .risk-high { background: #f8d7da; color: #721c24; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .scanners-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .scanner-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .scanner-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .scanner-header {
            padding: 1.5rem;
            border-bottom: 2px solid #f8f9fa;
        }
        
        .scanner-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .scanner-name {
            font-size: 1.3rem;
            font-weight: bold;
            color: #333;
        }
        
        .status-badge {
            padding: 0.4rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .status-secure { background: #d4edda; color: #155724; }
        .status-low { background: #cce5ff; color: #004085; }
        .status-medium { background: #fff3cd; color: #856404; }
        .status-high { background: #f8d7da; color: #721c24; }
        .status-error { background: #f8d7da; color: #721c24; }
        .status-warning { background: #e2e3e5; color: #383d41; }
        
        .scanner-description {
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }
        
        .scanner-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.5rem;
        }
        
        .stat-item {
            display: flex;
            justify-content: space-between;
            padding: 0.3rem 0;
            font-size: 0.9rem;
        }
        
        .scanner-body {
            padding: 1.5rem;
        }
        
        .scanner-summary {
            color: #555;
            margin-bottom: 1rem;
            font-style: italic;
        }
        
        .scanner-actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5a67d8;
            transform: translateY(-1px);
        }
        
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 1rem;
            border-radius: 5px;
            border-left: 4px solid #dc3545;
            margin-top: 1rem;
        }
        
        .recommendations {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        
        .recommendations h2 {
            color: #333;
            margin-bottom: 1.5rem;
            text-align: center;
        }
        
        .recommendation {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid #667eea;
        }
        
        .recommendation h3 {
            color: #667eea;
            margin-bottom: 0.5rem;
        }
        
        .recommendation p {
            color: #555;
            line-height: 1.6;
        }
        
        .footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            color: #666;
        }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header h1 { font-size: 2rem; }
            .scanners-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Security Assessment Report</h1>
            <p>Comprehensive Web Application Security Analysis</p>
        </div>
        
        <!-- Scan Information -->
        <div class="scan-info">
            <h2>📋 Scan Details</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Target URL:</span>
                    <span class="info-value">{{ target_url }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Scan Date:</span>
                    <span class="info-value">{{ scan_time }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Total Duration:</span>
                    <span class="info-value">{{ "%.1f"|format(scan_duration) }} seconds</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Scanners Used:</span>
                    <span class="info-value">{{ scanner_results|length }} modules</span>
                </div>
            </div>
        </div>
        
        <!-- Overview -->
        <div class="overview">
            <h2>📊 Security Overview</h2>
            
            <div class="risk-indicator">
                <div class="risk-level risk-{{ overall_risk_level.lower() }}">
                    Overall Risk: {{ overall_risk_level }}
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ total_vulnerabilities }}</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ scanner_results|selectattr('status', 'equalto', 'SECURE')|list|length }}</div>
                    <div class="stat-label">Secure Components</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ scanner_results|sum(attribute='links_crawled') }}</div>
                    <div class="stat-label">Links Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ scanner_results|sum(attribute='forms_found') }}</div>
                    <div class="stat-label">Forms Tested</div>
                </div>
            </div>
        </div>
        
        <!-- Scanner Results -->
        <div class="scanners-grid">
            {% for scanner in scanner_results %}
            <div class="scanner-card">
                <div class="scanner-header">
                    <div class="scanner-title">
                        <span class="scanner-name">{{ scanner.name }}</span>
                        <span class="status-badge {{ scanner.status_class }}">{{ scanner.status }}</span>
                    </div>
                    <div class="scanner-description">{{ scanner.description }}</div>
                    <div class="scanner-stats">
                        <div class="stat-item">
                            <span>Vulnerabilities:</span>
                            <span><strong>{{ scanner.vulnerabilities }}</strong></span>
                        </div>
                        <div class="stat-item">
                            <span>Links Crawled:</span>
                            <span><strong>{{ scanner.links_crawled }}</strong></span>
                        </div>
                        <div class="stat-item">
                            <span>Forms Found:</span>
                            <span><strong>{{ scanner.forms_found }}</strong></span>
                        </div>
                        <div class="stat-item">
                            <span>Scan Time:</span>
                            <span><strong>{{ "%.1f"|format(scanner.duration) }}s</strong></span>
                        </div>
                    </div>
                </div>
                
                <div class="scanner-body">
                    <div class="scanner-summary">{{ scanner.summary }}</div>
                    
                    {% if scanner.report_link %}
                    <div class="scanner-actions">
                        <a href="{{ scanner.report_link }}" class="btn btn-primary" target="_blank">
                            📄 View Detailed Report
                        </a>
                    </div>
                    {% endif %}
                    
                    {% if scanner.error_message %}
                    <div class="error-message">
                        <strong>Error:</strong> {{ scanner.error_message }}
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        
        <!-- Recommendations -->
        <div class="recommendations">
            <h2>💡 Security Recommendations</h2>
            {% for recommendation in recommendations %}
            <div class="recommendation">
                <h3>{{ recommendation.title }}</h3>
                <p>{{ recommendation.description }}</p>
            </div>
            {% endfor %}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>🔒 Generated by Advanced Security Scanner | Report ID: {{ scan_time.replace(' ', '_').replace(':', '-') }}</p>
            <p>This automated security assessment should be complemented with manual security testing.</p>
        </div>
    </div>
</body>
</html>
    """
    
    return Template(template).render(
        target_url=target_url,
        scan_time=scan_time,
        scan_duration=scan_duration,
        scanner_results=scanner_results,
        total_vulnerabilities=total_vulnerabilities,
        overall_risk_level=overall_risk_level,
        recommendations=recommendations
    )


def generate_security_recommendations(scanner_results, overall_risk_level):
    """Generate security recommendations based on scan results"""
    recommendations = []
    
    if overall_risk_level == "HIGH":
        recommendations.append({
            "title": "Immediate Action Required",
            "description": "Critical vulnerabilities have been identified that require immediate attention. Prioritize fixing high-severity issues and consider implementing additional security controls."
        })
    
    # Check for specific scanner issues
    has_access_issues = any(s['key'] == 'broken_access' and s['vulnerabilities'] > 0 for s in scanner_results)
    has_csrf_issues = any(s['key'] == 'csrf' and s['vulnerabilities'] > 0 for s in scanner_results)
    has_sql_issues = any(s['key'] == 'sqli' and s['vulnerabilities'] > 0 for s in scanner_results)
    has_xss_issues = any(s['key'] == 'xss' and s['vulnerabilities'] > 0 for s in scanner_results)
    
    if has_access_issues:
        recommendations.append({
            "title": "Strengthen Access Controls",
            "description": "Implement proper authorization checks, review user roles and permissions, and ensure sensitive endpoints are properly protected."
        })
    
    if has_csrf_issues:
        recommendations.append({
            "title": "Implement CSRF Protection",
            "description": "Add CSRF tokens to all state-changing operations, implement SameSite cookie attributes, and validate origin headers."
        })
    
    if has_sql_issues:
        recommendations.append({
            "title": "Secure Database Interactions",
            "description": "Use parameterized queries or prepared statements, implement input validation, and apply the principle of least privilege for database accounts."
        })
    
    if has_xss_issues:
        recommendations.append({
            "title": "Prevent Cross-Site Scripting",
            "description": "Implement proper output encoding, use Content Security Policy (CSP) headers, and validate all user inputs on both client and server sides."
        })
    
    # General recommendations
    recommendations.append({
        "title": "Regular Security Testing",
        "description": "Schedule regular security assessments, implement automated security testing in your CI/CD pipeline, and stay updated with latest security best practices."
    })
    
    recommendations.append({
        "title": "Security Headers",
        "description": "Implement security headers like HSTS, X-Frame-Options, X-Content-Type-Options, and Content Security Policy to enhance overall security posture."
    })
    
    return recommendations


def combine_reports_fallback(root: Path, results: dict):
    """Original combine_reports implementation as fallback"""
    # Build normalized relative links per scanner
    links = {}
    for name, out in (results.get("outputs") or {}).items():
        href = None
        if out and isinstance(out, dict) and out.get("html"):
            p = Path(out["html"])  # may be relative
            try:
                rel = p.resolve().relative_to(root.resolve())
            except Exception:
                # fallback: strip root prefix from string
                pstr = str(p).replace("\\", "/")
                rstr = str(root).replace("\\", "/")
                if pstr.startswith(rstr):
                    rel = pstr[len(rstr):].lstrip("/")
                else:
                    rel = p.name
            href = str(rel).replace("\\", "/")
        links[name] = href

    template = """
    <html><head><title>Combined Report</title></head><body>
    <h1>Combined Report for {{url}}</h1>
    <ul>
      {% for name, href in links.items() %}
        <li>{{name}}: 
          {% if href %}
            <a href="{{ href }}">HTML</a>
          {% else %}
            failed
          {% endif %}
        </li>
      {% endfor %}
    </ul>
    </body></html>
    """
    html = Template(template).render(url=results.get("url"), links=links)
    idx = root / "index.html"
    idx.write_text(html, encoding="utf-8")
    return {"html": str(idx)}
