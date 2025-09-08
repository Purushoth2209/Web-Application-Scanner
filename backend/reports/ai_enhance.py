"""AI-Enhanced report generation with Gemini integration"""
import json
import google.generativeai as genai
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Configure Gemini AI
GEMINI_API_KEY = "AIzaSyAlbMj12IXp82EoMo4PfqPHM9hUNvmuIFo"
GEMINI_MODEL = "gemini-2.0-flash"
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(GEMINI_MODEL)


def generate_ai_summary(scan_results: Dict[str, Any]) -> str:
    """Generate an AI-powered executive summary of all scan results"""
    try:
        prompt = f"""
        Analyze these comprehensive web security scan results and provide:

        1. **Executive Summary**: Brief overview of the security posture (2-3 sentences)
        2. **Critical Findings**: Most important vulnerabilities found
        3. **Risk Level**: Overall risk assessment (Critical/High/Medium/Low)
        4. **Priority Actions**: Top 3 immediate actions to take
        5. **Compliance Impact**: How findings might affect compliance (OWASP, PCI-DSS, etc.)

        Scan Results:
        {json.dumps(scan_results, indent=2)}

        Format the response in clean HTML for web display.
        """
        
        response = model.generate_content(prompt)
        return response.text
        
    except Exception as e:
        return f"""
        <div class="ai-summary-error">
            <h3>AI Analysis Unavailable</h3>
            <p>Unable to generate AI-powered summary: {str(e)}</p>
            <p>Standard scan results are available below.</p>
        </div>
        """


def generate_detailed_recommendations(vulnerabilities: List[Dict]) -> str:
    """Generate detailed remediation recommendations using AI"""
    try:
        prompt = f"""
        Based on these security vulnerabilities, provide detailed remediation guidance:

        Vulnerabilities:
        {json.dumps(vulnerabilities, indent=2)}

        For each vulnerability type, provide:
        1. **Technical Details**: What the vulnerability means
        2. **Business Impact**: Potential consequences if exploited
        3. **Remediation Steps**: Specific technical steps to fix
        4. **Prevention**: How to prevent similar issues
        5. **Testing**: How to verify the fix works

        Format as clean HTML with proper structure.
        """
        
        response = model.generate_content(prompt)
        return response.text
        
    except Exception as e:
        return f"<p>Detailed recommendations unavailable: {str(e)}</p>"


def generate_compliance_report(scan_results: Dict[str, Any]) -> str:
    """Generate compliance-focused analysis using AI"""
    try:
        prompt = f"""
        Analyze these security scan results for compliance implications:

        {json.dumps(scan_results, indent=2)}

        Provide analysis for:
        1. **OWASP Top 10 Compliance**: Which OWASP categories are affected
        2. **PCI DSS Requirements**: Any payment card industry impacts
        3. **GDPR/Privacy**: Data protection implications
        4. **ISO 27001**: Information security management alignment
        5. **Regulatory Risk**: Potential regulatory compliance issues

        Format as structured HTML report.
        """
        
        response = model.generate_content(prompt)
        return response.text
        
    except Exception as e:
        return f"<p>Compliance analysis unavailable: {str(e)}</p>"


def enhance_report_content(original_html: str, scan_type: str, results: Dict[str, Any]) -> str:
    """Enhance existing HTML reports with AI analysis"""
    try:
        prompt = f"""
        Enhance this {scan_type} security report with professional analysis:

        Original Report: {original_html}
        Scan Results: {json.dumps(results, indent=2)}

        Add:
        1. Professional styling and formatting
        2. Risk severity indicators
        3. Business impact assessment
        4. Remediation priority
        5. Executive summary section

        Return enhanced HTML that maintains all original data but improves presentation.
        """
        
        response = model.generate_content(prompt)
        return response.text
        
    except Exception as e:
        # Return original if enhancement fails
        return original_html


def generate_ai_enhanced_index(out_dir: Path, results: Dict[str, Any], target_url: str) -> str:
    """Generate AI-enhanced combined report index"""
    try:
        # Generate AI summary
        ai_summary = generate_ai_summary(results.get('outputs', {}))
        
        # Collect all vulnerabilities for detailed analysis
        all_vulns = []
        for scanner, output in results.get('outputs', {}).items():
            if scanner != 'combined' and output:
                if isinstance(output, dict) and 'vulnerabilities' in str(output):
                    all_vulns.extend(output.get('vulnerabilities', []))
        
        detailed_recommendations = generate_detailed_recommendations(all_vulns)
        compliance_report = generate_compliance_report(results)
        
        # Enhanced HTML template
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI-Enhanced Security Report - {target_url}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                    color: white;
                    padding: 40px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 2.5rem;
                    font-weight: 300;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    opacity: 0.9;
                }}
                .content {{
                    padding: 40px;
                }}
                .ai-section {{
                    background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
                    color: white;
                    padding: 30px;
                    margin: 30px -40px;
                    border-radius: 10px;
                }}
                .scan-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 25px;
                    margin: 30px 0;
                }}
                .scan-card {{
                    border: 1px solid #e0e0e0;
                    border-radius: 10px;
                    padding: 25px;
                    background: #f8f9fa;
                    transition: transform 0.3s ease;
                }}
                .scan-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                }}
                .status-high {{ border-left: 5px solid #e74c3c; }}
                .status-medium {{ border-left: 5px solid #f39c12; }}
                .status-low {{ border-left: 5px solid #27ae60; }}
                .download-links {{
                    margin-top: 15px;
                }}
                .download-links a {{
                    display: inline-block;
                    margin-right: 10px;
                    padding: 8px 16px;
                    background: #3498db;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 0.9rem;
                    transition: background 0.3s ease;
                }}
                .download-links a:hover {{
                    background: #2980b9;
                }}
                .timestamp {{
                    text-align: center;
                    color: #666;
                    margin-top: 30px;
                    font-style: italic;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ AI-Enhanced Security Report</h1>
                    <p>Comprehensive vulnerability assessment for <strong>{target_url}</strong></p>
                    <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                </div>
                
                <div class="content">
                    <div class="ai-section">
                        <h2>🤖 AI-Powered Analysis</h2>
                        {ai_summary}
                    </div>
                    
                    <h2>📊 Scan Results Overview</h2>
                    <div class="scan-grid">
        """
        
        # Add individual scanner results
        scanner_names = {
            'broken_access': 'Broken Access Control',
            'csrf': 'CSRF Protection',
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting'
        }
        
        for scanner, output in results.get('outputs', {}).items():
            if scanner == 'combined':
                continue
                
            scanner_name = scanner_names.get(scanner, scanner.upper())
            status_class = 'status-low'  # Default to low risk
            
            html_content += f"""
                        <div class="scan-card {status_class}">
                            <h3>{scanner_name}</h3>
                            <p>Security assessment completed for {scanner_name.lower()} vulnerabilities.</p>
                            <div class="download-links">
            """
            
            if output and isinstance(output, dict):
                if output.get('web_html'):
                    html_content += f'<a href="{output["web_html"]}">📄 View Report</a>'
                if output.get('web_json'):
                    html_content += f'<a href="{output["web_json"]}">📋 Raw Data</a>'
                if output.get('web_pdf'):
                    html_content += f'<a href="{output["web_pdf"]}">📑 PDF Report</a>'
            
            html_content += """
                            </div>
                        </div>
            """
        
        html_content += f"""
                    </div>
                    
                    <div class="ai-section">
                        <h2>🎯 Detailed Recommendations</h2>
                        {detailed_recommendations}
                    </div>
                    
                    <div class="ai-section">
                        <h2>📋 Compliance Analysis</h2>
                        {compliance_report}
                    </div>
                    
                    <div class="timestamp">
                        Report powered by Gemini AI • Web Security Scanner v2.0
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_content
        
    except Exception as e:
        # Fallback to basic report if AI enhancement fails
        return generate_basic_index(out_dir, results, target_url)


def generate_basic_index(out_dir: Path, results: Dict[str, Any], target_url: str) -> str:
    """Generate basic combined report if AI enhancement fails"""
    html_content = f"""
    <html>
    <head>
        <title>Security Report - {target_url}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .scanner {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
            a {{ color: #3498db; text-decoration: none; margin-right: 15px; }}
        </style>
    </head>
    <body>
        <h1>Security Scan Report for {target_url}</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    """
    
    for scanner, output in results.get('outputs', {}).items():
        if scanner == 'combined':
            continue
            
        html_content += f'<div class="scanner"><h2>{scanner.replace("_", " ").title()}</h2>'
        
        if output and isinstance(output, dict):
            if output.get('web_html'):
                html_content += f'<a href="{output["web_html"]}">HTML Report</a>'
            if output.get('web_json'):
                html_content += f'<a href="{output["web_json"]}">JSON Data</a>'
        
        html_content += '</div>'
    
    html_content += '</body></html>'
    return html_content
