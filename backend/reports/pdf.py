"""Enhanced PDF generation with Gemini AI and multiple fallback methods"""
from pathlib import Path
import logging
import json
from typing import Optional, Dict, Any
import google.generativeai as genai

# Configure Gemini AI
try:
    from config import GEMINI_API_KEY, GEMINI_MODEL, PDF_SETTINGS
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)
except ImportError:
    # Fallback configuration
    GEMINI_API_KEY = "AIzaSyAlbMj12IXp82EoMo4PfqPHM9hUNvmuIFo"
    GEMINI_MODEL = "gemini-2.0-flash"
    PDF_SETTINGS = {"format": "A4", "print_background": True}
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)

logger = logging.getLogger(__name__)


def enhance_report_with_ai(report_data: Dict[str, Any], scan_type: str) -> str:
    """Use Gemini AI to generate enhanced analysis and recommendations"""
    try:
        prompt = f"""
        Analyze this {scan_type} security scan report and provide:
        1. Executive Summary (2-3 sentences)
        2. Risk Assessment (High/Medium/Low with rationale)
        3. Key Findings (bullet points)
        4. Remediation Recommendations (actionable steps)
        5. Technical Details Summary

        Report Data: {json.dumps(report_data, indent=2)}

        Provide a well-formatted analysis that would be valuable for both technical and non-technical stakeholders.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.warning(f"AI enhancement failed: {e}")
        return f"Standard {scan_type} scan report - AI enhancement unavailable"


def html_to_pdf_gemini(html_content: str, pdf_path: Path, title: str = "Security Report") -> bool:
    """Generate PDF using Gemini AI to create enhanced content"""
    try:
        # Use Gemini to enhance the HTML content
        enhancement_prompt = f"""
        Convert this HTML security report into a professional PDF-ready format:
        1. Add a professional header with title: "{title}"
        2. Improve formatting and readability
        3. Add executive summary if missing
        4. Ensure proper structure for PDF conversion
        5. Add page breaks where appropriate
        
        HTML Content: {html_content}
        
        Return only the enhanced HTML content suitable for PDF conversion.
        """
        
        response = model.generate_content(enhancement_prompt)
        enhanced_html = response.text
        
        # Try ReportLab first
        if html_to_pdf_reportlab(enhanced_html, pdf_path):
            return True
            
        # Fallback to WeasyPrint
        if html_to_pdf_weasyprint(enhanced_html, pdf_path):
            return True
            
        return False
        
    except Exception as e:
        logger.error(f"Gemini PDF generation failed: {e}")
        return html_to_pdf_fallback(html_content, pdf_path)


def html_to_pdf_reportlab(html_content: str, pdf_path: Path) -> bool:
    """Generate PDF using ReportLab"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from bs4 import BeautifulSoup
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Create PDF
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = soup.find('title')
        if title:
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                alignment=1  # Center
            )
            story.append(Paragraph(title.get_text(), title_style))
            story.append(Spacer(1, 12))
        
        # Content
        for element in soup.find_all(['h1', 'h2', 'h3', 'p', 'li', 'div']):
            text = element.get_text().strip()
            if text:
                if element.name == 'h1':
                    story.append(Paragraph(text, styles['Heading1']))
                elif element.name == 'h2':
                    story.append(Paragraph(text, styles['Heading2']))
                elif element.name == 'h3':
                    story.append(Paragraph(text, styles['Heading3']))
                else:
                    story.append(Paragraph(text, styles['Normal']))
                story.append(Spacer(1, 6))
        
        doc.build(story)
        return pdf_path.exists()
        
    except Exception as e:
        logger.warning(f"ReportLab PDF generation failed: {e}")
        return False


def html_to_pdf_weasyprint(html_content: str, pdf_path: Path) -> bool:
    """Generate PDF using WeasyPrint"""
    try:
        import weasyprint
        
        # Add CSS styling for better PDF appearance
        styled_html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 2cm; line-height: 1.6; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #34495e; margin-top: 30px; }}
                .vulnerability {{ background-color: #fff5f5; border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }}
                .safe {{ background-color: #f0fff4; border-left: 4px solid #27ae60; padding: 10px; margin: 10px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .footer {{ position: fixed; bottom: 0; width: 100%; text-align: center; font-size: 10px; }}
            </style>
        </head>
        <body>
            {html_content}
            <div class="footer">Generated by Web Security Scanner</div>
        </body>
        </html>
        """
        
        weasyprint.HTML(string=styled_html).write_pdf(str(pdf_path))
        return pdf_path.exists()
        
    except Exception as e:
        logger.warning(f"WeasyPrint PDF generation failed: {e}")
        return False


def html_to_pdf_fallback(html_content: str, pdf_path: Path) -> bool:
    """Fallback PDF generation using simple text conversion"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html_content, 'html.parser')
        text_content = soup.get_text()
        
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = [Paragraph(text_content, styles['Normal'])]
        
        doc.build(story)
        return pdf_path.exists()
        
    except Exception as e:
        logger.error(f"Fallback PDF generation failed: {e}")
        return False


def html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    """Enhanced HTML to PDF conversion with Gemini AI and multiple fallback methods"""
    try:
        html_path = Path(html_path)
        pdf_path = Path(pdf_path)
        
        if not html_path.exists():
            logger.error(f"HTML file not found: {html_path}")
            return False
        
        # Read HTML content
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Try Gemini-enhanced PDF generation
        if html_to_pdf_gemini(html_content, pdf_path, html_path.stem):
            logger.info(f"PDF generated successfully with Gemini AI: {pdf_path}")
            return True
        
        # Try original Playwright method
        if html_to_pdf_playwright(html_path, pdf_path):
            logger.info(f"PDF generated successfully with Playwright: {pdf_path}")
            return True
        
        # Final fallback
        return html_to_pdf_fallback(html_content, pdf_path)
        
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return False


def html_to_pdf_playwright(html_path: Path, pdf_path: Path) -> bool:
    """Original Playwright PDF generation method"""
    try:
        from playwright.sync_api import sync_playwright
        
        html_path = Path(html_path)
        pdf_path = Path(pdf_path)
        
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(html_path.as_uri(), wait_until="load")
            page.pdf(path=str(pdf_path), **PDF_SETTINGS)
            browser.close()
        
        return pdf_path.exists()
        
    except Exception as e:
        logger.warning(f"Playwright PDF generation failed: {e}")
        return False
