import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, results, account_id, output_dir="."):
        self.results = results
        self.account_id = account_id
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_json(self):
        filename = os.path.join(self.output_dir, f"cis_report_{self.account_id}_{self.timestamp}.json")
        data = {
            "account_id": self.account_id,
            "timestamp": self.timestamp,
            "summary": self._generate_summary(),
            "results": self.results
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        return filename

    def generate_html(self):
        filename = os.path.join(self.output_dir, f"cis_report_{self.account_id}_{self.timestamp}.html")
        summary = self._generate_summary()
        
        # Simple HTML template
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AWS CIS Benchmark Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary-box {{ display: flex; gap: 20px; margin-bottom: 30px; }}
                .stat-box {{ padding: 15px; border-radius: 5px; color: white; min-width: 100px; text-align: center; font-weight: bold; }}
                .pass {{ background-color: #28a745; }}
                .fail {{ background-color: #dc3545; }}
                .error {{ background-color: #ffc107; color: black; }}
                .manual {{ background-color: #6c757d; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
                th {{ background-color: #f4f4f4; }}
                .row-PASS {{ background-color: #d4edda; }}
                .row-FAIL {{ background-color: #f8d7da; }}
                .row-ERROR {{ background-color: #fff3cd; }}
                .row-MANUAL_VERIFICATION_REQUIRED {{ background-color: #e2e3e5; }}
                .evidence-box {{ background-color: #f8f9fa; border: 1px solid #ddd; padding: 10px; font-family: monospace; white-space: pre-wrap; margin-top: 5px; font-size: 0.9em; display: none; }}
                .toggle-evidence {{ color: #007bff; cursor: pointer; text-decoration: underline; font-size: 0.9em; }}
            </style>
            <script>
                function toggleEvidence(id) {{
                    var x = document.getElementById(id);
                    if (x.style.display === "none") {{
                        x.style.display = "block";
                    }} else {{
                        x.style.display = "none";
                    }}
                }}
            </script>
        </head>
        <body>
            <h1>AWS CIS Benchmark Report</h1>
            <p><strong>Account ID:</strong> {self.account_id}</p>
            <p><strong>Generated At:</strong> {self.timestamp}</p>
            
            <div class="summary-box">
                <div class="stat-box pass">PASS: {summary['PASS']}</div>
                <div class="stat-box fail">FAIL: {summary['FAIL']}</div>
                <div class="stat-box error">ERROR: {summary['ERROR']}</div>
                <div class="stat-box manual">MANUAL: {summary.get('MANUAL_VERIFICATION_REQUIRED', 0)}</div>
            </div>
            
            <h2>Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Category</th>
                        <th>Title</th>
                        <th>Result</th>
                        <th>Details / Evidence</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for i, result in enumerate(self.results):
            details_html = "<br>".join(result['details']) if result['details'] else "N/A"
            evidence_html = ""
            if result.get('evidence'):
                evidence_json = json.dumps(result['evidence'], indent=2)
                evidence_id = f"evidence-{i}"
                evidence_html = f"""
                <div class="toggle-evidence" onclick="toggleEvidence('{evidence_id}')">Show/Hide Evidence</div>
                <div id="{evidence_id}" class="evidence-box">{evidence_json}</div>
                """
            
            status_class = f"row-{result['result']}"
            html_content += f"""
                    <tr class="{status_class}">
                        <td>{result['check_id']}</td>
                        <td>{result.get('check_type', 'AUTOMATED')}</td>
                        <td>{result['category']}</td>
                        <td>{result['title']}</td>
                        <td><strong>{result['result']}</strong></td>
                        <td>{details_html}{evidence_html}</td>
                    </tr>
            """
            
        html_content += """
                </tbody>
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        return filename

    def _generate_summary(self):
        summary = {"PASS": 0, "FAIL": 0, "ERROR": 0, "MANUAL_VERIFICATION_REQUIRED": 0}
        for result in self.results:
            status = result.get('result')
            if status in summary:
                summary[status] += 1
            else:
                summary[status] = 1
        return summary

    def generate_pdf(self):
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
        except ImportError:
            print("reportlab is required for PDF generation. Run: pip install reportlab")
            return None
            
        filename = os.path.join(self.output_dir, f"cis_report_{self.account_id}_{self.timestamp}.pdf")
        summary = self._generate_summary()
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = styles['Title']
        heading_style = styles['Heading2']
        normal_style = styles['Normal']
        code_style = ParagraphStyle('Code', parent=styles['Normal'], fontName='Courier', fontSize=8, backColor=colors.whitesmoke, borderPadding=2)
        
        elements = []
        
        # Title
        elements.append(Paragraph("AWS CIS Benchmark Report", title_style))
        elements.append(Spacer(1, 12))
        
        # Meta info
        elements.append(Paragraph(f"<b>Account ID:</b> {self.account_id}", normal_style))
        elements.append(Paragraph(f"<b>Generated At:</b> {self.timestamp}", normal_style))
        elements.append(Spacer(1, 12))
        
        # Summary
        summary_text = f"""
        <font color='green'>PASS: {summary['PASS']}</font> | 
        <font color='red'>FAIL: {summary['FAIL']}</font> | 
        <font color='#f39c12'>ERROR: {summary['ERROR']}</font> | 
        <font color='gray'>MANUAL: {summary.get('MANUAL_VERIFICATION_REQUIRED', 0)}</font>
        """
        elements.append(Paragraph(f"<b>Summary:</b> {summary_text}", normal_style))
        elements.append(Spacer(1, 20))
        
        # Table of Contents-ish list
        elements.append(Paragraph("Detailed Results", heading_style))
        elements.append(Spacer(1, 10))

        # We will render check details as blocks instead of a giant table which might break layout with large evidence
        for result in self.results:
            # Header line: ID - Title - Result
            res_color = "black"
            if result['result'] == 'PASS': res_color = "green"
            elif result['result'] == 'FAIL': res_color = "red"
            elif result['result'] == 'ERROR': res_color = "orange"
            elif result['result'] == 'MANUAL_VERIFICATION_REQUIRED': res_color = "gray"
            
            header_text = f"<b>{result['check_id']} [{result.get('check_type', 'AUTO')}] - {result['title']}</b>"
            elements.append(Paragraph(header_text, normal_style))
            elements.append(Paragraph(f"Result: <font color='{res_color}'><b>{result['result']}</b></font>", normal_style))
            
            if result['details']:
                details_text = "<br/>".join(result['details'])
                elements.append(Paragraph(f"Details:<br/>{details_text}", normal_style))
            
            if result.get('evidence'):
                evidence_str = json.dumps(result['evidence'], indent=2)
                # Truncate if too long for PDF
                if len(evidence_str) > 1000:
                    evidence_str = evidence_str[:1000] + "\n... (truncated)"
                elements.append(Paragraph("Evidence:", normal_style))
                elements.append(Paragraph(evidence_str.replace('\n', '<br/>').replace(' ', '&nbsp;'), code_style))
            
            elements.append(Spacer(1, 12))
            elements.append(Paragraph("_" * 60, normal_style)) # Separator
            elements.append(Spacer(1, 12))
        
        doc.build(elements)
        return filename
