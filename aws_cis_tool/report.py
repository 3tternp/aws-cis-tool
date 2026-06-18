import json
import os
import html
from datetime import datetime, date
from decimal import Decimal


class ReportGenerator:
    def __init__(self, results, account_id, output_dir="."):
        self.results = self._make_json_safe(results or [])
        self.account_id = self._make_json_safe(account_id)
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        os.makedirs(self.output_dir, exist_ok=True)

    # =========================================================
    # Main Fix: recursively convert all non-serializable objects
    # =========================================================
    def _make_json_safe(self, value):
        """
        Recursively converts Python objects into JSON-safe objects.
        This fixes:
        - datetime/date serialization
        - Decimal serialization
        - set/tuple serialization
        - nested dict/list values
        - boto3/custom objects
        """

        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, (datetime, date)):
            return value.isoformat()

        if isinstance(value, Decimal):
            return float(value)

        if isinstance(value, dict):
            safe_dict = {}
            for key, val in value.items():
                safe_key = str(key)
                safe_dict[safe_key] = self._make_json_safe(val)
            return safe_dict

        if isinstance(value, list):
            return [self._make_json_safe(item) for item in value]

        if isinstance(value, tuple):
            return [self._make_json_safe(item) for item in value]

        if isinstance(value, set):
            return [self._make_json_safe(item) for item in value]

        if hasattr(value, "isoformat"):
            try:
                return value.isoformat()
            except Exception:
                pass

        return str(value)

    def _safe_json_dumps(self, data, indent=4):
        safe_data = self._make_json_safe(data)
        return json.dumps(safe_data, indent=indent, ensure_ascii=False)

    def _safe_text(self, value):
        value = self._make_json_safe(value)

        if value is None:
            return ""

        return str(value)

    def _safe_html(self, value):
        return html.escape(self._safe_text(value))

    def _normalize_details(self, details):
        details = self._make_json_safe(details)

        if not details:
            return []

        if isinstance(details, list):
            return [self._safe_text(item) for item in details]

        return [self._safe_text(details)]

    # =========================================================
    # Summary
    # =========================================================
    def _generate_summary(self):
        summary = {
            "PASS": 0,
            "FAIL": 0,
            "ERROR": 0,
            "MANUAL_VERIFICATION_REQUIRED": 0
        }

        for result in self.results:
            if not isinstance(result, dict):
                summary["ERROR"] += 1
                continue

            status = result.get("result", "ERROR")

            if status in summary:
                summary[status] += 1
            else:
                summary[status] = 1

        return summary

    # =========================================================
    # JSON Report
    # =========================================================
    def generate_json(self):
        filename = os.path.join(
            self.output_dir,
            f"cis_report_{self.account_id}_{self.timestamp}.json"
        )

        data = {
            "account_id": self.account_id,
            "timestamp": self.timestamp,
            "summary": self._generate_summary(),
            "results": self.results
        }

        safe_data = self._make_json_safe(data)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(
                safe_data,
                f,
                indent=4,
                ensure_ascii=False
            )

        return filename

    # =========================================================
    # HTML Report
    # =========================================================
    def generate_html(self):
        filename = os.path.join(
            self.output_dir,
            f"cis_report_{self.account_id}_{self.timestamp}.html"
        )

        summary = self._generate_summary()

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AWS CIS Benchmark Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #ffffff;
            color: #222;
        }}

        h1 {{
            color: #333;
            margin-bottom: 5px;
        }}

        h2 {{
            margin-top: 30px;
            color: #333;
        }}

        .meta {{
            margin-bottom: 20px;
            font-size: 14px;
        }}

        .summary-box {{
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }}

        .stat-box {{
            padding: 15px;
            border-radius: 6px;
            color: white;
            min-width: 120px;
            text-align: center;
            font-weight: bold;
            box-shadow: 0 1px 3px rgba(0,0,0,0.15);
        }}

        .pass {{
            background-color: #28a745;
        }}

        .fail {{
            background-color: #dc3545;
        }}

        .error {{
            background-color: #ffc107;
            color: #000;
        }}

        .manual {{
            background-color: #6c757d;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 13px;
        }}

        th, td {{
            border: 1px solid #ddd;
            padding: 9px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background-color: #f4f4f4;
            font-weight: bold;
        }}

        .row-PASS {{
            background-color: #d4edda;
        }}

        .row-FAIL {{
            background-color: #f8d7da;
        }}

        .row-ERROR {{
            background-color: #fff3cd;
        }}

        .row-MANUAL_VERIFICATION_REQUIRED {{
            background-color: #e2e3e5;
        }}

        .evidence-box {{
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            padding: 10px;
            font-family: Consolas, monospace;
            white-space: pre-wrap;
            margin-top: 8px;
            font-size: 12px;
            display: none;
            max-height: 450px;
            overflow: auto;
        }}

        .toggle-evidence {{
            color: #007bff;
            cursor: pointer;
            text-decoration: underline;
            font-size: 12px;
            margin-top: 8px;
            display: inline-block;
        }}

        .status {{
            font-weight: bold;
        }}
    </style>

    <script>
        function toggleEvidence(id) {{
            var x = document.getElementById(id);
            if (x.style.display === "none" || x.style.display === "") {{
                x.style.display = "block";
            }} else {{
                x.style.display = "none";
            }}
        }}
    </script>
</head>

<body>
    <h1>AWS CIS Benchmark Report</h1>

    <div class="meta">
        <p><strong>Account ID:</strong> {self._safe_html(self.account_id)}</p>
        <p><strong>Generated At:</strong> {self._safe_html(self.timestamp)}</p>
    </div>

    <div class="summary-box">
        <div class="stat-box pass">PASS<br>{summary.get("PASS", 0)}</div>
        <div class="stat-box fail">FAIL<br>{summary.get("FAIL", 0)}</div>
        <div class="stat-box error">ERROR<br>{summary.get("ERROR", 0)}</div>
        <div class="stat-box manual">MANUAL<br>{summary.get("MANUAL_VERIFICATION_REQUIRED", 0)}</div>
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
            if not isinstance(result, dict):
                continue

            check_id = self._safe_html(result.get("check_id", "N/A"))
            check_type = self._safe_html(result.get("check_type", "AUTOMATED"))
            category = self._safe_html(result.get("category", "N/A"))
            title = self._safe_html(result.get("title", "N/A"))

            result_status_raw = self._safe_text(result.get("result", "ERROR"))
            result_status = self._safe_html(result_status_raw)

            details = self._normalize_details(result.get("details", []))

            if details:
                details_html = "<br>".join(self._safe_html(item) for item in details)
            else:
                details_html = "N/A"

            evidence_html = ""

            if result.get("evidence") is not None:
                evidence_json = self._safe_json_dumps(result.get("evidence"), indent=2)
                evidence_json = self._safe_html(evidence_json)
                evidence_id = f"evidence-{i}"

                evidence_html = f"""
                    <br>
                    <span class="toggle-evidence" onclick="toggleEvidence('{evidence_id}')">
                        Show/Hide Evidence
                    </span>
                    <div id="{evidence_id}" class="evidence-box">{evidence_json}</div>
                """

            status_class = f"row-{result_status_raw}"

            html_content += f"""
            <tr class="{status_class}">
                <td>{check_id}</td>
                <td>{check_type}</td>
                <td>{category}</td>
                <td>{title}</td>
                <td class="status">{result_status}</td>
                <td>{details_html}{evidence_html}</td>
            </tr>
"""

        html_content += """
        </tbody>
    </table>
</body>
</html>
"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filename

    # =========================================================
    # PDF Report
    # =========================================================
    def generate_pdf(self):
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
        except ImportError:
            print("reportlab is required for PDF generation.")
            print("Install it using: pip install reportlab")
            return None

        filename = os.path.join(
            self.output_dir,
            f"cis_report_{self.account_id}_{self.timestamp}.pdf"
        )

        summary = self._generate_summary()

        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        title_style = styles["Title"]
        heading_style = styles["Heading2"]
        normal_style = styles["Normal"]

        code_style = ParagraphStyle(
            "Code",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7,
            leading=9,
            backColor=colors.whitesmoke,
            borderPadding=4,
            spaceAfter=8
        )

        elements = []

        elements.append(Paragraph("AWS CIS Benchmark Report", title_style))
        elements.append(Spacer(1, 12))

        elements.append(
            Paragraph(
                f"<b>Account ID:</b> {self._safe_html(self.account_id)}",
                normal_style
            )
        )

        elements.append(
            Paragraph(
                f"<b>Generated At:</b> {self._safe_html(self.timestamp)}",
                normal_style
            )
        )

        elements.append(Spacer(1, 12))

        summary_text = f"""
        <font color="green">PASS: {summary.get("PASS", 0)}</font> |
        <font color="red">FAIL: {summary.get("FAIL", 0)}</font> |
        <font color="orange">ERROR: {summary.get("ERROR", 0)}</font> |
        <font color="gray">MANUAL: {summary.get("MANUAL_VERIFICATION_REQUIRED", 0)}</font>
        """

        elements.append(
            Paragraph(
                f"<b>Summary:</b> {summary_text}",
                normal_style
            )
        )

        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Detailed Results", heading_style))
        elements.append(Spacer(1, 10))

        for result in self.results:
            if not isinstance(result, dict):
                continue

            result_status = self._safe_text(result.get("result", "ERROR"))

            res_color = "black"

            if result_status == "PASS":
                res_color = "green"
            elif result_status == "FAIL":
                res_color = "red"
            elif result_status == "ERROR":
                res_color = "orange"
            elif result_status == "MANUAL_VERIFICATION_REQUIRED":
                res_color = "gray"

            check_id = self._safe_html(result.get("check_id", "N/A"))
            check_type = self._safe_html(result.get("check_type", "AUTOMATED"))
            category = self._safe_html(result.get("category", "N/A"))
            title = self._safe_html(result.get("title", "N/A"))

            header_text = f"<b>{check_id} [{check_type}] - {title}</b>"

            elements.append(Paragraph(header_text, normal_style))
            elements.append(Paragraph(f"<b>Category:</b> {category}", normal_style))

            elements.append(
                Paragraph(
                    f"<b>Result:</b> <font color='{res_color}'><b>{self._safe_html(result_status)}</b></font>",
                    normal_style
                )
            )

            details = self._normalize_details(result.get("details", []))

            if details:
                details_text = "<br/>".join(self._safe_html(item) for item in details)
                elements.append(
                    Paragraph(
                        f"<b>Details:</b><br/>{details_text}",
                        normal_style
                    )
                )

            if result.get("evidence") is not None:
                evidence_str = self._safe_json_dumps(result.get("evidence"), indent=2)

                if len(evidence_str) > 2000:
                    evidence_str = evidence_str[:2000] + "\n... evidence truncated for PDF output"

                evidence_str = self._safe_html(evidence_str)
                evidence_str = evidence_str.replace("\n", "<br/>").replace(" ", "&nbsp;")

                elements.append(Paragraph("<b>Evidence:</b>", normal_style))
                elements.append(Paragraph(evidence_str, code_style))

            elements.append(Spacer(1, 10))
            elements.append(Paragraph("_" * 70, normal_style))
            elements.append(Spacer(1, 10))

        doc.build(elements)

        return filename