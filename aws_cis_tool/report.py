import json
import os
import html
from datetime import datetime, date
from decimal import Decimal

from .remediation import SEVERITY_ORDER, enrich, severity_rank


class ReportGenerator:
    def __init__(self, results, account_id, output_dir="."):
        self.results = [enrich(r) if isinstance(r, dict) else r
                        for r in self._make_json_safe(results or [])]
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
    # Analytics shared by HTML / PDF / JSON
    # =========================================================
    def _stats(self):
        res = [r for r in self.results if isinstance(r, dict)]
        sev = {s: 0 for s in SEVERITY_ORDER}
        manual_sev = {s: 0 for s in SEVERITY_ORDER}
        cats = {}
        for r in res:
            st = r.get("result")
            c = cats.setdefault(r.get("category", "Other"),
                                {"PASS": 0, "FAIL": 0, "ERROR": 0, "MANUAL_VERIFICATION_REQUIRED": 0})
            c[st] = c.get(st, 0) + 1
            if st == "FAIL":
                sev[r.get("severity", "MEDIUM")] = sev.get(r.get("severity", "MEDIUM"), 0) + 1
            elif st == "MANUAL_VERIFICATION_REQUIRED":
                manual_sev[r.get("severity", "MEDIUM")] += 1
        summ = self._generate_summary()
        scored = summ.get("PASS", 0) + summ.get("FAIL", 0)
        score = round(summ.get("PASS", 0) / scored * 100) if scored else 0
        return {"severity": sev, "manual_severity": manual_sev, "categories": cats,
                "summary": summ, "score": score, "total": len(res)}

    def _ordered(self):
        """Failures first (most severe first), then errors, manual, passed."""
        order = {"FAIL": 0, "ERROR": 1, "MANUAL_VERIFICATION_REQUIRED": 2, "PASS": 3}

        def key(r):
            def num(x):
                return [int(p) if p.isdigit() else 0 for p in str(x).split(".")]
            return (order.get(r.get("result"), 4), severity_rank(r.get("severity")), num(r.get("check_id")))
        return sorted((r for r in self.results if isinstance(r, dict)), key=key)

    # =========================================================
    # JSON Report
    # =========================================================
    def generate_json(self):
        filename = os.path.join(self.output_dir, f"cis_report_{self.account_id}_{self.timestamp}.json")
        st = self._stats()
        data = {
            "account_id": self.account_id,
            "timestamp": self.timestamp,
            "summary": st["summary"],
            "severity_summary": st["severity"],
            "manual_checks_by_severity": st["manual_severity"],
            "compliance_score": st["score"],
            "results": self._ordered(),
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self._make_json_safe(data), f, indent=4, ensure_ascii=False)
        return filename

    # =========================================================
    # HTML Report
    # =========================================================
    _SEV_COLORS = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#2563eb"}

    def generate_html(self):
        filename = os.path.join(self.output_dir, f"cis_report_{self.account_id}_{self.timestamp}.html")
        e = self._safe_html
        st = self._stats()
        summ = st["summary"]
        when = self._pretty_time()

        sev_cards = ""
        for s in SEVERITY_ORDER:
            sev_cards += (f'<button class="sev-card sev-{s}" data-sev="{s}">'
                          f'<b>{st["severity"][s]}</b><span>{s.title()}</span>'
                          f'<small>{st["manual_severity"][s]} manual</small></button>')

        cat_rows = ""
        for name, c in sorted(st["categories"].items()):
            tot = sum(c.values()) or 1
            seg = "".join(
                f'<i class="seg {cls}" style="width:{c.get(k, 0) / tot * 100:.2f}%" title="{k}: {c.get(k, 0)}"></i>'
                for k, cls in (("PASS", "s-pass"), ("FAIL", "s-fail"), ("ERROR", "s-err"),
                               ("MANUAL_VERIFICATION_REQUIRED", "s-man")))
            cat_rows += (f'<div class="cat-row"><span>{e(name)}</span><div class="cat-bar">{seg}</div>'
                         f'<em>{c.get("PASS", 0)}/{tot}</em></div>')

        top = [r for r in self._ordered() if r.get("result") == "FAIL"][:5]
        top_html = "".join(
            f'<li><a href="#c-{e(r["check_id"])}"><span class="badge sev-{r["severity"]}">{r["severity"]}</span>'
            f'<b>{e(r["check_id"])}</b> {e(r["title"])}</a></li>' for r in top) or "<li>No failed checks 🎉</li>"

        cards = ""
        for r in self._ordered():
            status = r.get("result", "ERROR")
            label = "MANUAL" if status == "MANUAL_VERIFICATION_REQUIRED" else status
            details = self._normalize_details(r.get("details", []))
            det = "".join(f"<li>{e(d)}</li>" for d in details)
            cmd = r.get("command") or ""
            fix = ""
            if status != "PASS":
                fix = (f'<div class="fix"><h4>Recommendation</h4><p>{e(r.get("recommendation"))}</p>'
                       + (f'<h4>Remediation command</h4><div class="code"><button class="copy" type="button">Copy</button>'
                          f'<pre>{e(cmd)}</pre></div>' if cmd else "") + "</div>")
            ev = ""
            if r.get("evidence"):
                ev = (f'<details class="ev"><summary>Evidence</summary>'
                      f'<pre>{e(self._safe_json_dumps(r["evidence"], indent=2))}</pre></details>')
            cards += f"""
<details class="finding st-{status} sv-{r['severity']}" id="c-{e(r.get('check_id'))}" data-status="{status}" data-sev="{r['severity']}" data-cat="{e(r.get('category'))}" {'open' if status == 'FAIL' and r['severity'] in ('CRITICAL', 'HIGH') else ''}>
  <summary>
    <span class="cid">{e(r.get('check_id'))}</span>
    <span class="ttl">{e(r.get('title'))}<small>{e(r.get('category'))} · {e(r.get('check_type'))}</small></span>
    <span class="badge sev-{r['severity']}">{r['severity']}</span>
    <span class="badge stt-{status}">{label}</span>
  </summary>
  <div class="inner">
    <h4>Description</h4><p>{e(r.get('description'))}</p>
    {('<h4>Finding</h4><ul>' + det + '</ul>') if det else ''}
    {fix}{ev}
  </div>
</details>"""

        cats = sorted(st["categories"])
        cat_opts = "".join(f"<option>{e(c)}</option>" for c in cats)
        circ = 2 * 3.14159265 * 54
        off = circ * (1 - st["score"] / 100)
        ring_col = "#16a34a" if st["score"] >= 80 else "#d97706" if st["score"] >= 50 else "#dc2626"

        page = (_HTML_HEAD
                + f"""<body>
<header class="top">
  <div><h1>AWS CIS Benchmark Report</h1>
  <p>CIS AWS Foundations Benchmark v1.5 &middot; Account <b>{e(self.account_id)}</b> &middot; {e(when)}</p></div>
  <button id="theme" class="btn" type="button">◐ Theme</button>
</header>
<main>
<section class="dash">
  <div class="panel score">
    <svg viewBox="0 0 130 130" width="150" height="150"><circle cx="65" cy="65" r="54" class="ring-bg"/>
    <circle cx="65" cy="65" r="54" class="ring" stroke="{ring_col}" stroke-dasharray="{circ:.2f}" stroke-dashoffset="{off:.2f}"/></svg>
    <div class="score-num"><b>{st['score']}%</b><span>compliance</span></div>
    <p class="muted">{summ.get('PASS', 0)} of {summ.get('PASS', 0) + summ.get('FAIL', 0)} automated checks passed</p>
  </div>
  <div class="panel">
    <h3>Failed findings by risk</h3>
    <div class="sev-grid">{sev_cards}</div>
    <div class="status-row">
      <div class="mini pass"><b>{summ.get('PASS', 0)}</b>Passed</div>
      <div class="mini fail"><b>{summ.get('FAIL', 0)}</b>Failed</div>
      <div class="mini man"><b>{summ.get('MANUAL_VERIFICATION_REQUIRED', 0)}</b>Manual review</div>
      <div class="mini err"><b>{summ.get('ERROR', 0)}</b>Errors</div>
    </div>
  </div>
  <div class="panel">
    <h3>Results by category</h3>{cat_rows}
    <div class="legend"><i class="s-pass"></i>Pass <i class="s-fail"></i>Fail <i class="s-man"></i>Manual <i class="s-err"></i>Error</div>
  </div>
  <div class="panel">
    <h3>Fix first</h3><ol class="top5">{top_html}</ol>
  </div>
</section>

<section>
  <div class="toolbar">
    <input id="q" type="search" placeholder="Search checks…">
    <button class="chip on" data-st="ALL">All</button>
    <button class="chip" data-st="FAIL">Failed</button>
    <button class="chip" data-st="MANUAL_VERIFICATION_REQUIRED">Manual</button>
    <button class="chip" data-st="ERROR">Errors</button>
    <button class="chip" data-st="PASS">Passed</button>
    <select id="sev"><option value="">All severities</option>{''.join(f'<option value="{s}">{s.title()}</option>' for s in SEVERITY_ORDER)}</select>
    <select id="cat"><option value="">All categories</option>{cat_opts}</select>
    <button class="btn" id="expand" type="button">Expand all</button>
  </div>
  <p class="muted" id="count"></p>
  <div id="findings">{cards}</div>
</section>
</main>
<footer>Generated by AWS CIS Benchmark Tool. Severity is a guideline based on the typical impact of each control; adjust to your risk appetite.</footer>
<script>{_HTML_JS}</script>
</body></html>""")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(page)
        return filename

    def _pretty_time(self):
        try:
            return datetime.strptime(self.timestamp, "%Y%m%d_%H%M%S").strftime("%d %b %Y, %H:%M")
        except ValueError:
            return str(self.timestamp)

    # =========================================================
    # PDF Report
    # =========================================================
    def generate_pdf(self):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                            TableStyle, KeepTogether, PageBreak)
        except ImportError:
            print("reportlab is required for PDF generation.\nInstall it using: pip install reportlab")
            return None

        filename = os.path.join(self.output_dir, f"cis_report_{self.account_id}_{self.timestamp}.pdf")
        e = self._safe_html
        st = self._stats()
        summ = st["summary"]
        C = colors.HexColor
        sev_col = {k: C(v) for k, v in self._SEV_COLORS.items()}
        stat_col = {"PASS": C("#16a34a"), "FAIL": C("#dc2626"), "ERROR": C("#d97706"),
                    "MANUAL_VERIFICATION_REQUIRED": C("#2563eb")}
        ink, muted, line, soft = C("#111827"), C("#6b7280"), C("#e5e7eb"), C("#f3f4f6")

        ss = getSampleStyleSheet()
        base = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica", fontSize=9, leading=12.5, textColor=ink)
        small = ParagraphStyle("s", parent=base, fontSize=8, leading=10.5, textColor=muted)
        h1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26)
        h2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=17, spaceBefore=10, spaceAfter=6)
        lab = ParagraphStyle("l", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=muted, spaceBefore=5)
        code = ParagraphStyle("c", parent=base, fontName="Courier", fontSize=7.2, leading=9.2,
                              backColor=C("#0f172a"), textColor=C("#e2e8f0"), borderPadding=(5, 6, 5, 6),
                              wordWrap="CJK", spaceBefore=8, spaceAfter=8)
        ev_style = ParagraphStyle("e", parent=code, backColor=soft, textColor=C("#374151"))
        center = ParagraphStyle("ce", parent=base, alignment=1)

        def pill(text, col, w=52):
            t = Table([[Paragraph(f'<font color="white"><b>{text}</b></font>',
                                  ParagraphStyle("p", parent=center, fontSize=7, leading=9))]],
                      colWidths=[w], rowHeights=[13])
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), col),
                                   ("ROUNDEDCORNERS", [6, 6, 6, 6]),
                                   ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                   ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
            return t

        def stat_tile(value, label, col, sub=""):
            body = [Paragraph(f'<font size="22" color="{col.hexval().replace("0x", "#")}"><b>{value}</b></font>',
                              ParagraphStyle("v", parent=center, leading=28)),
                    Paragraph(f"<b>{label}</b>", ParagraphStyle("x", parent=center, fontSize=8, textColor=muted))]
            if sub:
                body.append(Paragraph(sub, ParagraphStyle("y", parent=center, fontSize=7, textColor=muted)))
            return body

        def footer(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(muted)
            canvas.drawString(15 * mm, 9 * mm, f"AWS CIS Benchmark Report  |  Account {self.account_id}")
            canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(filename, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                                topMargin=15 * mm, bottomMargin=17 * mm,
                                title="AWS CIS Benchmark Report", author="AWS CIS Benchmark Tool")
        W = A4[0] - 30 * mm
        els = []

        # ---- header band
        band = Table([[Paragraph('<font color="white"><b>AWS CIS Benchmark Report</b></font>',
                                 ParagraphStyle("hb", parent=h1, textColor=colors.white)),
                       ], [Paragraph(f'<font color="#c7d2fe">CIS AWS Foundations Benchmark v1.5 &nbsp;|&nbsp; '
                                     f'Account {e(self.account_id)} &nbsp;|&nbsp; {e(self._pretty_time())}</font>', base)]],
                     colWidths=[W])
        band.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), C("#312e81")),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 14), ("TOPPADDING", (0, 0), (0, 0), 14),
                                  ("BOTTOMPADDING", (0, -1), (-1, -1), 14)]))
        els += [band, Spacer(1, 14)]

        # ---- dashboard: score + severity tiles
        score_col = C("#16a34a") if st["score"] >= 80 else C("#d97706") if st["score"] >= 50 else C("#dc2626")
        tiles = [stat_tile(f'{st["score"]}%', "COMPLIANCE", score_col,
                           f'{summ.get("PASS", 0)} of {summ.get("PASS", 0) + summ.get("FAIL", 0)} passed')]
        for s in SEVERITY_ORDER:
            tiles.append(stat_tile(st["severity"][s], s, sev_col[s], f'{st["manual_severity"][s]} manual'))
        tw = W / 5
        dash = Table([tiles], colWidths=[tw] * 5)
        dash.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, line), ("INNERGRID", (0, 0), (-1, -1), 0.6, line),
                                  ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                                  ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                                  ("LINEABOVE", (1, 0), (1, 0), 3, sev_col["CRITICAL"]),
                                  ("LINEABOVE", (2, 0), (2, 0), 3, sev_col["HIGH"]),
                                  ("LINEABOVE", (3, 0), (3, 0), 3, sev_col["MEDIUM"]),
                                  ("LINEABOVE", (4, 0), (4, 0), 3, sev_col["LOW"]),
                                  ("LINEABOVE", (0, 0), (0, 0), 3, score_col)]))
        els += [Paragraph("Executive dashboard", h2),
                Paragraph("Failed findings by risk severity.", small), Spacer(1, 4), dash, Spacer(1, 10)]

        # ---- status row
        status_tiles = [
            stat_tile(summ.get("PASS", 0), "PASSED", stat_col["PASS"]),
            stat_tile(summ.get("FAIL", 0), "FAILED", stat_col["FAIL"]),
            stat_tile(summ.get("MANUAL_VERIFICATION_REQUIRED", 0), "MANUAL REVIEW", stat_col["MANUAL_VERIFICATION_REQUIRED"]),
            stat_tile(summ.get("ERROR", 0), "ERRORS", stat_col["ERROR"]),
        ]
        sw = W / 4
        srow = Table([status_tiles], colWidths=[sw] * 4)
        srow.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, line), ("INNERGRID", (0, 0), (-1, -1), 0.6, line),
                                  ("BACKGROUND", (0, 0), (-1, -1), soft),
                                  ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
        els += [srow, Spacer(1, 12)]

        # ---- category table with stacked bar
        from reportlab.graphics.shapes import Drawing, Rect
        rows = [[Paragraph("<b>Category</b>", small), Paragraph("<b>Distribution</b>", small),
                 Paragraph("<b>Pass</b>", small), Paragraph("<b>Fail</b>", small),
                 Paragraph("<b>Manual</b>", small), Paragraph("<b>Error</b>", small)]]
        for name, c in sorted(st["categories"].items()):
            tot = sum(c.values()) or 1
            d = Drawing(150, 9)
            x = 0
            for k in ("PASS", "FAIL", "MANUAL_VERIFICATION_REQUIRED", "ERROR"):
                w = 150 * c.get(k, 0) / tot
                if w:
                    d.add(Rect(x, 0, w, 9, fillColor=stat_col[k], strokeColor=None))
                    x += w
            rows.append([Paragraph(e(name), base), d, c.get("PASS", 0), c.get("FAIL", 0),
                         c.get("MANUAL_VERIFICATION_REQUIRED", 0), c.get("ERROR", 0)])
        ct = Table(rows, colWidths=[W * .26, 160, W * .1, W * .1, W * .1, W * .1], hAlign="LEFT")
        ct.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, line), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("FONTSIZE", (0, 0), (-1, -1), 9), ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                                ("BACKGROUND", (0, 0), (-1, 0), soft)]))
        els += [Paragraph("Results by category", h2), ct]

        # ---- fix first
        failed = [r for r in self._ordered() if r.get("result") == "FAIL"]
        if failed:
            els += [Paragraph("Fix first", h2)]
            tr = [[pill(r["severity"], sev_col[r["severity"]]),
                   Paragraph(f'<b>{e(r["check_id"])}</b> &nbsp;{e(r["title"])}', base)] for r in failed[:8]]
            t = Table(tr, colWidths=[60, W - 60])
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, line),
                                   ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
            els.append(t)

        els += [PageBreak(), Paragraph("Detailed findings", h2),
                Paragraph("Ordered by status, then severity. Full evidence is available in the HTML and JSON reports.", small),
                Spacer(1, 6)]

        # ---- findings
        sections = [("FAIL", "Failed checks"), ("ERROR", "Checks that could not be evaluated"),
                    ("MANUAL_VERIFICATION_REQUIRED", "Manual verification required"), ("PASS", "Passed checks")]
        ordered = self._ordered()
        for status, heading in sections:
            group = [r for r in ordered if r.get("result") == status]
            if not group:
                continue
            els.append(Paragraph(f"{heading} ({len(group)})", h2))
            for r in group:
                sev = r["severity"]
                head = Table([[pill(sev, sev_col[sev]), pill("MANUAL" if status.startswith("MANUAL") else status, stat_col.get(status, muted), 56),
                               Paragraph(f'<b>{e(r["check_id"])}</b> &nbsp;{e(r["title"])}', base)]],
                             colWidths=[56, 60, W - 116 - 12])
                head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), soft),
                                          ("LINEBEFORE", (0, 0), (0, 0), 3, sev_col[sev]),
                                          ("LEFTPADDING", (0, 0), (0, 0), 8),
                                          ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
                block = [head, Paragraph(f'{e(r.get("category"))} &middot; {e(r.get("check_type"))}', small)]
                details = self._normalize_details(r.get("details", []))
                if details:
                    txt = "<br/>".join(e(d) for d in details)
                    if len(txt) > 1500:
                        txt = txt[:1500] + "… (truncated, see HTML/JSON)"
                    block += [Paragraph("FINDING", lab), Paragraph(txt, base)]
                if status != "PASS":
                    block += [Paragraph("RECOMMENDATION", lab), Paragraph(e(r.get("recommendation")), base)]
                    if r.get("command"):
                        c = e(r["command"]).replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;")
                        block += [Paragraph("REMEDIATION COMMAND", lab), Paragraph(c, code)]
                block.append(Spacer(1, 9))
                # keep the header with the first part, but let long blocks flow across pages
                els.append(KeepTogether(block[:4]))
                els.extend(block[4:])

        doc.build(els, onFirstPage=footer, onLaterPages=footer)
        return filename


_HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS CIS Benchmark Report</title>
<style>
:root{--bg:#f4f5fb;--panel:#fff;--p2:#f1f2f9;--text:#151a30;--muted:#6b7089;--line:#e3e5f1;--accent:#6366f1;
--crit:#b91c1c;--high:#ea580c;--med:#d97706;--low:#2563eb;--pass:#16a34a;--fail:#dc2626;--code:#0f172a;
--shadow:0 1px 2px rgba(20,24,50,.06),0 8px 24px rgba(20,24,50,.06)}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0c0e1a;--panel:#151829;--p2:#1c2036;--text:#e8eaf6;--muted:#8a90ad;--line:#262b45;--shadow:none}}
:root[data-theme=dark]{--bg:#0c0e1a;--panel:#151829;--p2:#1c2036;--text:#e8eaf6;--muted:#8a90ad;--line:#262b45;--shadow:none}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.top{background:linear-gradient(135deg,#312e81,#6d28d9);color:#fff;padding:26px 32px;display:flex;justify-content:space-between;align-items:center;gap:16px}
.top h1{margin:0;font-size:24px}.top p{margin:4px 0 0;opacity:.85}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:10px;padding:8px 14px;font:inherit;cursor:pointer;font-weight:600}
.top .btn{background:rgba(255,255,255,.15);color:#fff;border-color:rgba(255,255,255,.3)}
main{max-width:1200px;margin:0 auto;padding:24px 20px 40px}
.dash{display:grid;grid-template-columns:230px 1fr;gap:18px;margin-bottom:26px}
@media(max-width:860px){.dash{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px 20px;box-shadow:var(--shadow)}
.panel h3{margin:0 0 12px;font-size:12px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.score{position:relative;text-align:center;grid-row:span 4;align-self:start}
.score svg{transform:rotate(-90deg)}.ring-bg{fill:none;stroke:var(--p2);stroke-width:12}
.ring{fill:none;stroke-width:12;stroke-linecap:round}
.score-num{position:absolute;top:64px;left:0;right:0}.score-num b{display:block;font-size:34px;line-height:1}
.score-num span{font-size:11px;color:var(--muted)}
.muted{color:var(--muted);font-size:12px}
.sev-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.sev-card{border:1px solid var(--line);border-top:4px solid;border-radius:12px;background:var(--p2);padding:14px;text-align:left;cursor:pointer;color:var(--text);font:inherit}
.sev-card b{display:block;font-size:30px;line-height:1.1}.sev-card span{font-weight:700;font-size:13px}.sev-card small{display:block;color:var(--muted);font-size:11px}
.sev-card.sev-CRITICAL{border-top-color:var(--crit)}.sev-card.sev-CRITICAL b{color:var(--crit)}
.sev-card.sev-HIGH{border-top-color:var(--high)}.sev-card.sev-HIGH b{color:var(--high)}
.sev-card.sev-MEDIUM{border-top-color:var(--med)}.sev-card.sev-MEDIUM b{color:var(--med)}
.sev-card.sev-LOW{border-top-color:var(--low)}.sev-card.sev-LOW b{color:var(--low)}
.status-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}
.mini{border-radius:12px;padding:10px 14px;background:var(--p2);font-size:12px;font-weight:600;color:var(--muted)}
.mini b{display:block;font-size:22px}.mini.pass b{color:var(--pass)}.mini.fail b{color:var(--fail)}.mini.man b{color:var(--low)}.mini.err b{color:var(--med)}
.dash .panel:nth-child(3),.dash .panel:nth-child(4){grid-column:2}
@media(max-width:860px){.dash .panel:nth-child(3),.dash .panel:nth-child(4){grid-column:1}.sev-grid,.status-row{grid-template-columns:repeat(2,1fr)}}
.cat-row{display:grid;grid-template-columns:90px 1fr 50px;gap:12px;align-items:center;margin:8px 0;font-weight:600;font-size:13px}
.cat-row em{color:var(--muted);font-style:normal;font-size:12px;text-align:right}
.cat-bar{display:flex;height:10px;border-radius:99px;overflow:hidden;background:var(--p2)}
.seg{display:block;height:100%}.s-pass{background:var(--pass)}.s-fail{background:var(--fail)}.s-err{background:var(--med)}.s-man{background:var(--low)}
.legend{font-size:11px;color:var(--muted);margin-top:10px}.legend i{display:inline-block;width:9px;height:9px;border-radius:3px;margin:0 4px 0 10px}
.top5{margin:0;padding:0;list-style:none}.top5 li{border-bottom:1px solid var(--line)}.top5 li:last-child{border:0}
.top5 a{display:flex;gap:10px;align-items:center;padding:8px 0;color:var(--text);text-decoration:none;font-size:13px}
.top5 a:hover{color:var(--accent)}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:6px}
.toolbar input,.toolbar select{padding:8px 12px;border-radius:10px;border:1px solid var(--line);background:var(--panel);color:var(--text);font:inherit}
.chip{border:1px solid var(--line);background:var(--panel);color:var(--text);padding:7px 14px;border-radius:99px;font:inherit;font-weight:600;font-size:12px;cursor:pointer}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff}
.finding{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--line);border-radius:12px;margin:10px 0;box-shadow:var(--shadow)}
.finding.sv-CRITICAL.st-FAIL{border-left-color:var(--crit)}.finding.sv-HIGH.st-FAIL{border-left-color:var(--high)}
.finding.sv-MEDIUM.st-FAIL{border-left-color:var(--med)}.finding.sv-LOW.st-FAIL{border-left-color:var(--low)}
.finding.st-PASS{border-left-color:var(--pass)}.finding.st-MANUAL_VERIFICATION_REQUIRED{border-left-color:var(--low)}.finding.st-ERROR{border-left-color:var(--med)}
.finding>summary{list-style:none;cursor:pointer;display:flex;gap:12px;align-items:center;padding:12px 16px}
.finding>summary::-webkit-details-marker{display:none}.finding>summary:hover{background:var(--p2);border-radius:12px}
.cid{font:700 13px ui-monospace,Menlo,Consolas,monospace;color:var(--muted);min-width:46px}
.ttl{flex:1;font-weight:600}.ttl small{display:block;font-weight:400;color:var(--muted);font-size:11px}
.badge{font-size:10.5px;font-weight:800;padding:3px 10px;border-radius:99px;letter-spacing:.04em;color:#fff;white-space:nowrap}
.badge.sev-CRITICAL{background:var(--crit)}.badge.sev-HIGH{background:var(--high)}.badge.sev-MEDIUM{background:var(--med)}.badge.sev-LOW{background:var(--low)}
.stt-PASS{background:var(--pass)}.stt-FAIL{background:var(--fail)}.stt-ERROR{background:var(--med)}.stt-MANUAL_VERIFICATION_REQUIRED{background:#64748b}
.st-PASS .badge[class*=sev-]{opacity:.35}
.inner{padding:2px 20px 18px;border-top:1px solid var(--line)}
.inner h4{margin:14px 0 4px;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.inner p,.inner ul{margin:0}.inner ul{padding-left:18px;word-break:break-word}
.fix{margin-top:6px;background:var(--p2);border-radius:12px;padding:2px 16px 14px;margin-top:14px}
.code{position:relative}.code pre{background:var(--code);color:#e2e8f0;border-radius:10px;padding:14px;overflow:auto;font-size:12px;margin:0}
.copy{position:absolute;top:8px;right:8px;border:0;border-radius:8px;padding:4px 10px;font-size:11px;font-weight:700;cursor:pointer;background:#334155;color:#fff}
.ev{margin-top:12px}.ev summary{cursor:pointer;color:var(--accent);font-weight:600;font-size:12px}
.ev pre{background:var(--p2);border:1px solid var(--line);padding:12px;border-radius:10px;overflow:auto;max-height:340px;font-size:11.5px}
footer{text-align:center;color:var(--muted);font-size:12px;padding:20px}
@media print{body{background:#fff}.toolbar,#theme{display:none}.finding{break-inside:avoid;box-shadow:none}.top{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style></head>
"""

_HTML_JS = """
const $=s=>document.querySelector(s),all=s=>[...document.querySelectorAll(s)];
let st="ALL";
function apply(){const q=$('#q').value.toLowerCase(),sv=$('#sev').value,ct=$('#cat').value;let n=0;
 all('.finding').forEach(f=>{const ok=(st==='ALL'||f.dataset.status===st)&&(!sv||f.dataset.sev===sv)&&(!ct||f.dataset.cat===ct)&&(!q||f.textContent.toLowerCase().includes(q));
  f.style.display=ok?'':'none';if(ok)n++});$('#count').textContent=n+' of '+all('.finding').length+' checks shown'}
all('.chip').forEach(c=>c.onclick=()=>{st=c.dataset.st;all('.chip').forEach(x=>x.classList.toggle('on',x===c));apply()});
all('.sev-card').forEach(c=>c.onclick=()=>{$('#sev').value=c.dataset.sev;st='FAIL';all('.chip').forEach(x=>x.classList.toggle('on',x.dataset.st==='FAIL'));apply();$('#findings').scrollIntoView({behavior:'smooth'})});
['#q','#sev','#cat'].forEach(s=>$(s).oninput=apply);
let open=false;$('#expand').onclick=function(){open=!open;all('.finding').forEach(f=>f.open=open);this.textContent=open?'Collapse all':'Expand all'};
all('.copy').forEach(b=>b.onclick=()=>{navigator.clipboard.writeText(b.nextElementSibling.textContent).then(()=>{b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200)})});
$('#theme').onclick=()=>{const r=document.documentElement;const d=getComputedStyle(r).getPropertyValue('--bg').trim()==='#0c0e1a';r.dataset.theme=d?'light':'dark'};
apply();
"""
