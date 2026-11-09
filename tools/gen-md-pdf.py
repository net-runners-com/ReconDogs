#!/usr/bin/env python3
"""Render a Markdown report to a Transilience-styled PDF with CJK (NotoSansJP).

Usage: python3 tools/gen-md-pdf.py <input.md> <output.pdf> [--title "..."]
Handles: # / ## / ### headings, paragraphs, - bullets, GFM pipe tables,
**bold**, `code`. Uses reportlab Platypus for auto wrap/pagination.
"""
import sys, re, argparse, html
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, KeepTogether)

import os as _os
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import config as apconfig
FONTS = str(apconfig.formats_fonts())
pdfmetrics.registerFont(TTFont("JP", f"{FONTS}/NotoSansJP-Regular.ttf"))
pdfmetrics.registerFont(TTFont("JPB", f"{FONTS}/NotoSansJP-Bold.ttf"))
pdfmetrics.registerFontFamily("JP", normal="JP", bold="JPB", italic="JP", boldItalic="JPB")

NAVY = colors.HexColor("#0B2447")
ORANGE = colors.HexColor("#F5821F")
GRAY = colors.HexColor("#555555")
LGRAY = colors.HexColor("#EEF1F5")

def inline(t):
    t = html.escape(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"`(.+?)`", r'<font backColor="#EEF1F5" color="#B2305A">\1</font>', t)
    return t

styles = {
    "h1": ParagraphStyle("h1", fontName="JPB", fontSize=22, leading=27, textColor=NAVY, spaceAfter=4),
    "h2": ParagraphStyle("h2", fontName="JPB", fontSize=14, leading=18, textColor=NAVY, spaceBefore=14, spaceAfter=6),
    "h3": ParagraphStyle("h3", fontName="JPB", fontSize=11.5, leading=15, textColor=ORANGE, spaceBefore=8, spaceAfter=3),
    "p":  ParagraphStyle("p",  fontName="JP", fontSize=9.5, leading=14, textColor=colors.black, spaceAfter=5),
    "li": ParagraphStyle("li", fontName="JP", fontSize=9.5, leading=14, textColor=colors.black, leftIndent=12, bulletIndent=2, spaceAfter=2),
    "cell": ParagraphStyle("cell", fontName="JP", fontSize=8.3, leading=11.5, textColor=colors.black),
    "cellh": ParagraphStyle("cellh", fontName="JPB", fontSize=8.5, leading=11.5, textColor=colors.white),
}

def build(md, title):
    flow = []
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        # table block
        if s.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|?$", lines[i+1].strip()):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1
            cells = []
            for r_idx, r in enumerate(rows):
                if re.match(r"^\|[\s:|-]+\|?$", r):
                    continue
                parts = [c.strip() for c in r.strip().strip("|").split("|")]
                st = styles["cellh"] if not cells else styles["cell"]
                cells.append([Paragraph(inline(p), st) for p in parts])
            if cells:
                ncol = len(cells[0])
                avail = A4[0] - 32*mm
                tbl = Table(cells, colWidths=[avail/ncol]*ncol, repeatRows=1)
                tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), NAVY),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, LGRAY]),
                    ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#C9D2DD")),
                    ("VALIGN", (0,0), (-1,-1), "TOP"),
                    ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4),
                    ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                ]))
                flow.append(tbl); flow.append(Spacer(1, 6))
            continue
        if s.startswith("# "):
            flow.append(Paragraph(inline(s[2:]), styles["h1"]))
            flow.append(HRFlowable(width="100%", thickness=2, color=ORANGE, spaceAfter=8))
        elif s.startswith("## "):
            flow.append(Paragraph(inline(s[3:]), styles["h2"]))
            flow.append(HRFlowable(width="100%", thickness=0.6, color=ORANGE, spaceAfter=5))
        elif s.startswith("### "):
            flow.append(Paragraph(inline(s[4:]), styles["h3"]))
        elif s.startswith("---"):
            flow.append(Spacer(1, 4))
        elif s.startswith("- ") or s.startswith("* "):
            flow.append(Paragraph(inline(s[2:]), styles["li"], bulletText="•"))
        elif s == "":
            flow.append(Spacer(1, 3))
        else:
            flow.append(Paragraph(inline(s), styles["p"]))
        i += 1
    return flow

def footer(c, doc):
    c.saveState()
    c.setFont("JP", 7.5); c.setFillColor(GRAY)
    c.drawString(16*mm, 10*mm, "Transilience — Confidential")
    c.drawRightString(A4[0]-16*mm, 10*mm, f"p.{doc.page}")
    c.setStrokeColor(ORANGE); c.setLineWidth(0.5); c.line(16*mm, 13*mm, A4[0]-16*mm, 13*mm)
    c.restoreState()

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("inp"); ap.add_argument("out")
    ap.add_argument("--title", default="")
    a = ap.parse_args()
    md = open(a.inp, encoding="utf-8").read()
    doc = SimpleDocTemplate(a.out, pagesize=A4, leftMargin=16*mm, rightMargin=16*mm,
                            topMargin=16*mm, bottomMargin=16*mm, title=a.title or "Report")
    doc.build(build(md, a.title), onFirstPage=footer, onLaterPages=footer)
    print("wrote", a.out)

if __name__ == "__main__":
    main()
