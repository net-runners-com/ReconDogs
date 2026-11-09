#!/usr/bin/env python3
"""Generic Transilience-style pentest report generator (data-driven).

Report generator that reads a per-site
data module so one engine renders every site's PDF with embedded Japanese fonts
(no mojibake, exact metrics -> no overlap).

Usage:
    python3 tools/gen_site_report.py <site_data.py>
The data file must define a module-level dict REPORT (schema: see data files).
"""

import sys, os, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config as apconfig
_jpdf = apconfig.jpdf_helpers()
if _jpdf:
    sys.path.insert(0, _jpdf)

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from jp_pdf_helpers import (
    draw_mixed, draw_mixed_centered, draw_mixed_right,
    mixed_para, draw_rounded_rect, COLORS, get_mixed_width,
    JP, JP_MIN, EN, EN_B,
)

# ---- Embed real Japanese TrueType fonts (fixes mojibake + overlap) ----
_FDIR = str(apconfig.formats_fonts())
pdfmetrics.registerFont(TTFont('HeiseiKakuGo-W5', os.path.join(_FDIR, 'NotoSansJP-Bold.ttf')))
pdfmetrics.registerFont(TTFont('HeiseiMin-W3',    os.path.join(_FDIR, 'NotoSansJP-Regular.ttf')))

# ---- Load site data ----
if len(sys.argv) < 2:
    sys.exit('usage: gen_site_report.py <site_data.py>')
_spec = importlib.util.spec_from_file_location('site_data', sys.argv[1])
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
R = _mod.REPORT

W, H = A4
NAVY   = COLORS['navy']
ORANGE = COLORS['accent']
GRAY   = COLORS['gray']
SEV_COLORS = {
    'CRITICAL': HexColor('#B71C1C'),
    'HIGH':     HexColor('#E53935'),
    'MEDIUM':   HexColor('#FB8C00'),
    'LOW':      HexColor('#FBC02D'),
    'INFO':     HexColor('#1976D2'),
}

FINDINGS = R['findings']
SEV_COUNT = {}
for f in FINDINGS:
    SEV_COUNT[f['sev']] = SEV_COUNT.get(f['sev'], 0) + 1

SUBTITLE = R['subtitle']
OUT = R['out']
os.makedirs(os.path.dirname(OUT), exist_ok=True)
c = canvas.Canvas(OUT, pagesize=A4)


# ================= Shared chrome =================
def header(title):
    c.setFillColor(NAVY);   c.rect(0, H-50, W, 50, fill=1, stroke=0)
    c.setFillColor(ORANGE); c.rect(0, H-54, W, 4,  fill=1, stroke=0)
    sub_w = get_mixed_width(c, SUBTITLE, JP, EN, 9)
    draw_mixed_right(c, W-40, H-32, SUBTITLE, JP, EN, 9, HexColor('#B0BEC5'))
    avail = (W - 40 - sub_w - 16) - 40
    size = 14
    while size > 9 and get_mixed_width(c, title, JP, EN_B, size) > avail:
        size -= 0.5
    t = title
    while t and get_mixed_width(c, t, JP, EN_B, size) > avail:
        t = t[:-1]
    if t != title:
        t = t[:-1] + '…'
    draw_mixed(c, 40, H-32, t, JP, EN_B, size, white)


def footer(n):
    draw_mixed_centered(c, W/2, 25, f'{R["footer_tag"]}  |  {n}', JP, EN, 8, GRAY)


# ================= Cover =================
def cover():
    c.setFillColor(NAVY); c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(ORANGE); c.rect(40, H-120, 100, 4, fill=1, stroke=0)
    draw_mixed(c, 40, H-170, 'PENETRATION TEST', JP, EN_B, 22, white)
    draw_mixed(c, 40, H-200, 'REPORT',           JP, EN_B, 22, white)
    draw_mixed(c, 40, H-240, R['title'],         JP, EN_B, 20, white)
    draw_mixed(c, 40, H-290, SUBTITLE,           JP, EN, 14, HexColor('#B0BEC5'))
    draw_mixed(c, 40, H-315, R['target_url'],    JP, EN, 10, HexColor('#B0BEC5'))

    y = H - 400
    for label, val in [
        ('実施日',    R['date']),
        ('範囲',      R['scope']),
        ('手法',      R['method']),
        ('所見件数',  f'{len(FINDINGS)} 件 (HIGH {SEV_COUNT.get("HIGH",0)} / '
                      f'MEDIUM {SEV_COUNT.get("MEDIUM",0)} / LOW {SEV_COUNT.get("LOW",0)} / '
                      f'INFO {SEV_COUNT.get("INFO",0)})'),
        ('インフラ',  R['infra']),
        ('検証ツール', R['tools']),
    ]:
        draw_mixed(c, 40, y, label, JP, EN, 10, ORANGE)
        draw_mixed(c, 160, y, val,  JP, EN, 11, white); y -= 20

    y = 220
    draw_mixed(c, 40, y, '所見サマリ', JP, EN_B, 14, white); y -= 30
    x = 40
    for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
        n = SEV_COUNT.get(sev, 0)
        c.setFillColor(SEV_COLORS[sev]); c.rect(x, y-30, 95, 50, fill=1, stroke=0)
        draw_mixed_centered(c, x+48, y,    str(n), EN_B, EN_B, 22, white)
        draw_mixed_centered(c, x+48, y-20, sev,    EN,   EN_B, 9,  white)
        x += 105

    draw_mixed_centered(c, W/2, 40,
        'CONFIDENTIAL — 本報告書は依頼者のみに提供される機密情報です',
        JP, EN, 9, HexColor('#B0BEC5'))
    c.showPage()


# ================= Exec summary =================
def exec_summary():
    header('エグゼクティブサマリ')
    y = H - 90

    draw_mixed(c, 40, y, '1. 評価対象', JP, EN_B, 13, NAVY); y -= 22
    for line in R['exec_overview']:
        draw_mixed(c, 40, y, line, JP_MIN, EN, 11, black); y -= 16
    y -= 10

    draw_mixed(c, 40, y, '2. 総合評価', JP, EN_B, 13, NAVY); y -= 22
    vlines = R['exec_verdict_lines']
    box_h = 26 + len(vlines) * 15 + 12
    vcol = SEV_COLORS[R['exec_verdict_sev']]
    bg = {'HIGH': '#FFEBEE', 'MEDIUM': '#FFF3E0', 'LOW': '#FFFDE7',
          'INFO': '#E3F2FD', 'CRITICAL': '#FFEBEE'}[R['exec_verdict_sev']]
    draw_rounded_rect(c, 40, y-box_h, W-80, box_h, 6, HexColor(bg), vcol)
    draw_mixed(c, 55, y-20, R['exec_verdict_title'], JP, EN_B, 13, vcol)
    for i, line in enumerate(vlines):
        draw_mixed(c, 55, y-38 - i*15, line, JP_MIN, EN, 10, black)
    y -= (box_h + 15)

    draw_mixed(c, 40, y, '3. 所見一覧', JP, EN_B, 13, NAVY); y -= 15

    data = [[mixed_para('ID', 'center', bold=True),
             mixed_para('深刻度', 'center', bold=True),
             mixed_para('タイトル', bold=True),
             mixed_para('CWE', 'center', bold=True)]]
    for f in FINDINGS:
        data.append([mixed_para(f['id'], 'center'),
                     mixed_para(f['sev'], 'center'),
                     mixed_para(f['title']),
                     mixed_para(f['cwe'], 'center')])
    t = Table(data, colWidths=[50, 60, 320, 85])
    style = [
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',  (0,0), (-1,0), white),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('GRID',       (0,0), (-1,-1), 0.5, HexColor('#CFD8DC')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, HexColor('#F5F5F5')]),
        ('LEFTPADDING',  (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
    ]
    for i, f in enumerate(FINDINGS, start=1):
        style.append(('TEXTCOLOR', (1,i), (1,i), SEV_COLORS[f['sev']]))
        style.append(('FONTNAME',  (1,i), (1,i), EN_B))
    t.setStyle(TableStyle(style))
    tw, th = t.wrapOn(c, W-80, 400)
    t.drawOn(c, 40, y - th)
    footer(2); c.showPage()


# ================= Finding page =================
def finding(f, page_num):
    fid, sev, title, cwe = f['id'], f['sev'], f['title'], f['cwe']
    header(f'{fid}  {title}')
    y = H - 90
    col = SEV_COLORS[sev]
    c.setFillColor(col); c.rect(40, y-6, 90, 24, fill=1, stroke=0)
    draw_mixed_centered(c, 85, y, sev, EN, EN_B, 11, white)
    meta = f'CWE: {cwe}'
    if f.get('cvss'):
        meta += f'   |   CVSS v3.1: {f["cvss"]}'
    draw_mixed(c, 140, y, meta, EN, EN, 10, GRAY)
    if f.get('cvss_vec'):
        y -= 15
        draw_mixed(c, 140, y, f['cvss_vec'], EN, EN, 8, GRAY)
    y -= 32

    def sec(label, lines, hex_):
        nonlocal y
        c.setFillColor(HexColor(hex_)); c.rect(40, y-3, 4, 14, fill=1, stroke=0)
        draw_mixed(c, 50, y, label, JP, EN_B, 11, NAVY); y -= 18
        for ln in lines:
            if y < 60:
                footer(page_num); c.showPage(); header(f'{fid}  {title} (続き)')
                y = H - 80
            draw_mixed(c, 55, y, ln, JP_MIN, EN, 10, black); y -= 14
        y -= 8

    sec('概要',               f['overview'],    '#1565C0')
    sec('影響・悪用シナリオ', f['impact'],      '#E53935')
    sec('技術的証拠',         f['evidence'],    '#FB8C00')
    sec('推奨対策',           f['remediation'], '#43A047')
    footer(page_num); c.showPage()


# ================= Appendix: methodology / surface =================
def appendix():
    header('付録 A — 手法と調査範囲')
    y = H - 90
    def block(title, lines):
        nonlocal y
        if y < 120:
            footer(99); c.showPage(); header('付録 A — 手法と調査範囲 (続き)'); y = H - 90
        draw_mixed(c, 40, y, title, JP, EN_B, 12, NAVY); y -= 20
        for ln in lines:
            if y < 60:
                footer(99); c.showPage(); header('付録 A (続き)'); y = H - 90
            draw_mixed(c, 50, y, ln, JP_MIN, EN, 10, black); y -= 14
        y -= 10
    for title, lines in R.get('appendix', []):
        block(title, lines)
    footer(99); c.showPage()


# ================= Build =================
cover()
exec_summary()
p = 3
for f in FINDINGS:
    finding(f, p); p += 1
if R.get('appendix'):
    appendix()
c.save()
print(f'[+] wrote {OUT}  ({os.path.getsize(OUT)//1024} KB, {len(FINDINGS)} findings)')
