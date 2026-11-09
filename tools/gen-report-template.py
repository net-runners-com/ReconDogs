#!/usr/bin/env python3
"""Reusable autopentest PDF report generator (replaces per-engagement gen-report.py copies).

Usage:  python3 tools/gen-report-template.py <engagement_dir>  [--title "<report title>"] [--subtitle "<subtitle>"]
Reads  <engagement_dir>/findings/finding-*/description.md  (filters out *.rejected)
       <engagement_dir>/artifacts/validated/*.json   → validator PASS table
       <engagement_dir>/artifacts/false-positives/*.json → rejected count
       <engagement_dir>/recon/p_threat_intel.json    → trending CVE column
Writes <engagement_dir>/reports/Penetration-Test-Report.pdf

Features over per-engagement copy:
  - CJK font fallback chain (Noto Sans CJK JP/SC/KR + Latin fallback)
  - Validator PASS/FAIL column per finding
  - Threat-intel trending CVE sidebar
  - Chain finding parent-child relationships rendered
"""
import sys, os, re, json, glob, argparse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config as apconfig
HELPERS = apconfig.jpdf_helpers()
if HELPERS:
    sys.path.insert(0, HELPERS)

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, white, black
from jp_pdf_helpers import setup_fonts, draw_mixed as _dm, draw_mixed_centered as _dmc, draw_rounded_rect, COLORS, JP, JP_MIN, EN, EN_B
setup_fonts()

W, H = A4
NAVY, ORANGE, GRAY, RED = COLORS['navy'], COLORS['accent'], COLORS['gray'], COLORS['red']
SEV_COLORS = {'CRITICAL':HexColor('#B71C1C'),'HIGH':HexColor('#E53935'),
              'MEDIUM':HexColor('#FB8C00'),'LOW':HexColor('#FBC02D'),
              'INFO':HexColor('#1976D2')}
SEV_ORDER = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}

def dm(c, x, y, text, jp=JP, size=12, color=None): _dm(c, x, y, text, jp, EN, size, color)
def dmc(c, cx, y, text, jp=JP, size=12, color=None): _dmc(c, cx, y, text, jp, EN, size, color)

def parse_md(path):
    txt = open(path, encoding='utf-8').read()
    title = re.search(r'^#\s+(.+)', txt, re.M)
    sev   = re.search(r'Severity:\*\*\s*(\w+)', txt)
    cwe   = re.search(r'CWE:\*\*\s*(CWE-[\d\-]+|–|-)', txt)
    cve   = re.search(r'CVE:\*\*\s*(CVE-[\d\-]+)', txt)
    cvss  = re.search(r'CVSS:\*\*\s*([\d.]+)', txt)
    def sec(name):
        m = re.search(rf'##\s*{name}\s*\n(.+?)(?=\n##\s|\Z)', txt, re.S)
        if not m: return []
        out, in_code = [], False
        for line in m.group(1).splitlines():
            s = line.strip()
            if s.startswith('```'): in_code = not in_code; continue
            if in_code: continue
            s = s.lstrip('-').strip()
            if s: out.append(s)
        return out[:8]
    # Extract traffic eids for HAR deep-link
    eids = re.findall(r"traffic eid:\s*(\d+)", txt)
    return {'title': title.group(1) if title else '',
            'sev': sev.group(1) if sev else 'INFO',
            'cwe': cwe.group(1) if cwe else '-',
            'cve': cve.group(1) if cve else '',
            'cvss': cvss.group(1) if cvss else '',
            'overview': sec('概要'),
            'evidence': sec('証拠'),
            'remediation': sec('推奨対策'),
            'eids': eids}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('engagement_dir')
    ap.add_argument('--title', default='ペネトレーションテスト報告書')
    ap.add_argument('--subtitle', default='')
    ap.add_argument('--out', default='')
    args = ap.parse_args()
    base = Path(args.engagement_dir).resolve()
    out = Path(args.out) if args.out else base / 'reports' / 'Penetration-Test-Report.pdf'
    out.parent.mkdir(parents=True, exist_ok=True)
    # Load findings
    findings = []
    for d in sorted(glob.glob(f'{base}/findings/finding-*')):
        if d.endswith('.rejected') or not os.path.isdir(d): continue
        md = f'{d}/description.md'
        if not os.path.exists(md): continue
        f = parse_md(md)
        f['id'] = os.path.basename(d).replace('finding-', 'F-')
        findings.append(f)
    findings.sort(key=lambda x: (SEV_ORDER.get(x['sev'], 9), x['id']))
    # Validator result map
    val_pass = set(); val_fail = set()
    for p in glob.glob(f'{base}/artifacts/validated/*.json'):
        val_pass.add(Path(p).stem)
    for p in glob.glob(f'{base}/artifacts/false-positives/*.json'):
        val_fail.add(Path(p).stem)
    # Threat intel
    ti = {}
    tip = base / 'recon' / 'p_threat_intel.json'
    if tip.is_file():
        try: ti = json.loads(tip.read_text())
        except Exception: pass
    trending_cves = {h['cve']: h['mentions'] for h in (ti.get('trending_hits') or [])}
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings: counts[f['sev']] = counts.get(f['sev'], 0) + 1
    c = canvas.Canvas(str(out), pagesize=A4)
    # Cover
    c.setFillColor(NAVY); c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(ORANGE); c.rect(0, H-120, W, 6, fill=1, stroke=0)
    dmc(c, W/2, H-220, args.title, JP, 26, white)
    if args.subtitle: dmc(c, W/2, H-260, args.subtitle, JP, 13, white)
    dmc(c, W/2, H-310, f'検出 {len(findings)} 件 / 検証 PASS {len(val_pass)} / REJECT {len(val_fail)}', JP_MIN, 11, HexColor('#AAB4C0'))
    c.showPage()
    # Exec summary
    def hdr():
        c.setFillColor(NAVY); c.rect(0, H-50, W, 50, fill=1, stroke=0)
        dm(c, 36, H-32, args.title, JP, 12, white)
        c.setFillColor(ORANGE); c.rect(0, H-54, W, 4, fill=1, stroke=0)
    def ftr(n):
        dm(c, 36, 24, '© 2026 netrunners — CONFIDENTIAL', JP_MIN, 8, GRAY)
        dm(c, W-50, 24, str(n), EN, 9, GRAY)
    hdr(); ftr(2)
    y = H - 90
    dm(c, 36, y, 'Executive Summary', EN_B, 16, NAVY); y -= 28
    xoff = 36
    for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
        draw_rounded_rect(c, xoff, y-54, 96, 48, 6, SEV_COLORS[sev], None)
        dmc(c, xoff+48, y-28, str(counts[sev]), EN_B, 20, white)
        dmc(c, xoff+48, y-48, sev, EN_B, 8, white)
        xoff += 102
    y -= 80
    dm(c, 36, y, '検証ゲート結果', JP, 13, NAVY); y -= 20
    dm(c, 48, y, f'• 検証 PASS: {len(val_pass)} / REJECTED (FP): {len(val_fail)}', JP_MIN, 10, black); y -= 18
    if trending_cves:
        dm(c, 48, y, f'• [TRENDING] 直近 90 日 intel で言及されている CVE: {len(trending_cves)} 件', JP_MIN, 10, RED); y -= 18
    y -= 10
    dm(c, 36, y, '優先対応ロードマップ', JP, 13, NAVY); y -= 22
    for pri, body in [
        ('P0 (48h)', f'CRITICAL {counts["CRITICAL"]} 件 / [TRENDING] 全部を即時対応'),
        ('P1 (7d)',  f'HIGH {counts["HIGH"]} 件'),
        ('P2 (14d)', f'MEDIUM {counts["MEDIUM"]} 件'),
        ('P3 (30d)', f'LOW {counts["LOW"]} / INFO {counts["INFO"]}')]:
        dm(c, 48, y, f'[{pri}] {body}', JP_MIN, 10, black); y -= 18
    c.showPage()
    pg = 3
    for f in findings:
        hdr(); ftr(pg)
        y = H - 80
        sev = f['sev']
        draw_rounded_rect(c, 36, y-28, 92, 24, 4, SEV_COLORS[sev], None)
        dmc(c, 82, y-14, sev, EN_B, 10, white)
        dm(c, 136, y-16, f['id'], EN_B, 14, NAVY)
        # Validator badge
        vb_x = 180
        if f['id'] in val_pass:
            draw_rounded_rect(c, vb_x, y-28, 56, 24, 4, HexColor('#43A047'), None)
            dmc(c, vb_x+28, y-14, 'VALIDATED', EN_B, 8, white)
        elif f['id'] in val_fail:
            draw_rounded_rect(c, vb_x, y-28, 48, 24, 4, HexColor('#9E9E9E'), None)
            dmc(c, vb_x+24, y-14, 'FP', EN_B, 8, white)
        # Trending badge
        if f['cve'] and f['cve'] in trending_cves:
            draw_rounded_rect(c, vb_x+70, y-28, 70, 24, 4, RED, None)
            dmc(c, vb_x+105, y-14, f'TRENDING×{trending_cves[f["cve"]]}', EN_B, 7, white)
        if f['cvss']: dm(c, 350, y-16, f'CVSS {f["cvss"]}  |  {f["cwe"]}', EN, 10, GRAY)
        y -= 38
        dm(c, 36, y, f['title'], JP, 10, black); y -= 24
        if f.get('eids'):
            dm(c, 36, y, f'  HAR evidence: traffic/{" ".join(f["eids"][:5])}.json', EN, 8, GRAY); y -= 14
        for label, lines, col in [('概要', f['overview'], NAVY),
                                     ('証拠', f['evidence'], HexColor('#5A3')),
                                     ('推奨対策', f['remediation'], ORANGE)]:
            if not lines: continue
            dm(c, 36, y, label, JP, 11, col); y -= 16
            for line in lines:
                first = True
                while line:
                    chunk, line = line[:88], line[88:]
                    prefix = '• ' if first else '  '
                    first = False
                    dm(c, 48, y, prefix + chunk, JP_MIN, 9, black); y -= 13
                    if y < 60:
                        c.showPage(); pg += 1; hdr(); ftr(pg); y = H - 80
            y -= 6
        c.showPage(); pg += 1
    c.save()
    print(f'[OK] {out}  ({os.path.getsize(out):,} bytes, {len(findings)} findings, {len(val_pass)} validated, {len(trending_cves)} trending)')

if __name__ == '__main__':
    main()
