#!/usr/bin/env python3
"""Generate a single-page PDF: aggressor engagement flow from consent to retest.
Transilience branding (navy + orange). Japanese labels.

Usage: python3 tools/gen-engagement-flow-pdf.py [--out path.pdf]
"""
import sys, argparse
from pathlib import Path

import os as _os
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import config as apconfig
HELPERS = apconfig.jpdf_helpers()
if HELPERS:
    sys.path.insert(0, HELPERS)

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.colors import HexColor, white, black
from jp_pdf_helpers import setup_fonts, draw_mixed as _dm, draw_mixed_centered as _dmc, draw_rounded_rect, COLORS, JP, JP_MIN, EN, EN_B
import os as _os
def cfg_byline():
    return _os.environ.get("AP_REPORT_BYLINE", "")


setup_fonts()

NAVY   = COLORS['navy']    # #1A237E
ORANGE = COLORS['accent']  # #FF6B35 ish
GRAY   = COLORS['gray']
GREEN  = HexColor('#43A047')
RED    = HexColor('#B71C1C')
LIGHT_BG = HexColor('#FBFBF8')
CARD_BG = HexColor('#FFFFFF')
BORDER = HexColor('#E3E6E4')

def dm(c, x, y, text, jp=JP, size=10, color=None): _dm(c, x, y, text, jp, EN, size, color)
def dmc(c, cx, y, text, jp=JP, size=10, color=None): _dmc(c, cx, y, text, jp, EN, size, color)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(apconfig.docs_dir() / "aggressor-engagement-flow.pdf"))
    args = ap.parse_args()
    OUT = Path(args.out)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    # A4 landscape for timeline layout
    W, H = landscape(A4)
    c = canvas.Canvas(str(OUT), pagesize=landscape(A4))

    # Background
    c.setFillColor(LIGHT_BG); c.rect(0, 0, W, H, fill=1, stroke=0)

    # Top band (navy)
    c.setFillColor(NAVY); c.rect(0, H-60, W, 60, fill=1, stroke=0)
    # Orange accent line
    c.setFillColor(ORANGE); c.rect(0, H-66, W, 4, fill=1, stroke=0)

    dm(c, 30, H-40, "aggressor 外部ペンテスト — 実施フロー", JP, 18, white)
    dm(c, W-200, H-40, "Transilience Security", EN_B, 11, HexColor('#AAB4C0'))
    dm(c, W-200, H-55, cfg_byline(), EN, 7, HexColor('#AAB4C0'))

    # ---- 3 phase swim lanes (horizontal timeline) ----
    PHASE_Y = H - 100
    PHASE_H = 30
    phase_colors = [
        ("契約・準備",    HexColor('#1976D2'), 30,  195),
        ("スキャン実行",  ORANGE,              225, 180),
        ("納品・再試験",  GREEN,               425, 350),
    ]
    for label, color, x, w in phase_colors:
        draw_rounded_rect(c, x, PHASE_Y - PHASE_H, w, PHASE_H, 6, color, None)
        dmc(c, x + w/2, PHASE_Y - 20, label, JP, 11, white)

    # ---- 11 step cards ----
    # (step_no, title, body_lines, color_hint, x, y, w, h, timing)
    STEPS = [
        # Contract / Prep (navy)
        ("1", "相談・見積",  ["初回相談", "対象範囲 ヒアリング", "費用 見積"], NAVY, 30, H-310, 100, 180, "T-21d"),
        ("2", "同意書 署名", ["Letter of", "Authorization", "(甲乙 両者)"],   NAVY, 135, H-310, 90, 180, "T-14d"),
        ("3", "スコープ合意",["対象ドメイン", "除外範囲", "検査深度"],         NAVY, 230, H-310, 95, 180, "T-10d"),
        # Scan (orange)
        ("4", "シナリオ合意",["profile 選定", "scenario 選定", "検査時間窓"], ORANGE, 335, H-310, 100, 180, "T-7d"),
        ("5", "事前通知",    ["SOC/CSIRT に", "発信 IP・UA", "通知配布"],     ORANGE, 440, H-310, 85, 180, "T-7d"),
        ("6", "キックオフ",  ["緊急連絡網 確認", "開始合意", "監視配置"],       ORANGE, 530, H-310, 90, 180, "T-0"),
        ("7", "スキャン実行",["330 phase", "並列実行", "2-6 時間"],            ORANGE, 625, H-310, 95, 180, "T-0〜T+1"),
        # Delivery (green)
        ("8", "CRITICAL\npre-notice", ["24h 以内", "緊急通知書", "送付"],        RED, 725, H-310, 90, 180, "T+1d"),
        ("9", "ドラフト",    ["validator 済", "report 送付", "顧客 review"],   GREEN, 820, H-310, 90, 180, "T+5d"),
        ("10","納品",         ["PDF/MD/SARIF", "証拠一式", "レビュー会"],        GREEN, 915, H-310, 90, 180, "T+10d"),
        ("11","再試験 (任意)",["対策完了後", "脆弱 phase 再実行", "diff report"], GREEN, 1010, H-310, 95, 180, "T+30-90d"),
    ]

    # Draw connecting line
    c.setStrokeColor(GRAY); c.setLineWidth(1); c.setDash(2, 3)
    c.line(80, H-220, 1055, H-220)
    c.setDash()

    for num, title, body, color, x, y, w, h, timing in STEPS:
        # Card
        draw_rounded_rect(c, x, y, w, h, 8, CARD_BG, BORDER)
        # Number badge
        c.setFillColor(color); c.circle(x+16, y+h-16, 12, fill=1, stroke=0)
        dmc(c, x+16, y+h-20, num, EN_B, 10, white)
        # Title
        dm(c, x+8, y+h-45, title, JP, 9, color)
        if "\n" in title:
            parts = title.split("\n")
            dm(c, x+8, y+h-45, parts[0], JP, 9, color)
            dm(c, x+8, y+h-58, parts[1], JP, 9, color)
        # Body
        line_y = y + h - 80 if "\n" not in title else y + h - 72
        for line in body:
            dm(c, x+8, line_y, "・" + line, JP, 7.5, black)
            line_y -= 13
        # Timing badge at bottom
        draw_rounded_rect(c, x+8, y+10, w-16, 20, 3, HexColor('#F0F4F8'), None)
        dmc(c, x+w/2, y+16, timing, EN, 7.5, GRAY)

    # ---- Key callouts (bottom section) ----
    CY = H - 540
    draw_rounded_rect(c, 30, CY - 60, W-60, 75, 8, HexColor('#FFF3E0'), None)
    c.setFillColor(ORANGE); c.rect(30, CY-60, 6, 75, fill=1, stroke=0)
    dm(c, 50, CY - 10, "重要ポイント", JP, 11, ORANGE)
    bullets = [
        "・契約前 (ステップ 1-3) で全てが決まる — スコープ外へのアクセスは厳格禁止",
        "・CRITICAL 発見時は正式レポートを待たず 24h 以内に緊急通知 (ステップ 8)",
        "・非破壊テスト保証 — システムを壊す操作はコードレベルで実行不可",
        "・再試験 (ステップ 11) は対策効果を同じ検査で確認、追加費用なし",
    ]
    bx = 50; by = CY - 28
    for b in bullets[:2]:
        dm(c, bx, by, b, JP_MIN, 8.5, black); by -= 14
    bx = W/2 + 10; by = CY - 28
    for b in bullets[2:]:
        dm(c, bx, by, b, JP_MIN, 8.5, black); by -= 14

    # ---- Legal / sample link row ----
    LY = CY - 80
    draw_rounded_rect(c, 30, LY - 48, W-60, 45, 6, HexColor('#F0F4F8'), None)
    dm(c, 50, LY - 20, "添付テンプレ (法務レビュー要)", JP, 10, NAVY)
    dm(c, 50, LY - 38, "・01 同意書 (Letter of Authorization)   ・02 スコープ定義書   ・03 シナリオ計画書   — docs/engagement-templates/",
         JP_MIN, 8, black)

    # Footer
    dmc(c, W/2, 22, "© 2026 Transilience Security — 本フローは標準例、個別契約で調整可", JP_MIN, 7.5, GRAY)

    c.save()
    print(f"[OK] {OUT}  ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
