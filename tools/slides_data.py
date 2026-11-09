#!/usr/bin/env python3
"""slides_data.py — map a completed engagement dir to a SlideGen `Report`.

Separated from gen_slides.py so the data derivation is testable on its own and
the render orchestration stays thin. Mirrors the fields the Transilience PDF
report consumes (findings/, artifacts/validated/*.json, recon/inventory.json,
recon/p9_wp_plugins.json, recon/mail.json, recon/headers.json, …) and maps them
onto SlideGen's `Report` interface (src/report.ts).

Every reader degrades gracefully: a missing file yields a sensible default so a
partial engagement still produces a deck.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Severity -> risk-score weight (points toward the 0-100 cover score).
SEV_WEIGHT = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 12, "LOW": 6, "INFO": 0}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Plugins with a validated CVE finding get flagged in the plugin table.
# key = plugin slug substring, value = note.


# ───────────────────────── json helpers ─────────────────────────
def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _registrable(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _fmt_date(iso: str) -> str:
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", iso or "")
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return f"{y}年{mo}月{d}日"
    return iso or ""


# ───────────────────────── findings ─────────────────────────
def _validated_findings(eng: Path) -> list[dict]:
    """Return validated findings as [{id, severity, title}] sorted by severity."""
    vdir = eng / "artifacts" / "validated"
    out: list[dict] = []
    if vdir.is_dir():
        for f in sorted(vdir.glob("*.json")):
            d = _load(f, {})
            if not d:
                continue
            out.append({
                "id": d.get("id", f.stem),
                "severity": (d.get("severity") or "INFO").upper(),
                "title": d.get("title", f.stem),
                "cve": d.get("cve", ""),
            })
    if not out:
        # fall back to findings.md table if validated/ is absent
        md = eng / "reports" / "findings.md"
        for row in re.finditer(r"\|\s*(F-\d+)\s*\|\s*(\w+)\s*\|\s*(.+?)\s*\|", md.read_text(encoding="utf-8")
                               if md.exists() else ""):
            out.append({"id": row.group(1), "severity": row.group(2).upper(),
                        "title": row.group(3), "cve": ""})
    out.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["id"]))
    return out


# ───────────────────────── derivations ─────────────────────────
def score_now(report: dict) -> int:
    return sum(f["now"] for f in report["findings"])


def score_worst(report: dict) -> int:
    return sum(f["worst"] for f in report["findings"])


def _rank(score: int) -> str:
    # Higher score == more urgent. A is worst. Tuned so sample (35->C, 85->A) holds.
    if score >= 70:
        return "A"
    if score >= 50:
        return "B"
    if score >= 30:
        return "C"
    if score >= 15:
        return "D"
    return "E"


def _short_title(t: str) -> str:
    """Compact a finding title for the score table's 'state' column."""
    m = re.search(r"wp-plugin:([\w-]+)", t)
    if m:
        return f"プラグイン {m.group(1)}"
    t = re.sub(r"\s*\(.*?\)\s*", "", t)       # drop parentheticals
    t = re.sub(r"\s*[—–-]\s*CVE-.*$", "", t)   # drop CVE tail
    if len(t) > 26:
        t = re.split(r"[:：]", t)[0]
    return t.strip()[:26]


def build_report(eng: Path):
    """Return (report_dict, slug, meta). meta carries plugin data for the extra slide."""
    inv = _load(eng / "recon" / "inventory.json", {})
    mail = _load(eng / "recon" / "mail.json", {})
    headers = _load(eng / "recon" / "headers.json", {})
    dns = _load(eng / "recon" / "dns.json", {})
    infra = _load(eng / "recon" / "infra.json", {})
    tech = _load(eng / "recon" / "technologies.json", {})
    wp = _load(eng / "recon" / "wordpress.json", {})
    plugins = (_load(eng / "recon" / "p9_wp_plugins.json", {}) or {}).get("plugins") \
        or (wp or {}).get("plugins") or {}

    target = inv.get("target") or _infer_target(eng)
    domain = target
    reg = _registrable(target)
    date = _fmt_date(inv.get("generated", ""))
    platform = "WordPress" if (wp.get("plugins") or "wordpress" in str(tech).lower()) else "Webサイト基盤"

    findings = _validated_findings(eng)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    n_crit, n_high = by_sev.get("CRITICAL", 0), by_sev.get("HIGH", 0)
    n_med, n_low = by_sev.get("MEDIUM", 0), by_sev.get("LOW", 0)

    # ── score-table rows: curated confirmed findings + one 要確認 aggregate ──
    rows: list[dict] = []
    confirmed = [f for f in findings if f["severity"] in ("HIGH", "MEDIUM", "LOW")][:4]
    for f in confirmed:
        w = SEV_WEIGHT.get(f["severity"], 0)
        rows.append({
            "state": _short_title(f["title"]),
            "status": "確認済み", "now": w, "worst": w,
            "why": f"{f['severity']} 相当。" + ("CVE 該当。優先対応。" if f["cve"] else "外部から観測可能。"),
        })
    # cap confirmed score at 100
    acc = 0
    for r in rows:
        if acc + r["now"] > 100:
            r["now"] = r["worst"] = max(0, 100 - acc)
        acc += r["now"]

    cand = n_crit + n_high
    worst_add = 50 if cand else (20 if n_med else 8 if n_low else 0)
    rows.append({
        "state": f"重大候補{cand}件" if cand else "未確認領域",
        "status": "要確認", "now": 0, "worst": min(worst_add, max(0, 100 - acc)),
        "why": (f"CRITICAL {n_crit}件、HIGH {n_high}件。\n確認されれば最優先Aへ上がる"
                if cand else "簡易診断で断定できない領域。\n深掘りで区分が変わり得る"),
    })

    report = {
        "client": {"name": f"{reg} ご担当者様", "domain": domain, "date": date or "—"},
        "platform": platform,
        "candidates": {"total": cand, "critical": n_crit, "high": n_high},
        "rank": {},  # filled below
        "confirmed": _confirmed_sentence(headers, mail, dns),
        "findings": rows,
        "risks": _risks(headers, mail, dns, infra, plugins),
        "diagram": _diagram(platform, infra, dns, plugins, tech),
        "signals": _signals(headers, mail, n_crit, n_high),
    }
    report["rank"] = {"now": _rank(score_now(report)), "worst": _rank(score_worst(report))}

    slug = re.sub(r"[^a-z0-9]+", "-", eng.name.lower()).strip("-") or "engagement"
    meta = {"plugins": plugins, "plugin_cves": _plugin_cves(findings)}
    return report, slug, meta


def _infer_target(eng: Path) -> str:
    httpx = _load(eng / "recon" / "httpx.json", {})
    if isinstance(httpx, dict) and httpx.get("host"):
        return httpx["host"]
    m = re.search(r"\d{6}_\d{6}_(.+?)(?:_auto|_rebuild)?$", eng.name)
    return (m.group(1).replace("-", ".") if m else eng.name)


def _plugin_cves(findings: list[dict]) -> dict[str, str]:
    """Map plugin slug -> CVE id from findings whose title names a plugin."""
    out: dict[str, str] = {}
    for f in findings:
        m = re.search(r"wp-plugin:([\w-]+)\s+[\d.]+\s*[—–-]\s*(CVE-\d{4}-\d+)", f["title"])
        if m:
            out[m.group(1)] = m.group(2)
    return out


# ── sentence / list builders (all defensive) ──
def _missing_on_root(headers: dict, name: str) -> bool:
    root = headers.get("/", {}).get("headers", {}) if isinstance(headers, dict) else {}
    h = root.get(name)
    return bool(h) and not h.get("present", False)


def _confirmed_sentence(headers: dict, mail: dict, dns: dict) -> str:
    parts = []
    if _missing_on_root(headers, "strict-transport-security") or _missing_on_root(headers, "content-security-policy"):
        parts.append("主要なセキュリティヘッダの欠落")
    if mail.get("spoofable") or (mail.get("dmarc_policy") in (None, "none", "")):
        parts.append("なりすましメール対策の不足（DMARC未適用）")
    if dns and not dns.get("dnssec_enabled", True):
        parts.append("DNSハードニング（DNSSEC/CAA等）の欠落")
    if not parts:
        parts = ["外部から観測できる構成上の弱点"]
    return "、".join(parts[:2]) + "を"


def _risks(headers: dict, mail: dict, dns: dict, infra: dict, plugins: dict) -> list[str]:
    r: list[str] = []
    cdn = (infra or {}).get("cdn", {})
    cdnvals = cdn.get("cdncheck", {}) if isinstance(cdn, dict) else {}
    if not cdnvals or all(v in ("unclassified", None, "") for v in cdnvals.values()):
        r.append("CDN なし")
    if _missing_on_root(headers, "strict-transport-security"):
        r.append("HSTS 未設定")
    if _missing_on_root(headers, "content-security-policy"):
        r.append("CSP 未設定")
    if mail.get("dmarc_policy") in (None, "none", "") or mail.get("spoofable"):
        r.append("DMARC 不備")
    if dns and not dns.get("dnssec_enabled", True):
        r.append("DNSSEC なし")
    if dns is not None and not dns.get("caa"):
        r.append("CAA なし")
    if plugins and len(plugins) >= 8:
        r.append("旧仕様の追加プラグイン多数")
    return r[:6] or ["外部観測で検出された構成リスク"]


def _diagram(platform: str, infra: dict, dns: dict, plugins: dict, tech: dict | None = None) -> dict:
    host = ""
    ptr = (dns or {}).get("ptr") or {}
    if isinstance(ptr, dict):
        for v in ptr.values():
            if v:
                host = (v[0] if isinstance(v, list) else str(v)).rstrip(".")
                break
    env = ((tech or {}).get("env", {}) or {}) or ((infra or {}).get("env", {}) or {})
    server = (env.get("server") or "").strip() or "リバースプロキシ"
    host_label = f"ホスティング基盤\n{host}" if host else "ホスティング基盤"
    plugin_label = f"{platform}拡張プラグイン群\n（{len(plugins)}個を検出）" if plugins else f"{platform}拡張プラグイン群"
    return {
        "boxes": [
            {"id": "user", "text": "エンドユーザ /\nブラウザ", "col": 0, "row": 0},
            {"id": "dns", "text": "公開DNS /\nDMARC未適用", "col": 1, "row": 0},
            {"id": "proxy", "text": f"{server} /\nリバースプロキシ・TLS", "col": 2, "row": 0, "size": 21},
            {"id": "plugins", "text": plugin_label, "col": 4, "row": 0.55},
            {"id": "cms", "text": f"{platform} コア /\nテーマ＋追加プラグイン", "col": 3, "row": 1, "h": 140, "size": 21},
            {"id": "db", "text": "データベース\nコンテンツ・\nユーザー・設定情報", "col": 4, "row": 1.35, "h": 130, "size": 21},
            {"id": "host", "text": host_label, "col": 2, "row": 2, "size": 20},
        ],
        "edges": [
            {"from": "user", "to": "dns", "label": "名前解決"},
            {"from": "dns", "to": "proxy", "label": "HTTPS"},
            {"from": "host", "to": "cms", "label": "PHP 実行"},
            {"from": "cms", "to": "plugins", "dashed": True, "plain": True},
            {"from": "cms", "to": "db", "label": "SQL"},
        ],
    }


def _signals(headers: dict, mail: dict, n_crit: int, n_high: int) -> list[dict]:
    sig = []
    sig.append({"title": "「セキュリティヘッダの欠落」",
                "body": "「HSTS・CSP 等、ブラウザ側の防御を有効化するヘッダが公開ページに付与されていない」"})
    sig.append({"title": "「なりすましメール対策」",
                "body": "「DMARC が p=none で、受信側がなりすましメールを拒否できない状態」"})
    sig.append({"title": "「最重要区分の候補」",
                "body": f"「CRITICAL候補{n_crit}件。実際に悪用可能かは要確認」"})
    sig.append({"title": "「高い危険区分の候補」",
                "body": f"「HIGH候補{n_high}件。実際に悪用可能かは要確認」"})
    return sig


# ───────────────────────── TS emitters ─────────────────────────
def _ts_str(s: str) -> str:
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def report_to_ts(report: dict) -> str:
    """Serialize the Report dict into a typed TS module (matches src/report.ts)."""
    def arr_findings(fs):
        return ",\n".join(
            "    { state: %s, status: %s, now: %d, worst: %d, why: %s }"
            % (_ts_str(f["state"]), _ts_str(f["status"]), f["now"], f["worst"], _ts_str(f["why"]))
            for f in fs)

    def arr_boxes(bs):
        out = []
        for b in bs:
            extra = "".join(f", {k}: {b[k]}" for k in ("h", "size") if k in b)
            out.append("      { id: %s, text: %s, col: %s, row: %s%s }"
                       % (_ts_str(b["id"]), _ts_str(b["text"]), b["col"], b["row"], extra))
        return ",\n".join(out)

    def arr_edges(es):
        out = []
        for e in es:
            extra = ""
            if "label" in e:
                extra += f", label: {_ts_str(e['label'])}"
            if e.get("dashed"):
                extra += ", dashed: true"
            if e.get("plain"):
                extra += ", plain: true"
            out.append("      { from: %s, to: %s%s }" % (_ts_str(e["from"]), _ts_str(e["to"]), extra))
        return ",\n".join(out)

    def arr_signals(ss):
        return ",\n".join("    { title: %s, body: %s }" % (_ts_str(s["title"]), _ts_str(s["body"]))
                          for s in ss)

    c = report["client"]
    cand = report["candidates"]
    rank = report["rank"]
    return f"""// AUTO-GENERATED by tools/gen_slides.py — do not edit by hand.
import type {{ Report }} from '../report'

export const report: Report = {{
  client: {{ name: {_ts_str(c['name'])}, domain: {_ts_str(c['domain'])}, date: {_ts_str(c['date'])} }},
  platform: {_ts_str(report['platform'])},
  candidates: {{ total: {cand['total']}, critical: {cand['critical']}, high: {cand['high']} }},
  rank: {{ now: {_ts_str(rank['now'])}, worst: {_ts_str(rank['worst'])} }},
  confirmed: {_ts_str(report['confirmed'])},
  findings: [
{arr_findings(report['findings'])},
  ],
  risks: [{', '.join(_ts_str(x) for x in report['risks'])}],
  diagram: {{
    boxes: [
{arr_boxes(report['diagram']['boxes'])},
    ],
    edges: [
{arr_edges(report['diagram']['edges'])},
    ],
  }},
  signals: [
{arr_signals(report['signals'])},
  ],
}}
"""


def plugin_slide_ts(plugins: dict, plugin_cves: dict) -> str | None:
    """Emit a standalone slide (src/slides/plugins.local.ts) with a 2-column
    plugin/version table, built from primitive nodes (same kit s5 uses)."""
    if not plugins:
        return None
    items = sorted(plugins.items())
    n = len(items)
    half = (n + 1) // 2
    cols = [items[:half], items[half:]]

    # layout geometry (2048x1152 canvas)
    top = 286           # table card top
    bottom = 1052       # table card bottom
    head_h = 56         # column-header strip
    rows = half
    row_h = (bottom - top - head_h) / max(rows, 1)
    col_x = [90, 1064]        # left edge of each column card
    col_w = 894
    nodes: list[str] = []

    def T(x, y, text, size, fill, *, font="F.sans", weight=400, origin=None, originY=None, w=None):
        extra = ""
        if origin:
            extra += f", origin: '{origin}'"
        if originY:
            extra += f", originY: '{originY}'"
        if w:
            extra += f", w: {w}"
        extra += f", weight: {weight}"
        return ("    { kind: 'text', x: %d, y: %d, text: %s, font: %s, size: %d, fill: %s%s }"
                % (x, y, _ts_str(text), font, size, fill, extra))

    # frame + title + rule
    nodes.append("    { kind: 'frame', variant: 'none' }")
    nodes.append("    { kind: 'emblem', shape: 'chart', x: 98, y: 86, size: 150, fill: C.gold, opacity: 0.95 }")
    nodes.append(T(214, 36, "検出された追加プラグインとバージョン", 64, "C.cream", font="F.serif", weight=700))
    nodes.append("    { kind: 'rule', x: 22, y: 152, w: 1966, stroke: C.goldLine, thickness: 2 }")
    nodes.append(T(214, 170, f"公開情報から {n} 個のプラグインを検出。赤字は検証済みの脆弱性が対応するもの。",
                   30, "C.paperWhite", weight=300))

    for ci, column in enumerate(cols):
        x = col_x[ci]
        nodes.append("    { kind: 'card', x: %d, y: %d, w: %d, h: %d, variant: 'notched' }"
                     % (x, top, col_w, bottom - top))
        # header strip
        nodes.append("    { kind: 'box', x: %d, y: %d, w: %d, h: %d, fill: '#15110B' }" % (x, top, col_w, head_h))
        nodes.append(T(x + 40, top + 14, "プラグイン", 28, "C.gold", font="F.serif", weight=700))
        nodes.append(T(x + col_w - 360, top + 14, "検出バージョン", 28, "C.gold", font="F.serif", weight=700))
        nodes.append(T(x + col_w - 150, top + 14, "状態", 28, "C.gold", font="F.serif", weight=700))
        for ri, (name, ver) in enumerate(column):
            ry = top + head_h + row_h * ri + row_h / 2
            cve = plugin_cves.get(name)
            fill = "'#9C2B1E'" if cve else "'#1E1810'"
            nodes.append(T(x + 40, ry, name, 28, fill, originY="center", weight=500))
            nodes.append(T(x + col_w - 360, ry, ver, 30, fill, font="F.mono", originY="center", weight=400))
            nodes.append(T(x + col_w - 150, ry, ("CVE該当" if cve else "—"), 24,
                           fill, originY="center", weight=700 if cve else 400))
            if ri < len(column) - 1:
                nodes.append("    { kind: 'rule', x: %d, y: %d, w: %d, stroke: 'rgba(120,95,60,0.4)' }"
                             % (x + 20, top + head_h + row_h * (ri + 1), col_w - 40))

    nodes.append("    { kind: 'pagenum', id: 'plugins.page', text: '09', total: '/ 09', variant: 'notch', size: 96 }")

    body = ",\n".join(nodes)
    return f"""// AUTO-GENERATED by tools/gen_slides.py — plugin/version table slide.
import {{ C, F }} from '../theme'
import type {{ Slide }} from '../types'

export const pluginsSlide: Slide = {{
  id: 'plugins',
  name: '09 プラグイン一覧',
  nodes: [
{body},
  ],
}}
"""
