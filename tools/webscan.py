#!/usr/bin/env python3
"""
webscan.py — 統一 Web 受動スキャナ (non-destructive recon)

目的: エンゲージメント毎に場当たりで recon すると出力がバラつき、成果物の品質が不安定になる。
      このスクリプトを唯一のスキャン入口に統一し、常に同じ順序・同じ構造で結果を出す。

使い方:
    python3 tools/webscan.py <domain> [--outdir DIR] [--no-cve] [--no-nmap]

出力 (必ず同じレイアウト):
    <outdir>/recon/webscan.json   — 機械可読な全結果
    <outdir>/recon/MASTER.md      — 人間可読サマリ (レポート付録Dと同じ構成)
    <outdir>/recon/raw/*.txt      — 各ステップの生出力

方針:
  - 完全非破壊: GET / dig / whois / openssl / nmap -sV のみ。POST は xmlrpc 活性確認(本文送らず)に限定。
  - ブルートフォース・エクスプロイト・ペイロード送信は一切しない。
  - CVE は NVD + wp.org で「導入版が影響範囲に入るか」を版比較で判定 (keyword ノイズを機械で除外)。
"""
import sys, os, re, json, ssl, time, socket, subprocess, argparse, urllib.request, urllib.parse
from datetime import datetime, timezone

CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
UA = 'webscan/1.0 (authorized-pentest)'
TIMEOUT = 15

# ---- helpers ---------------------------------------------------------------
def sh(cmd, t=60):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t).stdout.strip()
    except Exception as e:
        return f'ERR {type(e).__name__}: {e}'

def http(url, method='GET', host=None):
    """Return (status, headers_lower_dict, body_text). Never raises."""
    try:
        req = urllib.request.Request(url, method=method, headers={'User-Agent': UA})
        if host: req.add_header('Host', host)
        r = urllib.request.urlopen(req, context=CTX, timeout=TIMEOUT)
        body = r.read(2000000).decode('utf-8', 'replace')
        return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ''
    except Exception as e:
        return None, {}, f'ERR {type(e).__name__}: {e}'

def code(url, method='GET'):
    s, _, _ = http(url, method); return s

def vt(s):
    out = []
    for p in str(s).split('.'):
        n = ''.join(c for c in p if c.isdigit()); out.append(int(n) if n else 0)
    return tuple(out)

def nvd(cve=None, keyword=None):
    base = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
    q = {'cveId': cve} if cve else {'keywordSearch': keyword, 'resultsPerPage': 20}
    try:
        return json.load(urllib.request.urlopen(urllib.request.Request(base + urllib.parse.urlencode(q),
                         headers={'User-Agent': UA}), context=CTX, timeout=40))
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}

def wporg_latest(slug):
    try:
        j = json.load(urllib.request.urlopen(f'https://api.wordpress.org/plugins/info/1.0/{slug}.json',
                      context=CTX, timeout=TIMEOUT))
        return j.get('version'), (j.get('last_updated') or '')[:10]
    except Exception:
        return None, None

# ---- scan steps ------------------------------------------------------------
def scan_dns(d, R):
    o = {}
    o['A'] = sh(f'dig +short {d} A').splitlines()
    o['NS'] = sh(f'dig +short {d} NS').splitlines()
    o['MX'] = sh(f'dig +short {d} MX').splitlines()
    o['TXT'] = sh(f'dig +short {d} TXT').splitlines()
    o['DMARC'] = sh(f'dig +short _dmarc.{d} TXT').splitlines()
    o['CAA'] = sh(f'dig +short {d} CAA').splitlines()
    o['DS_DNSSEC'] = sh(f'dig +short {d} DS').splitlines()
    ip = o['A'][0] if o['A'] else None
    o['reverse'] = sh(f'dig +short -x {ip}') if ip else ''
    rnd = f'zzq{int(time.time())}random.{d}'
    o['wildcard'] = (sh(f'dig +short {rnd} A') == ip and bool(ip))
    o['whois'] = sh(f'whois {d} | grep -iE "Registrant|Registrar|Created|Expir|Organization|Status|Name Server" | head -20')
    R['dns'] = o
    return ip

def scan_http(d, R):
    s, h, body = http(f'https://{d}/')
    sec = ['strict-transport-security','content-security-policy','x-frame-options',
           'x-content-type-options','referrer-policy','permissions-policy','x-xss-protection']
    R['http'] = {
        'status': s, 'server': h.get('server'), 'x_powered_by': h.get('x-powered-by'),
        'security_headers': {k: (k in h) for k in sec},
        'missing_security_headers': [k for k in sec if k not in h],
        'set_cookie': h.get('set-cookie'),
        'tls': sh(f'echo | openssl s_client -connect {d}:443 -servername {d} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null'),
        'robots': http(f'https://{d}/robots.txt')[2][:500],
        'security_txt': code(f'https://{d}/.well-known/security.txt'),
        'ga4': sorted(set(re.findall(r'G-[A-Z0-9]{8,}', body))),
    }
    return body

def scan_ports(d, R, do_nmap=True):
    if not do_nmap:
        R['ports'] = {'skipped': True}; return
    top = sh(f'nmap -Pn -T4 --top-ports 100 {d} 2>/dev/null | grep open', t=120)
    svc = sh(f'nmap -Pn -sV --version-light -p 21,25,110,143,465,587,993,995 {d} 2>/dev/null | grep -E "^[0-9]+/tcp|Service Info"', t=180)
    R['ports'] = {'top100_open': top.splitlines(), 'service_versions': svc.splitlines()}

def scan_wordpress(d, R, body):
    wp = {'is_wordpress': 'wp-content' in body or 'wp-json' in body}
    if not wp['is_wordpress']:
        R['wordpress'] = wp; return wp
    gen = http(f'https://{d}/feed/')[2]
    m = re.search(r'wordpress\.org/\?v=([0-9.]+)', gen)
    wp['core_version'] = m.group(1) if m else None
    # REST user enum
    us = http(f'https://{d}/wp-json/wp/v2/users?per_page=100&_fields=id,slug,name')[2]
    try:
        wp['users'] = [{'id': u['id'], 'slug': u['slug'], 'name': u['name']} for u in json.loads(us)]
    except Exception:
        wp['users'] = []
    wp['xmlrpc_enabled'] = (code(f'https://{d}/xmlrpc.php', 'POST') == 200)
    # wp-json site info + namespaces (reveals hidden plugins)
    root = http(f'https://{d}/wp-json/?_fields=name,description,timezone_string,namespaces')[2]
    try:
        rj = json.loads(root)
        wp['site_name'] = rj.get('name'); wp['site_desc'] = rj.get('description')
        wp['timezone'] = rj.get('timezone_string'); wp['namespaces'] = rj.get('namespaces', [])
    except Exception:
        wp['namespaces'] = []
    # plugin slugs: frontend assets + REST namespaces + common-hidden list
    slugs = set(re.findall(r'wp-content/plugins/([a-z0-9-]+)/', body))
    ns_map = {'contact-form-7':'contact-form-7','metaslider':'ml-slider','backwpup':'backwpup',
              'ai1wm':'all-in-one-wp-migration','cptui':'custom-post-type-ui','duplicate-post':'duplicate-post',
              'wp-rollback':'wp-rollback','simple-page-ordering':'simple-page-ordering','akismet':'akismet',
              'categoryPosts':'category-posts','cocoon':None}
    for ns in wp.get('namespaces', []):
        base = ns.split('/')[0]
        if base in ns_map and ns_map[base]: slugs.add(ns_map[base])
    for common in ['really-simple-ssl','siteguard','ewww-image-optimizer','wp-multibyte-patch',
                   'wordpress-seo','google-site-kit','simple-tags','pdf-embedder','flexible-faq',
                   'contact-form-7-datepicker','cf7-conditional-fields','whats-new-genarator',
                   'wp-content-copy-protector']:
        if code(f'https://{d}/wp-content/plugins/{common}/readme.txt') == 200:
            slugs.add(common)
    # per-plugin installed version (readme Stable tag) + latest + status
    plugins = []
    for slug in sorted(slugs):
        txt = http(f'https://{d}/wp-content/plugins/{slug}/readme.txt')[2]
        mv = re.search(r'(?im)^stable tag:\s*([0-9.]+)', txt)
        inst = mv.group(1) if mv else '?'
        latest, upd = wporg_latest(slug)
        if inst != '?' and latest:
            status = 'OUTDATED' if vt(inst) < vt(latest) else 'current'
        elif inst != '?' and not latest:
            status = 'off-repo'   # installed but not in wp.org (closed/removed) -> no auto-update
        else:
            status = '?'
        plugins.append({'slug': slug, 'installed': inst, 'latest': latest, 'updated': upd, 'status': status})
    wp['plugins'] = plugins
    # theme
    wp['themes'] = sorted(set(re.findall(r'wp-content/themes/([a-z0-9_-]+)/', body)))
    R['wordpress'] = wp
    return wp

def scan_exposure(d, R):
    paths = ['readme.html','license.txt','wp-links-opml.php','error_log','access_log','debug.log',
             'wp-content/debug.log','wp-content/uploads/','wp-content/ai1wm-backups/','.env','.git/config',
             'wp-config.php.bak','backup.zip','server-status','nginx_status','wp-config.php',
             '.htaccess','wp-admin/install.php','wp-json/wp/v2/plugins','wp-json/wp/v2/settings']
    res = {}
    for p in paths:
        res[p] = code(f'https://{d}/{p}')
    # flag only genuinely exposed (200 with real content, excluding guarded/empty)
    exposed = []
    for p, cd in res.items():
        if cd == 200 and p not in ('wp-config.php','wp-content/ai1wm-backups/','wp-admin/install.php',
                                    'readme.html','license.txt','wp-links-opml.php'):
            exposed.append(p)
    R['exposure'] = {'probes': res, 'genuinely_exposed': exposed}

PLUGIN_NAMES = {'cf7-conditional-fields':'Conditional Fields for Contact Form 7',
    'contact-form-7-datepicker':'Contact Form 7 Datepicker','whats-new-genarator':"What's New Generator",
    'flexible-faq':'Flexible FAQ','contact-form-7':'Contact Form 7','ml-slider':'MetaSlider',
    'pdf-embedder':'PDF Embedder','custom-post-type-ui':'Custom Post Type UI','duplicate-post':'Duplicate Post',
    'simple-tags':'Simple Tags','category-posts':'Category Posts','really-simple-ssl':'Really Simple Security',
    'wp-content-copy-protector':'WP Content Copy Protection','siteguard':'SiteGuard','backwpup':'BackWPup',
    'all-in-one-wp-migration':'All-in-One WP Migration','ewww-image-optimizer':'EWWW Image Optimizer'}

def _toks(x):
    return set(t for t in re.split(r'[^a-z0-9]+', x.lower()) if len(t) > 2)

def _bound_ok_vs_latest(bound, latest):
    """Reject a CVE whose fix/upper-bound version is NEWER than the plugin's known latest:
    you cannot patch a flaw in a version that does not exist, so it belongs to a different
    same-named plugin (e.g. Simple Tags 4.0.0 vs a CVE fixed in 6.8.0)."""
    if not latest or not bound: return True
    m = re.search(r'([0-9]+\.[0-9][0-9.]*)', bound)
    if not m: return True
    return vt(m.group(1)) <= vt(latest)

def _ver_in_cpe(installed, m):
    iv = vt(installed); ok = True; bound = None
    if m.get('versionEndIncluding'):   bound = '<='+m['versionEndIncluding']; ok &= iv <= vt(m['versionEndIncluding'])
    if m.get('versionEndExcluding'):   bound = '<'+m['versionEndExcluding'];   ok &= iv <  vt(m['versionEndExcluding'])
    if m.get('versionStartIncluding'): ok &= iv >= vt(m['versionStartIncluding'])
    if m.get('versionStartExcluding'): ok &= iv >  vt(m['versionStartExcluding'])
    if bound is None:
        parts = m.get('criteria','').split(':'); cver = parts[5] if len(parts) > 5 else '*'
        if cver not in ('*','-'): bound = '=='+cver; ok &= (vt(installed) == vt(cver))
        else: ok = False
    return ok, bound

def _cve_applies(cve, slug, installed, latest=None):
    """CPE product must match the plugin (kills cross-product FPs e.g. a Chrome CVE matching 'PDF').
    When a CVE has NO CPE (common for Patchstack-sourced plugin CVEs), require the plugin's exact
    name in the description + a version bound."""
    desc = next((x['value'] for x in cve.get('descriptions', []) if x['lang']=='en'), '')
    name = PLUGIN_NAMES.get(slug, slug.replace('-',' ')); ptoks = _toks(slug) | _toks(name)
    cpes = [m for cfg in cve.get('configurations', []) for n in cfg.get('nodes', []) for m in n.get('cpeMatch', [])]
    if cpes:
        for m in cpes:
            parts = m.get('criteria','').split(':'); product = parts[4] if len(parts) > 4 else ''
            if _toks(product) & ptoks:
                ok, bound = _ver_in_cpe(installed, m)
                if ok and _bound_ok_vs_latest(bound, latest): return bound or 'cpe-match'
        return None
    if name.lower() not in desc.lower():
        return None
    for x in re.findall(r'(?:through|before|up to and including|up to|<=|\u2264)\s*(?:and including\s*)?(?:version\s*)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)', desc, re.I):
        before = re.search(r'before\s+(?:version\s*)?v?' + re.escape(x), desc, re.I)
        if (vt(installed) < vt(x)) if before else (vt(installed) <= vt(x)):
            b=('<' if before else '<=')+x
            if _bound_ok_vs_latest(b, latest): return b
    return None

def scan_cve(R, do_cve=True):
    """CPE/name-verified version-range CVE match for ALL plugins. Unverified keyword hits are dropped."""
    if not do_cve or 'wordpress' not in R:
        R['cve'] = {'skipped': True}; return
    targets = [p for p in R['wordpress'].get('plugins', []) if p['installed'] not in ('?', None)]
    out = []
    for p in targets:
        kw = PLUGIN_NAMES.get(p['slug'], p['slug'].replace('-', ' '))
        d = nvd(keyword=kw); hits = []
        for v in d.get('vulnerabilities', []):
            cve = v['cve']; bound = _cve_applies(cve, p['slug'], p['installed'], p.get('latest'))
            if not bound: continue
            mt = cve.get('metrics', {}); sc = sev = '?'
            for k in ('cvssMetricV31','cvssMetricV40','cvssMetricV30','cvssMetricV2'):
                if mt.get(k):
                    cd = mt[k][0]['cvssData']; sc = cd.get('baseScore'); sev = cd.get('baseSeverity', mt[k][0].get('baseSeverity','?')); break
            desc = next((x['value'] for x in cve.get('descriptions', []) if x['lang']=='en'), '')
            hits.append({'cve': cve['id'], 'cvss': sc, 'severity': sev, 'bound': bound, 'desc': desc[:160]})
        out.append({'slug': p['slug'], 'installed': p['installed'], 'applicable_cves': hits})
        time.sleep(7)
    R['cve'] = {'results': out, 'note': 'CPE/name-verified; unverified keyword hits dropped'}

# ---- reporting -------------------------------------------------------------
def write_master(d, R, path):
    wp = R.get('wordpress', {})
    L = [f'# {d} — webscan 統一スキャン結果 ({R["meta"]["timestamp"]})\n']
    L.append('## サーバー構成')
    L.append(f'- IP: {", ".join(R["dns"].get("A",[])) or "?"}  (reverse: {R["dns"].get("reverse","")})')
    L.append(f'- Web: {R["http"].get("server")}  / X-Powered-By: {R["http"].get("x_powered_by")}')
    if wp.get('core_version'): L.append(f'- WordPress: {wp["core_version"]}  / themes: {", ".join(wp.get("themes",[]))}')
    L.append(f'- 欠落セキュリティヘッダ: {", ".join(R["http"].get("missing_security_headers",[])) or "なし"}')
    L.append(f'- DMARC: {"あり" if R["dns"].get("DMARC") else "**無し**"}  / wildcard DNS: {"**有**" if R["dns"].get("wildcard") else "無"}')
    L.append(f'- GA4: {", ".join(R["http"].get("ga4",[])) or "-"}')
    L.append('\n## ポート')
    for ln in R.get('ports', {}).get('top100_open', []): L.append(f'- {ln}')
    if wp.get('users'):
        L.append('\n## ユーザー列挙 (REST)')
        for u in wp['users']: L.append(f'- id{u["id"]} {u["slug"]} | {u["name"]}')
    if wp.get('plugins'):
        L.append(f'\n## プラグイン ({len(wp["plugins"])}件)')
        L.append('| slug | 導入 | 最新 | 状態 |'); L.append('|---|---|---|---|')
        for p in wp['plugins']:
            L.append(f'| {p["slug"]} | {p["installed"]} | {p.get("latest") or "—"} | {p["status"]} |')
    cve = R.get('cve', {}).get('results', [])
    if cve:
        L.append('\n## 該当CVE (版範囲照合済)')
        for r in cve:
            for h in r['applicable_cves']:
                L.append(f'- {r["slug"]} {r["installed"]} → {h["cve"]} CVSS {h["cvss"]} {h["severity"]}')
    L.append('\n## 外部露出チェック')
    exp = R.get('exposure', {}).get('genuinely_exposed', [])
    L.append(f'- 実露出: {", ".join(exp) if exp else "**検出なし**"}')
    open(path, 'w').write('\n'.join(L) + '\n')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('domain')
    ap.add_argument('--outdir', default=None)
    ap.add_argument('--no-cve', action='store_true')
    ap.add_argument('--no-nmap', action='store_true')
    a = ap.parse_args()
    d = a.domain.replace('https://', '').replace('http://', '').strip('/')
    outdir = a.outdir or f'{datetime.now():%y%m%d_%H%M%S}_{d.replace(".","-")}_scan'
    recon = os.path.join(outdir, 'recon'); os.makedirs(os.path.join(recon, 'raw'), exist_ok=True)
    R = {'meta': {'target': d, 'timestamp': datetime.now(timezone.utc).isoformat(), 'tool': 'webscan.py/1.0'}}
    print(f'[*] webscan {d} -> {outdir}')
    print('[1/6] DNS/WHOIS');      scan_dns(d, R)
    print('[2/6] HTTP/TLS');       body = scan_http(d, R)
    print('[3/6] ports/services'); scan_ports(d, R, do_nmap=not a.no_nmap)
    print('[4/6] WordPress');      scan_wordpress(d, R, body)
    print('[5/6] exposure');       scan_exposure(d, R)
    print('[6/6] CVE sweep');      scan_cve(R, do_cve=not a.no_cve)
    json.dump(R, open(os.path.join(recon, 'webscan.json'), 'w'), ensure_ascii=False, indent=1)
    write_master(d, R, os.path.join(recon, 'MASTER.md'))
    print(f'[+] done: {recon}/webscan.json + MASTER.md')

if __name__ == '__main__':
    main()
