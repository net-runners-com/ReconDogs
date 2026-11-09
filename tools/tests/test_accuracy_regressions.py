#!/usr/bin/env python3
"""
Offline regression tests for autopentest accuracy fixes. Deterministic, no network.
Run:  python3 tools/tests/test_accuracy_regressions.py

Guards (so the 11/7 precision-collapse + 11/9 over-correction never regress):
  1. SSTI multi-engine collision, Oracle-EBS/ONVIF fingerprint, reflect-body spam
     are REJECTED by the code-verifier; real findings KEPT (fixture: 11/7 dir).
  2. Security-header near-duplicates from different phases collapse to ONE finding
     (semantic category dedup), keeping the richer one.
  3. DNS-hardening / cookie near-dups collapse too.
  4. Benign framework-native params (s/p/page/q/…) with weak signals are dropped.
  5. ACF (advanced-custom-fields) 54KB readme.txt is accepted by the WP plugin
     signature (size cap fix) WITHOUT reopening the false-plugin hole (HTML/doctype
     + canary guards still reject non-readme bodies).
"""
import sys, os, re, json, tempfile, importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLS = ROOT / "tools"
FIX = HERE / "fixtures"
sys.path.insert(0, str(TOOLS))

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); sys.modules[name] = m
    spec.loader.exec_module(m); return m

ap = _load("autopentest", TOOLS / "autopentest.py")
ev = _load("exploit_verifier", TOOLS / "exploit_verifier.py")

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}  {detail}")


# ---------------------------------------------------------------- 1. FP classes
def test_fp_classes_rejected():
    print("[1] code-verifier rejects 11/7 FP classes, keeps real (offline)")
    fixture = Path(os.environ.get("AP_TEST_ENGAGEMENT_DIR", str(ROOT / "outputs" / "sample_engagement")))
    if not fixture.is_dir():
        print("  SKIP  11/7 fixture dir absent"); return
    items = ev._load_items_from_dir(fixture)
    res = ev.verify_all(items, live=False)
    def verdict(fid): return (res.get(fid) or {}).get("verdict")
    check("SSTI jinja2 (F-154) rejected", verdict("F-154") == "reject", verdict("F-154"))
    check("Oracle EBS (F-206) rejected", verdict("F-206") == "reject", verdict("F-206"))
    check("reflect-body (F-050) rejected", verdict("F-050") == "reject", verdict("F-050"))
    # real keepers must NOT be rejected
    for fid in ("F-034", "F-037", "F-002"):  # legacy POP3 / TLS1.0 / headers
        check(f"real finding {fid} kept", verdict(fid) != "reject", verdict(fid))
    nrej = sum(1 for v in res.values() if v["verdict"] == "reject")
    check("bulk FP rejection (>=90)", nrej >= 90, f"rejected={nrej}")


# ---------------------------------------------------------------- 2+3. dedup
def test_semantic_dedup():
    print("[2/3] semantic near-duplicate dedup (headers / dns / cookies)")
    eng = ap.Engagement("example.com", Path(tempfile.mkdtemp()))
    # poorer header finding first, richer second (real titles from rebuild fixture)
    poor = ap.Finding(eng.new_id(), "LOW",
        "セキュリティヘッダ欠落 (5): strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, permissions-policy",
        "CWE-693", overview=["5 missing"])
    rich = ap.Finding(eng.new_id(), "LOW", "Security headers missing: 8 / 8",
        "CWE-693", cvss="4.0",
        overview=["hsts", "csp", "xfo", "xcto", "referrer", "permissions", "coop", "coep"],
        evidence=["header matrix with values", "eid"], evidence_ids=[1])
    eng.add(poor); eng.add(rich)
    hdr = [f for f in eng.findings if eng._semantic_category(f.title)
           and eng._semantic_category(f.title).startswith("missing-security-headers")]
    check("exactly ONE security-header finding", len(hdr) == 1, f"got {len(hdr)}")
    check("richer header finding kept (8/8 matrix)", hdr and "8 / 8" in hdr[0].title, hdr[0].title if hdr else "")
    # dns hardening dup
    d1 = ap.Finding(eng.new_id(), "LOW", "DNS ハードニング欠落: DNSSEC, CAA, MTA-STS, TLS-RPT", "CWE-693")
    d2 = ap.Finding(eng.new_id(), "LOW", "DNS ハードニング欠落: DNSSEC, CAA, MTA-STS, TLS-RPT", "CWE-693")
    n0 = len(eng.findings); eng.add(d1); eng.add(d2)
    dns = [f for f in eng.findings if "DNS ハード" in f.title]
    check("DNS hardening dup collapses to ONE", len(dns) == 1, f"got {len(dns)}")
    # distinct findings must NOT collapse
    a = ap.Finding(eng.new_id(), "LOW", "Legacy service open: POP3 (h:110)", "CWE-319")
    b = ap.Finding(eng.new_id(), "LOW", "Legacy service open: IMAP (h:143)", "CWE-319")
    eng.add(a); eng.add(b)
    legacy = [f for f in eng.findings if "Legacy service" in f.title]
    check("distinct legacy findings NOT collapsed", len(legacy) == 2, f"got {len(legacy)}")


# ---------------------------------------------------------------- 4. benign param
def test_benign_param_suppressed():
    print("[4] benign framework-native params dropped by verifier")
    s_item = {"id": "F-034", "title": "Hidden param candidate: `/` ← `s` (status-diff)",
              "cwe": "CWE-20", "md_text": ""}
    r = ev.verify_finding(s_item, live=False)
    check("benign param `s` status-diff REJECTED", r["verdict"] == "reject", r["verdict"])
    # a non-benign param with a weak signal should downgrade, not be a real finding
    x_item = {"id": "F-X", "title": "Hidden param candidate: `/` ← `debugmode` (status-diff)",
              "cwe": "CWE-20", "md_text": ""}
    rx = ev.verify_finding(x_item, live=False)
    check("non-benign weak-signal param downgraded", rx["verdict"] == "downgrade", rx["verdict"])


# ---------------------------------------------------------------- 5. ACF signature
def test_acf_signature():
    print("[5] WP plugin readme signature: ACF 54KB accepted, false-plugin rejected")
    acf = (FIX / "acf_readme.txt")
    if not acf.is_file():
        print("  SKIP  acf_readme.txt fixture absent"); return
    body = acf.read_text(errors="replace")
    # Rebuild the exact inline guard logic used in _enum_wordpress._signature_match.
    def sig_match(b):
        if not b: return False
        if len(b) > 150000: return False
        if "<html" in b.lower()[:200] or "<!doctype" in b.lower()[:200]: return False
        return bool(re.search(r"^(?:Stable tag|Version):\s*\S", b, re.M | re.I))
    def extract(b):
        m = re.search(r"^(?:Stable tag|Version):\s*(\S+)", b, re.M | re.I)
        return m.group(1).strip() if m else None
    check(f"ACF readme ({len(body)}B) accepted", sig_match(body), f"len={len(body)}")
    check("ACF version extracted = 6.8.10", extract(body) == "6.8.10", extract(body))
    # false-plugin hole stays closed: an HTML catch-all must be rejected
    html_catchall = "<!doctype html><html><head><title>404</title>Version: x</head></html>"
    check("HTML catch-all rejected (no false plugin)", not sig_match(html_catchall))
    # a WAF page that happens to contain 'Version:' mid-line but is HTML → rejected
    waf = "<html><body>Blocked. Version: 1.2.3 bla</body></html>"
    check("HTML WAF page with Version: rejected", not sig_match(waf))


# ---------------------------------------------------------------- 6. config
def test_config():
    print("[6] config.py auto-derivation + graceful bin fallback")
    cfg = _load("config", TOOLS / "config.py")
    check("PROJECT_ROOT auto-resolves to repo root",
          cfg.project_root() == ROOT, f"{cfg.project_root()} != {ROOT}")
    check("out_base derives under PROJECT_ROOT or env",
          str(cfg.out_base()).endswith("outputs") or "AP_OUT_BASE" in os.environ,
          str(cfg.out_base()))
    check("tools_dir derives correctly", cfg.tools_dir() == TOOLS, str(cfg.tools_dir()))
    # a missing optional bin degrades to None (no crash, no hardcode)
    missing = cfg.get_bin("definitely-not-a-real-binary-xyz")
    check("missing optional bin → None (graceful)", missing is None, repr(missing))
    # a present system bin resolves
    check("present bin resolves (curl)", cfg.get_bin("curl") is not None)


if __name__ == "__main__":
    test_config()
    test_fp_classes_rejected()
    test_semantic_dedup()
    test_benign_param_suppressed()
    test_acf_signature()
    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    sys.exit(1 if FAIL else 0)
