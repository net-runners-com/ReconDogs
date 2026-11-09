# ReconDogs

Autonomous external web-application recon & assessment toolkit with **code-based exploit verification** — it re-tests every candidate finding in code before reporting it, so the delivered set is high-precision (no reflection-as-evaluation false positives), and renders the result as a PDF report or slide deck.

## Why

Most automated scanners emit version-inferred CVE lists and reflection-based "findings" without proving exploitability, producing noisy, over-stated reports. ReconDogs runs a verifier (`exploit_verifier.py`) that:

- **SSTI**: sends fresh randomized `{{A*B}}` and requires the *evaluated* product in the body (not the literal payload); rejects physically-impossible multi-engine "matches" on one path.
- **Fingerprint findings**: require a product-specific signature; reject generic/CMS collisions.
- **Reflected XSS**: marker must reflect *unescaped* in an executable context.
- **Plugin CVEs**: installed version must fall in the affected range (readme.txt `Stable tag`).
- **Timing/smuggling**: no deterministic differential → downgraded to INFO.

Findings are de-duplicated by semantic signature, and every finding carries a concrete request/response evidence pair.

## Components

| File | Role |
|---|---|
| `tools/autopentest.py` | Scan engine (recon → environment profile → verified findings). Profiles, phase DAG, asset ledger. |
| `tools/exploit_verifier.py` | Standalone, stdlib-only code verifier (pass/fail per finding class). |
| `tools/validate-run.py` | Retroactive validator — re-run the verifier over an existing engagement dir. |
| `tools/webscan.py` | Unified passive web scanner. |
| `tools/nvd-lookup.py` | NVD CVE lookup + local cache (CVSS/severity/description). |
| `tools/gen-report-template.py`, `gen_site_report.py` | PDF report generators (ReportLab, embedded Noto CJK). |
| `tools/gen_slides.py`, `slides_data.py` | Slide-deck generator (engagement data → deck). Requires the separate [SlideGen](https://github.com/net-runners-com/SlideGen) app. |
| `tools/config.py` | Path/binary resolver: **env > `config.toml` > auto-derived default**. |
| `tools/tests/` | Offline regression suite (FP-class rejection, dedup, plugin signatures). |

## Install

```bash
git clone https://github.com/net-runners-com/ReconDogs
cd ReconDogs
cp config.example.toml config.toml   # optional — most values auto-derive
```

External tools are resolved via `config.py` (`PATH`, `~/go/bin`, or `config.toml`). The ProjectDiscovery stack (katana, subfinder, dnsx, cdncheck, tlsx, httpx) plus nmap/masscan/nuclei/feroxbuster/testssl enrich coverage when present; each phase degrades gracefully if a binary is missing.

## Usage

```bash
# Non-destructive diagnosis scan
python3 tools/autopentest.py --target example.com --profile diagnosis

# Re-validate an existing engagement with the code verifier
python3 tools/validate-run.py outputs/<engagement-dir>

# Generate a PDF report / slide deck
python3 tools/gen-report-template.py outputs/<engagement-dir>
python3 tools/gen_slides.py --engagement outputs/<engagement-dir>

# Run the regression suite
python3 tools/tests/test_accuracy_regressions.py
```

Output is written under `outputs/` (gitignored).

## Safety & authorization

- **Default runs are non-destructive.** Active exploitation (SQLi dump, RCE PoC, auth-bypass, DoS) is gated behind explicit `--level 2` / `--allow-*` flags and is **off by default**.
- Only test systems you are **explicitly authorized** to assess. This tool is for authorized penetration testing, bug bounty within program scope, and security research.
- `config.toml`, `.env`, and `outputs/` are gitignored — never commit credentials or engagement data.

## License

MIT — see [LICENSE](LICENSE).
