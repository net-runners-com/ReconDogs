#!/usr/bin/env python3
"""Retroactive validator — runs phase_validator on an existing autopentest engagement dir.
Usage: python3 tools/validate-run.py <engagement_dir>
Reconstructs findings from finding-*/description.md and runs the 5-check gate.
"""
import sys, os, re, json
from pathlib import Path
sys.path.insert(0, os.path.dirname(__file__))

# Import autopentest primitives
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "autopentest", os.path.join(os.path.dirname(__file__), "autopentest.py"))
_ap = importlib.util.module_from_spec(_spec)
sys.modules["autopentest"] = _ap  # register BEFORE exec so @dataclass can find module
_spec.loader.exec_module(_ap)

Finding    = _ap.Finding
Engagement = _ap.Engagement
phase_validator = _ap.phase_validator

def parse_md(p: Path) -> Finding | None:
    txt = p.read_text(encoding="utf-8")
    title = re.search(r"^#\s+F-\d+\s+—\s+(.+)", txt, re.M)
    fid   = re.search(r"^#\s+(F-\d+)", txt, re.M)
    sev   = re.search(r"Severity:\*\*\s*(\w+)", txt)
    cwe   = re.search(r"CWE:\*\*\s*(CWE-[\d\-]+|–|-)", txt)
    cve   = re.search(r"CVE:\*\*\s*(CVE-[\d\-]+)", txt)
    cvss  = re.search(r"CVSS:\*\*\s*([\d.]+)", txt)
    if not fid: return None
    f = Finding(id=fid.group(1), severity=(sev.group(1) if sev else "INFO"),
                title=(title.group(1) if title else fid.group(1)),
                cwe=(cwe.group(1) if cwe else "-"))
    if cve:  f.cve  = cve.group(1)
    if cvss: f.cvss = cvss.group(1)
    f.overview = []
    f.evidence = []
    f.remediation = []
    return f

def main():
    if len(sys.argv) < 2:
        print("Usage: validate-run.py <engagement_dir>"); sys.exit(1)
    d = Path(sys.argv[1]).resolve()
    if not (d / "findings").is_dir():
        print(f"ERR: no findings/ under {d}"); sys.exit(2)
    # Minimal Engagement stub
    eng = Engagement.__new__(Engagement)
    eng.target = "retroactive"
    eng.out = d
    eng.findings = []
    eng._dup_suppressed = 0
    # Context the gate + code-verifier consult. Offline verifier => deterministic,
    # network-independent re-check (cross-finding guards reject the FP classes).
    eng.ctx = {"env": {}, "_verifier_live": ("--live" in sys.argv)}
    class _TrafficStub:
        def get(self, _eid):
            return None
    eng.traffic = _TrafficStub()
    for fdir in sorted((d / "findings").glob("finding-*")):
        if ".rejected" in fdir.name: continue
        md = fdir / "description.md"
        if md.is_file():
            f = parse_md(md)
            if f: eng.findings.append(f)
    print(f"[validator] loaded {len(eng.findings)} findings from {d}")
    phase_validator(eng)
    print(f"[validator] done. See {d}/artifacts/validated/ and {d}/artifacts/false-positives/")

if __name__ == "__main__":
    main()
