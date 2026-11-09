#!/usr/bin/env python3
"""
config.py — single source of truth for environment-specific paths.

Precedence for every value:   env var  >  config file  >  auto-derived default.

Design goal: AUTO-DERIVE as much as possible so the committed config stays tiny.
  * PROJECT_ROOT is derived from this file's location — never hardcoded/configured.
  * OUT_BASE, .env, data/, formats/fonts, tools/ all derive from PROJECT_ROOT.
  * Only truly user-specific values (skills dir, node/strix bins, the synced
    japanese-pdf-report helpers UUID path) come from config file / env / which().

Config file: `<PROJECT_ROOT>/config.toml` (stdlib tomllib) or `config.json`.
A committed `config.example.toml` documents the keys; the real one is gitignored.
"""
from __future__ import annotations
import os, json, shutil
from pathlib import Path

try:
    import tomllib  # py3.11+
except Exception:
    tomllib = None

# --- PROJECT_ROOT: auto-derived, never configured --------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]

# --- load config file (optional) -------------------------------------------
_cfg: dict = {}
for _name in ("config.toml", "config.json"):
    _p = PROJECT_ROOT / _name
    if _p.is_file():
        try:
            if _name.endswith(".toml") and tomllib:
                _cfg = tomllib.loads(_p.read_text(encoding="utf-8"))
            elif _name.endswith(".json"):
                _cfg = json.loads(_p.read_text(encoding="utf-8"))
            break
        except Exception:
            _cfg = {}


def _cfg_get(dotted: str):
    cur = _cfg
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur if cur not in ("", None) else None


def get(dotted_key: str, env: str | None = None, default=None):
    """env var > config-file key > default."""
    if env and os.environ.get(env):
        return os.environ[env]
    v = _cfg_get(dotted_key)
    if v is not None:
        return v
    return default


# --- auto-derived path accessors -------------------------------------------
def project_root() -> Path:
    return PROJECT_ROOT

def tools_dir() -> Path:
    return PROJECT_ROOT / "tools"

def out_base() -> Path:
    return Path(get("paths.out_base", "AP_OUT_BASE", str(PROJECT_ROOT / "outputs")))

def env_file() -> Path:
    return Path(get("paths.env_file", "AP_ENV_FILE", str(PROJECT_ROOT / ".env")))

def data_dir() -> Path:
    return PROJECT_ROOT / "data"

def docs_dir() -> Path:
    return PROJECT_ROOT / "docs"

def formats_fonts() -> Path:
    return Path(get("paths.report_fonts", "AP_REPORT_FONTS",
                    str(PROJECT_ROOT / "formats" / "transilience-report-style" / "fonts")))

def skills_dir() -> Path:
    return Path(os.path.expanduser(
        get("paths.skills_dir", "AP_SKILLS_DIR", "~/.claude/skills")))

def webtrace() -> Path:
    v = get("bins.webtrace", "AP_WEBTRACE")
    if v:
        return Path(os.path.expanduser(v))
    return skills_dir() / "webtrace" / "scripts" / "trace.mjs"

def jpdf_helpers() -> str | None:
    """Path to the japanese-pdf-report `scripts/` dir. User-specific (synced skill
    carries a UUID) so prefer config/env; else auto-glob under skills_dir; else the
    in-repo skill copy; else None (callers degrade gracefully)."""
    v = get("paths.jpdf_helpers", "AP_JPDF_HELPERS")
    if v and Path(os.path.expanduser(v)).is_dir():
        return os.path.expanduser(v)
    # auto-glob the synced skill
    for base in (skills_dir() / "synced", skills_dir()):
        try:
            hits = sorted(base.glob("**/japanese-pdf-report/scripts"))
            if hits:
                return str(hits[0])
        except Exception:
            pass
    # in-repo fallback
    local = PROJECT_ROOT / "skills" / "japanese-pdf-report" / "scripts"
    return str(local) if local.is_dir() else None


# --- external binary resolution --------------------------------------------
# PD tools are go-installed into ~/go/bin which is usually NOT on PATH; and bare
# `httpx` on PATH may be the python httpx CLI — so callers still guard, but we
# prefer go/bin here.
_GO_BINS = [Path(os.path.expanduser("~/go/bin")),
            Path(os.path.expanduser("~/.go/bin"))]

def get_bin(name: str, env: str | None = None, candidates: list[str] | None = None) -> str | None:
    """Resolve an external tool:
    config[bins.<name>] > env > ~/go/bin > PATH(which) > explicit candidates > None.
    """
    env = env or f"AP_BIN_{name.upper().replace('-', '_')}"
    v = get(f"bins.{name}", env)
    if v and os.path.exists(os.path.expanduser(v)):
        return os.path.expanduser(v)
    for gb in _GO_BINS:
        p = gb / name
        if p.exists():
            return str(p)
    w = shutil.which(name)
    if w:
        return w
    for c in (candidates or []):
        if os.path.exists(os.path.expanduser(c)):
            return os.path.expanduser(c)
    return None
