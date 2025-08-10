#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Prettier: 80 col, but Python ignored; code formatted accordingly.

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))")
ARGPARSE_RE = re.compile(r"add_argument\(\s*['\"](-{1,2}[\w\-]+)['\"]")
SUBPROCESS_RE = re.compile(
    r"(?:subprocess\.(?:run|Popen|call|check_output)\s*\(\s*)(.+?)(?:\))",
    re.S,
)
SHELL_CMD_RE = re.compile(r"\b(\w[\w\-\_\.]+)\b")
SHEBANG_RE = re.compile(r"^#!\s*(.+)$")

KNOWN_EXT_TOOLS = {
    "masscan",
    "nmap",
    "hydra",
    "curl",
    "wget",
    "nikto",
    "amass",
    "sublist3r",
    "dnsrecon",
    "whatweb",
    "ffuf",
    "dirb",
    "gobuster",
    "openssl",
    "ssh",
    "ping",
    "traceroute",
    "powershell",
}

def read_text_safe(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def detect_shebang(code: str) -> Optional[str]:
    first = code.splitlines()[:1]
    if not first:
        return None
    m = SHEBANG_RE.match(first[0])
    return m.group(1).strip() if m else None

def detect_script_type(path: Path, code: str) -> str:
    she = detect_shebang(code) or ""
    ext = path.suffix.lower()
    if "python" in she or ext in {".py"}:
        return "python"
    if "bash" in she or "sh" in she or ext in {".sh"}:
        return "bash"
    if "powershell" in she or ext in {".ps1"}:
        return "powershell"
    if ext in {".bat", ".cmd"}:
        return "batch"
    return "unknown"

def extract_python_imports(code: str) -> List[str]:
    imports = set()
    for line in code.splitlines():
        m = PY_IMPORT_RE.match(line)
        if m:
            pkg = m.group(1) or m.group(2)
            if pkg:
                imports.add(pkg.split(".")[0])
    return sorted(imports)

def extract_argparse_flags(code: str) -> List[str]:
    return sorted(set(ARGPARSE_RE.findall(code)))

def extract_subprocess_commands(code: str) -> List[str]:
    cmds = []
    for m in SUBPROCESS_RE.findall(code):
        snippet = m.strip()
        # Try to detect list([])/string form safely
        try:
            if snippet.startswith("["):
                # Best-effort; avoid eval; simple tokenizer:
                # Replace quotes with sentinel to split
                items = []
                buf = ""
                q = None
                for ch in snippet:
                    if ch in "\"'":
                        if q is None:
                            q = ch
                            buf += ch
                        elif q == ch:
                            q = None
                            buf += ch
                        else:
                            buf += ch
                    else:
                        buf += ch
                # Fallback: just record raw
                cmds.append(snippet)
            else:
                cmds.append(snippet)
        except Exception:
            cmds.append(snippet)
    return cmds

def guess_external_tools_from_code(code: str) -> List[str]:
    tools = set()
    for token in SHELL_CMD_RE.findall(code):
        t = token.lower()
        if t in KNOWN_EXT_TOOLS:
            tools.add(t)
    return sorted(tools)

def analyze_file(path: Path, root: Path) -> Dict[str, Any]:
    rel = path.relative_to(root).as_posix()
    code = read_text_safe(path)
    stype = detect_script_type(path, code)
    shebang = detect_shebang(code)

    py_imports: List[str] = []
    flags: List[str] = []
    subprocess_calls: List[str] = []
    ext_tools: List[str] = []

    if stype == "python":
        py_imports = extract_python_imports(code)
        flags = extract_argparse_flags(code)
        subprocess_calls = extract_subprocess_commands(code)
        ext_tools = guess_external_tools_from_code(code)
    else:
        # Non-Python: detect tools by tokens
        ext_tools = guess_external_tools_from_code(code)

    # Heuristic: output type guesses
    outputs = []
    if "json" in code.lower():
        outputs.append("json")
    if "xml" in code.lower():
        outputs.append("xml")
    if "csv" in code.lower():
        outputs.append("csv")
    if "stdout" not in outputs:
        outputs.append("stdout")

    os_specific = []
    if stype in {"bash"}:
        os_specific.append("posix")
    if stype in {"powershell", "batch"}:
        os_specific.append("windows")

    return {
        "path": rel,
        "name": path.name,
        "script_type": stype,
        "shebang": shebang,
        "python_imports": py_imports,
        "arg_flags": flags,
        "subprocess_calls_raw": subprocess_calls,
        "external_tools": ext_tools,
        "possible_outputs": sorted(set(outputs)),
        "os_specific": os_specific,
        "size_bytes": path.stat().st_size if path.exists() else None,
    }

def rank_migration(entry: Dict[str, Any]) -> str:
    stype = entry["script_type"]
    tools = set(entry.get("external_tools", []))
    imports = set(entry.get("python_imports", []))

    if stype == "python":
        # If mostly HTTP/parsing, recommend rewrite in Rust
        if tools.issubset({"curl"}) and (
            {"requests", "json", "re"}.intersection(imports)
        ):
            return "rewrite_rust"
        # If heavy external tool orchestration, wrap first
        if len(tools - {"python", "pip"}) >= 1:
            return "wrap_then_refactor"
        # Default: wrap then gradually rewrite
        return "wrap_then_refactor"

    if stype in {"bash", "powershell", "batch"}:
        # Shell scripts orchestrating external tools -> wrap or convert to Rust Command pipeline
        return "wrap_then_refactor"

    return "inspect_manual"

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze legacy scripts and generate migration plan."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repo root (default: .)",
    )
    parser.add_argument(
        "--legacy-dirs",
        nargs="+",
        default=["legacy-python", "legacy-scripts"],
        help="Directories to scan",
    )
    parser.add_argument(
        "--out",
        default="tools/analysis",
        help="Output directory for reports",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    files: List[Path] = []
    for d in args.legacy_dirs:
        p = root / d
        if p.exists():
            for ext in ("*.py", "*.sh", "*.ps1", "*.bat", "*.cmd"):
                files.extend(p.rglob(ext))

    report: Dict[str, Any] = {
        "root": str(root),
        "scanned_dirs": args.legacy_dirs,
        "entries": [],
        "summary": {},
    }

    for f in sorted(files):
        entry = analyze_file(f, root)
        entry["migration_strategy"] = rank_migration(entry)
        report["entries"].append(entry)

    # Build summary
    by_strategy: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for e in report["entries"]:
        by_strategy[e["migration_strategy"]] = (
            by_strategy.get(e["migration_strategy"], 0) + 1
        )
        by_type[e["script_type"]] = by_type.get(e["script_type"], 0) + 1
    report["summary"] = {
        "count": len(report["entries"]),
        "by_strategy": by_strategy,
        "by_script_type": by_type,
    }

    (out_dir / "legacy_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    # Lightweight Markdown summary
    md_lines = [
        "# LEGION2 Legacy Analysis",
        "",
        f"Root: {root.as_posix()}",
        "",
        "## Summary",
        f"- Total scripts: {report['summary']['count']}",
        f"- By strategy: {report['summary']['by_strategy']}",
        f"- By type: {report['summary']['by_script_type']}",
        "",
        "## Entries",
    ]
    for e in report["entries"]:
        md_lines += [
            f"### {e['path']}",
            f"- type: {e['script_type']}",
            f"- strategy: {e['migration_strategy']}",
            f"- flags: {e.get('arg_flags')}",
            f"- imports: {e.get('python_imports')}",
            f"- external tools: {e.get('external_tools')}",
            f"- outputs: {e.get('possible_outputs')}",
            f"- os-specific: {e.get('os_specific')}",
            "",
        ]
    (out_dir / "legacy_report.md").write_text("\n".join(md_lines), encoding="utf-8")

    print(f"Wrote: {out_dir/'legacy_report.json'}")
    print(f"Wrote: {out_dir/'legacy_report.md'}")

if __name__ == "__main__":
    main()