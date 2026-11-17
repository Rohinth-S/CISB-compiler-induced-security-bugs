#!/usr/bin/env python3
"""
cisb-guard-cc: Unified compiler wrapper for CISB-Guard
Pipelines:
1. AST Rewriter (ub-check-guard) to secure ISpec1 UB checks
2. Clang-18 with libCISBGuard.so pass plugin (ScrubGuardPass, UndefFreezePass, CFGVerifyPass)
3. Structured JSON audit log emission
"""

import sys
import os
import re
import subprocess
import tempfile
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = REPO_ROOT / "build"
UB_TOOL = BUILD_DIR / "ub-check-guard"
PLUGIN_SO = BUILD_DIR / "libCISBGuard.so"

def rewrite_ast_fallback(source_text: str) -> tuple[str, list]:
    """
    Python fallback AST/source transformer for environments where ub-check-guard
    binary is not yet compiled or is executing during bootstrap.
    """
    edits = []
    text = source_text

    # 1. Signed overflow check rewrite:
    # if (x + c < x) -> if (__builtin_add_overflow((x), (c), &(int){0}))
    overflow_pat = re.compile(r'if\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)\s*<\s*\1\s*\)')
    if overflow_pat.search(text):
        text = overflow_pat.sub(r'if (__builtin_add_overflow((\1), (\2), &(int){0}))', text)
        edits.append({"rule": "ISpec1:SignedOverflow", "desc": "Rewrote signed overflow UB check to __builtin_add_overflow"})

    # if (a + c > a) -> if (!__builtin_add_overflow((a), (c), &(int){0}) && ((c) > 0))
    overflow_gt_pat = re.compile(r'if\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)\s*>\s*\1\s*\)')
    if overflow_gt_pat.search(text):
        text = overflow_gt_pat.sub(r'if (!__builtin_add_overflow((\1), (\2), &(int){0}) && ((\2) > 0))', text)
        edits.append({"rule": "ISpec1:SignedOverflowGT", "desc": "Rewrote signed overflow check (a + c > a) to __builtin_add_overflow"})

    # 2. Post-dereference null check barrier:
    # Only match if pointer was dereferenced within the same function prior to check
    def find_function_start(src, pos):
        last_brace = src.rfind('\n{', 0, pos)
        if last_brace == -1:
            last_brace = src.rfind('{', 0, pos)
        return last_brace if last_brace != -1 else 0

    null_pat = re.compile(r'(\n\s*)(if\s*\(\s*(!\s*([a-zA-Z0-9_]+)|([a-zA-Z0-9_]+)\s*==\s*(NULL|0))\s*\))')
    for match in list(null_pat.finditer(text)):
        ptr = match.group(4) or match.group(5)
        fn_start = find_function_start(text, match.start())
        fn_scope = text[fn_start:match.start()]
        if re.search(rf'(\*\s*{ptr}\b|{ptr}\s*->)', fn_scope):
            indent = match.group(1)
            barrier = f'{indent}__asm__ __volatile__("" : "+r"({ptr}));'
            text = text[:match.start()] + barrier + text[match.start():]
            edits.append({"rule": "ISpec1:PostDerefNull", "desc": f"Inserted memory barrier before null check on {ptr}"})
            break

    # 3. Narrow integer promotion check:
    # if (u8 + 1 == 0) -> if ((uint8_t)(u8 + 1) == 0)
    int_prom_pat = re.compile(r'if\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*1\s*==\s*0\s*\)')
    if int_prom_pat.search(text):
        text = int_prom_pat.sub(r'if ((uint8_t)(\1 + 1) == 0)', text)
        edits.append({"rule": "ISpec1:IntegerPromotion", "desc": "Added explicit narrowing cast to restore modular semantics"})

    # 4. Secret wipe memory barrier preservation (for gcc fallback / OSpec1):
    # memset(buf, 0, len) followed by memory barrier
    wipe_pat = re.compile(r'(\n\s*)(memset\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*0\s*,\s*[^;]+;\s*)')
    wipe_match = wipe_pat.search(text)
    if wipe_match and '__asm__' not in text[wipe_match.end():wipe_match.end()+100]:
        indent = wipe_match.group(1)
        buf_name = wipe_match.group(3)
        barrier = f'\n{indent}__asm__ __volatile__("" : : "r"({buf_name}) : "memory");'
        text = text[:wipe_match.end()] + barrier + text[wipe_match.end():]
        edits.append({"rule": "OSpec1:ScrubGuard", "desc": f"Added memory barrier after zeroing memset on {buf_name}"})

    return text, edits

def main():
    raw_args = sys.argv[1:]
    if not raw_args:
        print("Usage: cisb-guard-cc [compiler flags] [--keep-rewritten <path>] <source.c> -o <binary>")
        sys.exit(1)

    keep_rewritten_path = None
    args = []
    i = 0
    while i < len(raw_args):
        if raw_args[i] == "--keep-rewritten" and i + 1 < len(raw_args):
            keep_rewritten_path = raw_args[i + 1]
            i += 2
        else:
            args.append(raw_args[i])
            i += 1

    c_files = [a for a in args if a.endswith('.c')]
    other_args = [a for a in args if not a.endswith('.c')]

    audit_file = os.environ.get("CISB_AUDIT_LOG", str(REPO_ROOT / "results" / "audit.json"))
    os.makedirs(os.path.dirname(os.path.abspath(audit_file)), exist_ok=True)

    temp_files = []
    processed_sources = []
    audit_records = []

    for c_file in c_files:
        p = Path(c_file)
        if not p.exists():
            processed_sources.append(c_file)
            continue

        raw_code = p.read_text(encoding='utf-8', errors='ignore')
        rewritten_code = raw_code
        applied_edits = []

        if UB_TOOL.exists() and os.access(UB_TOOL, os.X_OK):
            fd, tmp_out = tempfile.mkstemp(suffix='.c', prefix='cisb_ast_')
            os.close(fd)
            temp_files.append(tmp_out)
            res = subprocess.run([str(UB_TOOL), str(p), "-o", tmp_out, "--"], capture_output=True, text=True)
            if res.returncode == 0 and Path(tmp_out).stat().st_size > 0:
                rewritten_code = Path(tmp_out).read_text(encoding='utf-8')
                applied_edits.append({"rule": "AST:ub-check-guard", "status": "Transformed via Clang LibTooling"})
            else:
                rewritten_code, applied_edits = rewrite_ast_fallback(raw_code)
                Path(tmp_out).write_text(rewritten_code, encoding='utf-8')
            processed_sources.append(tmp_out)
        else:
            rewritten_code, applied_edits = rewrite_ast_fallback(raw_code)
            if applied_edits:
                fd, tmp_out = tempfile.mkstemp(suffix='.c', prefix='cisb_ast_')
                os.close(fd)
                temp_files.append(tmp_out)
                Path(tmp_out).write_text(rewritten_code, encoding='utf-8')
                processed_sources.append(tmp_out)
            else:
                processed_sources.append(c_file)

        if keep_rewritten_path:
            try:
                Path(keep_rewritten_path).write_text(rewritten_code, encoding='utf-8')
            except Exception:
                pass

        if applied_edits:
            audit_records.append({
                "source": c_file,
                "edits": applied_edits
            })

    from backend.runner import find_tool
    compiler = find_tool("clang-18") or find_tool("clang") or find_tool("gcc") or "gcc"

    cmd = [compiler] + other_args + processed_sources

    if "clang" in compiler and PLUGIN_SO.exists():
        cmd.extend([f"-fpass-plugin={PLUGIN_SO}"])

    res = subprocess.run(cmd)

    if audit_records:
        try:
            with open(audit_file, "a", encoding="utf-8") as f:
                for rec in audit_records:
                    f.write(json.dumps(rec) + "\n")
        except Exception:
            pass

    for t in temp_files:
        try:
            os.remove(t)
        except OSError:
            pass

    sys.exit(res.returncode)

if __name__ == '__main__':
    main()
