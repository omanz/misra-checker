#!/usr/bin/env python3
"""
MISRA C++ 2023 Custom Checker
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Partial static analysis implementation of MISRA C++ 2023 rules.
Uses libclang (AST-based) when available, with regex/text analysis as fallback.

Usage:
  python misra_checker.py src/
  python misra_checker.py main.cpp --format html -o report.html
  python misra_checker.py src/ --format json -o findings.json
  python misra_checker.py src/ --rules 8.1.1,7.2.1
  python misra_checker.py --list-rules

NOTE: Rule IDs are approximate mappings to MISRA C++ 2023 categories.
      Always verify against the official MISRA C++ 2023 specification.
"""

import sys
import os
import re
import json
import argparse
import textwrap
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Callable, Optional
from enum import Enum

# ─── libclang (optional) ─────────────────────────────────────────────────────
CLANG_AVAILABLE = False
try:
    import clang.cindex as _clang_mod
    _clang_idx = _clang_mod.Index.create()
    CLANG_AVAILABLE = True
except Exception:
    pass


# ═════════════════════════════════════════════════════════════════════════════
# Data Models
# ═════════════════════════════════════════════════════════════════════════════

class Category(Enum):
    MANDATORY = "Mandatory"
    REQUIRED  = "Required"
    ADVISORY  = "Advisory"


@dataclass
class RuleDef:
    rule_id:    str
    category:   Category
    title:      str
    rationale:  str


@dataclass
class Finding:
    rule_id:   str
    category:  Category
    title:     str
    filepath:  str
    line:      int
    col:       int    = 0
    snippet:   str    = ""
    note:      str    = ""

    def to_dict(self) -> dict:
        return {
            "rule_id":  self.rule_id,
            "category": self.category.value,
            "title":    self.title,
            "file":     self.filepath,
            "line":     self.line,
            "col":      self.col,
            "snippet":  self.snippet,
            "note":     self.note,
        }


# ═════════════════════════════════════════════════════════════════════════════
# Rule Registry
# ═════════════════════════════════════════════════════════════════════════════

RULES: Dict[str, RuleDef] = {}

def _reg(rule_id: str, cat: Category, title: str, rationale: str) -> RuleDef:
    r = RuleDef(rule_id, cat, title, rationale)
    RULES[rule_id] = r
    return r

# --- Statements / Control Flow -----------------------------------------------
R_GOTO     = _reg("8.1.1",  Category.REQUIRED,
    "The goto statement shall not be used",
    "goto makes control flow impossible to statically analyse. Use structured loops/returns.")

R_BRACES   = _reg("9.3.1",  Category.REQUIRED,
    "Compound statements (braces) shall be used for all control-flow bodies",
    "Omitting braces causes subtle bugs. Every if/else/for/while body must be wrapped in {}.")

R_SWITCH   = _reg("9.4.1",  Category.REQUIRED,
    "Every switch-clause shall be terminated by break, return, throw, or [[fallthrough]]",
    "Implicit fall-through is a common defect source.")

# --- Expressions / Casts -----------------------------------------------------
R_NULL     = _reg("7.0.2",  Category.REQUIRED,
    "NULL shall not be used as a null-pointer constant; use nullptr",
    "NULL is an integer macro and is not type-safe. nullptr is the C++11 replacement.")

R_CCAST    = _reg("7.2.1",  Category.REQUIRED,
    "C-style casts shall not be used",
    "C-style casts bypass C++ type system. Use static_cast/reinterpret_cast/const_cast.")

R_OCTAL    = _reg("6.5.1",  Category.REQUIRED,
    "Octal integer literals shall not be used",
    "The leading-zero octal prefix is easily confused with decimal.")

R_HEXCASE  = _reg("6.5.2",  Category.ADVISORY,
    "Hexadecimal digit letters shall be uppercase (A–F)",
    "Lowercase l/1 ambiguity; consistent style aids readability.")

# --- Memory & Resources -------------------------------------------------------
R_DYNMEM   = _reg("11.5.1", Category.REQUIRED,
    "Dynamic heap memory allocation shall not be used (new/delete/malloc/free)",
    "Dynamic allocation introduces non-determinism and fragmentation in safety-critical systems.")

R_VARARGS  = _reg("8.4.2",  Category.REQUIRED,
    "Variable-argument functions (ellipsis) shall not be defined or called",
    "Ellipsis parameters bypass type checking entirely.")

# --- Declarations & Definitions -----------------------------------------------
R_REGISTER = _reg("6.3.1",  Category.REQUIRED,
    "The register storage-class specifier shall not be used",
    "register is deprecated in C++17 and removed in C++20.")

R_VOLATILE = _reg("6.2.1",  Category.ADVISORY,
    "volatile shall not be used without documented justification",
    "volatile is often misused as a concurrency primitive. Add a comment explaining intent.")

R_USINGNS  = _reg("6.1.1",  Category.REQUIRED,
    "using namespace shall not appear at file/global scope in header files",
    "Pollutes the namespace of every including translation unit.")

# --- Preprocessor ------------------------------------------------------------
R_DEFINE   = _reg("19.2.1", Category.REQUIRED,
    "#define shall not be used for constants or function-like macros",
    "Use constexpr for constants, inline functions or templates instead of macros.")

R_GUARD    = _reg("19.1.1", Category.REQUIRED,
    "Each header file shall have an include guard or #pragma once",
    "Prevents multiple-inclusion and redefinition errors.")

# --- Library -----------------------------------------------------------------
R_STDIO    = _reg("13.1.1", Category.REQUIRED,
    "C standard I/O functions shall not be used",
    "printf/scanf are not type-safe. Use C++ streams (<iostream>, <sstream>).")

R_MEMFUNC  = _reg("13.2.1", Category.REQUIRED,
    "C raw-memory and string functions shall not be used",
    "memcpy/strcpy etc. operate on raw bytes and bypass object semantics. Use std:: equivalents.")

R_EXIT     = _reg("15.3.1", Category.REQUIRED,
    "std::exit, std::abort, std::_Exit shall not be called",
    "Abrupt termination bypasses destructors and RAII, leaving resources leaked.")

R_EXCEPT   = _reg("15.0.1", Category.ADVISORY,
    "Exceptions shall not escape from destructors or main()",
    "Exception-unsafe destructors lead to terminate() calls.")


# ═════════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═════════════════════════════════════════════════════════════════════════════

def _is_comment_line(line: str) -> bool:
    s = line.strip()
    return s.startswith("//") or s.startswith("*") or s.startswith("/*")


def _strip_line_comment(line: str) -> str:
    """Remove trailing // comment (does not handle strings containing //)."""
    idx = line.find("//")
    return line[:idx] if idx != -1 else line


def _get_suppressions(lines: List[str]) -> Dict[int, set]:
    """
    Return {1-based line number: set of suppressed rule_ids}.
    Inline suppression syntax:  // MISRA-suppress: 7.2.1  reason
    """
    result: Dict[int, set] = {}
    pat = re.compile(r"MISRA-suppress:\s*([\d.]+)")
    for i, line in enumerate(lines, 1):
        m = pat.search(line)
        if m:
            result.setdefault(i, set()).add(m.group(1))
    return result


def _make(rule: RuleDef, filepath: str, line: int,
          col: int = 0, snippet: str = "", note: str = "") -> Finding:
    return Finding(rule.rule_id, rule.category, rule.title,
                   filepath, line, col, snippet.strip()[:120], note)


# ═════════════════════════════════════════════════════════════════════════════
# Text / Regex Checks
# ═════════════════════════════════════════════════════════════════════════════

def check_goto(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\bgoto\b")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        if pat.search(_strip_line_comment(line)):
            out.append(_make(R_GOTO, fp, i, snippet=line))
    return out


def check_null_macro(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\bNULL\b")
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if _is_comment_line(line):
            continue
        # Skip the system definition of NULL itself
        if s.startswith("#define") and "NULL" in s:
            continue
        if pat.search(_strip_line_comment(line)):
            out.append(_make(R_NULL, fp, i, snippet=line,
                             note="Replace NULL with nullptr"))
    return out


def check_c_style_cast(lines: List[str], fp: str) -> List[Finding]:
    """
    Heuristic detection: (Type)expr  where Type is a known built-in or
    PascalCase/ALL_CAPS identifier, followed by a variable/paren.
    """
    out = []
    # Pattern: (type) followed by alphanumeric, *, &, or (
    pat = re.compile(
        r"\(\s*(?:const\s+|unsigned\s+|signed\s+|long\s+)*"
        r"(?:int|long|short|char|float|double|bool|void\s*\*?"
        r"|[A-Z_][A-Za-z0-9_:<>,\s]*\*?\s*)\s*\)"
        r"\s*(?=[A-Za-z0-9_(\"\'&*])"
    )
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        code = _strip_line_comment(line)
        m = pat.search(code)
        if m:
            out.append(_make(R_CCAST, fp, i, col=m.start() + 1, snippet=line,
                             note=f"Found: {m.group(0).strip()} — use static_cast<T>()"))
    return out


def check_dynamic_memory(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\b(new|delete|malloc|free|calloc|realloc)\b")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        m = pat.search(_strip_line_comment(line))
        if m:
            out.append(_make(R_DYNMEM, fp, i, snippet=line,
                             note=f"Keyword/function: '{m.group(1)}'"))
    return out


def check_varargs(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\.\.\.")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        if pat.search(_strip_line_comment(line)):
            out.append(_make(R_VARARGS, fp, i, snippet=line))
    return out


def check_octal(lines: List[str], fp: str) -> List[Finding]:
    out = []
    # Octal: bare 0[0-7]+ not preceded by 0x/0b or followed by .
    pat = re.compile(r"(?<![xXbB\d.])0([0-7]{1,})\b(?!\.)")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        code = _strip_line_comment(line)
        for m in pat.finditer(code):
            digits = m.group(1)
            if digits:  # avoid bare 0
                out.append(_make(R_OCTAL, fp, i, col=m.start() + 1,
                                 snippet=line,
                                 note=f"Octal literal '0{digits}' — use decimal or hex"))
                break
    return out


def check_hex_case(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        for m in pat.finditer(_strip_line_comment(line)):
            val = m.group(0)
            hex_part = val[2:]
            if re.search(r"[a-f]", hex_part):
                out.append(_make(R_HEXCASE, fp, i, col=m.start() + 1,
                                 snippet=line,
                                 note=f"{val} → 0x{hex_part.upper()}"))
                break
    return out


def check_define_constants(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(\s+(.*))?$")
    guard_pat = re.compile(r"^[A-Z0-9_]+(?:_H(?:PP)?_?|_INCLUDED|_DEFINED)$")
    for i, line in enumerate(lines, 1):
        m = pat.match(line)
        if not m:
            continue
        name = m.group(1)
        value = (m.group(3) or "").strip()
        # Skip include guards (NAME_H, NAME_HPP, etc.)
        if guard_pat.match(name) and value in ("", "1"):
            continue
        # Skip #undef-able guards
        if name.endswith("_H") or name.endswith("_HPP"):
            continue
        out.append(_make(R_DEFINE, fp, i, snippet=line,
                         note=f"Use constexpr / inline function instead of #define {name}"))
    return out


def check_include_guard(lines: List[str], fp: str) -> List[Finding]:
    if Path(fp).suffix.lower() not in (".h", ".hpp", ".hh", ".hxx"):
        return []
    content = "\n".join(lines)
    has_pragma  = bool(re.search(r"^\s*#\s*pragma\s+once\b", content, re.M))
    has_ifndef  = bool(re.search(
        r"^\s*#\s*ifndef\s+\w+.*\n.*#\s*define\s+\w+", content, re.M))
    if not has_pragma and not has_ifndef:
        return [_make(R_GUARD, fp, 1,
                      note="Add '#pragma once' or an #ifndef/#define include guard")]
    return []


def check_stdio(lines: List[str], fp: str) -> List[Finding]:
    out = []
    func_pat = re.compile(
        r"\b(printf|fprintf|sprintf|snprintf|scanf|fscanf|sscanf"
        r"|gets|fgets|puts|fputs|fopen|fclose|fread|fwrite|perror)\s*\(")
    inc_pat = re.compile(r'#\s*include\s*[<"](?:stdio\.h|cstdio)[">]')
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        m = func_pat.search(line)
        if m:
            out.append(_make(R_STDIO, fp, i, snippet=line,
                             note=f"C I/O function '{m.group(1)}' — use std::cout/std::cin"))
        if inc_pat.search(line):
            out.append(_make(R_STDIO, fp, i, snippet=line,
                             note="Include of C I/O header — use <iostream> or <sstream>"))
    return out


def check_mem_functions(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(
        r"\b(memcpy|memset|memmove|memcmp|memchr"
        r"|strcpy|strncpy|strcat|strncat|strlen|strcmp|strncmp|sprintf)\s*\(")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        m = pat.search(line)
        if m:
            out.append(_make(R_MEMFUNC, fp, i, snippet=line,
                             note=f"C function '{m.group(1)}' — use std:: equivalents"))
    return out


def check_exit_abort(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\b(?:std::)?(?:exit|abort|_Exit|quick_exit)\s*\(")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        m = pat.search(_strip_line_comment(line))
        if m:
            out.append(_make(R_EXIT, fp, i, snippet=line,
                             note=f"'{m.group(0).strip()}' bypasses destructors"))
    return out


def check_using_namespace(lines: List[str], fp: str) -> List[Finding]:
    if Path(fp).suffix.lower() not in (".h", ".hpp", ".hh", ".hxx"):
        return []
    out = []
    pat = re.compile(r"^\s*using\s+namespace\b")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        if pat.match(line):
            out.append(_make(R_USINGNS, fp, i, snippet=line))
    return out


def check_braces(lines: List[str], fp: str) -> List[Finding]:
    """
    Detect control-flow keywords whose body opens on the NEXT line without {.
    Simplified heuristic — not a full parser.
    """
    out = []
    ctrl = re.compile(r"^\s*(if|else\s+if|for|while)\s*\(.*\)\s*$")
    else_alone = re.compile(r"^\s*else\s*$")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        if ctrl.match(line) or else_alone.match(line):
            if i < len(lines):
                nxt = lines[i].strip()   # lines[i] → 0-indexed next line
                if nxt and not nxt.startswith("{") and not _is_comment_line(lines[i]):
                    out.append(_make(R_BRACES, fp, i, snippet=line,
                                     note=f"Missing braces; next line: '{nxt[:60]}'"))
    return out


def check_switch_fallthrough(lines: List[str], fp: str) -> List[Finding]:
    """
    Basic heuristic: a 'case:' label without break/return/throw/[[fallthrough]]
    before the next 'case:' or '}'.
    """
    out = []
    case_pat    = re.compile(r"^\s*(?:case\s+.+|default)\s*:")
    term_pat    = re.compile(r"\b(break|return|throw|continue)\b|fallthrough")
    in_switch   = False
    last_case   = -1

    for i, line in enumerate(lines, 1):
        if re.match(r"\s*switch\s*\(", line):
            in_switch = True
        if not in_switch:
            continue
        if case_pat.match(line):
            if last_case != -1:
                # scan back from i-1 to last_case for a terminator
                block = lines[last_case:i - 1]
                if not any(term_pat.search(bl) for bl in block):
                    out.append(_make(R_SWITCH, fp, last_case + 1,
                                     snippet=lines[last_case].strip(),
                                     note="No break/return/throw/[[fallthrough]] before next case"))
            last_case = i - 1
        if line.strip() == "}":
            in_switch = False
            last_case = -1
    return out


def check_volatile(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\bvolatile\b")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        if pat.search(_strip_line_comment(line)):
            out.append(_make(R_VOLATILE, fp, i, snippet=line,
                             note="Ensure volatile is documented with justification comment"))
    return out


def check_register(lines: List[str], fp: str) -> List[Finding]:
    out = []
    pat = re.compile(r"\bregister\b")
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        if pat.search(_strip_line_comment(line)):
            out.append(_make(R_REGISTER, fp, i, snippet=line,
                             note="register is deprecated in C++17 / removed in C++20"))
    return out


# ═════════════════════════════════════════════════════════════════════════════
# AST-Based Checks (libclang)
# ═════════════════════════════════════════════════════════════════════════════

def _ast_checks(fp: str, lines: List[str]) -> List[Finding]:
    if not CLANG_AVAILABLE:
        return []
    out = []
    try:
        import clang.cindex as cx
        tu = _clang_idx.parse(
            fp, args=["-std=c++17", "-x", "c++"],
            options=cx.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )

        def visit(node):
            if node.location.file and node.location.file.name == fp:
                ln = node.location.line
                snip = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""

                if node.kind == cx.CursorKind.GOTO_STMT:
                    out.append(_make(R_GOTO, fp, ln, col=node.location.column, snippet=snip))

                if node.kind == cx.CursorKind.CSTYLE_CAST_EXPR:
                    out.append(_make(R_CCAST, fp, ln, col=node.location.column, snippet=snip,
                                     note="C-style cast detected via AST"))

                if node.kind == cx.CursorKind.CXX_NEW_EXPR:
                    out.append(_make(R_DYNMEM, fp, ln, col=node.location.column,
                                     snippet=snip, note="new expression"))

                if node.kind == cx.CursorKind.CXX_DELETE_EXPR:
                    out.append(_make(R_DYNMEM, fp, ln, col=node.location.column,
                                     snippet=snip, note="delete expression"))

                if node.kind == cx.CursorKind.FUNCTION_DECL:
                    if node.type.is_function_variadic():
                        out.append(_make(R_VARARGS, fp, ln, snippet=snip,
                                         note="Variadic function definition"))

            for child in node.get_children():
                visit(child)

        visit(tu.cursor)
    except Exception:
        pass
    return out


# ═════════════════════════════════════════════════════════════════════════════
# Checker Orchestration
# ═════════════════════════════════════════════════════════════════════════════

TEXT_CHECKERS: List[Callable] = [
    check_goto,
    check_null_macro,
    check_c_style_cast,
    check_dynamic_memory,
    check_varargs,
    check_octal,
    check_hex_case,
    check_define_constants,
    check_include_guard,
    check_stdio,
    check_mem_functions,
    check_exit_abort,
    check_using_namespace,
    check_braces,
    check_switch_fallthrough,
    check_volatile,
    check_register,
]

CPP_EXTENSIONS = {".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".hh", ".hxx"}


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule_id, f.filepath, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def check_file(fp: str) -> List[Finding]:
    path = Path(fp)
    if not path.exists():
        print(f"[WARN] File not found: {fp}", file=sys.stderr)
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        print(f"[WARN] Cannot read {fp}: {e}", file=sys.stderr)
        return []

    suppressions = _get_suppressions(lines)
    findings: List[Finding] = []

    # Text checks
    for checker in TEXT_CHECKERS:
        findings.extend(checker(lines, fp))

    # AST checks (deduplicate against text findings afterward)
    if CLANG_AVAILABLE:
        findings.extend(_ast_checks(fp, lines))

    # Apply per-line suppressions
    filtered = [
        f for f in findings
        if f.rule_id not in suppressions.get(f.line, set())
    ]

    return _deduplicate(filtered)


def check_paths(paths: List[str], extensions: set) -> List[Finding]:
    all_findings: List[Finding] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for ext in extensions:
                for f in sorted(path.rglob(f"*{ext}")):
                    all_findings.extend(check_file(str(f)))
        elif path.is_file():
            all_findings.extend(check_file(str(path)))
        else:
            print(f"[WARN] Path not found: {p}", file=sys.stderr)
    return all_findings


# ═════════════════════════════════════════════════════════════════════════════
# Reporters
# ═════════════════════════════════════════════════════════════════════════════

_ANSI = {
    Category.MANDATORY: "\033[91m",
    Category.REQUIRED:  "\033[93m",
    Category.ADVISORY:  "\033[94m",
    "reset":            "\033[0m",
    "bold":             "\033[1m",
    "dim":              "\033[2m",
}


def report_terminal(findings: List[Finding]) -> None:
    if not findings:
        print("\n\033[92m✅  No MISRA C++ 2023 violations found.\033[0m\n")
        return

    by_file: Dict[str, List[Finding]] = {}
    for f in sorted(findings, key=lambda x: (x.filepath, x.line)):
        by_file.setdefault(x.filepath, []).append(x) if (x := f) else None
    # redo cleanly
    by_file = {}
    for f in sorted(findings, key=lambda x: (x.filepath, x.line)):
        by_file.setdefault(f.filepath, []).append(f)

    for file_path, ff in by_file.items():
        print(f"\n{'─' * 72}")
        print(f"  📄  {_ANSI['bold']}{file_path}{_ANSI['reset']}"
              f"  {_ANSI['dim']}({len(ff)} finding{'s' if len(ff) != 1 else ''}){_ANSI['reset']}")
        print(f"{'─' * 72}")
        for f in ff:
            color = _ANSI.get(f.category, "")
            label = f"[{f.category.value:9s}]"
            print(f"  {color}{label}{_ANSI['reset']} "
                  f"Line {f.line:4d}  "
                  f"{_ANSI['bold']}Rule {f.rule_id:<8}{_ANSI['reset']}  "
                  f"{f.title}")
            if f.snippet:
                print(f"  {'':>14}↳  {_ANSI['dim']}{f.snippet}{_ANSI['reset']}")
            if f.note:
                print(f"  {'':>14}ℹ  {f.note}")

    mand = sum(1 for f in findings if f.category == Category.MANDATORY)
    req  = sum(1 for f in findings if f.category == Category.REQUIRED)
    adv  = sum(1 for f in findings if f.category == Category.ADVISORY)

    print(f"\n{'═' * 72}")
    print(f"  {_ANSI['bold']}Total: {len(findings)}{_ANSI['reset']}  │  "
          f"{_ANSI[Category.MANDATORY]}Mandatory: {mand}{_ANSI['reset']}  │  "
          f"{_ANSI[Category.REQUIRED]}Required: {req}{_ANSI['reset']}  │  "
          f"{_ANSI[Category.ADVISORY]}Advisory: {adv}{_ANSI['reset']}")
    print(f"{'═' * 72}\n")


def report_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def report_html(findings: List[Finding],
                title: str = "MISRA C++ 2023 — Static Analysis Report") -> str:
    mand = sum(1 for f in findings if f.category == Category.MANDATORY)
    req  = sum(1 for f in findings if f.category == Category.REQUIRED)
    adv  = sum(1 for f in findings if f.category == Category.ADVISORY)

    cat_color = {
        "Mandatory": "#e74c3c",
        "Required":  "#e67e22",
        "Advisory":  "#3498db",
    }

    rows = ""
    for f in sorted(findings, key=lambda x: (x.filepath, x.line)):
        cc   = cat_color.get(f.category.value, "#888")
        name = Path(f.filepath).name
        snip = f.snippet.replace("<", "&lt;").replace(">", "&gt;")
        note = f.note.replace("<", "&lt;").replace(">", "&gt;")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{cc}">{f.category.value}</span></td>
          <td><code class="ruleid">{f.rule_id}</code></td>
          <td>{f.title}</td>
          <td title="{f.filepath}">{name}</td>
          <td class="num">{f.line}</td>
          <td><code class="snip">{snip}</code></td>
          <td class="note">{note}</td>
        </tr>"""

    # Build rule summary table
    rule_counts: Dict[str, int] = {}
    for f in findings:
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1

    rule_rows = ""
    for rid, cnt in sorted(rule_counts.items(), key=lambda x: -x[1]):
        rd = RULES.get(rid)
        if rd:
            cc = cat_color.get(rd.category.value, "#888")
            rule_rows += f"""
            <tr>
              <td><code>{rid}</code></td>
              <td><span class="badge" style="background:{cc}">{rd.category.value}</span></td>
              <td>{rd.title}</td>
              <td class="num">{cnt}</td>
            </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{
    --red:    #e74c3c; --orange: #e67e22; --blue: #3498db;
    --dark:   #2c3e50; --light:  #ecf0f1; --bg: #f8f9fa;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: var(--bg); color: #333; padding: 24px; font-size: 14px; }}
  h1   {{ color: var(--dark); margin-bottom: 6px; font-size: 1.6em; }}
  .subtitle {{ color: #777; margin-bottom: 24px; font-size: .9em; }}
  .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 32px; }}
  .stat {{ background: white; border-radius: 10px; padding: 14px 22px;
           box-shadow: 0 2px 8px rgba(0,0,0,.08); text-align: center; min-width: 90px; }}
  .stat .num {{ font-size: 2em; font-weight: 700; line-height: 1; }}
  .stat .lbl {{ font-size: .75em; color: #888; margin-top: 4px; text-transform: uppercase; letter-spacing: .05em; }}
  h2   {{ color: var(--dark); margin: 28px 0 12px; border-bottom: 2px solid var(--light); padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 10px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08);
           margin-bottom: 32px; }}
  th   {{ background: var(--dark); color: white; padding: 11px 12px; text-align: left;
          font-size: .8em; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }}
  td   {{ padding: 9px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
  tr:hover {{ background: #fafafa; }}
  .badge {{ color: white; padding: 2px 8px; border-radius: 4px;
            font-size: .75em; font-weight: 700; white-space: nowrap; }}
  code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-size: .85em; }}
  .ruleid {{ color: var(--dark); font-weight: 600; }}
  .snip   {{ display: block; max-width: 320px; white-space: nowrap;
             overflow: hidden; text-overflow: ellipsis; color: #555; }}
  .note   {{ color: #666; font-size: .85em; }}
  .num    {{ text-align: center; }}
  .footer {{ text-align: center; color: #aaa; font-size: .8em; margin-top: 24px; }}
  .warn   {{ background: #fff8e1; border-left: 4px solid #f39c12;
             padding: 10px 14px; border-radius: 4px; margin-bottom: 24px; font-size: .88em; }}
</style>
</head>
<body>
<h1>🔍 {title}</h1>
<p class="subtitle">Generated by misra_checker.py &nbsp;·&nbsp; Rule IDs are approximate — verify against the official MISRA C++ 2023 specification.</p>

<div class="warn">
  ⚠️  <strong>Partial coverage:</strong> This tool implements a representative subset of MISRA C++ 2023 rules
  using static text/regex analysis{"&nbsp;+&nbsp;libclang AST" if CLANG_AVAILABLE else " (libclang not available — install with <code>pip install libclang</code> for AST-based checks)"}.
  It does not replace a certified MISRA tool (e.g. LDRA, Polyspace, PC-lint Plus).
</div>

<div class="stats">
  <div class="stat"><div class="num" style="color:var(--red)">{mand}</div><div class="lbl">Mandatory</div></div>
  <div class="stat"><div class="num" style="color:var(--orange)">{req}</div><div class="lbl">Required</div></div>
  <div class="stat"><div class="num" style="color:var(--blue)">{adv}</div><div class="lbl">Advisory</div></div>
  <div class="stat"><div class="num">{len(findings)}</div><div class="lbl">Total</div></div>
  <div class="stat"><div class="num">{len(set(f.filepath for f in findings))}</div><div class="lbl">Files</div></div>
  <div class="stat"><div class="num">{len(rule_counts)}</div><div class="lbl">Rules Hit</div></div>
</div>

<h2>All Findings</h2>
<table>
<thead><tr>
  <th>Category</th><th>Rule ID</th><th>Description</th>
  <th>File</th><th>Line</th><th>Snippet</th><th>Note</th>
</tr></thead>
<tbody>{rows if rows else "<tr><td colspan='7' style='text-align:center;color:#aaa;padding:24px'>✅ No findings</td></tr>"}</tbody>
</table>

<h2>Rule Summary</h2>
<table>
<thead><tr>
  <th>Rule ID</th><th>Category</th><th>Description</th><th>Count</th>
</tr></thead>
<tbody>{rule_rows if rule_rows else "<tr><td colspan='4' style='text-align:center;color:#aaa;padding:24px'>No violations</td></tr>"}</tbody>
</table>

<div class="footer">
  misra_checker.py &nbsp;·&nbsp; MISRA C++ 2023 custom checker &nbsp;·&nbsp;
  {len(RULES)} rules implemented &nbsp;·&nbsp;
  {"libclang AST active" if CLANG_AVAILABLE else "regex-only mode"}
</div>
</body>
</html>"""


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="MISRA C++ 2023 Custom Static Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python misra_checker.py src/
              python misra_checker.py main.cpp --format html -o report.html
              python misra_checker.py src/ --format json -o findings.json
              python misra_checker.py src/ --rules 7.2.1,11.5.1
              python misra_checker.py src/ --exclude-rules 6.5.2,6.2.1
              python misra_checker.py --list-rules

            Inline suppression (add to source file):
              int x = (int)y;  // MISRA-suppress: 7.2.1  legacy API, reviewed by <name>
        """),
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to analyse")
    parser.add_argument(
        "--ext", default=".cpp,.cxx,.cc,.c,.h,.hpp,.hh,.hxx",
        help="Comma-separated file extensions (default: C/C++ sources & headers)",
    )
    parser.add_argument(
        "--format", choices=["terminal", "json", "html"],
        default="terminal", help="Output format (default: terminal)",
    )
    parser.add_argument("-o", "--output", help="Output file path (for json/html formats)")
    parser.add_argument("--rules", help="Only check these rule IDs (comma-separated)")
    parser.add_argument("--exclude-rules", dest="exclude", help="Skip these rule IDs (comma-separated)")
    parser.add_argument(
        "--fail-on", choices=["any", "required", "mandatory", "never"],
        default="required",
        help="Exit-code policy: fail if findings >= this category (default: required)",
    )
    parser.add_argument("--list-rules", action="store_true", help="Print all implemented rules and exit")

    args = parser.parse_args()

    # ── List rules ──────────────────────────────────────────────────────────
    if args.list_rules:
        print(f"\n{'─' * 78}")
        print(f"  {'Rule ID':<10}  {'Category':<10}  Description")
        print(f"{'─' * 78}")
        for rid, rd in sorted(RULES.items()):
            color = _ANSI.get(rd.category, "")
            print(f"  {color}{rid:<10}  {rd.category.value:<10}{_ANSI['reset']}  {rd.title}")
            print(f"  {'':10}  {'':10}  {_ANSI['dim']}{rd.rationale}{_ANSI['reset']}\n")
        print(f"  {len(RULES)} rules implemented")
        if not CLANG_AVAILABLE:
            print(f"\n  ⚠️  libclang not found — AST checks disabled.")
            print(f"     pip install libclang")
        print(f"{'─' * 78}\n")
        return 0

    if not args.paths:
        parser.print_help()
        return 1

    extensions = {e.strip() for e in args.ext.split(",")}

    # Header
    clang_status = (
        f"\033[92m✅ AST active\033[0m" if CLANG_AVAILABLE
        else f"\033[93m⚠️  regex-only\033[0m  (pip install libclang for AST checks)"
    )
    print(f"\n\033[1m🔍  MISRA C++ 2023 Checker\033[0m  │  libclang: {clang_status}\n")

    # Analyse
    findings = check_paths(args.paths, extensions)

    # Filter
    if args.rules:
        wanted = {r.strip() for r in args.rules.split(",")}
        findings = [f for f in findings if f.rule_id in wanted]
    if args.exclude:
        excluded = {r.strip() for r in args.exclude.split(",")}
        findings = [f for f in findings if f.rule_id not in excluded]

    # Report
    if args.format == "terminal":
        report_terminal(findings)
    elif args.format == "json":
        out = report_json(findings)
        if args.output:
            Path(args.output).write_text(out)
            print(f"✅  JSON report → {args.output}")
        else:
            print(out)
    elif args.format == "html":
        out = report_html(findings)
        dest = args.output or "misra_report.html"
        Path(dest).write_text(out)
        print(f"✅  HTML report → {dest}")

    # Exit code
    if args.fail_on == "never":
        return 0
    if args.fail_on == "any":
        return 1 if findings else 0
    if args.fail_on == "mandatory":
        return 1 if any(f.category == Category.MANDATORY for f in findings) else 0
    # default: "required" — fail on Required or Mandatory
    return 1 if any(f.category in (Category.MANDATORY, Category.REQUIRED)
                    for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
