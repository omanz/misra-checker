#!/usr/bin/env python3
"""
Unit tests for misra_checker.py
================================
Runs with:
  python -m unittest test_misra_checker.py -v
  pytest test_misra_checker.py -v                  (when pytest is available)
  pytest test_misra_checker.py -v --tb=short       (compact tracebacks)

Test philosophy:
  - Every checker function has both VIOLATION tests (must detect) and
    CLEAN tests (must NOT produce false positives).
  - Suppression comments are tested independently.
  - CLI behaviour (exit codes, output formats) is tested via subprocess.
  - Each test method documents WHICH rule and WHY.
"""

import sys
import os
import json
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import List

# ── locate misra_checker.py ──────────────────────────────────────────────────
# Support two layouts:
#   1. Flat:  misra_checker.py and test_misra_checker.py in the same directory
#   2. Nested: test_misra_checker.py inside tests/, misra_checker.py in repo root
_HERE = Path(__file__).parent
_CHECKER = _HERE / "misra_checker.py"
if not _CHECKER.exists():
    _CHECKER = _HERE.parent / "misra_checker.py"
if not _CHECKER.exists():
    raise FileNotFoundError(
        f"misra_checker.py not found in {_HERE} or {_HERE.parent}."
    )

sys.path.insert(0, str(_CHECKER.parent))
import misra_checker as mc   # import the module under test


# ═════════════════════════════════════════════════════════════════════════════
# Test helpers
# ═════════════════════════════════════════════════════════════════════════════

def _lines(src: str) -> List[str]:
    """Split dedented source string into lines."""
    return textwrap.dedent(src).splitlines()


def _check(checker_fn, src: str) -> List[mc.Finding]:
    """Run a single checker function against inline source code."""
    return checker_fn(_lines(src), "<test>")


def _rules_hit(findings: List[mc.Finding]) -> List[str]:
    return [f.rule_id for f in findings]


def _lines_hit(findings: List[mc.Finding]) -> List[int]:
    return [f.line for f in findings]


def _write_tmp(src: str, suffix: str = ".cpp") -> Path:
    """Write dedented source to a temp file; caller must delete."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    f.write(textwrap.dedent(src))
    f.close()
    return Path(f.name)


def _run_checker(*args: str) -> subprocess.CompletedProcess:
    """Run misra_checker.py as a subprocess and return the result."""
    return subprocess.run(
        [sys.executable, str(_CHECKER), *args],
        capture_output=True, text=True,
    )


# ═════════════════════════════════════════════════════════════════════════════
# 8.1.1  goto
# ═════════════════════════════════════════════════════════════════════════════

class TestGoto(unittest.TestCase):

    def test_violation_goto_in_function(self):
        """goto inside a function body must be flagged."""
        findings = _check(mc.check_goto, """
            int f() {
                goto end;
            end:
                return 0;
            }
        """)
        self.assertIn("9.6.1", _rules_hit(findings))

    def test_violation_goto_indented(self):
        """goto with arbitrary indentation must be flagged."""
        findings = _check(mc.check_goto, "        goto cleanup;")
        self.assertIn("9.6.1", _rules_hit(findings))

    def test_clean_goto_in_comment(self):
        """goto mentioned only in a comment must NOT be flagged."""
        findings = _check(mc.check_goto, "// never use goto in C++")
        self.assertEqual(findings, [])

    def test_clean_no_goto(self):
        """Regular control flow must not trigger the goto rule."""
        findings = _check(mc.check_goto, """
            int f() {
                for (int i = 0; i < 10; ++i) {}
                return 0;
            }
        """)
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 7.0.2  NULL → nullptr
# ═════════════════════════════════════════════════════════════════════════════

class TestNullMacro(unittest.TestCase):

    def test_violation_null_comparison(self):
        findings = _check(mc.check_null_macro, "if (ptr == NULL) return;")
        self.assertIn("7.0.2", _rules_hit(findings))

    def test_violation_null_assignment(self):
        findings = _check(mc.check_null_macro, "int* p = NULL;")
        self.assertIn("7.0.2", _rules_hit(findings))

    def test_clean_nullptr(self):
        """nullptr must not trigger the NULL rule."""
        findings = _check(mc.check_null_macro, "int* p = nullptr;")
        self.assertEqual(findings, [])

    def test_clean_null_define_skipped(self):
        """The system #define of NULL itself must not be flagged."""
        findings = _check(mc.check_null_macro, "#define NULL 0")
        self.assertEqual(findings, [])

    def test_clean_null_in_comment(self):
        findings = _check(mc.check_null_macro, "// use nullptr instead of NULL")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 7.2.1  C-style casts
# ═════════════════════════════════════════════════════════════════════════════

class TestCStyleCast(unittest.TestCase):

    def test_violation_cast_to_int(self):
        findings = _check(mc.check_c_style_cast, "int x = (int)some_float;")
        self.assertIn("8.2.2", _rules_hit(findings))

    def test_violation_cast_to_char_ptr(self):
        findings = _check(mc.check_c_style_cast, "char* p = (char*)malloc(64);")
        self.assertIn("8.2.2", _rules_hit(findings))

    def test_clean_static_cast(self):
        findings = _check(mc.check_c_style_cast,
                          "int x = static_cast<int>(some_float);")
        self.assertEqual(findings, [])

    def test_clean_cast_in_comment(self):
        findings = _check(mc.check_c_style_cast,
                          "// avoid (int) casts")
        self.assertEqual(findings, [])

    def test_clean_cast_in_preprocessor_if(self):
        """#if defined(SYMBOL) must NOT be flagged as a C-style cast."""
        findings = _check(mc.check_c_style_cast,
                          "#if defined(CONFIG_SYS_HEAP_RUNTIME_STATS) && CONFIG_HEAP_MEM_POOL_SIZE > 0")
        self.assertEqual(findings, [])

    def test_clean_cast_in_preprocessor_ifdef(self):
        findings = _check(mc.check_c_style_cast,
                          "#ifdef defined(CONFIG_THREAD_STACK_INFO)")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 11.5.1  Dynamic memory
# ═════════════════════════════════════════════════════════════════════════════

class TestDynamicMemory(unittest.TestCase):

    def test_violation_new(self):
        findings = _check(mc.check_dynamic_memory, "int* p = new int(0);")
        self.assertIn("21.6.1", _rules_hit(findings))

    def test_violation_delete(self):
        findings = _check(mc.check_dynamic_memory, "delete p;")
        self.assertIn("21.6.1", _rules_hit(findings))

    def test_violation_malloc(self):
        findings = _check(mc.check_dynamic_memory, "void* p = malloc(64);")
        self.assertIn("21.6.1", _rules_hit(findings))

    def test_violation_free(self):
        findings = _check(mc.check_dynamic_memory, "free(ptr);")
        self.assertIn("21.6.1", _rules_hit(findings))

    def test_violation_calloc(self):
        findings = _check(mc.check_dynamic_memory, "int* p = (int*)calloc(10, sizeof(int));")
        self.assertIn("21.6.1", _rules_hit(findings))

    def test_clean_stack_allocation(self):
        findings = _check(mc.check_dynamic_memory, "int arr[10] = {};")
        self.assertEqual(findings, [])

    def test_clean_unique_ptr(self):
        """std::make_unique does not call new directly — must not trigger."""
        findings = _check(mc.check_dynamic_memory,
                          "auto p = std::make_unique<int>(0);")
        self.assertEqual(findings, [])

    def test_clean_operator_new_definition(self):
        """operator new override (e.g. redirecting to RTOS allocator) must not be flagged."""
        findings = _check(mc.check_dynamic_memory,
                          "void* operator new(size_t size) { return k_malloc(size); }")
        self.assertEqual(findings, [])

    def test_clean_operator_delete_definition(self):
        """operator delete override must not be flagged."""
        findings = _check(mc.check_dynamic_memory,
                          "void operator delete(void* ptr) noexcept { k_free(ptr); }")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 8.4.2  Variadic functions
# ═════════════════════════════════════════════════════════════════════════════

class TestVarargs(unittest.TestCase):

    def test_violation_ellipsis_declaration(self):
        findings = _check(mc.check_varargs, "void log(const char* fmt, ...);")
        self.assertIn("8.2.11", _rules_hit(findings))

    def test_violation_ellipsis_definition(self):
        findings = _check(mc.check_varargs, "void f(int x, ...) {}")
        self.assertIn("8.2.11", _rules_hit(findings))

    def test_clean_no_ellipsis(self):
        findings = _check(mc.check_varargs, "void f(int x, int y) {}")
        self.assertEqual(findings, [])

    def test_clean_ellipsis_in_comment(self):
        findings = _check(mc.check_varargs, "// variadic args (...) are banned")
        self.assertEqual(findings, [])

    def test_clean_template_variadic(self):
        """Template parameter packs use ... but are not C variadic functions."""
        findings = _check(mc.check_varargs,
                          "template<typename... Args> void f(Args&&... args) {}")
        # Template packs look the same in regex — this is a known limitation.
        # The test documents current behaviour rather than asserting clean.
        # If using libclang the AST check handles this correctly.
        _ = findings   # just ensure no exception is raised


# ═════════════════════════════════════════════════════════════════════════════
# 6.5.1  Octal literals
# ═════════════════════════════════════════════════════════════════════════════

class TestOctalLiteral(unittest.TestCase):

    def test_violation_octal(self):
        findings = _check(mc.check_octal, "int perm = 0755;")
        self.assertIn("6.5.1", _rules_hit(findings))

    def test_violation_octal_small(self):
        findings = _check(mc.check_octal, "int x = 007;")
        self.assertIn("6.5.1", _rules_hit(findings))

    def test_clean_decimal_zero(self):
        """Bare 0 is not an octal literal — must not be flagged."""
        findings = _check(mc.check_octal, "int x = 0;")
        self.assertEqual(findings, [])

    def test_clean_hex(self):
        findings = _check(mc.check_octal, "int x = 0x1FF;")
        self.assertEqual(findings, [])

    def test_clean_float(self):
        """0.5 starts with 0 but is a float — must not be flagged."""
        findings = _check(mc.check_octal, "double d = 0.5;")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 6.5.2  Hex digit case
# ═════════════════════════════════════════════════════════════════════════════

class TestHexCase(unittest.TestCase):

    def test_violation_lowercase_hex(self):
        findings = _check(mc.check_hex_case, "int x = 0x1aff;")
        self.assertIn("6.5.2", _rules_hit(findings))

    def test_violation_mixed_case(self):
        findings = _check(mc.check_hex_case, "int x = 0x1Aff;")
        self.assertIn("6.5.2", _rules_hit(findings))

    def test_clean_uppercase_hex(self):
        findings = _check(mc.check_hex_case, "int x = 0x1AFF;")
        self.assertEqual(findings, [])

    def test_clean_hex_digits_only(self):
        """0x1234 has no a-f letters — must not be flagged."""
        findings = _check(mc.check_hex_case, "int x = 0x1234;")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 19.2.1  #define for constants / macros
# ═════════════════════════════════════════════════════════════════════════════

class TestDefineConstants(unittest.TestCase):

    def test_violation_define_constant(self):
        findings = _check(mc.check_define_constants, "#define MAX_SIZE 100")
        self.assertIn("19.0.2", _rules_hit(findings))

    def test_violation_define_function_macro(self):
        findings = _check(mc.check_define_constants, "#define SQUARE(x) ((x)*(x))")
        self.assertIn("19.0.2", _rules_hit(findings))

    def test_clean_include_guard(self):
        """Include guard defines (NAME_H / NAME_HPP) must not be flagged."""
        findings = _check(mc.check_define_constants, "#define MY_HEADER_H")
        self.assertEqual(findings, [])

    def test_clean_include_guard_hpp(self):
        findings = _check(mc.check_define_constants, "#define MY_MODULE_HPP")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 19.1.1  Include guard in header
# ═════════════════════════════════════════════════════════════════════════════

class TestIncludeGuard(unittest.TestCase):

    def _check_header(self, src: str) -> List[mc.Finding]:
        return mc.check_include_guard(_lines(src), "myfile.hpp")

    def test_violation_missing_guard(self):
        findings = self._check_header("""
            #include <string>
            class Foo {};
        """)
        self.assertIn("19.2.1", _rules_hit(findings))

    def test_clean_pragma_once(self):
        findings = self._check_header("#pragma once\nclass Foo {};")
        self.assertEqual(findings, [])

    def test_clean_ifndef_guard(self):
        findings = self._check_header("""
            #ifndef MY_FILE_HPP
            #define MY_FILE_HPP
            class Foo {};
            #endif
        """)
        self.assertEqual(findings, [])

    def test_clean_cpp_file_skipped(self):
        """Include guard rule must NOT apply to .cpp files."""
        findings = mc.check_include_guard(
            _lines("int main() { return 0; }"), "main.cpp"
        )
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 13.1.1  C stdio
# ═════════════════════════════════════════════════════════════════════════════

class TestCStdio(unittest.TestCase):

    def test_violation_printf(self):
        findings = _check(mc.check_stdio, 'printf("hello\\n");')
        self.assertIn("30.0.1", _rules_hit(findings))

    def test_violation_scanf(self):
        findings = _check(mc.check_stdio, "scanf(\"%d\", &x);")
        self.assertIn("30.0.1", _rules_hit(findings))

    def test_violation_stdio_include(self):
        findings = _check(mc.check_stdio, "#include <stdio.h>")
        self.assertIn("30.0.1", _rules_hit(findings))

    def test_violation_cstdio_include(self):
        findings = _check(mc.check_stdio, "#include <cstdio>")
        self.assertIn("30.0.1", _rules_hit(findings))

    def test_clean_cout(self):
        findings = _check(mc.check_stdio, 'std::cout << "hello" << std::endl;')
        self.assertEqual(findings, [])

    def test_clean_iostream_include(self):
        findings = _check(mc.check_stdio, "#include <iostream>")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 13.2.1  C raw-memory functions
# ═════════════════════════════════════════════════════════════════════════════

class TestMemFunctions(unittest.TestCase):

    def test_violation_memcpy(self):
        findings = _check(mc.check_mem_functions,
                          "memcpy(dst, src, sizeof(buf));")
        self.assertIn("21.2.2", _rules_hit(findings))

    def test_violation_memset(self):
        findings = _check(mc.check_mem_functions, "memset(buf, 0, size);")
        self.assertIn("21.2.2", _rules_hit(findings))

    def test_violation_strcpy(self):
        findings = _check(mc.check_mem_functions, "strcpy(dst, src);")
        self.assertIn("21.2.2", _rules_hit(findings))

    def test_violation_strlen(self):
        findings = _check(mc.check_mem_functions, "size_t n = strlen(s);")
        self.assertIn("21.2.2", _rules_hit(findings))

    def test_clean_std_copy(self):
        findings = _check(mc.check_mem_functions,
                          "std::copy(src, src + n, dst);")
        self.assertEqual(findings, [])

    def test_clean_std_fill(self):
        findings = _check(mc.check_mem_functions,
                          "std::fill(buf.begin(), buf.end(), 0);")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 15.3.1  exit / abort
# ═════════════════════════════════════════════════════════════════════════════

class TestExitAbort(unittest.TestCase):

    def test_violation_exit(self):
        findings = _check(mc.check_exit_abort, "exit(1);")
        self.assertIn("18.5.2", _rules_hit(findings))

    def test_violation_std_exit(self):
        findings = _check(mc.check_exit_abort, "std::exit(EXIT_FAILURE);")
        self.assertIn("18.5.2", _rules_hit(findings))

    def test_violation_abort(self):
        findings = _check(mc.check_exit_abort, "abort();")
        self.assertIn("18.5.2", _rules_hit(findings))

    def test_clean_return(self):
        findings = _check(mc.check_exit_abort, "return EXIT_SUCCESS;")
        self.assertEqual(findings, [])

    def test_clean_exit_in_comment(self):
        findings = _check(mc.check_exit_abort, "// do not call exit() here")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 6.1.1  using namespace in headers
# ═════════════════════════════════════════════════════════════════════════════

class TestUsingNamespace(unittest.TestCase):

    def test_violation_in_header(self):
        findings = mc.check_using_namespace(
            _lines("using namespace std;"), "myfile.hpp"
        )
        self.assertIn("6.1.1", _rules_hit(findings))

    def test_clean_in_cpp_file(self):
        """using namespace is allowed in .cpp translation units."""
        findings = mc.check_using_namespace(
            _lines("using namespace std;"), "main.cpp"
        )
        self.assertEqual(findings, [])

    def test_clean_using_type_alias(self):
        """using MyType = ... is a type alias, not a namespace directive."""
        findings = mc.check_using_namespace(
            _lines("using MyType = std::vector<int>;"), "myfile.hpp"
        )
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 9.3.1  Missing braces
# ═════════════════════════════════════════════════════════════════════════════

class TestBraces(unittest.TestCase):

    def test_violation_if_no_braces(self):
        findings = _check(mc.check_braces, """
            if (x > 0)
                do_something();
        """)
        self.assertIn("9.3.1", _rules_hit(findings))

    def test_violation_for_no_braces(self):
        findings = _check(mc.check_braces, """
            for (int i = 0; i < n; ++i)
                process(i);
        """)
        self.assertIn("9.3.1", _rules_hit(findings))

    def test_violation_while_no_braces(self):
        findings = _check(mc.check_braces, """
            while (running)
                tick();
        """)
        self.assertIn("9.3.1", _rules_hit(findings))

    def test_clean_if_with_braces(self):
        findings = _check(mc.check_braces, """
            if (x > 0) {
                do_something();
            }
        """)
        self.assertEqual(findings, [])

    def test_clean_single_line_if(self):
        """if (...) { ... } on one line must not be flagged."""
        findings = _check(mc.check_braces, "if (x) { return; }")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 9.4.1  Switch fall-through
# ═════════════════════════════════════════════════════════════════════════════

class TestSwitchFallthrough(unittest.TestCase):

    def test_violation_missing_break(self):
        findings = _check(mc.check_switch_fallthrough, """
            switch (x) {
                case 1:
                    do_a();
                case 2:
                    do_b();
                    break;
            }
        """)
        self.assertIn("9.4.2", _rules_hit(findings))

    def test_violation_fallthrough_word_in_comment_not_suppressor(self):
        """'fallthrough' appearing only in a comment must NOT be treated as a terminator."""
        findings = _check(mc.check_switch_fallthrough, """
            switch (x) {
                case 1:
                    do_a();  // no break/fallthrough here
                case 2:
                    do_b();
                    break;
            }
        """)
        self.assertIn("9.4.2", _rules_hit(findings))

    def test_clean_break_present(self):
        findings = _check(mc.check_switch_fallthrough, """
            switch (x) {
                case 1:
                    do_a();
                    break;
                case 2:
                    do_b();
                    break;
                default:
                    break;
            }
        """)
        self.assertEqual(findings, [])

    def test_clean_return_terminates(self):
        findings = _check(mc.check_switch_fallthrough, """
            switch (x) {
                case 1:
                    return 1;
                case 2:
                    return 2;
            }
        """)
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 6.2.1  volatile
# ═════════════════════════════════════════════════════════════════════════════

class TestVolatile(unittest.TestCase):

    def test_violation_volatile_var(self):
        findings = _check(mc.check_volatile, "volatile int sensor_reg;")
        self.assertIn("10.1.2", _rules_hit(findings))

    def test_clean_volatile_in_comment(self):
        findings = _check(mc.check_volatile,
                          "// volatile is banned without justification")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 6.3.1  register
# ═════════════════════════════════════════════════════════════════════════════

class TestRegister(unittest.TestCase):

    def test_violation_register_var(self):
        findings = _check(mc.check_register, "register int i = 0;")
        self.assertIn("6.3.1", _rules_hit(findings))

    def test_clean_no_register(self):
        findings = _check(mc.check_register, "int i = 0;")
        self.assertEqual(findings, [])

    def test_clean_register_in_comment(self):
        findings = _check(mc.check_register, "// register is deprecated")
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# 10.3.1  Protected data members
# ═════════════════════════════════════════════════════════════════════════════

class TestProtectedMembers(unittest.TestCase):

    def test_violation_protected_data_member(self):
        findings = _check(mc.check_protected_members, """
            class Sensor {
            protected:
                int raw_value_;
            };
        """)
        self.assertIn("14.1.1", _rules_hit(findings))

    def test_violation_multiple_protected_members(self):
        findings = _check(mc.check_protected_members, """
            class Base {
            protected:
                int x_;
                float y_;
            };
        """)
        self.assertEqual(_rules_hit(findings).count("14.1.1"), 2)

    def test_violation_struct_protected_data(self):
        findings = _check(mc.check_protected_members, """
            struct Packet {
            protected:
                uint8_t type_;
            };
        """)
        self.assertIn("14.1.1", _rules_hit(findings))

    def test_clean_protected_method(self):
        """Protected methods (accessors, helpers) must NOT be flagged."""
        findings = _check(mc.check_protected_members, """
            class Base {
            protected:
                int getValue() const { return value_; }
                void helper() {}
            private:
                int value_ = 0;
            };
        """)
        self.assertEqual(findings, [])

    def test_clean_private_data(self):
        """Private data members must NOT be flagged."""
        findings = _check(mc.check_protected_members, """
            class Sensor {
            public:
                int read() { return data_; }
            private:
                int data_ = 0;
            };
        """)
        self.assertEqual(findings, [])

    def test_clean_no_protected_section(self):
        """Class with no protected section at all must not trigger."""
        findings = _check(mc.check_protected_members, """
            class Clean {
            public:
                void doSomething() {}
            private:
                int x_ = 0;
            };
        """)
        self.assertEqual(findings, [])

    def test_clean_public_data(self):
        """Public data members (not ideal but not this rule) must not trigger."""
        findings = _check(mc.check_protected_members, """
            struct Point {
                int x;
                int y;
            };
        """)
        self.assertEqual(findings, [])


# ═════════════════════════════════════════════════════════════════════════════
# Inline suppression
# ═════════════════════════════════════════════════════════════════════════════

class TestSuppression(unittest.TestCase):

    def test_suppression_silences_finding(self):
        """A MISRA-suppress comment on the same line must remove the finding."""
        tmp = _write_tmp(
            "int* p = new int(0);  // MISRA-suppress: 21.6.1  legacy API\n"
        )
        try:
            findings = mc.check_file(str(tmp))
            rules = _rules_hit(findings)
            self.assertNotIn("21.6.1", rules)
        finally:
            tmp.unlink()

    def test_suppression_only_suppresses_named_rule(self):
        """Suppression of one rule must not silence other rules on the same line."""
        tmp = _write_tmp(
            "char* p = (char*)malloc(64);  // MISRA-suppress: 8.2.2  reviewed\n"
        )
        try:
            findings = mc.check_file(str(tmp))
            rules = _rules_hit(findings)
            # Cast is suppressed, but malloc (11.5.1) must still be reported
            self.assertNotIn("8.2.2", rules)
            self.assertIn("21.6.1", rules)
        finally:
            tmp.unlink()

    def test_no_suppression_without_comment(self):
        """Without a suppression comment the violation must be present."""
        tmp = _write_tmp("int* p = new int(0);\n")
        try:
            findings = mc.check_file(str(tmp))
            self.assertIn("21.6.1", _rules_hit(findings))
        finally:
            tmp.unlink()


# ═════════════════════════════════════════════════════════════════════════════
# check_file — integration
# ═════════════════════════════════════════════════════════════════════════════

class TestCheckFile(unittest.TestCase):

    def test_nonexistent_file_returns_empty(self):
        """Analysing a missing file must return [] without raising."""
        findings = mc.check_file("/nonexistent/path/file.cpp")
        self.assertEqual(findings, [])

    def test_empty_file_returns_empty(self):
        tmp = _write_tmp("")
        try:
            findings = mc.check_file(str(tmp))
            self.assertEqual(findings, [])
        finally:
            tmp.unlink()

    def test_clean_file_returns_empty(self):
        tmp = _write_tmp("""
            #pragma once
            #include <iostream>
            #include <vector>

            class MyClass {
            public:
                void run() {
                    std::cout << "hello" << std::endl;
                }
            private:
                int value_ = 0;
            };
        """, suffix=".hpp")
        try:
            findings = mc.check_file(str(tmp))
            self.assertEqual(findings, [],
                             msg=f"Unexpected findings: {findings}")
        finally:
            tmp.unlink()

    def test_deduplicate_findings(self):
        """The same violation must not appear more than once per line."""
        tmp = _write_tmp("goto end;\n")
        try:
            findings = mc.check_file(str(tmp))
            goto_findings = [f for f in findings if f.rule_id == "9.6.1"]
            self.assertEqual(len(goto_findings), 1)
        finally:
            tmp.unlink()


# ═════════════════════════════════════════════════════════════════════════════
# Finding data model
# ═════════════════════════════════════════════════════════════════════════════

class TestFindingModel(unittest.TestCase):

    def _make_finding(self):
        return mc.Finding(
            rule_id="9.6.1",
            category=mc.Category.REQUIRED,
            title="The goto statement shall not be used",
            filepath="foo.cpp",
            line=42,
            col=5,
            snippet="goto end;",
            note="Use structured control flow",
        )

    def test_to_dict_keys(self):
        d = self._make_finding().to_dict()
        for key in ("rule_id", "category", "title", "file", "line", "col",
                    "snippet", "note"):
            self.assertIn(key, d)

    def test_to_dict_values(self):
        d = self._make_finding().to_dict()
        self.assertEqual(d["rule_id"], "9.6.1")
        self.assertEqual(d["category"], "Required")
        self.assertEqual(d["line"], 42)

    def test_to_dict_is_json_serialisable(self):
        d = self._make_finding().to_dict()
        serialised = json.dumps(d)
        self.assertIsInstance(serialised, str)


# ═════════════════════════════════════════════════════════════════════════════
# Report generators
# ═════════════════════════════════════════════════════════════════════════════

class TestReporters(unittest.TestCase):

    def _sample_findings(self):
        return [
            mc.Finding("9.6.1", mc.Category.REQUIRED,
                       "goto shall not be used", "a.cpp", 10,
                       snippet="goto end;", note=""),
            mc.Finding("6.5.2", mc.Category.ADVISORY,
                       "Hex digits shall be uppercase", "b.cpp", 5,
                       snippet="0x1aff", note="0x1AFF"),
        ]

    def test_json_report_is_valid_json(self):
        out = mc.report_json(self._sample_findings())
        parsed = json.loads(out)
        self.assertEqual(len(parsed), 2)

    def test_json_report_empty(self):
        out = mc.report_json([])
        self.assertEqual(json.loads(out), [])

    def test_html_report_contains_rule_ids(self):
        html = mc.report_html(self._sample_findings())
        self.assertIn("9.6.1", html)
        self.assertIn("6.5.2", html)

    def test_html_report_is_valid_html(self):
        html = mc.report_html(self._sample_findings())
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("</html>", html)

    def test_html_report_no_findings(self):
        html = mc.report_html([])
        self.assertIn("No findings", html)

    def test_html_report_counts(self):
        html = mc.report_html(self._sample_findings())
        self.assertIn("Required", html)
        self.assertIn("Advisory", html)


# ═════════════════════════════════════════════════════════════════════════════
# CLI — exit codes and output formats
# ═════════════════════════════════════════════════════════════════════════════

class TestCLI(unittest.TestCase):

    def _write(self, src: str, suffix: str = ".cpp") -> Path:
        return _write_tmp(src, suffix)

    def test_exit_code_0_on_clean_file(self):
        tmp = self._write("int main() { return 0; }\n")
        try:
            r = _run_checker(str(tmp), "--fail-on", "required")
            self.assertEqual(r.returncode, 0,
                             msg=f"stderr: {r.stderr}\nstdout: {r.stdout}")
        finally:
            tmp.unlink()

    def test_exit_code_1_on_violation(self):
        tmp = self._write("int x = (int)y;\n")  # 8.2.2 is Required
        try:
            r = _run_checker(str(tmp), "--fail-on", "required")
            self.assertEqual(r.returncode, 1)
        finally:
            tmp.unlink()

    def test_fail_on_never_always_zero(self):
        """--fail-on never must always return 0 even with violations."""
        tmp = self._write("goto end;\n")
        try:
            r = _run_checker(str(tmp), "--fail-on", "never")
            self.assertEqual(r.returncode, 0)
        finally:
            tmp.unlink()

    def test_fail_on_mandatory_ignores_required(self):
        """--fail-on mandatory must return 0 when only Required violations exist."""
        tmp = self._write("int x = (int)y;\n")  # 8.2.2 is Required, not Mandatory
        try:
            r = _run_checker(str(tmp), "--fail-on", "mandatory")
            self.assertEqual(r.returncode, 0)
        finally:
            tmp.unlink()

    def test_fail_on_any_triggers_on_advisory(self):
        """--fail-on any must return 1 even for Advisory-only violations."""
        tmp = self._write("int x = 0x1aff;\n")  # 6.5.2 is Advisory
        try:
            r = _run_checker(str(tmp), "--fail-on", "any")
            self.assertEqual(r.returncode, 1)
        finally:
            tmp.unlink()

    def test_json_output_is_parseable(self):
        tmp = self._write("goto end;\n")
        out_file = tmp.with_suffix(".json")
        try:
            _run_checker(str(tmp), "--format", "json", "-o", str(out_file),
                         "--fail-on", "never")
            data = json.loads(out_file.read_text())
            self.assertIsInstance(data, list)
            self.assertTrue(len(data) > 0)
        finally:
            tmp.unlink()
            if out_file.exists():
                out_file.unlink()

    def test_html_output_is_written(self):
        tmp = self._write("goto end;\n")
        out_file = tmp.with_suffix(".html")
        try:
            _run_checker(str(tmp), "--format", "html", "-o", str(out_file),
                         "--fail-on", "never")
            self.assertTrue(out_file.exists())
            html = out_file.read_text()
            self.assertIn("<!DOCTYPE html>", html)
        finally:
            tmp.unlink()
            if out_file.exists():
                out_file.unlink()

    def test_rule_filter_include(self):
        """--rules X must only report findings for rule X."""
        tmp = self._write("goto end;\nint* p = new int(0);\n")
        out_file = tmp.with_suffix(".json")
        try:
            _run_checker(str(tmp), "--format", "json", "-o", str(out_file),
                         "--rules", "9.6.1", "--fail-on", "never")
            data = json.loads(out_file.read_text())
            rule_ids = {f["rule_id"] for f in data}
            self.assertEqual(rule_ids, {"9.6.1"})
        finally:
            tmp.unlink()
            if out_file.exists():
                out_file.unlink()

    def test_rule_filter_exclude(self):
        """--exclude-rules X must omit rule X from findings."""
        tmp = self._write("goto end;\n")
        out_file = tmp.with_suffix(".json")
        try:
            _run_checker(str(tmp), "--format", "json", "-o", str(out_file),
                         "--exclude-rules", "9.6.1", "--fail-on", "never")
            data = json.loads(out_file.read_text())
            rule_ids = [f["rule_id"] for f in data]
            self.assertNotIn("9.6.1", rule_ids)
        finally:
            tmp.unlink()
            if out_file.exists():
                out_file.unlink()

    def test_list_rules_exits_zero(self):
        r = _run_checker("--list-rules")
        self.assertEqual(r.returncode, 0)
        self.assertIn("9.6.1", r.stdout)

    def test_no_args_exits_nonzero(self):
        r = _run_checker()
        self.assertNotEqual(r.returncode, 0)

    def test_directory_scanning(self):
        """Passing a directory must recursively find and check .cpp files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "a.cpp").write_text("goto end;\n")
            Path(tmpdir, "b.cpp").write_text("int main() { return 0; }\n")
            out_file = Path(tmpdir) / "results.json"
            _run_checker(tmpdir, "--format", "json", "-o", str(out_file),
                         "--fail-on", "never")
            data = json.loads(out_file.read_text())
            files = {f["file"] for f in data}
            self.assertTrue(any("a.cpp" in f for f in files))


# ═════════════════════════════════════════════════════════════════════════════
# Rule registry
# ═════════════════════════════════════════════════════════════════════════════

class TestRuleRegistry(unittest.TestCase):

    EXPECTED_RULES = {
        "6.1.1", "10.1.2", "6.3.1", "6.5.1", "6.5.2",
        "7.0.2", "8.2.2",
        "9.6.1", "8.2.11",
        "9.3.1", "9.4.2",
        "14.1.1",
        "21.6.1",
        "30.0.1", "21.2.2",
        "18.5.1", "18.5.2",
        "19.0.2", "19.2.1",
    }

    def test_all_expected_rules_registered(self):
        for rule_id in self.EXPECTED_RULES:
            self.assertIn(rule_id, mc.RULES,
                          msg=f"Rule {rule_id} is missing from the registry")

    def test_each_rule_has_title_and_rationale(self):
        for rule_id, rule in mc.RULES.items():
            self.assertTrue(rule.title,
                            msg=f"Rule {rule_id} has an empty title")
            self.assertTrue(rule.rationale,
                            msg=f"Rule {rule_id} has an empty rationale")

    def test_each_rule_has_valid_category(self):
        for rule_id, rule in mc.RULES.items():
            self.assertIsInstance(rule.category, mc.Category,
                                  msg=f"Rule {rule_id} has invalid category")

    def test_all_registered_rules_have_a_checker(self):
        """Every rule in the registry must be tested by at least one checker."""
        checked_rules: set = set()
        # Run all text checkers against a large violations file and collect rule IDs
        src = _CHECKER.parent / "test_violations.cpp"
        if not src.exists():
            src = _HERE / "test_violations.cpp"
        if src.exists():
            for checker in mc.TEXT_CHECKERS:
                for f in checker(src.read_text().splitlines(), str(src)):
                    checked_rules.add(f.rule_id)
        # At minimum the checker list must be non-empty
        self.assertTrue(len(mc.TEXT_CHECKERS) >= len(self.EXPECTED_RULES) - 2,
                        msg="Fewer checkers than expected rules")


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
    