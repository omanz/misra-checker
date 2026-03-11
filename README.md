# MISRA C++ 2023 Custom Checker

A free, open-source Python tool that checks C++ source code against a representative
subset of **MISRA C++ 2023** rules using regex/text analysis and (optionally) libclang AST.

> ⚠️ **Disclaimer**: Rule IDs are approximate mappings.  
> Always verify against the official [MISRA C++ 2023 specification](https://www.misra.org.uk).  
> This tool does **not** replace a certified MISRA checker (LDRA, Polyspace, PC-lint Plus, etc.).

---

## Implemented Rules

| Rule ID  | Category  | Description |
|----------|-----------|-------------|
| 6.1.1    | Required  | `using namespace` shall not appear at file scope in headers |
| 6.2.1    | Advisory  | `volatile` shall not be used without documented justification |
| 6.3.1    | Required  | The `register` storage-class specifier shall not be used |
| 6.5.1    | Required  | Octal integer literals shall not be used |
| 6.5.2    | Advisory  | Hexadecimal digit letters shall be uppercase (A-F) |
| 7.0.2    | Required  | `NULL` shall not be used; use `nullptr` |
| 7.2.1    | Required  | C-style casts shall not be used |
| 8.1.1    | Required  | `goto` shall not be used |
| 8.4.2    | Required  | Variable-argument functions shall not be defined or called |
| 9.3.1    | Required  | Compound statements (braces) required for all control-flow bodies |
| 9.4.1    | Required  | Every switch-clause shall be terminated by `break`/`return`/`throw`/`[[fallthrough]]` |
| 10.3.1   | Required  | Member data shall be private; protected data members are not permitted |
| 11.5.1   | Required  | Dynamic heap memory (`new`/`delete`/`malloc`/`free`) shall not be used |
| 13.1.1   | Required  | C standard I/O functions shall not be used |
| 13.2.1   | Required  | C raw-memory and string functions shall not be used |
| 15.0.1   | Advisory  | Exceptions shall not escape from destructors or `main()` |
| 15.3.1   | Required  | `std::exit`, `std::abort`, `std::_Exit` shall not be called |
| 19.1.1   | Required  | Each header file shall have an include guard or `#pragma once` |
| 19.2.1   | Required  | `#define` shall not be used for constants or function-like macros |

---

## Installation

```bash
# No external dependencies for basic regex mode
python misra_checker.py src/

# Optional: install libclang for AST-based checks (more accurate)
pip install libclang
```

### Use `pyenv`

It is best if you do not pollute your environment. As a result

1. Create an environment
   ```bash
   pyenv virtualenv misra_checker
   ```
1. Activate it
   ```bash
   pyenv activate misra_checker
   ```
1. Install the dependencies
   ```bash
   pip install libclang
   ```
---

## Usage

```bash
# Check a directory
python misra_checker.py src/

# Check specific files
python misra_checker.py main.cpp utils.cpp

# Generate HTML report
python misra_checker.py src/ --format html -o report.html

# Generate JSON report (for CI integration)
python misra_checker.py src/ --format json -o findings.json

# Check only specific rules
python misra_checker.py src/ --rules 8.1.1,7.2.1,11.5.1

# Exclude advisory rules
python misra_checker.py src/ --exclude-rules 6.2.1,6.5.2

# List all implemented rules
python misra_checker.py --list-rules

# Custom file extensions
python misra_checker.py src/ --ext .cpp,.hpp
```

---

## Exit Codes

| `--fail-on` | Fails when... |
|-------------|---------------|
| `never`     | Never (always 0) |
| `any`       | Any finding exists (including Advisory) |
| `required`  | Any Required or Mandatory finding (default) |
| `mandatory` | Any Mandatory finding |

This makes it easy to integrate in CI/CD:

```yaml
# GitHub Actions example
- name: MISRA C++ check
  run: python misra_checker.py src/ --format json -o misra.json --fail-on required
```

---

## Inline Suppression

Add a suppression comment on the same line to silence a specific rule:

```cpp
int x = (int)legacy_api();  // MISRA-suppress: 7.2.1  legacy API, reviewed by John 2024-01-15
```

Format: `// MISRA-suppress: <rule-id>  <mandatory justification text>`

---

## Pipelines

In the repositories there are 3 `github` workflows:

1. `misra-analysis.yml`: workflow to be used by external users (like students)
   to run an analysis on their code. 
   
   **Note**: the workflow expects the code to
   be in the `src` folder
1. `misra-checker-tests.yml`: workflow to test the checker itself
1. `misra-analysis-no-download.yml`: same as `misra-analysis.yml` but requires
   the `misra_check.py` to be present in the repository. Typically used in the
   present repository.


The source code folders to analyse are specified in `misra.config.json`. Here an
extract:
```bash
{
  "sources": [
    "blinky",
    "semaphores",
    "CarSystem"
  ],
  "fail_on": "required",
  "exclude_rules": [],
  "extensions": ".cpp,.cxx,.cc,.c,.h,.hpp,.hh,.hxx"
}
```
---

## Analysis Modes

### Regex mode (default, always available)
Pure text/regex analysis. Fast, no dependencies. Catches most violations but can
produce false positives in edge cases (e.g. casts inside string literals).

### AST mode (requires `pip install libclang`)
Uses the Clang compiler frontend to build a proper Abstract Syntax Tree.
More accurate for: C-style casts, `goto`, `new`/`delete`, variadic functions.
Results are deduplicated against regex findings.

---

## Comparison with Commercial Tools

| Feature                    | This tool | PC-lint Plus | Polyspace | LDRA |
|----------------------------|-----------|--------------|-----------|------|
| MISRA C++ 2023 certified   | ❌        | ✅           | ✅        | ✅   |
| Cost                       | Free      | ~$1k+/seat   | ~$5k+     | ~$10k+ |
| Rules covered              | ~18       | 250+         | 250+      | 250+ |
| False positive rate        | Medium    | Low          | Very Low  | Very Low |
| CI/CD integration          | ✅        | ✅           | ✅        | ✅   |
| HTML/JSON reports          | ✅        | ✅           | ✅        | ✅   |

**Recommended workflow**: Use this tool for fast feedback during development,
supplement with a certified tool for formal compliance evidence.

---

## Contributing New Rules

Each checker function follows this signature:

```python
def check_my_rule(lines: List[str], fp: str) -> List[Finding]:
    out = []
    for i, line in enumerate(lines, 1):
        if _is_comment_line(line):
            continue
        # ... detection logic ...
        out.append(_make(R_MY_RULE, fp, i, snippet=line, note="explanation"))
    return out
```

Register the rule at the top of the file:

```python
R_MY_RULE = _reg("X.Y.Z", Category.REQUIRED,
    "Rule title",
    "Rationale explaining why this rule exists.")
```

Then add your function to `TEXT_CHECKERS`.
