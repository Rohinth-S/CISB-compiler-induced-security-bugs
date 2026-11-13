# CISB Compiler-Induced Security Bugs

Educational, safe simulation dashboard for demonstrating compiler-induced security bugs and mitigation strategies.

## Run
Double-click start-demo.bat on Windows, then open http://localhost:8080. Or run `node server.js`. The dashboard uses only Node.js built-ins and needs no npm install.

The dashboard supports four cases: secret-wipe elimination, null-check removal, integer-promotion wraparound, and constant-time timing changes. It supports baseline/mitigation switching, run-all, and audit JSON export.

## Research-inspired plan
The design follows the supplied CISB research: optimization-sensitive patterns, IR/AST-oriented mitigation ideas, baseline-versus-mitigated cross-validation, audit evidence, and a future path toward a Clang/LLVM wrapper and coverage-guided testing. This repository is a portable classroom simulation, not a production compiler hardening tool.

## Architecture
simulator.py contains deterministic case models and the cross-validation oracle. server.js exposes the dependency-free HTTP API and serves web/. tests/ verifies the logic.

## Professor explanation
1. Source-level security code can be correct.
2. Optimization can change behavior under compiler assumptions.
3. The dashboard models the transformation and runs the same input through baseline and mitigation paths.
4. Mitigations make the security property explicit: check before dereference, preserve a wipe, use checked arithmetic, or use constant-time primitives.
5. Exported audit JSON makes the demonstration repeatable.

## Tests
Run `node tests/smoke.js`. The Python reference implementation and tests are also included for environments with Python installed.



