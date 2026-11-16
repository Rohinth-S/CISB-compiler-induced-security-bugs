# CISB-Guard: Course Implementation Plan & Architecture Specification

## Project Overview

**CISB-Guard** is a working compiler-hardening framework and dynamic verification harness designed to mitigate **Compiler-Induced Security Bugs (CISBs)** across the three primary vulnerability classes identified in recent security research (EuroSec '26 / USENIX Security '23):

1. **OSpec1 (Dead Store Elimination on Sensitive Buffers):** Compilers optimizing under ISO C abstract-machine rules discard secret-clearing calls (`memset`) before stack deallocation.
2. **ISpec1 (Deleted Security Checks & Undef Condition Erasure):** Compilers exploiting undefined behavior (signed overflow, post-dereference null checks, integer promotions, and undef-condition propagation) delete user defensive bounds checks.
3. **ISpec2 (Reordered or Circumvented Security Checks):** Path reordering and control-flow optimization moving operations outside the protection boundary of defensive checks.

---

## Completed Architecture & Deliverables

### 1. Dual-Layer Mitigation Engine
* **LLVM 18 IR Pass Plugin (`src/llvm_plugin/`):**
  * `ScrubGuardPass`: Taint-guided def-use analysis marking cryptographic and zero-scrub memory writes as `volatile` with inline memory barriers (`asm volatile("" ::: "memory")`).
  * `UndefFreezePass`: Injects `FreezeInst` on undefined branching conditions to prevent compiler EarlyCSE/SSCE condition erasure.
  * `CFGVerifyPass`: Pre/post-optimization CFG dominator and XOR post-dominance analysis (`MustFail(BT) ^ MustFail(BF)`) verifying defensive boundary survival.
  * `CISBGuardPlugin`: Registers the passes with LLVM 18's New Pass Manager extension points (`EP_OptimizerEarly`, `EP_PipelineStart`).
* **Clang LibTooling AST Rewriter (`src/clang_tool/UBCheckGuard.cpp`):**
  * Normalizes signed overflow expressions `(x + c < x)` into compiler-safe checked intrinsics (`__builtin_add_overflow`).
  * Hoists post-dereference null checks or injects opaque optimization barriers (`asm volatile("" : "+r"(p))`).
  * Inserts explicit narrowing casts on sub-`int` integer promotions (`((uint8_t)(u8 + 1) == 0)`).
* **Unified Compiler Wrapper (`bin/cisb-guard-cc`, `bin/cisb_guard_cc.py`):**
  * Provides a drop-in compiler driver replacing standard `clang`/`gcc`.
  * Emits machine-readable verification and transformation audits (`results/audit.json`).
  * Supports dual execution: full native LLVM 18 plugin mode in Linux/Docker environments and direct AST-hardened compiler execution on Windows hosts.

### 2. Comprehensive 12-Case Security Test Suite (`tests/cases/`)
* **OSpec1:**
  * `01_stack_key_leak.c`: Stack key residue disclosure after return.
  * `02_password_scrub.c`: High-privilege password buffer wiping.
  * `03_crypto_hash_scrub.c`: Linux kernel `drivers/char/random.c` entropy extraction hash scrub.
  * `04_unnamed_dead_memset.c`: Anonymous dead-store CFG reachability analysis.
* **ISpec1:**
  * `05_signed_overflow_check.c`: Upper-bound signed integer wraparound guard.
  * `06_signed_overflow_gt.c`: Lower-bound signed integer wraparound guard (CISBFuzz Fig. 4).
  * `07_post_deref_null_check.c`: Post-dereference defensive pointer check (GCC Bug 33629 / CVE-2009-1897).
  * `08_int_promotion_u8.c`: Narrow `uint8_t` promotion wraparound failure (GCC Bug 87060).
  * `09_undef_ssce_mutant.ll`: EarlyCSE undefined conditional branch folding (EuroSec '26 Fig. 5).
* **ISpec2:**
  * `10_div_zero_check_audit.c`: CFG dominance division-by-zero guard verification (Debian Bug 616180).
  * `11_failure_cfg_check.c`: Linux kernel `VM_SHARED` / `BUG()` XOR post-dominance check discovery.
  * `12_null_check_survival.c`: Pre/post-optimization defensive check survival auditor.

### 3. Empirical Performance Benchmarking (`tests/benchmarks/`)
* Workloads: Cryptographic hashing (`bench_sha256.c`), sorting (`bench_quicksort.c`), and numerical linear algebra (`bench_matmul.c`).
* Evaluates 5 compiler configurations:
  1. `Clang -O3` (Baseline unmitigated)
  2. `Clang -O3 -Wall` (Compiler warning baseline)
  3. `Clang -O3 -fsanitize=undefined` (Sanitizer baseline)
  4. `Clang -O0` (Optimization-disabled baseline)
  5. `CISB-Guard (-O3)` (Hardened release optimization)

### 4. Interactive Web Demonstration Dashboard (`web/`, `backend/`)
* Hardened HTTP API (`backend/app.py`, `backend/runner.py`) running live compilations and binary executions.
* 6 Presentation Views:
  1. **Live Exploit Showcases**: Real-time visual comparison of exploit execution vs. defense.
  2. **Test Cases Explorer**: Interactive C source inspection, disassembly diffs (`objdump -d`), and compiler flags.
  3. **12-Case Matrix**: Comprehensive test matrix with one-click re-execution.
  4. **Performance Benchmarks**: Interactive charts and runtime overhead comparison.
  5. **LLVM CFG Audit Log**: Real-time inspection of compiler optimization actions and memory barriers.
  6. **Viva Q&A & Architecture Guide**: Academic questions, answers, and defense strategies.
