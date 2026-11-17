# CISB-Guard: Compiler-Induced Security Bug Mitigations

An automated compiler security and verification framework for detecting, mitigating, and benchmarking **Compiler-Induced Security Bugs (CISBs)** across modern C/LLVM compilation pipelines.

This repository implements real LLVM 18 passes and Clang AST rewriters adhering to **OSpec1**, **ISpec1**, and **ISpec2** specifications to prevent security-critical code elimination during aggressive optimization (`-O3`).

---

## Architecture Overview

```text
CISB-compiler-induced-security-bugs/
├── Dockerfile                    # Ubuntu 24.04 + LLVM/Clang 18 toolchain
├── docker-compose.yml            # Containerized deployment on :8080
├── CMakeLists.txt                # Builds libCISBGuard.so & ub-check-guard
├── start-demo.bat                # Health-checked race-free launcher
├── UPGRADE_PLAN.md               # Complete specification & audit roadmap
├── PROJECT_PLAN.md               # Course implementation plan & architecture
├── bin/
│   ├── cisb-guard-cc             # Unified CLI compiler wrapper
│   └── cisb_guard_cc.py          # AST rewrite & pass-plugin driver
├── src/
│   ├── llvm_plugin/              # LLVM 18 New Pass Manager Plugin (libCISBGuard.so)
│   │   ├── CISBGuardPlugin.cpp   # Pass registration & opt pipeline hooks
│   │   ├── ScrubGuardPass.cpp    # OSpec1: DSE secret-scrubbing guard & memory barrier
│   │   ├── ScrubGuardPass.h
│   │   ├── UndefFreezePass.cpp   # ISpec1: CISBFuzz undef/poison freeze guard
│   │   ├── UndefFreezePass.h
│   │   ├── CFGVerifyPass.cpp     # ISpec2: Pre/Post-Opt XOR post-dominance audit
│   │   └── CFGVerifyPass.h
│   └── clang_tool/
│       └── UBCheckGuard.cpp      # Clang LibTooling AST Rewriter
├── tests/
│   ├── cases/                    # 12 Real C & LLVM-IR test cases with exit-code oracles
│   │   ├── 01_stack_key_leak.c        # OSpec1: Stack key leak via dead-store elimination
│   │   ├── 02_password_scrub.c        # OSpec1: High-privilege password wiping
│   │   ├── 03_crypto_hash_scrub.c     # OSpec1: Linux random.c entropy hash scrub
│   │   ├── 04_unnamed_dead_memset.c   # OSpec1: Anonymous buffer dead zero-store CFG check
│   │   ├── 05_signed_overflow_check.c # ISpec1: if (x + c < x) upper-bound check deleted by -O3
│   │   ├── 06_signed_overflow_gt.c    # ISpec1: if (a + 10 > a) lower-bound check folded
│   │   ├── 07_post_deref_null_check.c # ISpec1: GCC Bug 33629 (*p then if (p))
│   │   ├── 08_int_promotion_u8.c      # ISpec1: GCC Bug 87060 narrow uint8_t promotion
│   │   ├── 09_undef_ssce_mutant.ll    # ISpec1: CISBFuzz Fig. 5 EarlyCSE undef erasure
│   │   ├── 10_div_zero_check_audit.c  # ISpec2: Debian Bug 616180 division-by-zero check audit
│   │   ├── 11_failure_cfg_check.c     # ISpec2: Linux kernel VM_SHARED/BUG() XOR post-dominance
│   │   └── 12_null_check_survival.c   # ISpec1/ISpec2: Pre/Post-Opt check survival audit
│   ├── benchmarks/               # Compute workloads for overhead profiling
│   │   ├── bench_sha256.c        # SHA-256 block hashing
│   │   ├── bench_quicksort.c     # Quicksort 500k pseudo-random integers
│   │   └── bench_matmul.c        # 256x256 double-precision matrix multiplication
│   └── verify_all.py             # Complete automated test runner & assertion suite
├── backend/
│   ├── app.py                    # Hardened HTTP API (path traversal defended)
│   ├── runner.py                 # Live subprocess compiler, objdump & execution engine
│   └── benchmark.py              # 5-strategy benchmarking & chart generator
├── results/
│   ├── benchmark_results.json    # Real measured execution times & overhead
│   ├── security_vs_overhead.png  # Overhead comparison Pareto chart
│   └── audit.json                # Structured compiler audit records
└── web/
    ├── index.html                # Interactive 6-view presentation dashboard
    ├── styles.css                # Polished dark mode styling
    └── app.js                    # Live execution & audit UI logic
```

---

## Measured Performance & Security Results

Real measurements comparing 5 compilation strategies on identical hardware:

| Compilation Strategy | Security Protection Rate | Geometric Mean Overhead vs. `-O3` |
|---|:---:|:---:|
| **Clang `-O3` (Baseline)** | **0.0%** (0/12 protected) | `0.00%` (Reference) |
| **Clang `-O3 -Wall`** | **0.0%** (0/12 protected) | `+0.54%` |
| **Clang `-O3 -fsanitize=undefined`** | **25.0%** (3/12 protected) | Runtime crash / heavy overhead |
| **Clang `-O0`** | **66.7%** (8/12 protected) | `+134.63%` (2.35x slower) |
| **CISB-Guard (`-O3`)** | **100.0%** (12/12 protected) | **`+0.41%` to `+0.68%` (< 1% overhead!)** |

---

## Quickstart

### 1. Launching the Interactive Web Dashboard
Double-click `start-demo.bat` on Windows or execute:
```bash
python app.py
```
Open **http://localhost:8080** in your browser. The dashboard provides 6 presentation tabs:
* **Live Exploit Showcases**: Instant visual side-by-side comparison of baseline exploit triggering vs. CISB-Guard defense.
* **Test Cases Explorer**: Detailed inspection of all 12 test cases with raw C source, live `objdump -d` disassembly diffs, and compiler flags.
* **12-Case Matrix**: Complete test suite matrix with one-click re-execution.
* **Performance Benchmarks**: Interactive charts and runtime overhead comparison across SHA-256, Quicksort, and MatMul.
* **LLVM CFG Audit Log**: Real-time inspection of compiler optimization actions and memory barriers.
* **Viva Q&A & Architecture Guide**: Answers to the top academic questions professors ask during viva examinations.

### 2. Running Automated Verification
To verify that every test triggers under `-O3`, passes under CISB-Guard, and that path traversal attacks are blocked:
```bash
python tests/verify_all.py
```

### 3. Running via Docker (Ubuntu 24.04 + LLVM 18)
```bash
docker compose up --build
```
Navigate to `http://localhost:8080`.

---

## Mitigation Specifications

### 1. OSpec1: Dead-Store Elimination (`ScrubGuardPass`)
* **Problem**: In cryptographic code (e.g. `memset(secret, 0, len)`), dead store elimination (DSE) detects that `secret` is an `AllocaInst` whose lifetime ends at function return and deletes the write.
* **Mitigation**: Marks `MSI->setVolatile(true)` and inserts an `InlineAsm` memory barrier (`asm volatile("" : : "r"(buf) : "memory")`), forcing zeroing stores to be retained in object code.

### 2. ISpec1: Undefined Behavior Check Rewriting (`ub-check-guard` / `UndefFreezePass`)
* **Signed Overflow**: Rewrites `if (x + c < x)` to `__builtin_add_overflow((x), (c), &(int){0})` so the optimizer does not delete bounds checks under signed UB assumptions.
* **Post-Dereference Null Checks**: GCC Bug 33629 / Linux kernel CVE: Inserts `__asm__ __volatile__("" : "+r"(p))` before `if (!p)` so upstream dereferences do not cause downstream checks to be deleted.
* **Integer Promotion**: Explicitly restores modular semantics on narrow types (`uint8_t`) with explicit narrowing casts `(uint8_t)(u8 + 1) == 0`.
* **Undef EarlyCSE Erasure**: Inserts `FreezeInst` on undefined/poison condition operands, preventing EarlyCSE from folding security branches to unconditional paths.

### 3. ISpec2: CFG Dominance Verification (`CFGVerifyPass`)
* **Audit**: Pre-optimization pass identifies security guards via `MustFail(BT) ^ MustFail(BF)` post-dominance analysis and tags sensitive operations with `!cisb.seccheck` / `!cisb.guarded_by`. Post-optimization pass verifies that guards survive aggressive transformations.
