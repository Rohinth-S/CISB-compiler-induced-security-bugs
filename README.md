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
├── bin/
│   ├── cisb-guard-cc             # Unified CLI compiler wrapper
│   └── cisb_guard_cc.py          # AST rewrite & pass-plugin driver
├── src/
│   ├── llvm_plugin/              # LLVM 18 New Pass Manager Plugin (libCISBGuard.so)
│   │   ├── CISBGuardPlugin.cpp   # Pass registration & opt pipeline hooks
│   │   ├── ScrubGuardPass.cpp    # OSpec1: DSE secret-scrubbing guard & memory barrier
│   │   ├── UndefFreezePass.cpp   # ISpec1: CISBFuzz undef/poison freeze guard
│   │   └── CFGVerifyPass.cpp     # ISpec2: Pre/Post-Opt XOR post-dominance audit
│   └── clang_tool/
│       └── UBCheckGuard.cpp      # Clang LibTooling AST Rewriter
├── tests/
│   ├── cases/                    # 8 Real C & LLVM-IR test cases with exit-code oracles
│   │   ├── 01_secret_wipe.c      # OSpec1: Stack key leak via dead-store elimination
│   │   ├── 02_dead_memset_anon.c # OSpec1: Anonymous buffer dead zero-store CFG check
│   │   ├── 03_signed_overflow.c  # ISpec1: if (offset + 100 < offset) deleted by -O3
│   │   ├── 04_null_after_deref.c # ISpec1: GCC Bug 33629 (*p then if (p))
│   │   ├── 05_int_promotion.c    # ISpec1: GCC Bug 87060 (u8 + 1 == 0)
│   │   ├── 06_undef_ssce.ll      # ISpec1: CISBFuzz Fig. 5 EarlyCSE undef erasure
│   │   ├── 07_div_zero_audit.c   # ISpec2: Debian Bug 616180 CFG dominance audit
│   │   └── 08_cfg_xor_discover.c # ISpec2: Linux kernel XOR post-dominance check
│   ├── benchmarks/               # Compute workloads for overhead profiling
│   │   ├── bench_sha256.c        # SHA-256 block hashing
│   │   ├── bench_quicksort.c     # Quicksort 200k pseudo-random integers
│   │   └── bench_matmul.c        # 256x256 double-precision matrix multiplication
│   └── verify_all.py             # Complete automated test runner & assertion suite
├── backend/
│   ├── app.py                    # Hardened HTTP API (path traversal defended)
│   ├── runner.py                 # Live subprocess compiler, objdump & execution engine
│   └── benchmark.py              # 5-strategy benchmarking & chart generator
├── results/
│   ├── benchmark_results.json    # Real measured execution times & overhead
│   ├── security_vs_overhead.png  # Overhead comparison bar chart
│   └── audit.json                # Structured compiler audit records
└── web/
    ├── index.html                # Interactive split-view dashboard
    ├── styles.css                # Dark mode styling
    └── app.js                    # Live execution & audit UI logic
```

---

## Measured Performance & Security Results

Real measurements comparing 5 compilation strategies on identical hardware:

| Compilation Strategy | Security Protection Rate | Geometric Mean Overhead vs. `-O3` |
|---|:---:|:---:|
| **Clang `-O3` (Baseline)** | **0.0%** (0/8 protected) | `0.00%` (Reference) |
| **Clang `-O3 -Wall`** | **0.0%** (0/8 protected) | `+2.71%` |
| **Clang `-O3 -fsanitize=undefined`** | **37.5%** (3/8 protected) | Runtime crash / overhead |
| **Clang `-O0`** | **75.0%** (6/8 protected) | `+138.08%` (2.38x slower) |
| **CISB-Guard (`-O3`)** | **100.0%** (8/8 protected) | **`+0.74%` (< 1% overhead!)** |

---

## Quickstart

### 1. Launching the Interactive Web Dashboard
Double-click `start-demo.bat` on Windows or execute:
```bash
python backend/app.py
```
Open **http://localhost:8080** in your browser. The dashboard lets you:
* Choose any of the 8 test cases.
* Toggle between **Baseline (`-O3`)** and **CISB-Guard (`-O3`)**.
* Click **Compile & Execute Live** to inspect the real C source diff, real `objdump -d` disassembly, live binary stdout, and exit code (`0` = PROTECTED, `1` = VULNERABLE).
* Run the **Benchmark Suite** and **Export Audit JSON**.

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
