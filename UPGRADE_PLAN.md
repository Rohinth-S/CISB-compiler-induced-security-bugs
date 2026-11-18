# UPGRADE_PLAN.md -- Upgrading CISB-compiler-induced-security-bugs From Mockup to Real Compiler Security System

## Core Architectural Directives
1. **ZERO MOCKING / ZERO HARDCODED RESULTS**: Delete `server.js`, `simulator.py`, and `.server.pid`. Every API response in `app.py` executes real binaries/compilers via `subprocess.run()` and returns real `stdout`, `stderr`, exit codes, real `clang`/AST diffs, real `objdump` assembly, and real wall-clock timings.
2. **DOCKER / WSL2 LINUX TARGET**: All C++ compiler plugins and C test compilations run in Ubuntu 24.04 with `clang-18`, `llvm-18-dev`, `libclang-18-dev`, `libclang-cpp18-dev`, `cmake`, `ninja-build`, `binutils` (`objdump`), and Python 3.
3. **LLVM 18 COMPLIANCE**: Opaque Pointers (`ptr`) only, New Pass Manager (`PassInfoMixin`) only, `-fno-rtti` for LLVM plugins, and link `ub-check-guard` against shared `clang-cpp` and `LLVM`.
4. **SECURE CODING IN THE DASHBOARD**: Fix path traversal in `app.py` by verifying `resolved_path.is_relative_to(WEB_ROOT.resolve())` and `resolved_path.is_file()`, strictly allowlist case IDs, and avoid `shell=True`.

---

## Target Repository Structure

```text
CISB-compiler-induced-security-bugs/
|-- Dockerfile                    # Ubuntu 24.04 + LLVM/Clang 18 + Python 3
|-- docker-compose.yml            # Exposes http://localhost:8080
|-- CMakeLists.txt                # Builds libCISBGuard.so + ub-check-guard
|-- start-demo.bat                # Health-checked launcher
|-- README.md                     # Accurate architecture, real results, run instructions
|-- src/
|   |-- llvm_plugin/
|   |   |-- CISBGuardPlugin.cpp   # New Pass Manager plugin registration
|   |   |-- ScrubGuardPass.h/cpp  # Pass 1: OSpec1 DSE secret-scrubbing guard
|   |   |-- UndefFreezePass.h/cpp # Pass 2: CISBFuzz undef SSCE freeze guard
|   |   `-- CFGVerifyPass.h/cpp   # Pass 3: Pre/Post-Opt XOR post-dom check auditor
|   `-- clang_tool/
|       `-- UBCheckGuard.cpp      # AST Rewriter: ISpec1 overflow, null-deref, int-promotion
|-- bin/
|   `-- cisb-guard-cc             # Unified CLI wrapper: AST rewrite -> clang-18 + plugin
|-- tests/
|   |-- cases/                    # Real C / LLVM-IR test cases with exit-code oracles
|   |   |-- 01_secret_wipe.c      # OSpec1: Stack key leak via DSE
|   |   |-- 02_dead_memset_anon.c # OSpec1: Unnamed buffer dead zero-store CFG check
|   |   |-- 03_signed_overflow.c  # ISpec1: if (offset + 100 < offset) deleted by -O3
|   |   |-- 04_null_after_deref.c # ISpec1: GCC Bug 33629 (*b then if (b))
|   |   |-- 05_int_promotion.c    # ISpec1: GCC Bug 87060 (u8 + 1 == 0)
|   |   |-- 06_undef_ssce.ll      # ISpec1: CISBFuzz Fig. 5 EarlyCSE undef erasure
|   |   |-- 07_div_zero_audit.c   # ISpec2: Debian Bug 616180 CFG dominance audit
|   |   `-- 08_cfg_xor_discover.c # ISpec2: Linux kernel XOR post-dominance check test
|   |-- benchmarks/               # Real CPU workloads for overhead measurement
|   |   |-- bench_sha256.c
|   |   |-- bench_quicksort.c
|   |   `-- bench_matmul.c
|   `-- verify_all.py             # Complete automated test runner & assertion suite
|-- backend/
|   |-- app.py                    # Clean, secure Python HTTP server
|   |-- runner.py                 # Real subprocess compiler/binary/objdump execution engine
|   `-- benchmark.py              # Compares -O3, -Wall, UBSan, -O0, CISB-Guard
`-- web/
    |-- index.html                # Interactive UI showing live C diff, IR/Asm diff,
    |-- styles.css                # stdout, exploit status, & benchmark charts
    `-- app.js
```
