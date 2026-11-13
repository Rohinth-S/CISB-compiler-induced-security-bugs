# Course Implementation Plan

This project is a safe classroom simulation inspired by the supplied CISB research and implementation notes.

## Milestones

1. **Case modeling and oracle**: represent optimization-sensitive patterns and compare baseline against a mitigated path.
2. **AST/IR-inspired guards**: explain rewrites such as moving null checks before dereference, preserving secure wipes, and restoring narrow integer semantics.
3. **Compiler wrapper concept**: document the planned `cisb-guard-cc` flow: rewrite or audit input, compile with instrumentation, and emit an audit JSON report.
4. **Security suite**: model the 12-test-suite direction from the plan. The dashboard currently includes four representative cases that are easy to explain in class.
5. **Coverage and performance**: the research-inspired next step is coverage-guided input exploration plus baseline/mitigated runtime comparisons.

## Mitigation matrix

| Bug pattern | Mitigation | Dashboard evidence |
|---|---|---|
| Secret wipe removed | observable wipe / barrier / memset_s | preserved store |
| Null check removed | check before dereference / opaque boundary | guard dominates dereference |
| Integer promotion mismatch | explicit narrowing / checked arithmetic | checked add |
| Timing shape changed | constant-time primitive / equalized work | equal branch count |

The implementation intentionally stops at a deterministic simulation so students can demonstrate the principle without relying on a particular LLVM installation.
