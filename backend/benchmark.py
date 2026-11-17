"""
Comprehensive performance & security benchmarking suite for CISB-Guard.
Evaluates 5 compiler strategies across compute benchmarks & security cases:
1. Clang -O3 (Standard aggressive optimization)
2. Clang -O3 -Wall (Standard with diagnostic warnings)
3. Clang -O3 -fsanitize=undefined (UBSan runtime sanitizer)
4. Clang -O0 (Unoptimized baseline)
5. CISB-Guard -O3 (Our hardened compilation pipeline)
"""

import os
import sys
import subprocess
import tempfile
import json
import time
import math
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.runner import CASES_INFO, run_case_real, find_tool

BENCHMARKS_DIR = REPO_ROOT / "tests" / "benchmarks"
CASES_DIR = REPO_ROOT / "tests" / "cases"
RESULTS_DIR = REPO_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
BIN_WRAPPER = REPO_ROOT / "bin" / "cisb-guard-cc"

STRATEGIES = {
    "Clang -O3": ["-O3", "-fno-stack-protector"],
    "Clang -O3 -Wall": ["-O3", "-Wall", "-fno-stack-protector"],
    "Clang -O3 -fsanitize=undefined": ["-O3", "-fsanitize=undefined", "-fno-sanitize-recover=all", "-fno-stack-protector"],
    "Clang -O0": ["-O0", "-fno-stack-protector"],
    "CISB-Guard (-O3)": ["-O3", "-fno-stack-protector"]
}

def find_compiler():
    return find_tool("clang-18") or find_tool("clang") or find_tool("gcc")

def run_single_benchmark(src_path, flags, is_cisb_guard=False, runs=3):
    compiler = find_compiler()
    temp_dir = tempfile.mkdtemp(prefix="cisb_bench_")
    exe_name = "bench_bin.exe" if sys.platform == "win32" else "bench_bin"
    exe_path = Path(temp_dir) / exe_name

    try:
        if is_cisb_guard:
            cmd = [sys.executable, str(BIN_WRAPPER)] + flags + [str(src_path), "-o", str(exe_path)]
        else:
            cmd = [compiler] + flags + [str(src_path), "-o", str(exe_path)]

        c_res = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
        if c_res.returncode != 0 or not exe_path.exists():
            return None

        timings = []
        for _ in range(runs):
            t0 = time.perf_counter()
            r = subprocess.run([str(exe_path)], capture_output=True, text=True, errors='replace', timeout=10)
            t1 = time.perf_counter()
            if r.returncode == 0:
                timings.append((t1 - t0) * 1000.0)

        if not timings:
            return None

        timings.sort()
        median_time = timings[len(timings) // 2]
        return median_time
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def measure_protection_rate(strat_name, flags):
    """Dynamically evaluate security test cases for a given compiler configuration."""
    compiler = find_compiler()
    is_cisb_guard = (strat_name == "CISB-Guard (-O3)")
    protected_count = 0
    total = len(CASES_INFO)

    for cid, info in CASES_INFO.items():
        src_path = CASES_DIR / info["file"]
        if not src_path.exists():
            continue

        if is_cisb_guard:
            res = run_case_real(cid, mitigated=True)
            if res.get("status") == "PROTECTED" and res.get("exit_code") == 0:
                protected_count += 1
        elif src_path.suffix == ".ll":
            # Baseline .ll case under optimizer
            res = run_case_real(cid, mitigated=False)
            if res.get("status") == "PROTECTED" and res.get("exit_code") == 0:
                protected_count += 1
        else:
            temp_dir = tempfile.mkdtemp(prefix=f"cisb_sec_{cid}_")
            try:
                exe_name = "case_bin.exe" if sys.platform == "win32" else "case_bin"
                exe_path = Path(temp_dir) / exe_name
                cmd = [compiler] + flags + [str(src_path), "-o", str(exe_path)]
                c_res = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
                if c_res.returncode == 0 and exe_path.exists():
                    r = subprocess.run([str(exe_path)], capture_output=True, text=True, errors='replace', timeout=5)
                    if r.returncode == 0:
                        protected_count += 1
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

    pct = (protected_count / total) * 100.0 if total > 0 else 0.0
    return pct, protected_count, total

def run_benchmarks():
    print("[*] Running CISB-Guard Performance & Security Benchmark Suite...")
    benchmarks = ["bench_sha256.c", "bench_quicksort.c", "bench_matmul.c"]
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "strategies": list(STRATEGIES.keys()),
        "workloads": {},
        "overhead_vs_o3": {},
        "security_protection_rate": {},
        "protection_pct": {}
    }

    # 1. Compute Benchmark Workloads
    for bench in benchmarks:
        bname = bench.replace(".c", "").replace("bench_", "")
        results["workloads"][bname] = {}
        src_path = BENCHMARKS_DIR / bench

        for strat_name, flags in STRATEGIES.items():
            is_guard = (strat_name == "CISB-Guard (-O3)")
            med_time = run_single_benchmark(src_path, flags, is_cisb_guard=is_guard, runs=3)

            if med_time is not None:
                results["workloads"][bname][strat_name] = round(med_time, 2)
            else:
                results["workloads"][bname][strat_name] = None

    # 2. Compute geometric mean overhead vs -O3
    overheads = {strat: [] for strat in STRATEGIES}
    overhead_pct_val = {}
    for bname, times in results["workloads"].items():
        base = times.get("Clang -O3")
        if not base: continue
        for strat, t in times.items():
            if t is not None and base > 0:
                ratio = t / base
                overheads[strat].append(ratio)

    for strat, ratios in overheads.items():
        if ratios:
            geomean = math.exp(sum(math.log(r) for r in ratios) / len(ratios))
            pct_diff = (geomean - 1.0) * 100.0
            results["overhead_vs_o3"][strat] = f"{pct_diff:+.2f}%"
            overhead_pct_val[strat] = round(pct_diff, 2)
        else:
            results["overhead_vs_o3"][strat] = "N/A"
            overhead_pct_val[strat] = 0.0

    # 3. Dynamically Measure Real Security Protection Rate for Each Strategy
    print("[*] Evaluating empirical security protection rates across all 12 cases...")
    for strat_name, flags in STRATEGIES.items():
        pct, prot, tot = measure_protection_rate(strat_name, flags)
        results["security_protection_rate"][strat_name] = f"{pct:.1f}% ({prot}/{tot} protected)"
        results["protection_pct"][strat_name] = pct
        print(f"  {strat_name:30s}: {results['security_protection_rate'][strat_name]}")

    # Save JSON results
    out_json = RESULTS_DIR / "benchmark_results.json"
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[+] Benchmark results saved to {out_json}")

    # 4. Generate 2-Panel Comprehensive Pareto Chart
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        fig, (ax_bar, ax_pareto) = plt.subplots(1, 2, figsize=(14, 5.5))

        # Panel 1: Workload Execution Times
        workload_names = list(results["workloads"].keys())
        strats_bar = ["Clang -O3", "Clang -O0", "CISB-Guard (-O3)"]
        x = np.arange(len(workload_names))
        width = 0.25

        colors = ["#4A90E2", "#E74C3C", "#2ECC71"]
        for i, s in enumerate(strats_bar):
            vals = [results["workloads"][w].get(s, 0) or 0 for w in workload_names]
            ax_bar.bar(x + (i - 1) * width, vals, width, label=s, color=colors[i], alpha=0.9)

        ax_bar.set_ylabel("Execution Time (ms, lower is better)", fontsize=10, fontweight='bold')
        ax_bar.set_title("Runtime Overhead Across Compute Workloads", fontsize=11, fontweight='bold')
        ax_bar.set_xticks(x)
        ax_bar.set_xticklabels([w.upper() for w in workload_names], fontweight='bold')
        ax_bar.legend(frameon=True)
        ax_bar.grid(axis='y', linestyle='--', alpha=0.4)

        # Panel 2: 2D Pareto Tradeoff: Overhead vs Protection
        scatter_colors = {
            "Clang -O3": "#E74C3C",
            "Clang -O3 -Wall": "#E67E22",
            "Clang -O3 -fsanitize=undefined": "#F1C40F",
            "Clang -O0": "#9B59B6",
            "CISB-Guard (-O3)": "#2ECC71"
        }

        pareto_points = []
        for strat in STRATEGIES:
            ov = overhead_pct_val.get(strat, 0.0)
            prot = results["protection_pct"].get(strat, 0.0)
            if results["overhead_vs_o3"].get(strat) != "N/A":
                pareto_points.append((ov, prot, strat))
                color = scatter_colors.get(strat, "#333333")
                size = 140 if strat == "CISB-Guard (-O3)" else 80
                ax_pareto.scatter(ov, prot, color=color, s=size, edgecolors="black", linewidths=1.5, zorder=5)
                ax_pareto.annotate(
                    strat,
                    (ov, prot),
                    textcoords="offset points",
                    xytext=(8, 4 if prot < 90 else -12),
                    fontsize=9,
                    fontweight='bold' if strat == "CISB-Guard (-O3)" else 'normal'
                )

        ax_pareto.set_xlabel("Mean Runtime Overhead vs -O3 (%)", fontsize=10, fontweight='bold')
        ax_pareto.set_ylabel("Empirical Security Protection Rate (%)", fontsize=10, fontweight='bold')
        ax_pareto.set_title("Security vs. Performance Pareto Frontier", fontsize=11, fontweight='bold')
        ax_pareto.set_ylim(-5, 110)
        ax_pareto.grid(True, linestyle='--', alpha=0.4)

        # Highlight optimal corner (low overhead, high protection)
        ax_pareto.axhspan(90, 105, color='#2ECC71', alpha=0.1, label='Target Defense Zone (>90%)')
        ax_pareto.legend(loc='lower right', frameon=True)

        chart_path = RESULTS_DIR / "security_vs_overhead.png"
        fig.tight_layout()
        fig.savefig(chart_path, dpi=200)
        plt.close(fig)
        print(f"[+] Performance & Pareto chart saved to {chart_path}")
    except Exception as e:
        print(f"[!] Warning: Chart generation failed: {e}")

    return results

if __name__ == '__main__':
    run_benchmarks()
