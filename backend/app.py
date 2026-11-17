import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import sys

# Ensure repository root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.runner import CASES_INFO, run_case_real, run_all_cases, find_tool
from backend.benchmark import run_benchmarks

WEB_DIR = (ROOT / 'web').resolve()
RESULTS_DIR = (ROOT / 'results').resolve()
AUDIT_FILE = RESULTS_DIR / 'audit.json'

DEMOS_LIST = [
    {
        "id": "demo_a",
        "name": "Live Demo A: OSpec1 Stack Secret Leak",
        "case_id": "01_stack_key_leak",
        "tag": "OSpec1 · Dead Store Elimination",
        "headline": "Watch the Secret Leak — Then Watch CISB-Guard Stop It",
        "target_fn": "authenticate",
        "explanation": "Standard -O3 Dead Store Elimination (DSE) removes memset(secret_key, 0, 64) before return because buffer lifetime ends. Attacker reading uninitialized stack memory recovers 'TOP_SECRET_AES256_KEY_99481'. CISB-Guard ScrubGuardPass makes memset volatile and injects an inline memory barrier, forcing zeroing stores (movups/pxor) to survive in assembly."
    },
    {
        "id": "demo_b",
        "name": "Live Demo B: ISpec1 Integer Overflow Bypass",
        "case_id": "05_signed_overflow_check",
        "tag": "ISpec1 · Undefined Behavior",
        "headline": "Watch Signed Overflow Check Disappear — Then Reappear as Safe Checked Arithmetic",
        "target_fn": "check_buffer_offset",
        "explanation": "Under the C No-UB assumption, signed integer overflow cannot occur. Clang -O3 deduces (offset + 100 < offset) is always false and erases the security abort. CISB-Guard UBCheckGuard rewrites this into __builtin_add_overflow, producing a single hardware carry check (jo) with zero UB."
    },
    {
        "id": "demo_c",
        "name": "Live Demo C: ISpec1 CISBFuzz Undef Condition Erasure",
        "case_id": "09_undef_ssce_mutant",
        "tag": "EuroSec '26 · Silent Security Check Erasure",
        "headline": "Watch EarlyCSE Fold Security Gate on Undef — Then Freeze It",
        "target_fn": "security_gate",
        "explanation": "When an uninitialized/undef operand feeds a comparison guard, EarlyCSE simplifies it to 'br i1 false', deleting the security gate. CISB-Guard UndefFreezeGuardPass inserts FreezeInst, fixing the undef value and preserving the conditional security branch."
    }
]

class CISBHandler(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. API Health Check
        if path == '/api/health':
            toolchain = {
                "compiler": find_tool("clang-18") or find_tool("clang") or find_tool("gcc"),
                "objdump": find_tool("objdump"),
                "opt": find_tool("opt-18") or find_tool("opt"),
                "plugin_built": (ROOT / "build" / "libCISBGuard.so").exists(),
                "ub_tool_built": (ROOT / "build" / "ub-check-guard").exists()
            }
            return self.send_json({"status": "ok", "service": "CISB-Guard", "toolchain": toolchain})

        # 2. API Cases List
        if path == '/api/cases':
            cases_list = []
            for cid, info in sorted(CASES_INFO.items()):
                cases_list.append({
                    "id": cid,
                    "title": info["title"],
                    "class_name": info["class"],
                    "description": info["desc"],
                    "paper_cite": info.get("paper_cite", ""),
                    "file": info["file"]
                })
            return self.send_json(cases_list)

        # 3. API Demos List
        if path == '/api/demos':
            return self.send_json(DEMOS_LIST)

        # 4. API Run Single Case Live
        if path == '/api/run' or path == '/api/simulate':
            q = parse_qs(parsed.query)
            cid = q.get('case', ['01_stack_key_leak'])[0]
            mitigated = q.get('mitigated', ['false'])[0].lower() in ('true', '1')

            if cid not in CASES_INFO:
                return self.send_json({'error': f'Unknown case: {cid}'}, 404)

            res = run_case_real(cid, mitigated)
            return self.send_json(res)

        # 5. API Run All Cases Live
        if path == '/api/run-all':
            return self.send_json(run_all_cases())

        # 6. API Benchmarks
        if path == '/api/benchmarks':
            q = parse_qs(parsed.query)
            refresh = q.get('refresh', ['false'])[0].lower() in ('true', '1')
            bench_json = RESULTS_DIR / 'benchmark_results.json'
            if bench_json.exists() and not refresh:
                try:
                    data = json.loads(bench_json.read_text(encoding='utf-8'))
                    return self.send_json(data)
                except Exception:
                    pass
            return self.send_json(run_benchmarks())

        # 7. API Export Audit Log
        if path == '/api/export-audit':
            records = []
            if AUDIT_FILE.exists():
                for line in AUDIT_FILE.read_text(encoding='utf-8', errors='ignore').splitlines():
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except Exception:
                            records.append({"raw": line})
            return self.send_json({"audit_records": records, "total_events": len(records)})

        # 8. Static Files Serving WITH STRICT PATH TRAVERSAL DEFENSE
        rel_path = path.lstrip('/')
        if not rel_path:
            rel_path = 'index.html'

        if rel_path.startswith('results/'):
            target = (ROOT / rel_path).resolve()
            base_dir = RESULTS_DIR
        else:
            target = (WEB_DIR / rel_path).resolve()
            base_dir = WEB_DIR

        try:
            if not target.is_relative_to(base_dir) or not target.is_file():
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'404 Not Found')
                return
        except (ValueError, AttributeError):
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 Not Found')
            return

        mime_type, _ = mimetypes.guess_type(str(target))
        if not mime_type:
            mime_type = 'application/octet-stream'

        data = target.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', mime_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {args[0]} {args[1]} {args[2]}\n")

def run_server(port=8080):
    server = ThreadingHTTPServer(('0.0.0.0', port), CISBHandler)
    print(f"CISB-Guard Security Dashboard live at: http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
