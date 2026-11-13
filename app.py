import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse,parse_qs
from simulator import CASES,run_case,run_all
ROOT=Path(__file__).parent
class Handler(BaseHTTPRequestHandler):
 def send_json(self,obj,status=200):
  data=json.dumps(obj,indent=2).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
 def do_GET(self):
  p=urlparse(self.path)
  if p.path=='/api/cases': return self.send_json([c.__dict__ for c in CASES.values()])
  if p.path=='/api/run-all': return self.send_json(run_all())
  if p.path=='/api/simulate':
   q=parse_qs(p.query); cid=q.get('case',['secret-wipe'])[0]; mit=q.get('mitigated',['false'])[0].lower()=='true'
   if cid not in CASES: return self.send_json({'error':'unknown case'},404)
   return self.send_json(run_case(cid,mit))
  f=ROOT/'web'/('index.html' if p.path=='/' else p.path.lstrip('/'))
  if f.exists() and f.is_file():
   data=f.read_bytes(); typ='text/html' if f.suffix=='.html' else 'text/css' if f.suffix=='.css' else 'application/javascript'; self.send_response(200); self.send_header('Content-Type',typ); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
  else: self.send_json({'error':'not found'},404)
 def log_message(self,*args): pass
if __name__=='__main__': print('CISB Guard dashboard: http://localhost:8080'); ThreadingHTTPServer(('127.0.0.1',8080),Handler).serve_forever()
