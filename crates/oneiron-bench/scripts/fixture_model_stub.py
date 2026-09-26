import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        model=body['model']
        system=body['messages'][0]['content']
        answer=('1' if model.startswith('gpt-4.1-mini') else
                'contract launch code' if 'search query' in str(system) else 'tulip')
        payload={'id':'fixture-only','object':'chat.completion','model':model,
                 'choices':[{'index':0,'message':{'role':'assistant','content':answer},'finish_reason':'stop'}],
                 'usage':{'prompt_tokens':100,'completion_tokens':3,'total_tokens':103}}
        data=json.dumps(payload).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
ThreadingHTTPServer(('127.0.0.1',8080),Handler).serve_forever()
