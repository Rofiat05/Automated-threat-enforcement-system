"""LOCAL mock RESTCONF-style server. Do not expose beyond localhost."""
import json
import os
import re
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATE = Path(os.getenv('CISCO_MOCK_STATE', 'mock_device_state.json'))
TOKEN = os.getenv('CISCO_MOCK_TOKEN', 'local-demo-token')
PREFIX = '/restconf/data/mock-acl'
RULE_ID = re.compile(r'^com732-(?:\d{1,3}-){3}\d{1,3}$')

def load():
    if not STATE.exists():
        return {}
    return json.loads(STATE.read_text(encoding='utf-8'))

def save(rules):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(STATE.parent), prefix='.mock-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2)
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def reply(self, status, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/yang-data+json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_request(self):
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            return self.reply(401, {'error': 'unauthorised'})
        if self.path == PREFIX:
            if self.command != 'GET':
                return self.reply(405, {'error': 'method not allowed'})
            return self.reply(200, {'rules': load()})
        if not self.path.startswith(PREFIX + '/'):
            return self.reply(404, {'error': 'not found'})
        rid = self.path[len(PREFIX) + 1:]
        if not RULE_ID.fullmatch(rid):
            return self.reply(400, {'error': 'invalid rule id'})
        rules = load()
        if self.command == 'PUT':
            length = int(self.headers.get('Content-Length', '0'))
            if length > 4096 or length == 0:
                return self.reply(400, {'error': 'invalid body size'})
            try:
                rule = json.loads(self.rfile.read(length))
                if not isinstance(rule, dict) or rule.get('owner') != 'com732-driver' or rule.get('action') != 'deny' or not isinstance(rule.get('expires_at'), str) or not isinstance(rule.get('source_ip'), str):
                    raise ValueError()
            except (ValueError, UnicodeDecodeError):
                return self.reply(400, {'error': 'invalid rule'})
            rules[rid] = rule
            save(rules)
            return self.reply(200, {'result': 'stored'})
        if self.command == 'DELETE':
            if rid not in rules:
                return self.reply(404, {'error': 'not found'})
            del rules[rid]
            save(rules)
            return self.reply(200, {'result': 'deleted'})
        return self.reply(405, {'error': 'method not allowed'})

    do_GET = handle_request
    do_PUT = handle_request
    do_DELETE = handle_request

if __name__ == '__main__':
    print('Local mock RESTCONF server listening at http://127.0.0.1:8765', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()