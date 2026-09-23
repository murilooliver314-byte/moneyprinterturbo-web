#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
import hashlib, hmac, html, os, time

USER = os.environ["AUTH_USER"]
PASSWORD = os.environ["AUTH_PASSWORD"]
COOKIE_NAME = "mpt_session"
SESSION_TTL = 7 * 24 * 60 * 60

def make_token():
    expires = str(int(time.time()) + SESSION_TTL)
    sig = hmac.new(PASSWORD.encode(), f"{USER}|{expires}".encode(), hashlib.sha256).hexdigest()
    return f"{expires}.{sig}"

def valid_token(raw):
    try:
        expires, signature = raw.split(".", 1)
        if int(expires) < int(time.time()):
            return False
        expected = hmac.new(PASSWORD.encode(), f"{USER}|{expires}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return
    def send_body(self, status, body, content_type="text/plain; charset=utf-8", headers=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)
    def cookie_value(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            return jar[COOKIE_NAME].value if COOKIE_NAME in jar else ""
        except Exception:
            return ""
    def do_GET(self):
        if self.path == "/verify":
            valid = valid_token(self.cookie_value())
            self.send_body(200 if valid else 401, "ok" if valid else "login")
            return
        if self.path in ("/login", "/login/"):
            page = """<!doctype html><html lang=\"pt-BR\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Entrar — MoneyPrinterTurbo</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101827;color:#f5f7fb;font:16px system-ui,sans-serif}.card{width:min(92vw,400px);padding:30px;border:1px solid #334155;border-radius:20px;background:#172235;box-shadow:0 18px 60px #0006}h1{font-size:24px;margin:0 0 8px}p{color:#b9c4d3;margin:0 0 24px}label{display:block;margin:14px 0 6px}input{width:100%;padding:13px;border:1px solid #475569;border-radius:10px;background:#0f172a;color:white;font-size:16px}button{width:100%;margin-top:22px;padding:13px;border:0;border-radius:10px;background:#48d6bd;color:#06241f;font-weight:700;font-size:16px}</style><main class=\"card\"><h1>MoneyPrinterTurbo</h1><p>Entre com o usuário e a senha de acesso.</p><form method=\"post\" action=\"/login-submit\"><label for=\"user\">Usuário</label><input id=\"user\" name=\"username\" autocomplete=\"username\" required><label for=\"pass\">Senha</label><input id=\"pass\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required><button type=\"submit\">Entrar</button></form></main></html>"""
            self.send_body(200, page, "text/html; charset=utf-8")
            return
        if self.path == "/logout":
            self.send_body(303, "", headers=[("Set-Cookie", f"{COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"), ("Location", "/login")])
            return
        self.send_body(404, "Not found")
    def do_POST(self):
        if self.path != "/login-submit":
            self.send_body(404, "Not found")
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 10000)
            fields = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            username = fields.get("username", [""])[0]
            password = fields.get("password", [""])[0]
        except Exception:
            username, password = "", ""
        if hmac.compare_digest(username, USER) and hmac.compare_digest(password, PASSWORD):
            cookie = f"{COOKIE_NAME}={make_token()}; Max-Age={SESSION_TTL}; Path=/; Secure; HttpOnly; SameSite=Lax"
            self.send_body(303, "", headers=[("Set-Cookie", cookie), ("Location", "/")])
        else:
            self.send_body(401, "Usuário ou senha incorretos. Volte e tente novamente.")

ThreadingHTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
