#!/usr/bin/env python3
"""Lab de demo para probar ht_scanner localmente (OBJETIVO AUTORIZADO).
Tiene cabeceras debiles, archivo sensible, rutas y un param SQLi.
SOLO local / CTF."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse, sqlite3, os

DB = "/tmp/htdemo.db"
if not os.path.exists(DB):
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute("CREATE TABLE users(id INTEGER, u TEXT, p TEXT)")
    cur.execute("INSERT INTO users VALUES(1,'admin','secret')")
    c.commit(); c.close()

class H(BaseHTTPRequestHandler):
    def _s(self, body, code=200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type","text/html; charset=utf-8")
        if extra:
            for k,v in extra.items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        p = self.path.split('?')[0]
        if p == '/search':
            q = urllib.parse.urlparse(self.path).query
            term = urllib.parse.parse_qs(q).get('q', [''])[0]
            # XSS reflejado: el termino se imprime sin filtrar
            self._s(f"<h1>Resultados para: {term}</h1><p>_next static assets</p>")
        elif p == '/' or p == '/index.html':
            self._s("<html><body><h1>Demo Target</h1>"
                    "<a href='/login'>login</a>"
                    "<script src='/x.js'></script>"
                    "<div class='_next'>Next.js app</div>"
                    "<script>var x=1;</script></body></html>")
        elif p == '/login':
            self._s("<h1>Login</h1>")
        elif p == '/admin':
            self._s("<h1>Admin panel</h1>", 200)
        elif p == '/.git/config':
            self._s("[core]\nrepositoryformatversion = 0\n", 200)
        elif p == '/robots.txt':
            self._s("User-agent: *\nDisallow: /admin\n", 200)
        elif p.startswith('/api'):
            self._s('{"ok":true}', 200)
        elif p == '/notes':
            q = urllib.parse.urlparse(self.path).query
            pid = urllib.parse.parse_qs(q).get('id',['1'])[0]
            # vulnerable a SQLi por GET
            sql = f"SELECT title FROM notes WHERE id = {pid}"
            try:
                c = sqlite3.connect(DB); cur = c.cursor(); cur.execute(sql)
                row = cur.fetchone(); c.close()
                self._s(f"note: {row}<br>query: {sql}")
            except Exception as e:
                self._s(f"<h2>Error SQL:</h2><pre>{e}</pre>")
        elif p == '/doc':
            q = urllib.parse.urlparse(self.path).query
            did = urllib.parse.parse_qs(q).get('id',['1'])[0]
            # IDOR: no comprueba dueno
            self._s(f"Documento {did} del sistema")
        else:
            self._s("404", 404)
    def log_message(self,*a): pass

if __name__ == "__main__":
    print("[*] demo target en http://127.0.0.1:9090")
    HTTPServer(("127.0.0.1",9090), H).serve_forever()
