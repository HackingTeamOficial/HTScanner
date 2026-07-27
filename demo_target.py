#!/usr/bin/env python3
"""Lab de demo para probar ht_scanner localmente (OBJETIVO AUTORIZADO).
Tiene cabeceras debiles, archivo sensible, rutas y multiples vulnerabilidades
para que el scanner las detecte de verdad: SQLi, XSS, IDOR, LFI, Path
Traversal, RCE y un endpoint que hace include/parse de contenido (RFI/XXE OOB).
SOLO local / CTF."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse, sqlite3, os, subprocess

DB = "/tmp/htdemo.db"
if not os.path.exists(DB):
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute("CREATE TABLE users(id INTEGER, u TEXT, p TEXT)")
    cur.execute("INSERT INTO users VALUES(1,'admin','secret')")
    c.commit(); c.close()

# Archivo local para probar LFI/Traversal
with open("/tmp/secret_notes.txt", "w") as f:
    f.write("root:x:0:0:root:/root:/bin/bash\n")


class H(BaseHTTPRequestHandler):
    def _s(self, body, code=200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if extra:
            for k, v in extra.items(): self.send_header(k, v)
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
            pid = urllib.parse.parse_qs(q).get('id', ['1'])[0]
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
            did = urllib.parse.parse_qs(q).get('id', ['1'])[0]
            # IDOR: no comprueba dueno
            self._s(f"Documento {did} del sistema")
        elif p == '/download':
            # VULNERABLE a Path Traversal: concatena el nombre sin sanitizar
            q = urllib.parse.urlparse(self.path).query
            name = urllib.parse.parse_qs(q).get('file', [''])[0] or \
                   urllib.parse.parse_qs(q).get('name', [''])[0] or \
                   urllib.parse.parse_qs(q).get('img', [''])[0]
            if name:
                try:
                    with open("/var/www/" + name, 'r') as fh:
                        self._s(f"<pre>{fh.read()}</pre>")
                except Exception as e:
                    self._s(f"error: {e}")
            else:
                self._s("pendiente param file/name/img")
            # VULNERABLE a LFI / Path Traversal: incluye el parametro 'file' directo
            q = urllib.parse.urlparse(self.path).query
            fparam = urllib.parse.parse_qs(q).get('file', [''])[0]
            if fparam:
                try:
                    with open(fparam, 'r') as fh:
                        self._s(f"<pre>{fh.read()}</pre>")
                except Exception as e:
                    self._s(f"error: {e}")
            else:
                self._s("pendiente param file/name/img")
        elif p == '/file':
            # VULNERABLE a LFI / Path Traversal: incluye el parametro 'file' directo
            q = urllib.parse.urlparse(self.path).query
            fparam = urllib.parse.parse_qs(q).get('file', [''])[0]
            if fparam:
                try:
                    with open(fparam, 'r') as fh:
                        self._s(f"<pre>{fh.read()}</pre>")
                except Exception as e:
                    self._s(f"error: {e}")
            else:
                self._s("pendiente param file")
        elif p == '/include':
            # VULNERABLE a RFI: carga el recurso pasado en 'url' (GET o POST)
            q = urllib.parse.urlparse(self.path).query
            url = urllib.parse.parse_qs(q).get('url', [''])[0]
            self._include(url)
        elif p == '/ping':
            # VULNERABLE a RCE: concatena el param 'host' a un comando
            q = urllib.parse.urlparse(self.path).query
            host = urllib.parse.parse_qs(q).get('host', [''])[0]
            if host:
                try:
                    out = subprocess.check_output(f"ping -c 1 {host}", shell=True,
                                                  stderr=subprocess.STDOUT, timeout=3)
                    self._s(f"<pre>{out.decode()}</pre>")
                except Exception as e:
                    self._s(f"cmd error: {e}")
            else:
                self._s("pendiente param host")
        else:
            self._s("404", 404)

    def _include(self, url):
        # RFI: intenta cargar el recurso remoto (dispara callback OOB del scanner)
        import urllib.request
        if not url:
            self._s("pendiente param url")
            return
        try:
            r = urllib.request.urlopen(url, timeout=2)
            self._s(f"included: {r.read(200).decode()}")
        except Exception as e:
            self._s(f"include error: {e}")

    def do_POST(self):
        # Endpoint que hace include/fopen de una URL (RFI) y parsea XML (XXE)
        p = self.path.split('?')[0]
        n = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(n).decode('utf-8', 'replace')
        if p == '/include':
            # RFI: intenta cargar el recurso pasado en 'url'
            import urllib.request
            url = urllib.parse.parse_qs(raw).get('url', [''])[0] or \
                  urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('url', [''])[0]
            try:
                r = urllib.request.urlopen(url, timeout=2)
                self._s(f"included: {r.read(200).decode()}")
            except Exception as e:
                self._s(f"include error: {e}")
        elif p == '/xml':
            # XXE: parser XML naive que resuelve entidades externas (simula vuln)
            # Extrae la URL de la entidad SYSTEM y la solicita (dispara callback OOB)
            import re, urllib.request
            m = re.search(r'SYSTEM\s+"([^"]+)"', raw)
            if m:
                try:
                    urllib.request.urlopen(m.group(1), timeout=2)
                    self._s(f"XXE resolved: {m.group(1)}")
                except Exception as e:
                    self._s(f"xml error: {e}")
            else:
                self._s("no external entity found")
        else:
            self._s("404", 404)

    def log_message(self, *a): pass


if __name__ == "__main__":
    print("[*] demo target en http://127.0.0.1:9090")
    HTTPServer(("127.0.0.1", 9090), H).serve_forever()
