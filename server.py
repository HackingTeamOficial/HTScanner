#!/usr/bin/env python3
"""ht_scanner - backend del scanner GUI de hacking team.
Sirve una web local y ejecuta escaneos REALES (no fake) contra objetivos
autorizados / labs propios. Solo fines educativos / CTF local.

Modulos: headers, archivos, rutas, SQLi, IDOR, XSS, tech
+ soporte de plantillas YAML compatibles con Nuclei (requests definidos por el usuario)
+ control de pausa / reanudar / saltar modulo en vivo.

El frontend pide /api/scan?target=... y recibe eventos via SSE (text/event-stream).
El control (pausar/continuar/saltar) se hace con /api/control?action=...&scan_id=...
"""
import json
import os
import ssl
import urllib.request
import urllib.parse
import urllib.error
import time
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from http.server import SimpleHTTPRequestHandler

try:
    import yaml
    HAS_YAML = True
except Exception:
    HAS_YAML = False

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = 8777

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

# Wordlists
SENSITIVE = [".env", ".env.local", ".git/config", "wp-config.php", "phpinfo.php",
             "robots.txt", "sitemap.xml", ".well-known/security.txt", "backup.zip",
             "config.php", "xmlrpc.php", "admin/", "login/", "dashboard/",
             "api/", ".aws/credentials"]
ROUTES = ["admin", "login", "dashboard", "api", "config", "panel", "wp-admin",
          "phpmyadmin", "uploads", "backup", ".git", "test", "dev", "staging"]

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1-- -",
                 "admin' -- -", "0 UNION SELECT 1,2-- -"]
IDOR_PAYLOADS = ["1", "2", "3", "0", "999", "../../etc/passwd"]

# Registro de escaneos activos: scan_id -> dict de control
SCANS = {}
SCANS_LOCK = threading.Lock()


def req(method, url, data=None, cookie=None, timeout=10):
    hdr = {"User-Agent": UA, "Accept": "*/*"}
    if cookie:
        hdr["Cookie"] = cookie
    if method.upper() == "GET":
        if data:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(data)
        body = None
    else:
        body = urllib.parse.urlencode(data).encode() if data else b""
        hdr["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout, context=SSL_CTX)
        return {"code": resp.getcode(), "body": resp.read().decode("utf-8", "replace"),
                "headers": dict(resp.getheaders()), "err": None}
    except urllib.error.HTTPError as e:
        return {"code": e.code, "body": e.read().decode("utf-8", "replace"),
                "headers": dict(e.headers), "err": None}
    except Exception as e:
        return {"code": 0, "body": "", "headers": {}, "err": str(e)}


def check_control(scan_id, current_module):
    """Lee el estado de control del escaneo. Devuelve ('run'|'skip'|'stop')."""
    with SCANS_LOCK:
        st = SCANS.get(scan_id)
        if not st:
            return "run"
        if st.get("action") == "stop":
            return "stop"
        if st.get("skip_module") == current_module:
            st["skip_module"] = None
            return "skip"
        # pausa: esperar hasta que action cambie o se reanude
        while st.get("action") == "pause":
            time.sleep(0.2)
            if st.get("action") == "stop":
                return "stop"
            if st.get("skip_module") == current_module:
                st["skip_module"] = None
                return "skip"
        return "run"


def run_nuclei_templates(scan_id, target, templates, bus, emit):
    """Ejecuta plantillas YAML estilo Nuclei (formato simplificado)."""
    if not HAS_YAML:
        emit({"type": "module", "name": "nuclei", "status": "done",
              "msg": "PyYAML no instalado. Instala con: pip install pyyaml"})
        return
    hits = []
    for tmpl in templates:
        name = tmpl.get("id", "template")
        reqs = tmpl.get("requests", [])
        for r in reqs:
            ctrl = check_control(scan_id, "nuclei")
            if ctrl == "stop":
                emit({"type": "module", "name": "nuclei", "status": "done", "msg": "detenido"})
                return
            if ctrl == "skip":
                break
            method = (r.get("method") or "GET").upper()
            path = r.get("path") or "/"
            full = target.rstrip("/") + path
            # matchers
            matchers = r.get("matchers", [])
            rr = req(method, full)
            match = True
            if matchers:
                match = False
                for m in matchers:
                    mtype = m.get("type")
                    mpart = m.get("part", "body")
                    mwords = m.get("words", [])
                    mstatus = m.get("status", [])
                    content = rr.get("body", "") if mpart in ("body", "raw") else json.dumps(rr.get("headers", {}))
                    if mtype == "word" and any(w.lower() in content.lower() for w in mwords):
                        match = True
                    if mtype == "status" and rr.get("code") in mstatus:
                        match = True
            if match:
                hits.append(name)
                emit({"type": "finding", "severity": (tmpl.get("severity") or "info"),
                      "module": "nuclei", "detail": f"Template '{name}' coincide en {full} (HTTP {rr['code']})"})
        if hits:
            break
    emit({"type": "module", "name": "nuclei", "status": "done",
          "msg": f"Nuclei: {len(hits)} plantilla(s) coincidente(s)"})


def load_templates_from_yaml(text):
    if not HAS_YAML:
        return []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def scan_target(scan_id, target, bus, templates=None):
    """Ejecuta modulos y emite eventos. Soporta control de pausa/saltar/stop."""
    def emit(ev):
        bus(ev)

    if not target.startswith("http"):
        target = "http://" + target
    mods = ["headers", "archivos", "rutas", "sqli", "idor", "xss", "tech"]
    if templates:
        mods = mods + ["nuclei"]
    total = len(mods)
    done = 0

    emit({"type": "start", "target": target, "total": total})
    emit({"type": "scan_id", "scan_id": scan_id})
    time.sleep(0.3)

    # 1) HEADERS
    ctrl = check_control(scan_id, "headers")
    if ctrl == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "headers", "status": "running", "msg": f"Analizando cabeceras de {target}..."})
    r = req("GET", target)
    issues = []
    h = r.get("headers", {})
    if "strict-transport-security" not in (k.lower() for k in h):
        issues.append("Falta HSTS")
    if "content-security-policy" not in (k.lower() for k in h):
        issues.append("Falta CSP")
    if h.get("x-frame-options") is None and h.get("X-Frame-Options") is None:
        issues.append("Falta X-Frame-Options (clickjacking)")
    if h.get("server"):
        issues.append(f"Server expuesto: {h.get('server')}")
    emit({"type": "module", "name": "headers", "status": "done",
          "msg": f"HTTP {r['code']} | hallazgos: {', '.join(issues) if issues else 'ninguno'}", "findings": issues})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 2) ARCHIVOS
    if check_control(scan_id, "archivos") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "archivos", "status": "running", "msg": "Buscando archivos sensibles expuestos..."})
    found = []
    for f in SENSITIVE:
        if check_control(scan_id, "archivos") == "stop":
            emit({"type": "done", "summary": "Escaneo detenido"}); return
        if check_control(scan_id, "archivos") == "skip":
            break
        rr = req("GET", target.rstrip("/") + "/" + f)
        if rr["code"] in (200, 403) and rr["err"] is None:
            found.append(f"{f} ({rr['code']})")
            emit({"type": "finding", "severity": "medium", "module": "archivos", "detail": f"{f} accesible -> HTTP {rr['code']}"})
        time.sleep(0.05)
    emit({"type": "module", "name": "archivos", "status": "done", "msg": f"Encontrados: {len(found)}", "findings": found})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 3) RUTAS
    if check_control(scan_id, "rutas") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "rutas", "status": "running", "msg": "Enumerando rutas/endpoints..."})
    rfound = []
    for rt in ROUTES:
        if check_control(scan_id, "rutas") == "stop":
            emit({"type": "done", "summary": "Escaneo detenido"}); return
        if check_control(scan_id, "rutas") == "skip":
            break
        rr = req("GET", target.rstrip("/") + "/" + rt)
        if rr["code"] in (200, 301, 302, 403) and rr["err"] is None:
            rfound.append(f"/{rt} ({rr['code']})")
            emit({"type": "finding", "severity": "low", "module": "rutas", "detail": f"/{rt} -> HTTP {rr['code']}"})
        time.sleep(0.05)
    emit({"type": "module", "name": "rutas", "status": "done", "msg": f"Rutas: {len(rfound)}", "findings": rfound})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 4) SQLi
    if check_control(scan_id, "sqli") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "sqli", "status": "running", "msg": "Probando inyeccion SQL en parametros GET..."})
    sqli_hits = []
    SQLI_ERRORS = ["error in your sql", "sql syntax", "sqlite", "you have an error",
                   "unclosed quotation mark", "sqlstate", "ora-", "pg_", "warning: mysqli",
                   "microsoft sql server", "syntax error", "near \"", "unrecognized token",
                   "operationalerror", "database error", "could not"]
    sqli_paths = ["", "/notes", "/doc", "/article", "/view", "/product", "/item", "/post", "/news"]
    for sp in sqli_paths:
        base_url = target.rstrip("/") + sp
        for param in ["id", "q", "page", "search", "note", "cat", "pid"]:
            base = req("GET", base_url, {param: "1"})
            base_len = len(base.get("body", ""))
            base_code = base.get("code")
            for p in SQLI_PAYLOADS:
                if check_control(scan_id, "sqli") == "stop":
                    emit({"type": "done", "summary": "Escaneo detenido"}); return
                if check_control(scan_id, "sqli") == "skip":
                    break
                rr = req("GET", base_url, {param: p})
                body_l = rr.get("body", "").lower()
                hit = False
                if any(s in body_l for s in SQLI_ERRORS):
                    hit = True
                elif rr.get("code") != base_code and rr.get("code") != 0:
                    hit = True
                elif abs(len(rr.get("body", "")) - base_len) > 80:
                    hit = True
                if hit:
                    sqli_hits.append(f"{sp or '/'}{param}={p}")
                    emit({"type": "finding", "severity": "high", "module": "sqli",
                          "detail": f"Posible SQLi en '{base_url}' param '{param}' con: {p}"})
                    break
                time.sleep(0.03)
            if sqli_hits:
                break
        if sqli_hits:
            break
    emit({"type": "module", "name": "sqli", "status": "done", "msg": f"SQLi: {len(sqli_hits)} hallazgo(s)", "findings": sqli_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 5) IDOR
    if check_control(scan_id, "idor") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "idor", "status": "running", "msg": "Probando IDOR (enumeracion de objetos por id)..."})
    idor_hits = []
    idor_paths = ["", "/doc", "/note", "/file", "/user", "/account", "/profile", "/view"]
    for ip in idor_paths:
        base_url = target.rstrip("/") + ip
        for idparam in ["id", "doc", "uid", "user", "file", "pid"]:
            for pid in IDOR_PAYLOADS:
                if check_control(scan_id, "idor") == "stop":
                    emit({"type": "done", "summary": "Escaneo detenido"}); return
                if check_control(scan_id, "idor") == "skip":
                    break
                rr = req("GET", base_url, {idparam: pid})
                if (rr.get("code") == 200 and len(rr.get("body", "")) > 30
                        and "not found" not in rr.get("body", "").lower()
                        and "404" not in rr.get("body", "")):
                    idor_hits.append(f"{ip or '/'}{idparam}={pid}")
                    emit({"type": "finding", "severity": "medium", "module": "idor",
                          "detail": f"Objeto {base_url} {idparam}={pid} accesible (revisar control de acceso)"})
                    break
            if idor_hits:
                break
        if idor_hits:
            break
    emit({"type": "module", "name": "idor", "status": "done", "msg": f"IDOR: {len(idor_hits)} sospechoso(s)", "findings": idor_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 6) XSS
    if check_control(scan_id, "xss") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "xss", "status": "running", "msg": "Probando XSS reflejado en parametros GET..."})
    xss_hits = []
    XSS_PATHS = ["", "/search", "/buscar", "/q", "/s", "/find"]
    XSS_PAYLOADS = ["<script>alert(1)</script>", "\"<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>", "'><svg/onload=alert(1)>"]
    for xp in XSS_PATHS:
        base_url = target.rstrip("/") + xp
        for param in ["q", "search", "s", "id", "name", "term"]:
            for p in XSS_PAYLOADS:
                if check_control(scan_id, "xss") == "stop":
                    emit({"type": "done", "summary": "Escaneo detenido"}); return
                if check_control(scan_id, "xss") == "skip":
                    break
                rr = req("GET", base_url, {param: p})
                if p in (rr.get("body", "") or "") and rr.get("code") == 200:
                    xss_hits.append(f"{base_url} {param}")
                    emit({"type": "finding", "severity": "high", "module": "xss",
                          "detail": f"XSS reflejado en '{base_url}' param '{param}': payload no filtrado"})
                    break
            if xss_hits:
                break
        if xss_hits:
            break
    emit({"type": "module", "name": "xss", "status": "done", "msg": f"XSS: {len(xss_hits)} hallazgo(s)", "findings": xss_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 7) TECH
    if check_control(scan_id, "tech") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "tech", "status": "running", "msg": "Detectando tecnologia (server, CMS, frameworks)..."})
    tech_hits = []
    rh = req("GET", target)
    h = rh.get("headers", {})
    server_hdr = h.get("server") or h.get("Server")
    if server_hdr:
        tech_hits.append(f"Server: {server_hdr}")
    powered = h.get("x-powered-by") or h.get("X-Powered-By")
    if powered:
        tech_hits.append(f"Powered-by: {powered}")
    body_l = (rh.get("body", "") or "").lower()
    if "wordpress" in body_l:
        tech_hits.append("CMS: WordPress")
    if "drupal" in body_l:
        tech_hits.append("CMS: Drupal")
    if "laravel" in body_l or "csrf-token" in body_l:
        tech_hits.append("Framework: Laravel/PHP")
    if "next.js" in body_l or "_next" in body_l:
        tech_hits.append("Framework: Next.js")
    if "react" in body_l:
        tech_hits.append("Framework: React")
    if "jquery" in body_l:
        tech_hits.append("Lib: jQuery")
    emit({"type": "module", "name": "tech", "status": "done", "msg": f"Tech: {len(tech_hits)} senal(es)", "findings": tech_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 8) NUCLEI (plantillas YAML del usuario)
    if templates:
        if check_control(scan_id, "nuclei") == "stop":
            emit({"type": "done", "summary": "Escaneo detenido"}); return
        emit({"type": "module", "name": "nuclei", "status": "running", "msg": "Ejecutando plantillas YAML (estilo Nuclei)..."})
        run_nuclei_templates(scan_id, target, templates, bus, emit)
        done += 1
        emit({"type": "progress", "done": done, "total": total})

    emit({"type": "done", "target": target, "summary": f"Escaneo completado. Modulos: {total}. Revisa los hallazgos."})


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def do_GET(self):
        if self.path.startswith("/api/scan?"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            target = params.get("target", [""])[0]
            scan_id = str(uuid.uuid4())[:8]
            with SCANS_LOCK:
                SCANS[scan_id] = {"action": "run", "skip_module": None}
            # Cargar plantillas YAML si se pasan por ?templates=<contenido urlencoded>
            templates = None
            raw = params.get("templates", [""])[0]
            if raw:
                templates = load_templates_from_yaml(urllib.parse.unquote(raw))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            def bus(ev):
                try:
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
                    self.wfile.flush()
                except Exception:
                    pass

            try:
                scan_target(scan_id, target, bus, templates)
            except Exception as e:
                bus({"type": "error", "msg": str(e)})
            try:
                self.wfile.write(b"event: end\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
            with SCANS_LOCK:
                SCANS.pop(scan_id, None)
            return

        if self.path.startswith("/api/control?"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            scan_id = params.get("scan_id", [""])[0]
            action = params.get("action", [""])[0]
            mod = params.get("module", [""])[0]
            with SCANS_LOCK:
                st = SCANS.get(scan_id)
                if st:
                    if action in ("pause", "resume", "stop"):
                        st["action"] = action if action != "resume" else "run"
                    if action == "skip" and mod:
                        st["skip_module"] = mod
                    ok = True
                else:
                    ok = False
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "scan_id": scan_id, "action": action}).encode())
            return

        return super().do_GET()

    def do_POST(self):
        # Permite subir el YAML por POST (mas limpio que por URL)
        if self.path == "/api/templates":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace")
            templates = load_templates_from_yaml(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "templates": len(templates)}).encode())
            return
        return super().do_POST()


def run():
    print(f"[*] ht_scanner GUI en http://127.0.0.1:{PORT}")
    if not HAS_YAML:
        print("[!] PyYAML no instalado: el modulo Nuclei/YAML no estara disponible.")
        print("    Instala con: pip install pyyaml")
    # ThreadingHTTPServer: cada conexion en su propio hilo (SSE no bloquea otras)
    HTTPServer.allow_reuse_address = True
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.serve_forever()


if __name__ == "__main__":
    run()
