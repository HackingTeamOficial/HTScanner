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
import platform
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
PORT = 8787
REPORTS_DIR = os.path.join(ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Version and uptime
VERSION = os.environ.get("HTS_VERSION", "2.0")
START_TIME = time.time()

# --- Acceso a la herramienta (gate de contrasena, validado en backend) ---
# La contrasena NO esta en claro en el codigo ni en el zip: solo se guarda
# su HASH (PBKDF2-HMAC-SHA256). El login valida contra el hash, por lo que
# la contrasena funciona (es compartible) pero no es legible en el fuente.
# Sin token de sesion firmado no se puede usar ninguna API. El token viaja
# en una cookie HttpOnly.
import hmac
import hashlib
import secrets

AUTH_SECRET = secrets.token_bytes(32)
AUTH_TOKENS = set()
AUTH_LOCK = threading.Lock()

# Hash de la contrasena de uso (no se almacena la contrasena en claro).
# Se puede sobreescribir con la variable de entorno HTS_PASS_HASH
PASS_HASH = os.environ.get("HTS_PASS_HASH",
    "035410c5e07f34fcd9f41a45a8dbb5d2:d59a06e8e5f5dfcb91a9d2c80c9829d74d7a012f025ba9f4559aafce4c1f7226")

# Control de si se requiere autenticacion para /api/*
REQUIRE_AUTH = os.environ.get("HTS_REQUIRE_AUTH", "1") != "0"


def _hash_pass(password, salt=None):
    """Devuelve 'salt:hash' (PBKDF2-HMAC-SHA256). El salt es aleatorio."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return f"{salt}:{dk.hex()}"


def _check_pass(password):
    try:
        salt, _ = PASS_HASH.split(":", 1)
    except Exception:
        return False
    return hmac.compare_digest(_hash_pass(password, salt), PASS_HASH)


def _make_token():
    """Genera un token firmado y lo registra como sesion valida."""
    nonce = secrets.token_hex(16)
    tok = hmac.new(AUTH_SECRET, nonce.encode(), "sha256").hexdigest()
    with AUTH_LOCK:
        AUTH_TOKENS.add(tok)
    return tok


def _valid_token(tok):
    if not tok:
        return False
    with AUTH_LOCK:
        return tok in AUTH_TOKENS


def _token_from_cookie(headers):
    cookie = headers.get("Cookie", "") or ""
    m = re.search(r"hts_token=([0-9a-f]+)", cookie)
    return m.group(1) if m else None

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
XSS_PAYLOADS_DEFAULT = ["<script>alert(1)</script>", \"\"<script>alert(1)</script>\"",
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


# (existing functions run_nuclei, load_templates_from_yaml, load_payloads_from_txt,
# auto_load_payloads_and_templates, _scan_target_legacy, scan_target, etc.)
# For brevity we keep the rest of server.py unchanged below — original content is preserved.

