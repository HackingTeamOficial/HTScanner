#!/usr/bin/env python3
"""engine.py - compatibilidad y nucleo orquestador de HTScanner.

El nucleo real vive en core/ (http, oob, control, eventbus, plugin, context, db).
Este modulo actua como fachada:
  * re-exporta ScanContext, PluginManager, EventBus, helpers de confirmacion
  * mantiene los confirmadores de falsos positivos (SQLi/LFI/XSS)
  * run_modules(): ejecutor concurrente de modulos (semaforo)

No importa server.py (se acabo el acoplamiento).
"""
import threading
import re

# Re-exportaciones del nucleo desacoplado
from core.context import ScanContext
from core.plugin import Plugin, PluginManager
from core.eventbus import EventBus
from core.control import STORE, ControlStore
from core.http import request
from core.oob import start_oob, wait_oob_responsive, stop_oob
from core.db import save_scan, get_scans, get_scan, compare_scans


# ---------------------------------------------------------------------------
# Confirmadores (reducen falsos positivos)
# ---------------------------------------------------------------------------
LFI_SIGNATURES = [
    ("unix_passwd", lambda b: "root:x:0:0:" in b),
    ("win_ini", lambda b: "[extensions]" in b.lower() or "for 16-bit app support" in b.lower()),
    ("php_source", lambda b: "<?php" in b),
    ("bin_bash", lambda b: "/bin/bash" in b or "/bin/sh" in b),
    ("apache_conf", lambda b: "ServerRoot" in b or "DocumentRoot" in b),
]


def confirm_lfi(body, payload):
    """Confirma que el cuerpo es realmente un archivo sensible, no ruido."""
    for name, fn in LFI_SIGNATURES:
        try:
            if fn(body):
                return name
        except Exception:
            pass
    return None


def _text_diff_ratio(a, b):
    if not a and not b:
        return 0.0
    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    na = set(a[i:i + 8] for i in range(0, max(0, len(a) - 7)))
    nb = set(b[i:i + 8] for i in range(0, max(0, len(b) - 7)))
    if not na and not nb:
        return 0.0
    inter = na & nb
    union = na | nb
    return 1.0 - (len(inter) / len(union) if union else 1.0)


def confirm_sqli_boolean(ctx, url_base, param, true_val, false_val):
    """SQLi ciego por diferencia booleana."""
    try:
        r_true = ctx.req("GET", url_base, {param: true_val})
        r_false = ctx.req("GET", url_base, {param: false_val})
        if r_true.get("err") or r_false.get("err"):
            return False
        b_t, b_f = r_true.get("body", ""), r_false.get("body", "")
        if len(b_t) != len(b_f) and abs(len(b_t) - len(b_f)) > 30:
            return True
        if b_t != b_f and _text_diff_ratio(b_t, b_f) > 0.15:
            return True
    except Exception:
        return False
    return False


def confirm_xss_reflected(body, payload):
    """XSS: el payload debe aparecer reflejado sin escapar."""
    if payload not in body:
        return False
    if "&lt;script" in body.lower() or "&quot;" in body.split(payload)[0][-20:]:
        return False
    return True


# ---------------------------------------------------------------------------
# Manejo de sesion / auth (desacoplado: usa core.http)
# ---------------------------------------------------------------------------
def establish_session(ctx):
    """Si hay auth configurado, hace login y captura la cookie de sesion.
    Usa core.http.request (no server). Devuelve la cookie o None."""
    from core.http import request
    if not ctx.auth:
        return ctx.cookie
    try:
        a = ctx.auth
        login_url = a.get("url")
        if not login_url:
            return ctx.cookie
        form = {a.get("user_field", "username"): a.get("user", ""),
                a.get("pass_field", "password"): a.get("password", "")}
        for k, v in (a.get("extra_fields") or {}).items():
            form[k] = v
        rr = request("POST", login_url, data=form, timeout=10)
        sc = rr.get("headers", {}).get("Set-Cookie") or rr.get("headers", {}).get("set-cookie")
        if sc:
            cookie = sc.split(";")[0].strip()
            ctx.cookie = (ctx.cookie + "; " + cookie) if ctx.cookie else cookie
            ctx.emit({"type": "log", "msg": "Sesion autenticada capturada (cookie de sesion).",
                      "level": "info"})
        else:
            ctx.emit({"type": "log", "msg": "Login no devolvio cookie; continuando sin sesion.",
                      "level": "warn"})
    except Exception as e:
        ctx.emit({"type": "log", "msg": f"Error en login: {e}", "level": "warn"})
    return ctx.cookie


# ---------------------------------------------------------------------------
# Ejecutor concurrente de modulos
# ---------------------------------------------------------------------------
def run_modules(ctx, modules, module_runners):
    """Lanza cada modulo en su propio hilo con semaforo de concurrencia.
    Los eventos se publican via ctx.emit (EventBus)."""
    sem = threading.Semaphore(ctx.concurrency)
    threads = []
    errors = []

    def _wrap(name):
        def target():
            with sem:
                try:
                    module_runners[name](ctx)
                except Exception as e:
                    ctx.emit({"type": "error", "module": name,
                              "msg": f"Error en modulo {name}: {e}"})
                    errors.append((name, str(e)))
            d, t = ctx.record_progress()
            ctx.emit({"type": "progress", "done": d, "total": t})
        return target

    ctx.set_total(len(modules))
    for name in modules:
        ctx.emit({"type": "module", "name": name, "status": "running",
                  "msg": f"Iniciando {name}..."})
        t = threading.Thread(target=_wrap(name), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=300)
    return errors


# ---------------------------------------------------------------------------
# Carga de plugins (delegada a PluginManager)
# ---------------------------------------------------------------------------
def load_plugins(plugins_dir=None):
    """Carga plugins dinamicamente. Devuelve dict name -> Plugin."""
    import os
    if plugins_dir is None:
        plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
    return PluginManager(plugins_dir).load_all()


def plugin_runners_from_plugins(plugins):
    return {name: (lambda ctx, p=p: p.run(ctx)) for name, p in plugins.items()}
