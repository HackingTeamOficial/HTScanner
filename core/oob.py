#!/usr/bin/env python3
"""core/oob.py - servidor Out-Of-Band local para detectar RFI/XXE.

Levanta un socket TCP que espera un token unico. Si el servidor victima
intenta cargar nuestro callback, el token aparece y confirmamos la vuln.
No importa server.py. El estado de escaneo viene de core.control.STORE.
"""
import socket
import threading
import time
import uuid

# Un OOB activo a la vez por scan (simplicidad). Token por escaneo.
_OOB = {}  # scan_id -> {"token":..., "hit":Event,"server":socket}


def start_oob(scan_id):
    """Levanta servidor OOB para el scan_id. Devuelve (host, port, token)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    token = "HTSCN" + uuid.uuid4().hex[:12]
    hit = threading.Event()
    _OOB[scan_id] = {"token": token, "hit": hit, "server": srv}

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


def stop_oob(scan_id):
    rec = _OOB.pop(scan_id, None)
    if rec and rec.get("server"):
        try:
            rec["server"].close()
        except Exception:
            pass


def wait_oob_responsive(scan_id, current_module, timeout=1.2):
    """Espera el callback OOB pero chequea skip/stop cada 0.1s (respuesta rapida)."""
    from core.control import STORE
    rec = _OOB.get(scan_id)
    if not rec:
        return False
    hit = rec["hit"]
    end = time.time() + timeout
    while time.time() < end:
        if hit.is_set():
            return True
        ctrl = STORE.check(scan_id, current_module)
        if ctrl in ("skip", "stop"):
            return False
        time.sleep(0.1)
    return hit.is_set()
