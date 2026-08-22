#!/usr/bin/env python3
"""core/context.py - ScanContext: une http/oob/control/eventbus.

Es 100% independiente del frontend y del server (sin importar server.py).
"""
import threading

from core.http import request
from core.control import STORE
from core.oob import start_oob, wait_oob_responsive, stop_oob


class ScanAbort(Exception):
    """Lanzada cuando el usuario detiene/pausa y el modulo debe frenar."""
    pass


class ScanContext:
    """Agrupa todo lo necesario para un escaneo y expone:
      * emit(ev)      -> publica en el EventBus (thread-safe)
      * req(...)      -> peticion HTTP (core.http)
      * ctrl(module)  -> control pause/skip/stop (core.control)
      * auth/session  -> cookie jar + login opcional
    """

    def __init__(self, scan_id, target, bus, mode="active",
                 cookie=None, auth=None, concurrency=4):
        self.scan_id = scan_id
        self.target = target
        self.bus = bus                 # core.eventbus.EventBus
        self.bus_lock = threading.RLock()
        self.mode = mode
        self.cookie = cookie
        self.auth = auth
        self.concurrency = max(1, min(concurrency, 12))
        self._report = {
            "findings": [],
            "modules_list": [],
            "system": {"host": "", "server": "", "tech": "", "ports": ""},
        }
        self._report_lock = threading.Lock()
        self._done_count = 0
        self._total = 0
        self._prog_lock = threading.Lock()
        self.modules_run = []
        # estado extra que los modulos de recon adjuntan
        self._fingerprint = None
        self._crawl = None

    # ----- publicacion de eventos (thread-safe) -----
    def emit(self, ev):
        # asegurar que los hallazgos traigan confidence (default confirmed)
        if ev.get("type") == "finding" and "confidence" not in ev:
            ev = dict(ev)
            ev["confidence"] = "confirmed"
        with self.bus_lock:
            try:
                # El bus puede ser una funcion handler directa (callable)
                # o un EventBus con metodo .publish().
                if callable(self.bus) and not hasattr(self.bus, "publish"):
                    self.bus(ev)
                else:
                    self.bus.publish(ev)
            except Exception:
                pass
        if ev.get("type") == "finding":
            with self._report_lock:
                self._report["findings"].append({
                    "severity": ev.get("severity", "low"),
                    "module": ev.get("module", ""),
                    "detail": ev.get("detail", ""),
                    "evidence": ev.get("evidence", {}),
                    "confidence": ev.get("confidence", "confirmed"),
                })
        elif ev.get("type") == "module" and ev.get("status") == "done":
            with self._report_lock:
                self._report["modules_list"].append({
                    "name": ev.get("name", ""), "ok": True, "msg": ev.get("msg", "")})

    def record_progress(self):
        with self._prog_lock:
            self._done_count += 1
            return self._done_count, self._total

    def set_total(self, n):
        with self._prog_lock:
            self._total = n

    # ----- control -----
    def ctrl(self, module):
        return STORE.check(self.scan_id, module)

    def _check_abort(self):
        """Consulta control global: lanza ScanAbort si stop, espera si pause."""
        st = STORE._scans.get(self.scan_id) if hasattr(STORE, "_scans") else None
        action = st.get("action") if st else "run"
        if action == "stop":
            raise ScanAbort("detenido por el usuario")
        if action == "pause":
            import time
            while True:
                s2 = STORE._scans.get(self.scan_id) if hasattr(STORE, "_scans") else None
                a2 = s2.get("action") if s2 else "run"
                if a2 == "stop":
                    raise ScanAbort("detenido por el usuario")
                if a2 == "run":
                    break
                time.sleep(0.2)

    # ----- red -----
    def req(self, method, url, data=None, timeout=10, raw=False, **kwargs):
        # chequeo de control antes de cada peticion: esto hace que
        # detener/pausar funcione DENTRO de cualquier modulo (todos usan req)
        self._check_abort()
        return request(method, url, data=data, cookie=self.cookie,
                       timeout=timeout, raw=raw, **kwargs)

    # ----- OOB -----
    def start_oob(self):
        return start_oob(self.scan_id)

    def wait_oob(self, module, timeout=1.2):
        return wait_oob_responsive(self.scan_id, module, timeout)

    def stop_oob(self):
        stop_oob(self.scan_id)
