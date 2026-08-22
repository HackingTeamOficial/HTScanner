#!/usr/bin/env python3
"""core/control.py - estado y control de escaneos.

Un store central de estados de escaneo (pause/skip/stop) accesible por
cualquier modulo sin importar server.py. El EventBus y el contexto lo usan.
"""
import threading
import time


class ControlStore:
    """Registro de escaneos activos: scan_id -> {action, skip_module}."""
    def __init__(self):
        self._lock = threading.Lock()
        self._scans = {}

    def create(self, scan_id):
        with self._lock:
            self._scans[scan_id] = {"action": "run", "skip_module": None}

    def drop(self, scan_id):
        with self._lock:
            self._scans.pop(scan_id, None)

    def set_action(self, scan_id, action):
        """action: run | pause | resume | stop"""
        with self._lock:
            st = self._scans.get(scan_id)
            if not st:
                return
            st["action"] = "run" if action == "resume" else action

    def skip(self, scan_id, module):
        with self._lock:
            st = self._scans.get(scan_id)
            if st:
                st["skip_module"] = module

    def check(self, scan_id, current_module):
        """Devuelve 'run' | 'skip' | 'stop'. Consume skip por modulo.
        No mantiene el lock mientras espera (evita deadlock con set_action)."""
        while True:
            with self._lock:
                st = self._scans.get(scan_id)
                if not st:
                    return "run"
                if st.get("action") == "stop":
                    return "stop"
                if st.get("skip_module") == current_module:
                    st["skip_module"] = None
                    return "skip"
                if st.get("action") != "pause":
                    return "run"
            # pausa: soltar lock y esperar fuera
            time.sleep(0.2)


# Instancia global (singleton del proyecto)
STORE = ControlStore()
