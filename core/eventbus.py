#!/usr/bin/env python3
"""core/eventbus.py - bus de eventos pub/sub desacoplado.

Los plugins, el scanner, la GUI, la API y los logs se suscriben al bus.
Nadie habla directo con nadie: todos pasan por el bus.

Ejemplo:
    bus = EventBus()
    bus.subscribe("finding", gui_handler)
    bus.subscribe("finding", db_handler)
    bus.publish({"type": "finding", ...})
"""
import threading


class EventBus:
    def __init__(self):
        self._subs = {}          # tipo_evento -> [handlers]
        self._lock = threading.RLock()

    def subscribe(self, event_type, handler):
        with self._lock:
            self._subs.setdefault(event_type, []).append(handler)

    def subscribe_many(self, types, handler):
        for t in types:
            self.subscribe(t, handler)

    def unsubscribe(self, event_type, handler):
        with self._lock:
            lst = self._subs.get(event_type, [])
            if handler in lst:
                lst.remove(handler)

    def publish(self, event):
        """Publica un evento a todos los suscriptores de su tipo.
        Tambien a los suscriptores '*' (catch-all). No lanza excepciones."""
        etype = event.get("type")
        with self._lock:
            handlers = list(self._subs.get(etype, [])) + list(self._subs.get("*", []))
        for h in handlers:
            try:
                h(event)
            except Exception as e:
                # un handler roto no debe tumbar el scan
                try:
                    self._on_handler_error and self._on_handler_error(e, event)
                except Exception:
                    pass

    def set_error_handler(self, fn):
        self._on_handler_error = fn
