#!/usr/bin/env python3
"""core/ - nucleo desacoplado de HTScanner.

Cada modulo es independiente y NO importa server.py ni engine.py:

  http.py      -> request()  (capa de red)
  oob.py       -> servidor OOB local (RFI/XXE) + estado de scans
  control.py   -> control de escaneos (pause/skip/stop) + estado
  eventbus.py  -> bus de eventos pub/sub (scanner/plugin/gui/api/logs)
  plugin.py    -> clase Plugin + PluginManager (carga dinamica)
  context.py   -> ScanContext (une http/oob/control/eventbus)
  db.py        -> persistencia SQLite (objetivos/hallazgos/tech/riesgo)

El server.py solo hace: HTTP server -> API -> llama al engine/context -> frontend.
Nada de logica de escaneo vive en server.py.
"""
