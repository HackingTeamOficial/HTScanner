# Arquitectura de HTScanner

## Visión general
- **Frontend**: `index.html` + `app.js` + `style.css` (SPA monolítica, SSE push).
- **Backend**: `server.py` (`ThreadingHTTPServer`) sirve estáticos y SSE en `/api/scan`.
- **Motor**: `engine.py` orquesta `scan_target()` en `server.py`.
- **Plugins**: `plugins/*.py` con `run(ctx)`; carga dinámica vía `core.plugin_manager.PluginManager`.
- **Perfiles**: `core/profiles.py` define `recon`, `passive`, `full`, `cms`, `wordpress`, `xss2shell`, etc.

## Flujo de escaneo
1. Usuario abre GUI, marca autorización, pulsa INICIAR.
2. `app.js` crea `EventSource` a `/api/scan?...`.
3. `server.py` crea `ScanContext`, fija `total` global (headers + recon + ataque).
4. Fase recon: fingerprint, crawler, discovery, archivos.
5. Fase ataque: plugins del perfil + runners internos (`rfi`, `xxe`).
6. Cada módulo emite `module` (running/done); las peticiones emiten `progress_tick`.
7. Frontend anima gauge Ookla (`requestAnimationFrame`) + barra.

## SSE events
- `scan_id`, `mode`, `module`, `finding`, `recon`, `progress`, `progress_tick`,
  `report`, `profile`, `chain`, `diff`, `done`, `error`, `log`.

## Configuración
- `config/telegram.example.json` — ejemplo para notificaciones Telegram.
- No hay lock screen en v0.1.0; el backend no exige token para `/api/*`.

## Puertos
- Backend GUI: **8787** (http://127.0.0.1:8787)
- Lab local: **9090** (`demo_target.py`)
