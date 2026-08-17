# Changelog

## [0.1.0] - 2026-08-14
### Añadido
- GUI tema blanco/negro, medidor Ookla (gauge circular animado).
- Gate de login desactivado para uso local/CTF.
- Handler de estáticos propio en `server.py` (sin `SimpleHTTPRequestHandler`).
- Plugins: `xss2shell` (WordPress Pre-Auth XSS → RCE Chain detector).
- Perfil dedicado `xss2shell`.
- Suite de tests `tests/test_scan.py` (lab local `demo_target.py`).
- Blindaje Unicode: `errors="replace"` en todos los subprocess/lecturas.
- Puerto 8787 (evita conflicto con instancias zombie en 8777).

### Corregido
- `case "progress"` con `const` suelto → SyntaxError en navegador.
- Botones del banner eliminados (Telegram config + Comparar).
- `demo_target.py` rutas `/tmp` → relativas (funciona en Windows).

### Documentación
- `docs/ARCHITECTURE.md`, `docs/CONTRIBUTING.md`, este `CHANGELOG.md`.
