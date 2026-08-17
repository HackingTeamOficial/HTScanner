# Cómo contribuir / añadir un plugin

## 1. Crea el plugin en `plugins/`
```python
# plugins/mi_plugin.py
def run(ctx):
    ctx.emit({"type":"log","msg":"mi_plugin: iniciando","level":"info"})
    # ... tu lógica ...
    ctx.emit({"type":"module","name":"mi_plugin","status":"done","msg":"hecho"})
```

## 2. Regístralo en `core/profiles.py`
Añade el nombre a `ALL_ATTACK` (y al perfil que corresponda).

## 3. Eventos SSE
Usa `ctx.emit({...})` para:
- `finding` (hallazgos)
- `module` (estado del módulo)
- `log` (logs visibles)
- `progress` / `progress_tick` (progreso)

## 4. No toques `final.rar`
`final.rar` es la baseline congelada. Trabaja en `HTScanner-dev/`.
