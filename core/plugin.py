#!/usr/bin/env python3
"""core/plugin.py - clase Plugin + PluginManager (carga dinamica).

Un plugin es un modulo .py en plugins/ que define:

    PLUGIN_NAME = "XSS"
    PLUGIN_SEVERITY = "High"   # usado por defecto si el plugin no lo cambia
    def run(context):
        ... # usa context.req / context.emit / context.ctrl
        context.emit({"type": "finding", "severity": "...", ...})
        return [...]   # lista de hallazgos (opcional)

El PluginManager los carga y ejecuta. Anadir un modulo = copiar un archivo.
"""
import os
import sys
import importlib.util


class Plugin:
    """Envuelve un modulo plugin cargado."""
    def __init__(self, name, module):
        self.name = name
        self.module = module
        self.severity = getattr(module, "PLUGIN_SEVERITY", "Medium")
        self.description = getattr(module, "PLUGIN_DESC", "")

    def run(self, context):
        return self.module.run(context)


class PluginManager:
    """Descubre y carga plugins desde un directorio. Cachea."""

    def __init__(self, plugins_dir):
        self.plugins_dir = plugins_dir
        self._cache = None

    def load_all(self):
        if self._cache is not None:
            return self._cache
        plugins = {}
        if not os.path.isdir(self.plugins_dir):
            self._cache = plugins
            return plugins
        for fn in sorted(os.listdir(self.plugins_dir)):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            path = os.path.join(self.plugins_dir, fn)
            try:
                spec = importlib.util.spec_from_file_location("hts_plugin_" + fn[:-3], path)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                name = getattr(mod, "PLUGIN_NAME", fn[:-3])
                if hasattr(mod, "run"):
                    plugins[name] = Plugin(name, mod)
            except Exception as e:
                sys.stderr.write(f"[plugin error] {fn}: {e}\n")
        self._cache = plugins
        return plugins

    def names(self):
        return list(self.load_all().keys())

    def runner(self, name):
        """Devuelve func(context) para ejecutar el plugin 'name'."""
        p = self.load_all().get(name)
        if p:
            return lambda ctx: p.run(ctx)
        return None

    def runners(self):
        """Dict name -> func(context) para todos los plugins."""
        return {name: (lambda ctx, p=p: p.run(ctx)) for name, p in self.load_all().items()}


def discover_plugins(plugins_dir):
    """Funcion de conveniencia: devuelve dict name -> Plugin."""
    return PluginManager(plugins_dir).load_all()
