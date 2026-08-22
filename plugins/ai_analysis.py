#!/usr/bin/env python3
"""Plugin ai_analysis: priorizacion de hallazgos con Ollama local.

Envía un resumen de los hallazgos a un modelo Ollama local
(http://127.0.0.1:11434/api/generate) y emite una recomendacion de
priorizacion. Si Ollama no esta disponible, degrada limpiamente (log warn)
sin fallar el escaneo. Usa urllib (sin subprocess, sin shell).
"""
import json
import time
import urllib.request

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"


def _ask(prompt, model="qwen3:1.7b"):
    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")).get("response", "")
    except Exception:
        return None


def run(ctx):
    # los hallazgos se acumulan durante el escaneo (corre en paralelo);
    # esperamos un poco para recolectar la mayoria antes de analizar.
    time.sleep(15)
    findings = getattr(ctx, "_report", {}).get("findings", [])
    if not findings:
        ctx.emit({"type": "module", "name": "ai_analysis", "status": "done",
                  "msg": "ai_analysis: sin hallazgos para analizar"})
        return
    summary = "\n".join(
        f"- [{f.get('severity')}] {f.get('module')}: {f.get('detail', '')[:160]}"
        for f in findings[:40])
    prompt = ("Eres un analista de seguridad ofensiva. Prioriza estos hallazgos de un "
              "escaneo web ordenados por riesgo y sugiere el siguiente paso para cada uno. "
              "Sé conciso.\n\n" + summary)
    ans = _ask(prompt)
    if ans is None:
        ctx.emit({"type": "log",
                  "msg": "ai_analysis: Ollama no disponible (127.0.0.1:11434). Omitiendo analisis IA.",
                  "level": "warn"})
        ctx.emit({"type": "module", "name": "ai_analysis", "status": "done",
                  "msg": "ai_analysis: Ollama no disponible"})
        return
    ctx.emit({"type": "finding", "severity": "info", "module": "ai_analysis",
              "confidence": "sospechoso",
              "detail": "Analisis IA (Ollama local):\n" + ans[:1500]})
    ctx.emit({"type": "module", "name": "ai_analysis", "status": "done",
              "msg": "ai_analysis: priorizacion IA generada"})
