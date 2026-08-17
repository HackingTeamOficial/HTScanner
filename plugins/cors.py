#!/usr/bin/env python3
"""Plugin CORS: detecta CORS demasiado permisivo (wildcard + credentials)."""
import re


def run(ctx):
    target = ctx.target
    hits = []
    # peticion con Origin externo para provocar respuesta CORS
    hdr = {"Origin": "https://evil.example.com"}
    try:
        import urllib.request, urllib.parse
        from server import UA, SSL_CTX
        req = urllib.request.Request(target, headers={"User-Agent": UA, "Origin": "https://evil.example.com"})
        resp = urllib.request.urlopen(req, timeout=10, context=SSL_CTX)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao:
            if acao == "*" and acac == "true":
                sev = "high"
                conf = "confirmed"
                msg = "CORS wildcard con Access-Control-Allow-Credentials: true (robo de credenciales)"
            elif acao == "*":
                sev = "low"
                conf = "confirmed"
                msg = "CORS wildcard (Access-Control-Allow-Origin: *) — sin credenciales"
            elif "evil.example.com" in acao:
                sev = "medium"
                conf = "confirmed"
                msg = f"CORS refleja el Origin del atacante ({acao})"
            else:
                sev = "info"
                conf = "confirmed"
                msg = f"CORS presente: {acao}"
            hits.append(acao)
            ctx.emit({"type": "finding", "severity": sev, "module": "cors",
                      "confidence": conf,
                      "detail": msg, "evidence": {"acao": acao, "acac": acac}})
    except Exception as e:
        ctx.emit({"type": "log", "msg": f"CORS: no se pudo probar ({e})", "level": "warn"})
    ctx.emit({"type": "module", "name": "cors", "status": "done",
              "msg": f"CORS: {len(hits)} hallazgo(s)", "findings": hits})
