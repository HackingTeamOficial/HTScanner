#!/usr/bin/env python3
"""Plugin CORS: detecta CORS demasiado permisivo (wildcard + credentials)."""
import re


def run(ctx):
    target = ctx.target
    hits = []
    try:
        # Usar el contexto SSL centralizado via ctx.req
        rr = ctx.req("GET", target, headers={"Origin": "https://evil.example.com"})
        headers = {k.lower(): v for k, v in (rr.get("headers", {}) or {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
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
        # 403/Forbidden es respuesta válida del target; no es error del scanner.
        emsg = str(e)
        if "403" in emsg or "Forbidden" in emsg:
            ctx.emit({"type": "log", "msg": "CORS: objetivo responde 403 (Origin externo bloqueado) — sin hallazgo", "level": "info"})
        else:
            ctx.emit({"type": "log", "msg": f"CORS: no se pudo probar ({emsg})", "level": "warn"})
    ctx.emit({"type": "module", "name": "cors", "status": "done",
              "msg": f"CORS: {len(hits)} hallazgo(s)", "findings": hits})
