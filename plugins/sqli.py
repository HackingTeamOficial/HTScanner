#!/usr/bin/env python3
"""Plugin SQLi: inyeccion SQL con confirmacion para reducir falsos positivos.
Usa diferencia de respuesta (error SQL o diferencia booleana) antes de reportar.
"""
import re
import urllib.parse

SQLI_ERRORS = ["error in your sql", "sql syntax", "sqlite", "you have an error",
               "unclosed quotation mark", "sqlstate", "ora-", "pg_", "warning: mysqli",
               "microsoft sql server", "syntax error", "near \"", "unrecognized token",
               "operationalerror", "database error", "could not", "sql command not properly ended"]

# condiciones booleanas para inyeccion ciega
BOOL_TRUE = ["' OR '1'='1", "\" OR \"1\"=\"1", "1 OR 1=1", "1) OR (1=1"]
BOOL_FALSE = ["' AND '1'='2", "\" AND \"1\"=\"2", "1 AND 1=2", "1) AND (1=2)"]

SQLI_PATHS = ["", "/notes", "/doc", "/article", "/view", "/product", "/item", "/post", "/news"]
SQLI_PARAMS = ["id", "q", "page", "search", "note", "cat", "pid", "uid", "user"]


def run(ctx):
    target = ctx.target
    from engine import confirm_sqli_boolean
    hits = []
    for sp in SQLI_PATHS:
        base_url = target.rstrip("/") + sp
        for param in SQLI_PARAMS:
            if ctx.ctrl("sqli") in ("stop", "skip"):
                break
            base = ctx.req("GET", base_url, {param: "1"})
            if base.get("err"):
                continue
            base_len = len(base.get("body", ""))
            base_code = base.get("code")
            confirmed = False
            for p in SQLI_ERRORS[:6] + ["' OR '1'='1"]:
                if ctx.ctrl("sqli") in ("stop", "skip"):
                    break
                rr = ctx.req("GET", base_url, {param: p})
                body_l = (rr.get("body", "") or "").lower()
                if any(s in body_l for s in SQLI_ERRORS):
                    confirmed = True
                    break
                elif rr.get("code") not in (base_code, 0) and rr.get("code") == 500:
                    confirmed = True
                    break
                elif abs(len(rr.get("body", "")) - base_len) > 80:
                    confirmed = True
                    break
            # confirmacion booleana ciega si no hubo error evidente
            if not confirmed:
                for t, f in zip(BOOL_TRUE, BOOL_FALSE):
                    if ctx.ctrl("sqli") in ("stop", "skip"):
                        break
                    if confirm_sqli_boolean(ctx, base_url, param, t, f):
                        confirmed = True
                        break
            if confirmed:
                hits.append(f"{sp or '/'}{param}")
                ctx.emit({"type": "finding", "severity": "high", "module": "sqli",
                          "detail": f"SQLi confirmada en '{base_url}' param '{param}' (error O diferencia booleana)",
                          "evidence": {"url": base_url, "param": param,
                                       "method": "error-based o boolean-blind"}})
                break
    ctx.emit({"type": "module", "name": "sqli", "status": "done",
              "msg": f"SQLi: {len(hits)} confirmada(s)", "findings": hits})
