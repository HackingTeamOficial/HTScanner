#!/usr/bin/env python3
"""Plugin IDOR: enumeracion de objetos por id + deteccion de acceso sin control.

Mejora v2:
  * Usa la superficie REAL del crawler (formularios y parametros descubiertos)
    ademas de las rutas por defecto.
  * Compara la respuesta para id=1 vs id=2 vs id=999: si el servidor responde
    contenido distinto a cada id (y no un 404/denied), hay enumeracion de
    objetos. Reduce falsos positivos respecto al chequeo de solo "200 + body".
"""
IDOR_PATHS = ["", "/doc", "/note", "/file", "/user", "/account", "/profile",
              "/view", "/api/user", "/api/users", "/order", "/invoice", "/item"]
IDOR_PARAMS = ["id", "doc", "uid", "user", "file", "pid", "account", "email",
               "order", "item", "cid", "oid"]
IDOR_VALUES = ["1", "2", "3", "0", "999", "1001"]


def run(ctx):
    crawl = getattr(ctx, "_crawl", {}) or {}
    targets = []
    seen = set()

    def add(url_base, param):
        key = (url_base.rstrip("/"), param)
        if key not in seen:
            seen.add(key)
            targets.append((url_base, param))

    for f in (crawl.get("forms") or []):
        act = f.get("action") or ctx.target
        for p in (f.get("params") or []):
            add(act, p)
    crawled_urls = sorted(u.split("?")[0] for u in (crawl.get("urls") or set()))
    for p in (crawl.get("params") or set()):
        p = str(p)
        if p:
            add(ctx.target, p)
            for u in crawled_urls:
                if u.startswith(ctx.target.rstrip("/")):
                    add(u, p)
    for sp in IDOR_PATHS:
        base_url = ctx.target.rstrip("/") + sp
        for param in IDOR_PARAMS:
            add(base_url, param)

    hits = []
    for base_url, param in targets:
        if ctx.ctrl("idor") in ("stop", "skip"):
            break
        bodies = {}
        for vid in IDOR_VALUES:
            if ctx.ctrl("idor") in ("stop", "skip"):
                break
            rr = ctx.req("GET", base_url, {param: vid})
            code = rr.get("code")
            body = (rr.get("body", "") or "")
            low = body.lower()
            if code == 200 and len(body) > 30 and \
               "not found" not in low and "404" not in low and \
               "denied" not in low and "forbidden" not in low:
                bodies[vid] = body
        # Si al menos 2 ids distintos devuelven contenido diferente => enumerable
        uniq = set(b[:200] for b in bodies.values())
        if len(bodies) >= 2 and len(uniq) >= 2:
            hits.append(f"{base_url} {param}")
            ctx.emit({"type": "finding", "severity": "medium", "module": "idor",
                      "detail": f"Objeto enumerable en '{base_url}' param '{param}': "
                                f"ids distintos devuelven contenido distinto sin control de acceso",
                      "evidence": {"url": base_url, "param": param,
                                   "ids_probados": list(bodies.keys())}})
    ctx.emit({"type": "module", "name": "idor", "status": "done",
              "msg": f"IDOR: {len(hits)} enumerable(s)", "findings": hits})
