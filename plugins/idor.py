#!/usr/bin/env python3
"""Plugin IDOR: enumeracion de objetos por id + deteccion de acceso sin control."""
IDOR_PATHS = ["", "/doc", "/note", "/file", "/user", "/account", "/profile", "/view", "/api/user"]
IDOR_PARAMS = ["id", "doc", "uid", "user", "file", "pid", "account", "email"]
IDOR_VALUES = ["1", "2", "3", "0", "999", "1001"]


def run(ctx):
    target = ctx.target
    hits = []
    for ip in IDOR_PATHS:
        base_url = target.rstrip("/") + ip
        for idparam in IDOR_PARAMS:
            if ctx.ctrl("idor") in ("stop", "skip"):
                break
            for vid in IDOR_VALUES:
                if ctx.ctrl("idor") in ("stop", "skip"):
                    break
                rr = ctx.req("GET", base_url, {idparam: vid})
                body = (rr.get("body", "") or "").lower()
                if (rr.get("code") == 200 and len(rr.get("body", "")) > 30
                        and "not found" not in body and "404" not in body
                        and "denied" not in body and "forbidden" not in body):
                    hits.append(f"{ip or '/'}{idparam}={vid}")
                    ctx.emit({"type": "finding", "severity": "medium", "module": "idor",
                              "detail": f"Objeto {base_url} {idparam}={vid} accesible sin control de acceso aparente",
                              "evidence": {"url": base_url, "param": idparam, "value": vid}})
                    break
    ctx.emit({"type": "module", "name": "idor", "status": "done",
              "msg": f"IDOR: {len(hits)} sospechoso(s)", "findings": hits})
