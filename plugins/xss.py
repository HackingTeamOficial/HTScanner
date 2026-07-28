#!/usr/bin/env python3
"""Plugin XSS: reflejado con confirmacion de reflexion no escapada."""
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "'><svg/onload=alert(1)>", "\"><script>alert(1)</script>"]
XSS_PATHS = ["", "/search", "/buscar", "/q", "/s", "/find", "/comment"]
XSS_PARAMS = ["q", "search", "s", "id", "name", "term", "query", "text"]


def run(ctx):
    from engine import confirm_xss_reflected
    target = ctx.target
    hits = []
    for xp in XSS_PATHS:
        base_url = target.rstrip("/") + xp
        for param in XSS_PARAMS:
            if ctx.ctrl("xss") in ("stop", "skip"):
                break
            for p in XSS_PAYLOADS:
                if ctx.ctrl("xss") in ("stop", "skip"):
                    break
                rr = ctx.req("GET", base_url, {param: p})
                if rr.get("code") == 200 and confirm_xss_reflected(rr.get("body", ""), p):
                    hits.append(f"{base_url} {param}")
                    ctx.emit({"type": "finding", "severity": "high", "module": "xss",
                              "detail": f"XSS reflejado en '{base_url}' param '{param}' (payload no escapado)",
                              "evidence": {"url": base_url, "param": param, "payload": p}})
                    break
    ctx.emit({"type": "module", "name": "xss", "status": "done",
              "msg": f"XSS: {len(hits)} confirmado(s)", "findings": hits})
