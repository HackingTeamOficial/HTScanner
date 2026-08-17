#!/usr/bin/env python3
"""Plugin CSRF: comprueba si formularios sensibles carecen de token CSRF.

Confirmacion REAL: si el formulario POST no tiene token, reenviamos el
POST (sin token) y miramos si el servidor lo acepta (200/302) en lugar
de rechazarlo (403/419). Si lo acepta => CSRF confirmado; si pide
token => sospechoso (el server si valida).

Escanea target + paginas descubiertas por el crawler (ctx._crawl).
"""
import re
import urllib.parse

CSRF_TOKEN_HINTS = ["csrf", "_token", "authenticity_token",
                     "__requestverificationtoken", "token", "xsrf", "_csrf"]


def _post_no_token(ctx, action, inputs):
    """Intenta un POST sin token CSRF; devuelve True si el server lo acepta."""
    data = {}
    for name in inputs:
        nl = name.lower()
        if any(w in nl for w in ("user", "email", "login", "name")):
            data[name] = "test"
        elif "pass" in nl:
            data[name] = "test"
        else:
            data[name] = "1"
    try:
        rr = ctx.req("POST", action, data=data, timeout=10)
        code = rr.get("code") or 0
        # 2xx/3xx => aceptado sin token => CSRF confirmado
        return 200 <= int(code) < 400
    except Exception:
        return False


def _check_page(ctx, url):
    """Devuelve lista de hallazgos (dicts) para una pagina."""
    out = []
    try:
        rr = ctx.req("GET", url, timeout=10)
    except Exception:
        return out
    body = rr.get("body", "") or ""
    forms = re.findall(r"<form[^>]*method=['\"]?post['\"]?[^>]*>(.*?)</form>",
                       body, re.IGNORECASE | re.DOTALL)
    for i, frm in enumerate(forms):
        fl = frm.lower()
        inputs = re.findall(r"name=['\"]([^'\"]+)['\"]", frm)
        if not inputs:
            continue
        has_token = any(h in fl for h in [t.lower() for t in CSRF_TOKEN_HINTS])
        if not has_token:
            action = re.search(r"action=['\"]?([^'\">\s]*)", frm)
            act = action.group(1) if action else url
            if act.startswith("/"):
                p = urllib.parse.urlparse(url)
                act = f"{p.scheme}://{p.netloc}{act}"
            accepted = _post_no_token(ctx, act, inputs)
            if accepted:
                sev = "medium"
                conf = "confirmed"
                msg = (f"CSRF confirmado: formulario POST #{i+1} sin token y el "
                       f"servidor ACEPTA el POST sin token (403/419 esperado)")
            else:
                sev = "low"
                conf = "sospechoso"
                msg = (f"CSRF sospechoso: formulario POST #{i+1} sin token CSRF; "
                       f"el servidor rechaza el POST sin token (posiblemente valida)")
            out.append({"severity": sev, "confidence": conf, "msg": msg,
                        "evidence": {"url": act, "inputs": inputs}})
    return out


def run(ctx):
    target = ctx.target
    # paginas a revisar: target + las descubiertas por el crawler
    pages = [target]
    crawl = getattr(ctx, "_crawl", {}) or {}
    for u in (crawl.get("urls", set()) or set()):
        if u.startswith(target.rstrip("/")):
            pages.append(u)
    seen_pages = set()
    hits = []
    for pg in pages:
        if pg in seen_pages:
            continue
        seen_pages.add(pg)
        if ctx.ctrl("csrf") in ("stop", "skip"):
            break
        for h in _check_page(ctx, pg):
            hits.append(f"{pg} #{h['msg'].split('#')[-1].split(' ')[0]}")
            ctx.emit({"type": "finding", "severity": h["severity"], "module": "csrf",
                      "confidence": h["confidence"],
                      "detail": h["msg"], "evidence": h["evidence"]})
    ctx.emit({"type": "module", "name": "csrf", "status": "done",
              "msg": f"CSRF: {len(hits)} formulario(s) revisado(s)",
              "findings": hits})
