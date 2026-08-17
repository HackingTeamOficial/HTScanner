#!/usr/bin/env python3
"""Plugin osint_urls: descubrimiento OSINT de URLs (Wayback CDX, sitemap, robots).

Amplia la superficie via fuentes publicas (web.archive.org CDX API) y archivos
del propio target (robots.txt, sitemap.xml). No requiere APIs de pago.
Todo por ctx.req (core.http). Actualiza ctx._crawl para alimentar otros modulos.
"""
from urllib.parse import urlparse


def _wayback_url(domain):
    return ("https://web.archive.org/cdx/search/cdx?url=%s/*&output=text"
            "&fl=original&collapse=urlkey&limit=200" % domain)


def run(ctx):
    host = urlparse(ctx.target).netloc
    domain = host.split(":")[0]
    found = set()

    # 1) Wayback CDX (historico de URLs)
    r = ctx.req("GET", _wayback_url(domain), timeout=15)
    if not r.get("err") and r.get("body"):
        for line in r.get("body", "").splitlines():
            u = line.strip()
            if u.startswith("http"):
                found.add(u)

    # 2) robots.txt / sitemap.xml del propio target
    for path in ["/robots.txt", "/sitemap.xml"]:
        rr = ctx.req("GET", ctx.target.rstrip("/") + path, timeout=10)
        if rr.get("code") == 200 and rr.get("body"):
            for line in rr["body"].splitlines():
                s = line.strip()
                for tok in ("Sitemap:", "Disallow:", "Allow:"):
                    if s.startswith(tok):
                        val = s.split(":", 1)[1].strip()
                        if not val:
                            continue
                        if val.startswith("http"):
                            found.add(val)
                        else:
                            found.add(ctx.target.rstrip("/") + ("" if val.startswith("/") else "/") + val)

    found = sorted(found)

    # alimentar _crawl para los plugins de ataque
    crawl = getattr(ctx, "_crawl", {}) or {}
    urls = set(crawl.get("urls", set()))
    urls.update(found)
    crawl["urls"] = urls
    ctx._crawl = crawl

    for u in found[:30]:
        ctx.emit({"type": "finding", "severity": "info", "module": "osint_urls",
                  "confidence": "sospechoso", "detail": f"URL OSINT descubierta: {u}"})
    ctx.emit({"type": "module", "name": "osint_urls", "status": "done",
              "msg": f"osint_urls: {len(found)} URL(s) descubierta(s)",
              "findings": found[:30]})
