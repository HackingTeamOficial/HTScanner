#!/usr/bin/env python3
"""core/recon_extra.py - Descubrimiento ampliado (Fase 3).

Capacidades (todas stdlib, sin pip):
  * sitemap.xml / sitemap_index.xml -> parsea URLs y las anade a la superficie.
  * JS Sourcemaps (.js.map) -> descarga el mapa y extrae rutas/sources originales.
  * Parametros ocultos -> inputs type=hidden y data-* ya los caza el crawler;
    aqui se anaden parametros comunes de frameworks para ampliar la superficie.
  * Endpoints antiguos -> wordlist de rutas legacy (versiones previas, backups de ruta).
  * Wayback (opcional, SOLO si hay red) -> lista de URLs historicas del target;
    con fallback silencioso a lo local si no hay conectividad.

Devuelve un dict que el scan_target puede fusionar en ctx._crawl para que
los plugins de ataque (sqli/xss/lfi...) aprovechen la superficie ampliada.
"""
import re
import urllib.parse
import urllib.request

# Wordlist de endpoints antiguos / legacy (versiones previas, rutas tipicas)
LEGACY_ENDPOINTS = [
    "/admin/old", "/old/admin", "/legacy", "/v1", "/api/v1", "/api/old",
    "/backup", "/bak", "/old", "/temp", "/tmp", "/dev", "/devel", "/stage",
    "/staging", "/beta", "/preview", "/cgi-bin", "/cgi-bin/test", "/_profiler",
    "/_wdt", "/phpmyadmin", "/pma", "/adminer", "/setup", "/install",
    "/xmlrpc.php", "/wp-login.php", "/wp-admin", "/joomla/administrator",
    "/console", "/actuator", "/actuator/env", "/.git", "/.svn", "/webdav",
]

# Parametros comunes de frameworks para ampliar la superficie de ataque
COMMON_PARAMS = [
    "id", "cat", "q", "search", "page", "file", "path", "url", "redirect",
    "return", "next", "lang", "token", "email", "user", "username", "name",
    "title", "content", "body", "msg", "callback", "jsonp", "format", "view",
    "action", "do", "module", "ref", "img", "src", "document", "download",
]


def _get(ctx, url, timeout=8):
    try:
        return ctx.req("GET", url, timeout=timeout)
    except Exception:
        return None


def sitemap(ctx, found=None):
    """Parsea /sitemap.xml y /sitemap_index.xml; anade URLs al set 'found'."""
    if found is None:
        found = set()
    for sm in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"):
        rr = _get(ctx, ctx.target.rstrip("/") + sm)
        if not rr or rr.get("code") != 200:
            continue
        body = rr.get("body", "") or ""
        # sitemap index -> seguir los sub-sitemaps
        for loc in re.findall(r"<loc>([^<]+)</loc>", body):
            if "sitemap" in loc.lower():
                sub = _get(ctx, loc)
                if sub and sub.get("code") == 200:
                    for l2 in re.findall(r"<loc>([^<]+)</loc>", sub.get("body", "")):
                        found.add(l2)
            else:
                found.add(loc)
        # sitemap plano (txt, uno por linea)
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("http"):
                found.add(line)
    return found


def sourcemaps(ctx, js_files, found_urls=None, found_params=None):
    """Busca .js.map para cada JS y extrae rutas/sources originales."""
    if found_params is None:
        found_params = set()
    for js in list(js_files or []):
        if not js.endswith(".js"):
            continue
        map_url = js + ".map"
        rr = _get(ctx, map_url, timeout=6)
        if not rr or rr.get("code") != 200:
            continue
        try:
            data = json_safe(rr.get("body", ""))
            # sources: archivos originales (pueden revelar rutas/estructura)
            for src in (data.get("sources") or []):
                if isinstance(src, str) and src.startswith("/"):
                    found_urls and found_urls.add(_abs(ctx.target, src))
            # "sourcesContent" a veces trae endpoints en comentarios
            for sc in (data.get("sourcesContent") or []):
                if isinstance(sc, str):
                    for m in re.findall(r"['\"](/[a-zA-Z0-9_./-]+)['\"]", sc):
                        if len(m) > 1:
                            found_urls and found_urls.add(_abs(ctx.target, m))
        except Exception:
            continue
    return found_urls, found_params


def json_safe(text):
    import json
    try:
        return json.loads(text)
    except Exception:
        return {}


def _abs(base, link):
    p = urllib.parse.urlparse(base)
    if link.startswith("//"):
        return p.scheme + ":" + link
    if link.startswith("/"):
        return f"{p.scheme}://{p.netloc}{link}"
    return urllib.parse.urljoin(base, link)


def legacy_endpoints(ctx, found=None):
    """Prueba endpoints antiguos/legacy y anade los que responden 200/403."""
    if found is None:
        found = set()
    for ep in LEGACY_ENDPOINTS:
        if ctx.ctrl("archivos") in ("stop", "skip"):
            break
        url = ctx.target.rstrip("/") + ep
        rr = _get(ctx, url, timeout=5)
        if rr and rr.get("code") in (200, 403) and rr.get("err") is None:
            found.add(url)
    return found


def wayback(ctx, found=None):
    """Wayback Machine (SOLO si hay red). Fallback silencioso si no hay."""
    if found is None:
        found = set()
    try:
        host = urllib.parse.urlparse(ctx.target).netloc
        api = f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=text&fl=original&collapse=urlkey&limit=200"
        req = urllib.request.Request(api, headers={"User-Agent": "HT-Scanner"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            for line in resp.read().decode("utf-8", "replace").splitlines():
                line = line.strip()
                if line.startswith("http"):
                    found.add(line)
    except Exception:
        # sin red -> no anade nada (comportamiento local)
        pass
    return found


def run_extra_recon(ctx):
    """Ejecuta todo el descubrimiento ampliado y devuelve un dict para
    fusionar en ctx._crawl. Tambien emite hallazgos info de lo descubierto."""
    crawl = getattr(ctx, "_crawl", {}) or {}
    urls = set(crawl.get("urls") or set())
    params = set(crawl.get("params") or set())
    js_files = set(crawl.get("js_files") or set())

    # 1) sitemap
    sm_urls = sitemap(ctx, set())
    for u in sm_urls:
        if u not in urls:
            urls.add(u)
            ctx.emit({"type": "finding", "severity": "info", "module": "recon_extra",
                      "detail": f"URL descubierta via sitemap.xml: {u}"})
    # 2) sourcemaps
    urls, params = sourcemaps(ctx, js_files, urls, params)
    # 3) endpoints legacy
    leg = legacy_endpoints(ctx, set())
    for u in leg:
        if u not in urls:
            urls.add(u)
            ctx.emit({"type": "finding", "severity": "low", "module": "recon_extra",
                      "detail": f"Endpoint antiguo/legacy activo: {u}"})
    # 4) wayback (red opcional)
    wb = wayback(ctx, set())
    for u in wb:
        if u not in urls:
            urls.add(u)
            ctx.emit({"type": "finding", "severity": "info", "module": "recon_extra",
                      "detail": f"URL historica (Wayback): {u}"})
    # 5) parametros comunes de frameworks
    for p in COMMON_PARAMS:
        params.add(p)

    return {"urls": urls, "params": params, "js_files": js_files}
