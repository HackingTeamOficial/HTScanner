#!/usr/bin/env python3
"""crawler.py - Crawler mejorado con parseo HTML real (html.parser).

Descubre:
  * Enlaces, formularios y parámetros con parseo HTML real.
  * Redirecciones 3xx.
  * Endpoints en JS (rutas, fetch/axios, router SPA).
  * APIs/GraphQL/OpenAPI.
"""
import re
import urllib.parse
from html.parser import HTMLParser

JS_ROUTE_RE = re.compile(r"""['"`]((?:/[a-zA-Z0-9_\-.]{1,4}(?:/[A-Za-z0-9_\-.]{1,4})?))['"`]""")
SPA_ROUTE_RE = re.compile(r"""(?:path|to)\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE)
JS_CALL_RE = re.compile(r"""(?:fetch|axios|http|request|router\.\w+|\$\.get|\$\.post)\s*\(?\s*['"`]([^'"`]+)['"`]""")
JS_IMPORT_RE = re.compile(r"""from\s+['"]([^'"]+\.js)['"]""")
API_HINTS = ["api", "graphql", "rest", "v1", "v2", "admin", "user", "login",
             "auth", "token", "oauth", "swagger", "openapi", "proxy", "dashboard"]


def _abs(base, link):
    if link.startswith("//"):
        return urllib.parse.urlparse(base).scheme + ":" + link
    if link.startswith("/"):
        p = urllib.parse.urlparse(base)
        return f"{p.scheme}://{p.netloc}{link}"
    if link.startswith("http"):
        return link
    if link.startswith("#") or link.startswith("javascript:") or link.startswith("mailto:"):
        return ""
    return urllib.parse.urljoin(base, link)


def _is_same_host(base, url):
    try:
        return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(base).netloc
    except Exception:
        return False


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.params = set()

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href", "")
        if tag == "a" and href:
            self.links.append(href)
        if tag == "form":
            action = dict(attrs).get("action", "")
            method = dict(attrs).get("method", "GET").upper()
            self.forms.append({"action": action, "method": method, "params": []})
        if tag == "input":
            name = dict(attrs).get("name", "")
            if name:
                self.params.add(name)
                if self.forms:
                    self.forms[-1]["params"].append(name)


def _analyze_js(js_url, depth=0, seen=None):
    if seen is None:
        seen = set()
    if js_url in seen or depth > 3:
        return set(), set(), set()
    seen.add(js_url)
    js_endpoints = set()
    apis = set()
    spa_routes = set()
    try:
        import urllib.request
        rr = urllib.request.urlopen(js_url, timeout=8)
        txt = rr.read().decode("utf-8", "replace")
        for m in JS_ROUTE_RE.findall(txt):
            path = m.strip()
            if len(path) > 1 and not path.startswith("//"):
                low = path.lower()
                if any(h in low for h in API_HINTS) or low.startswith("/api"):
                    js_endpoints.add(path)
                    apis.add(path)
        for m in SPA_ROUTE_RE.findall(txt):
            if m.startswith("/"):
                spa_routes.add(m)
                if any(h in m.lower() for h in API_HINTS):
                    apis.add(m)
        for m in JS_CALL_RE.findall(txt):
            if m.startswith("/") and len(m) > 1:
                js_endpoints.add(m)
                if any(h in m.lower() for h in API_HINTS):
                    apis.add(m)
        for imp in JS_IMPORT_RE.findall(txt):
            absi = _abs(js_url, imp)
            if absi and absi.endswith(".js") and absi not in seen and depth < 2:
                je, ap, sr = _analyze_js(absi, depth + 1, seen)
                js_endpoints |= je; apis |= ap; spa_routes |= sr
    except Exception:
        pass
    return js_endpoints, apis, spa_routes


def crawl(ctx, max_pages=80, max_js=30):
    base = ctx.target
    visited = set()
    to_visit = [base]
    urls = set()
    forms = []
    params = set()
    js_files = set()
    js_endpoints = set()
    spa_routes = set()
    apis = set()
    redirects = set()

    # semilla inteligente si el crawler no descubre nada útil al inicio
    seed_paths = [
        "/artists.php", "/artist.php",
        "/product.php", "/products.php", "/listproducts.php",
        "/search.php", "/search", "/category.php",
        "/item.php", "/detail.php", "/view.php",
        "/doc", "/note", "/news.php", "/article.php",
        "/books", "/post.php",
    ]
    for sp in seed_paths:
        candidate = base.rstrip("/") + sp
        if candidate not in visited:
            to_visit.append(candidate)

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        if ctx.ctrl("crawler") in ("stop", "skip"):
            break
        try:
            rr = ctx.req("GET", url, timeout=10, follow_redirects=False)
        except Exception:
            continue
        code = rr.get("code")
        hdrs = {k.lower(): v for k, v in (rr.get("headers", {}) or {}).items()}
        if code and 300 <= int(code) < 400:
            loc = hdrs.get("location")
            if loc:
                absr = _abs(url, loc.split("?")[0])
                if absr:
                    redirects.add(absr)
                    if _is_same_host(base, absr) and absr not in visited and len(to_visit) < max_pages:
                        to_visit.append(absr)
        body = rr.get("body", "") or ""
        # parseo HTML real
        parser = _LinkParser()
        try:
            parser.feed(body)
        except Exception:
            pass
        for href in parser.links:
            clean = href.split("#")[0]
            absu = _abs(url, clean)
            if not absu:
                continue
            if absu.startswith(base.rstrip("/")):
                urls.add(absu)
                if absu.endswith(".js") or "/static/" in absu or "/assets/" in absu:
                    js_files.add(absu)
                elif absu not in visited and len(to_visit) < max_pages:
                    to_visit.append(absu)
        forms.extend([
            {
                "action": _abs(url, f["action"]) if f["action"] else url,
                "method": f["method"],
                "params": f["params"],
            }
            for f in parser.forms
        ])
        params |= parser.params
        # parámetros en query strings
        q = urllib.parse.urlparse(url).query
        for k, _ in urllib.parse.parse_qsl(q):
            params.add(k)
        # APIs comunes
        for api in ["/api", "/graphql", "/swagger", "/swagger.json", "/openapi.json",
                    "/redoc", "/api/v1", "/api/v2"]:
            if api in (body.lower() + url.lower()):
                apis.add(api)

    # analizar JS
    n = 0
    for jf in list(js_files):
        if n >= max_js:
            break
        if ctx.ctrl("crawler") in ("stop", "skip"):
            break
        je, ap, sr = _analyze_js(jf)
        js_endpoints |= je; apis |= ap; spa_routes |= sr
        n += 1

    return {
        "urls": urls,
        "forms": forms,
        "params": params,
        "js_endpoints": js_endpoints,
        "spa_routes": spa_routes,
        "apis": apis,
        "js_files": js_files,
        "redirects": redirects,
        "visited": visited,
    }
