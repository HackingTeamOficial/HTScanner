import time
#!/usr/bin/env python3
"""core/http.py - capa de red desacoplada.

request() es la unica funcion de red del proyecto. Todo modulo (plugins,
crawler, fingerprint, etc.) debe pasar por aqui. No importa server ni engine.
"""
import ssl
import urllib.request
import urllib.parse
import urllib.error

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

# Contexto SSL que no valida cert (para escanear labs locales con cert self-signed)
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handler que NO sigue redirects: devuelve el 3xx con su Location."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # no redirigir


def request(method, url, data=None, cookie=None, timeout=10, raw=False,
            follow_redirects=True, headers=None):
    """Realiza una peticion HTTP y devuelve dict:
    {code, body, headers, err}. Nunca lanza excepciones (devuelve err).
    headers: dict opcional de cabeceras extra (se fusionan con las por defecto)."""
    hdr = {"User-Agent": UA, "Accept": "*/*"}
    if cookie:
        hdr["Cookie"] = cookie
    if headers:
        hdr.update(headers)
    method = method.upper()
    if method == "GET":
        if data:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(data)
        body = None
    else:
        if raw:
            body = data.encode() if isinstance(data, str) else data
            hdr["Content-Type"] = "text/xml; charset=utf-8"
        else:
            body = urllib.parse.urlencode(data).encode() if data else b""
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=body, headers=hdr, method=method)
    opener = None
    if not follow_redirects:
        from urllib.request import HTTPHandler, HTTPSHandler
        # opener sin redirect: debe incluir handlers HTTP y HTTPS (con contexto SSL)
        opener = urllib.request.build_opener(
            HTTPHandler(), HTTPSHandler(context=SSL_CTX), _NoRedirect())
    last_err = None
    for attempt in range(3):
        try:
            if opener:
                resp = opener.open(r, timeout=timeout)
            else:
                resp = urllib.request.urlopen(r, timeout=timeout, context=SSL_CTX)
            hdrs = dict(resp.getheaders())
            return {"code": resp.getcode(), "body": resp.read().decode("utf-8", "replace"),
                    "headers": hdrs, "err": None}
        except urllib.error.HTTPError as e:
            # con _NoRedirect, los 3xx llegan aqui; Location puede estar en e.headers
            # 429/503 con Retry-After: respetar y reintentar
            if e.code in (429, 503):
                ra = None
                try:
                    ra = e.headers.get("Retry-After") if e.headers else None
                    wait = min(int(ra), 30) if ra and str(ra).isdigit() else 2 ** (attempt + 1)
                except Exception:
                    wait = 2 ** (attempt + 1)
                last_err = f"HTTP {e.code} retry {attempt+1}/3 after {wait}s"
                time.sleep(wait)
                continue
            try:
                hdrs = dict(e.headers) if e.headers else {}
            except Exception:
                hdrs = {}
            loc = None
            try:
                loc = e.headers.get("Location") if e.headers else None
            except Exception:
                loc = hdrs.get("Location")
            return {"code": e.code, "body": e.read().decode("utf-8", "replace"),
                    "headers": {**hdrs, "location": loc} if loc else hdrs, "err": None}
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(2 ** (attempt + 1))
    return {"code": 0, "body": "", "headers": {}, "err": last_err or "max retries"}
