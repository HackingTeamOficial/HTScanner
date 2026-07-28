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
            follow_redirects=True):
    """Realiza una peticion HTTP y devuelve dict:
    {code, body, headers, err}. Nunca lanza excepciones (devuelve err)."""
    hdr = {"User-Agent": UA, "Accept": "*/*"}
    if cookie:
        hdr["Cookie"] = cookie
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
        return {"code": 0, "body": "", "headers": {}, "err": str(e)}
