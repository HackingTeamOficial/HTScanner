#!/usr/bin/env python3
"""fingerprint.py - Fingerprinting y reconocimiento avanzado (estilo WhatWeb/Wappalyzer).
Todo en stdlib:
  * Tecnologia + versiones (Apache, PHP, Laravel, Nginx, WordPress, jQuery, React, ...)
  * WAF / CDN (Cloudflare, Akamai, ...)
  * Certificado TLS (emisor, CN, SAN, validez)
  * DNS (A, CNAME, MX)
  * Deteccion heuristica de HTTP/2 y HTTP/3 (Upgrade / Alt-Svc)
  * Headers de seguridad (HSTS, CSP, X-Frame, Cookies flags)
"""
import re
import socket
import ssl
import urllib.parse
import json
import os

SIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures")
_SIG_CACHE = {}


def load_signatures():
    """Carga signatures/tech.json (reglas JSON de deteccion). Cacheado."""
    global _SIG_CACHE
    if _SIG_CACHE:
        return _SIG_CACHE
    data = {"tech": [], "cloud": [], "admin_panels": [], "js_libs": []}
    path = os.path.join(SIG_DIR, "tech.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            pass
    _SIG_CACHE = data
    return data


def _match_rule(rule, headers, body_l, url, js_files):
    m = rule.get("match", {})
    # header contains/absent/exists/equals
    if "header" in m:
        hval = headers.get(m["header"].lower())
        if "contains" in m:
            return bool(hval and m["contains"].lower() in str(hval).lower())
        if "equals" in m:
            return bool(hval and m["equals"].lower() == str(hval).lower())
        if "exists" in m:
            return (hval is not None) == m["exists"]
        if "absent" in m:
            return (hval is None) == m["absent"]
    if "body" in m:
        return m["body"].lower() in body_l
    if "url" in m:
        return m["url"].lower() in (url or "").lower()
    if "js" in m:
        return any(m["js"].lower() in (j or "").lower() for j in (js_files or []))
    return False


# Reglas de tecnologia (legacy, se mantienen como fallback)
TECH_RULES = [
    ("Apache", [r"apache"], "server"),
    ("Nginx", [r"nginx"], "server"),
    ("Microsoft-IIS", [r"iis", r"microsoft-iis"], "server"),
    ("PHP", [r"php", r"x-powered-by: php"], "header_or_body"),
    ("Laravel", [r"laravel", r"csrf-token", r"_token"], "body"),
    ("WordPress", [r"wordpress", r"wp-content", r"wp-includes"], "body"),
    ("Drupal", [r"drupal"], "body"),
    ("Joomla", [r"joomla"], "body"),
    ("React", [r"react", r"_next", r"reactjs"], "body"),
    ("Vue", [r"vue", r"__vue__"], "body"),
    ("Angular", [r"angular", r"ng-"], "body"),
    ("jQuery", [r"jquery"], "body"),
    ("Bootstrap", [r"bootstrap"], "body"),
    ("Cloudflare", [r"cloudflare", r"cf-ray", r"__cf"], "header_or_body"),
    ("Akamai", [r"akamai", r"akamaighost"], "header_or_body"),
    ("AWS", [r"x-amz", r"amazonaws", r"cloudfront"], "header_or_body"),
    ("Next.js", [r"next\.js", r"_next"], "body"),
    ("Spring", [r"spring[- ]framework", r"org\.springframework", r"x-application-context"], "header_or_body"),
    ("Apache Tomcat", [r"apache tomcat", r"tomcat/", r"jsessionid"], "header_or_body"),
    ("Elementor", [r"elementor", r"elementor\-"], "body"),
    ("WooCommerce", [r"woocommerce", r"wc\-"], "body"),
    ("WPForms", [r"wpforms", r"wpforms\-"], "body"),
    ("Revslider", [r"revslider", r"slider\-revolution", r"rs\-"], "body"),
    ("Atlassian Confluence", [r"confluence", r"ajs\-"], "body"),
    ("GitLab", [r"gitlab", r"gitlab\-"], "header_or_body"),
    ("Apache Struts", [r"struts", r"webwork", r"x\-workflow"], "body"),
    ("OpenSSL", [r"openssl"], "header_or_body"),
    ("Fortinet FortiOS", [r"fortios", r"fortigate", r"svprogress"], "header_or_body"),
]

WAF_RULES = [
    ("Cloudflare", [r"cloudflare", r"cf-ray", r"__cfduid"]),
    ("Akamai", [r"akamaighost", r"akamai"]),
    ("AWS WAF", [r"x-amzn-requestid", r"awselb"]),
    ("ModSecurity", [r"mod_security", r"modsecurity"]),
    ("Sucuri", [r"sucuri", r"x-sucuri"]),
    ("Imperva", [r"incapsula", r"visid"]),
]

# extraccion de versiones
VER_PATTERNS = {
    "Apache": r"apache/([0-9.]+)",
    "Nginx": r"nginx/([0-9.]+)",
    "PHP": r"php/([0-9.]+)",
    "Laravel": r"laravel/([0-9.]+)",
    "jQuery": r"jquery[./-]([0-9.]+)",
    "WordPress": r"wordpress ([0-9.]+)",
    "Bootstrap": r"bootstrap[./-]([0-9.]+)",
    "React": r"react[./-]([0-9.]+)",
    "Spring": r"spring[ ./_-]?framework[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "Apache Tomcat": r"apache[- ]tomcat/?([0-9]+\.[0-9]+\.[0-9]+)",
    "Elementor": r"elementor[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "WooCommerce": r"woocommerce[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "WPForms": r"wpforms[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "Revslider": r"revslider[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "Atlassian Confluence": r"confluence[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "GitLab": r"gitlab[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "Apache Struts": r"struts[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
    "OpenSSL": r"openssl[ /v]*([0-9]+\.[0-9]+\.[0-9]+[a-z]?)",
    "Fortinet FortiOS": r"fortios[ /v]*([0-9]+\.[0-9]+\.[0-9]+)",
}


def fingerprint(ctx):
    """Devuelve dict con la informacion de fingerprinting."""
    target = ctx.target
    p = urllib.parse.urlparse(target)
    host = p.netloc or target
    scheme = p.scheme or "http"
    info = {
        "tech": [], "versions": {}, "waf": [], "cdn": [], "cloud": [],
        "admin_panels": [], "js_libs": [],
        "server": "", "tls": {}, "cert": {}, "dns": {}, "headers_sec": {},
        "http2": False, "http3": False,
    }
    rr = ctx.req("GET", target)
    headers = {k.lower(): v for k, v in (rr.get("headers", {}) or {}).items()}
    body_l = (rr.get("body", "") or "").lower()

    # server
    info["server"] = headers.get("server", "")
    # tecnologias
    text = body_l
    for hname, hval in headers.items():
        text += "\n" + hname + ": " + str(hval).lower()
    for name, pats, _ in TECH_RULES:
        for pat in pats:
            if re.search(pat, text):
                if name not in info["tech"]:
                    info["tech"].append(name)
                # version
                if name in VER_PATTERNS:
                    m = re.search(VER_PATTERNS[name], text)
                    if m:
                        info["versions"][name] = m.group(1)
                break
    # WAF / CDN
    for name, pats in WAF_RULES:
        for pat in pats:
            if re.search(pat, text):
                if name not in info["waf"]:
                    info["waf"].append(name)
                if any(c in name for c in ("Cloudflare", "Akamai", "AWS")):
                    if name not in info["cdn"]:
                        info["cdn"].append(name)
                break

    # headers de seguridad
    info["headers_sec"] = {
        "hsts": "strict-transport-security" in headers,
        "csp": "content-security-policy" in headers,
        "x_frame": headers.get("x-frame-options") is not None,
        "x_content_type": headers.get("x-content-type-options") is not None,
        "referrer_policy": "referrer-policy" in headers,
    }
    # cookies flags
    sc = headers.get("set-cookie", "") or ""
    info["headers_sec"]["cookie_httponly"] = "httponly" in sc.lower()
    info["headers_sec"]["cookie_secure"] = "secure" in sc.lower()

    # HTTP/2 / HTTP/3 heuristica
    if "http2" in text or headers.get("version", "").startswith("HTTP/2"):
        info["http2"] = True
    if "alt-svc" in headers or "h3=" in (headers.get("alt-svc", "") or ""):
        info["http3"] = True

    # DNS
    try:
        info["dns"]["a"] = socket.gethostbyname_ex(host)[2]
    except Exception:
        info["dns"]["a"] = []
    try:
        import dns.resolver  # opcional
        info["dns"]["mx"] = [str(r.exchange) for r in dns.resolver.resolve(host, "MX")]
    except Exception:
        info["dns"]["mx"] = []

    # TLS / cert (solo https)
    if scheme == "https":
        try:
            ctx2 = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info["tls"]["version"] = ssock.version()
                    subject = dict(x[0] for x in (cert.get("subject") or []))  # type: ignore
                    issuer = dict(x[0] for x in (cert.get("issuer") or []))  # type: ignore
                    info["cert"] = {
                        "subject_cn": subject.get("commonName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "not_after": cert.get("notAfter", ""),
                        "san": cert.get("subjectAltName", []),
                    }
        except Exception as e:
            info["tls"]["error"] = str(e)

    # ---- Firmas JSON (tech/cloud/admin_panels/js_libs) ----
    sigs = load_signatures()
    js_files = list((getattr(ctx, "_crawl", {}) or {}).get("js_files", set()))
    crawl_urls = list((getattr(ctx, "_crawl", {}) or {}).get("urls", set()))
    urls_to_check = set(crawl_urls)
    urls_to_check.add(target)
    # cloud
    for rule in sigs.get("cloud", []):
        if _match_rule(rule, headers, body_l, target, js_files):
            if rule["name"] not in info["cloud"]:
                info["cloud"].append(rule["name"])
            if rule["name"] not in info["cdn"]:
                info["cdn"].append(rule["name"])
    # admin_panels (por URL descubierta)
    for rule in sigs.get("admin_panels", []):
        for u in urls_to_check:
            if _match_rule(rule, headers, body_l, u, js_files):
                if rule["name"] not in info["admin_panels"]:
                    info["admin_panels"].append(rule["name"])
                break
    # js_libs (por archivo js descubierto)
    for rule in sigs.get("js_libs", []):
        if _match_rule(rule, headers, body_l, target, js_files):
            if rule["name"] not in info["js_libs"]:
                info["js_libs"].append(rule["name"])
    # tech desde firmas JSON (complementa TECH_RULES legacy)
    for rule in sigs.get("tech", []):
        if _match_rule(rule, headers, body_l, target, js_files):
            if rule["name"] not in info["tech"]:
                info["tech"].append(rule["name"])

    return info
