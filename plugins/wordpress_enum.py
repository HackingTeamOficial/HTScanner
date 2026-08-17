#!/usr/bin/env python3
"""Plugin WordPress Enum: enumeracion de plugins/temas y sus versiones (estilo WPScan).

Mejora de deteccion para el cruce CVE:
  * Detecta si el objetivo es WordPress (meta generator / wp-json / wp-login).
  * Enumera plugins activos probando rutas wp-content/plugins/<slug>/readme.txt
    (wordlist de plugins comunes) y extrae la version del readme estandar WP
    ("Stable tag:" o la cabecera "=== Plugin Name === ... Version:").
  * Emite hallazgos de tipo 'tech' (module='wordpress_enum') que luego
    core/vulndb cruza contra signatures/vulns.json (CVE/KEV/EDB).
  * Opcionalmente enumera usuarios (wp-json/wp/v2/users) para enumeracion de cuentas.

Todo en stdlib, sin pip. Respeta el control de ctx.ctrl('wordpress_enum').
"""
import re
import threading
import urllib.parse

PLUGIN_NAME = "wordpress_enum"

# Wordlist de plugins WordPress comunes (slugs). Ampliable.
WP_PLUGINS = [
    "elementor", "elementor-pro", "woocommerce", "wpforms-lite", "wpforms",
    "revslider", "slider-revolution", "contact-form-7", "yoast-seo",
    "wordfence", "really-simple-ssl", "updraftplus", "all-in-one-seo-pack",
    "jetpack", "wp-super-cache", "w3-total-cache", "duplicate-post",
    "akismet", "siteground-optimizer", "wp-rocket", "litespeed-cache",
    "the-events-calendar", "give", "learndash", "bbpress", "buddypress",
    "mailpoet", "popup-maker", "smush", "nextgen-gallery", "gravityforms",
    "ultimate-member", "profile-builder", "download-manager", "downloads",
    "wp-file-manager", "wp-discord", "quiz-master-next", "paid-memberships-pro",
    "sucuri-scanner", "iwp-client", "wp-migrate-db", "backwpup", "duplicator",
]

WP_THEMES = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo", "twentytwentyone",
    "astra", "oceanwp", "generatepress", "divi", "avada", "enfold",
    "betheme", "bridge", "salient", "the7", "newspaper", "jnews",
]

# Version de plugin en readme.txt estandar de WP: "Stable tag: 3.18.1" o
# cabecera del propio readme "Version: 3.18.1"
VER_RE = re.compile(r"(?:Stable tag|Version)\s*:\s*([0-9][0-9a-zA-Z.\-]*)", re.I)


def _is_wp(ctx):
    rr = ctx.req("GET", ctx.target)
    body = (rr.get("body", "") or "").lower()
    headers = {k.lower(): v for k, v in (rr.get("headers", {}) or {}).items()}
    if "wordpress" in body:
        return True
    if "wp-json" in body or "wp-content" in body or "wp-includes" in body:
        return True
    if "x-powered-by" in headers and "wordpress" in str(headers.get("x-powered-by", "")).lower():
        return True
    # wp-json API
    try:
        j = ctx.req("GET", ctx.target.rstrip("/") + "/wp-json/wp/v2/", timeout=6)
        if j.get("code") == 200 and "wp-api" in (j.get("body", "") or ""):
            return True
    except Exception:
        pass
    return False


def _plugin_version(ctx, slug):
    """Intenta leer la version del plugin desde su readme.txt."""
    url = ctx.target.rstrip("/") + f"/wp-content/plugins/{slug}/readme.txt"
    try:
        rr = ctx.req("GET", url, timeout=6)
    except Exception:
        return None
    if rr.get("code") != 200 or not rr.get("body"):
        return None
    m = VER_RE.search(rr.get("body", ""))
    if m:
        return m.group(1)
    return "desconocida"


def run(ctx):
    if ctx.ctrl(PLUGIN_NAME) in ("stop", "skip"):
        return
    target = ctx.target
    if not _is_wp(ctx):
        ctx.emit({"type": "log", "module": PLUGIN_NAME,
                  "msg": "No parece WordPress; saltando enumeracion.", "level": "info"})
        return

    ctx.emit({"type": "module", "name": PLUGIN_NAME, "status": "running",
              "msg": "WordPress detectado: enumerando plugins/temas..."})

    found = []  # (slug, version, tipo)

    def probe_plugin(slug):
        if ctx.ctrl(PLUGIN_NAME) in ("stop", "skip"):
            return
        ver = _plugin_version(ctx, slug)
        if ver:
            found.append((slug, ver, "plugin"))
            sev = "low"
            tech = _slug_to_tech(slug)
            # alimentar el fingerprint para el cruce CVE (vulndb)
            fp = getattr(ctx, "_fingerprint", None) or {}
            fp.setdefault("versions", {})[tech] = ver
            ctx._fingerprint = fp
            detail = f"Plugin WordPress activo: {slug} (v{ver})"
            ctx.emit({"type": "finding", "severity": sev, "module": PLUGIN_NAME,
                      "confidence": "confirmado" if ver != "desconocida" else "sospechoso",
                      "detail": detail,
                      "evidence": {"tech": tech, "version": ver, "slug": slug,
                                   "url": ctx.target.rstrip("/") + f"/wp-content/plugins/{slug}/"}})

    def probe_theme(slug):
        if ctx.ctrl(PLUGIN_NAME) in ("stop", "skip"):
            return
        # temas: version en style.css header
        url = ctx.target.rstrip("/") + f"/wp-content/themes/{slug}/style.css"
        try:
            rr = ctx.req("GET", url, timeout=6)
        except Exception:
            return
        if rr.get("code") != 200 or not rr.get("body"):
            return
        m = re.search(r"Version\s*:\s*([0-9][0-9a-zA-Z.\-]*)", rr.get("body", ""), re.I)
        ver = m.group(1) if m else "desconocida"
        found.append((slug, ver, "tema"))
        tech = _slug_to_tech(slug)
        fp = getattr(ctx, "_fingerprint", None) or {}
        fp.setdefault("versions", {})[tech] = ver
        ctx._fingerprint = fp
        ctx.emit({"type": "finding", "severity": "low", "module": PLUGIN_NAME,
                  "confidence": "confirmado" if ver != "desconocida" else "sospechoso",
                  "detail": f"Tema WordPress activo: {slug} (v{ver})",
                  "evidence": {"tech": tech, "version": ver, "slug": slug}})

    threads = []
    for slug in WP_PLUGINS:
        if ctx.ctrl(PLUGIN_NAME) in ("stop", "skip"):
            break
        t = threading.Thread(target=probe_plugin, args=(slug,), daemon=True)
        t.start(); threads.append(t)
    for slug in WP_THEMES:
        if ctx.ctrl(PLUGIN_NAME) in ("stop", "skip"):
            break
        t = threading.Thread(target=probe_theme, args=(slug,), daemon=True)
        t.start(); threads.append(t)
    for t in threads:
        t.join(timeout=60)

    # enumeracion de usuarios (opcional, fija info valiosa para ataques)
    try:
        jr = ctx.req("GET", ctx.target.rstrip("/") + "/wp-json/wp/v2/users?per_page=20", timeout=6)
        if jr.get("code") == 200 and jr.get("body"):
            try:
                import json
                users = json.loads(jr.get("body", "[]"))
                if isinstance(users, list) and users:
                    names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
                    if names:
                        ctx.emit({"type": "finding", "severity": "medium", "module": PLUGIN_NAME,
                                  "confidence": "confirmado",
                                  "detail": f"Usuarios WordPress enumerables (API wp-json): {', '.join(names)}",
                                  "evidence": {"users": names}})
            except Exception:
                pass
    except Exception:
        pass

    ctx.emit({"type": "module", "name": PLUGIN_NAME, "status": "done",
              "msg": f"WordPress enum: {len([f for f in found if f[2]=='plugin'])} plugins, "
                     f"{len([f for f in found if f[2]=='tema'])} temas detectados"})


# Mapeo slug -> nombre de tech usado en vulns.json (para que vulndb cruce)
SLUG_TO_TECH = {
    "elementor": "Elementor", "elementor-pro": "Elementor",
    "woocommerce": "WooCommerce", "wpforms": "WPForms", "wpforms-lite": "WPForms",
    "revslider": "Revslider", "slider-revolution": "Revslider",
}


def _slug_to_tech(slug):
    return SLUG_TO_TECH.get(slug, slug)
