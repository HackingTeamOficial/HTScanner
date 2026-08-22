#!/usr/bin/env python3
"""core/profiles.py - perfiles/modos de escaneo.

Cada perfil define qué módulos (plugins) se ejecutan, el modo por defecto
(activo/pasivo) y si hace descubrimiento profundo. Añadir un perfil = añadir
una entrada al dict. No requiere tocar el motor.

Perfiles:
  recon       -> recon solo (crawler, fingerprint, archivos, jsecret, tech)
  passive     -> sin enviar payloads (cabeceras, fingerprint, crawler, archivos)
  full        -> todos los plugins + recon
  bugbounty   -> full + foco en superficie (archivos ampliado, jsecret, graphql)
  api         -> solo superficie API (crawler, graphql, cors, jwt, csrf, jsecret)
  cms         -> full + foco WordPress/Joomla/Drupal (archivos, lfi, traversal)
  wordpress   -> CMS orientado a WP (wp-login, xmlrpc, usuarios, plugins)
  xss2shell   -> WordPress Pre-Auth XSS -> RCE chain (solo cadena WP: wordpress_enum + xss2shell)
"""
# Plugins disponibles (deben coincidir con plugins/PLUGIN_NAME)
ALL_ATTACK = ["sqli", "idor", "xss", "lfi", "traversal", "rce", "rfi", "xxe",
              "cors", "jwt", "graphql", "csrf", "wordpress_enum",
              "sqli_confirm", "redteam_exploit", "osint_urls", "ai_analysis",
              "xss2shell"]
RECON = ["nmap", "tech", "crawler", "archivos", "jsecret", "recon_cbh"]

PROFILES = {
    "recon": {
        "desc": "Solo reconocimiento (sin ataque)",
        "mode": "active",
        "recon": RECON,
        "attack": [],
        "discovery_deep": False,
    },
    "passive": {
        "desc": "Sin enviar payloads (solo observar respuestas)",
        "mode": "passive",
        "recon": ["headers", "tech", "crawler", "archivos"],
        "attack": [],
        "discovery_deep": False,
    },
    "full": {
        "desc": "Todos los módulos (recon + ataque)",
        "mode": "active",
        "recon": RECON,
        "attack": ALL_ATTACK,
        "discovery_deep": True,
    },
    "bugbounty": {
        "desc": "Foco bug bounty: superficie amplia",
        "mode": "active",
        "recon": RECON,
        "attack": ALL_ATTACK,
        "discovery_deep": True,
    },
    "api": {
        "desc": "Solo superficie de APIs",
        "mode": "active",
        "recon": ["tech", "crawler", "jsecret"],
        "attack": ["cors", "jwt", "graphql", "csrf", "idor"],
        "discovery_deep": False,
    },
    "cms": {
        "desc": "Foco CMS (WordPress/Joomla/Drupal)",
        "mode": "active",
        "recon": RECON,
        "attack": ["lfi", "traversal", "sqli", "xss", "idor", "csrf"] + ALL_ATTACK,
        "discovery_deep": True,
    },
    "wordpress": {
        "desc": "Orientado a WordPress",
        "mode": "active",
        "recon": ["tech", "crawler", "archivos"],
        "attack": ["idor", "xss", "sqli", "lfi", "traversal", "csrf", "rce", "wordpress_enum"],
        "discovery_deep": True,
    },
    "redteam": {
        "desc": "Red team: full + OSINT URLs + exploit framework + IA (Ollama)",
        "mode": "active",
        "recon": ["tech", "crawler", "archivos", "jsecret", "recon_cbh"],
        "attack": ALL_ATTACK,
        "discovery_deep": True,
    },
    "xss2shell": {
        "desc": "XSS2Shell: WordPress Pre-Auth XSS -> RCE (solo cadena WP)",
        "mode": "active",
        "recon": ["tech", "crawler", "archivos"],
        "attack": ["wordpress_enum", "xss2shell"],
        "discovery_deep": True,
    },
}


def get_profile(name):
    """Devuelve el dict del perfil o 'full' por defecto."""
    return PROFILES.get(name, PROFILES["full"])


def list_profiles():
    return {k: v["desc"] for k, v in PROFILES.items()}


def resolve_modules(name, available_plugins):
    """Devuelve (recon_order, attack_order, mode) para el perfil, filtrando
    los plugins que realmente existen."""
    p = get_profile(name)
    attack = [m for m in p["attack"] if m in available_plugins]
    seen = set()
    attack_u = []
    for m in attack:
        if m not in seen:
            seen.add(m); attack_u.append(m)
    recon = list(p["recon"])
    return recon, attack_u, p.get("mode", "active")
