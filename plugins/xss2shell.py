#!/usr/bin/env python3
"""Plugin xss2shell: XSS2Shell - WordPress Pre-Auth XSS -> RCE Chain (detector autorizado).

Cadena clasica de compromiso en WordPress:
  1) XSS pre-auth (inyeccion de JS sin sesion) - vectores tipicos:
     - wp-comments-post.php (comentarios) sin saneo del autor/url
     - parametros reflejados en paginas/archivos
     - vulnerabilidades de plugins/tesmas expuestos anonymamente
  2) Pivote a admin: el JS inyectado llama al panel (/wp-admin/) aprovechando
     una sesion de administrador activa (el admin visita el payload).
  3) RCE: el JS crea/edita un plugin o tema via /wp-admin/plugin-editor.php
     (o theme-editor.php) para escribir codigo PHP ejecutable.

MODO ETICO: este plugin SOLO DETECTA y REPORTA las superficies de la cadena
(enumeracion + chequeos de configuracion). NO ejecuta el XSS ni el RCE contra
el objetivo. El usuario debe tener autorizacion explicita para el objetivo.

Requisitos: objetivo WordPress (lo detecta via fingerprint del core).
"""
from urllib.parse import urljoin, urlparse, quote


def _get(ctx, path, params=None, timeout=8):
    try:
        return ctx.req("GET", urljoin(ctx.target, path), params=params, timeout=timeout)
    except Exception:
        return None


def _wp_present(ctx):
    """Devuelve True si el objetivo parece WordPress."""
    info = getattr(ctx, "_fingerprint", {}) or {}
    tech = " ".join(str(t).lower() for t in (info.get("tech") or []))
    if "wordpress" in tech:
        return True
    r = _get(ctx, "/")
    if r and r.get("body"):
        b = r["body"].lower()
        if "wp-content" in b or "wp-includes" in b or "wordpress" in b:
            return True
    # sondeo ligero de rutas WP
    for p in ("/wp-login.php", "/xmlrpc.php", "/wp-json/"):
        rr = _get(ctx, p)
        if rr and rr.get("code") in (200, 401, 403):
            return True
    return False


def _check_comment_xss(ctx):
    """Comprueba si el formulario de comentarios expone superficie XSS pre-auth.

    No envia payload ejecutable: solo Inspecciona el form y la ausencia de
    cabeceras de proteccion (CSP) y la presencia del endpoint anonimo.
    """
    hits = []
    r = _get(ctx, "/")
    form_ok = False
    if r and r.get("body"):
        b = r["body"].lower()
        if "wp-comments-post.php" in b and 'name="comment"' in b:
            form_ok = True
    if form_ok:
        # superficie de comentario anonimo expuesta => pre-auth XSS posible
        hits.append("wp-comments-post.php (formulario de comentarios anonimo expuesto)")
    # CSP ausente => el XSS no se mitiga en origen
    csp = (r.get("headers", {}) or {}).get("Content-Security-Policy") if r else None
    if not csp:
        hits.append("Sin Content-Security-Policy (CSP) -> el XSS reflejado/almacenado no se mitiga")
    return hits


def _check_admin_editors(ctx):
    """Detecta los editores de codigo que permiten RCE tras pivote de admin."""
    hits = []
    for ep in ("/wp-admin/plugin-editor.php", "/wp-admin/theme-editor.php"):
        rr = _get(ctx, ep)
        if rr and rr.get("code") in (200, 302, 401, 403):
            # 401/403 = existe pero requiere auth; 200 = expuesto (peor)
            sev = "high" if rr.get("code") == 200 else "medium"
            hits.append((ep, sev, rr.get("code")))
    # DISALLOW_FILE_EDIT desactivado => el editor de plugins/temas esta habilitado
    # (no podemos leer wp-config remotamente; lo infiereimos si el editor responde 200)
    return hits


def run(ctx):
    name = "xss2shell"
    if not _wp_present(ctx):
        ctx.emit({"type": "module", "name": name, "status": "done",
                  "msg": "xss2shell: objetivo no es WordPress (cadena no aplicable)"})
        return

    ctx.emit({"type": "log", "msg": "xss2shell: WordPress detectado, analizando cadena XSS->RCE", "level": "info"})

    findings = []

    # Paso 1: superficie XSS pre-auth
    xss_hits = _check_comment_xss(ctx)
    for h in xss_hits:
        findings.append({"severity": "high", "module": name, "confidence": "sospechoso",
                          "detail": f"[XSS2Shell·Paso1 XSS pre-auth] {h}",
                          "evidence": {"chain": "xss", "vector": h}})

    # Paso 2/3: editores de codigo (RCE tras pivote de admin)
    editor_hits = _check_admin_editors(ctx)
    for ep, sev, code in editor_hits:
        findings.append({"severity": sev, "module": name, "confidence": "sospechoso",
                          "detail": f"[XSS2Shell·Paso3 RCE] Editor expuesto {ep} (HTTP {code}) "
                                    f"-> si un admin visita el XSS, el JS puede escribir PHP y lograr RCE",
                          "evidence": {"chain": "rce", "endpoint": ep, "http_code": code}})

    # Hallazgo de cadena si hay tanto XSS como editor
    if xss_hits and editor_hits:
        findings.append({"severity": "critical", "module": name, "confidence": "sospechoso",
                          "detail": "CADENA COMPLETA XSS2Shell: XSS pre-auth + editor de codigo accesible "
                                    "=> compromiso RCE via pivote de administrador (el admin debe visitar el payload). "
                                    "Verificar manualmente con autorizacion.",
                          "evidence": {"chain": "xss2shell", "xss": xss_hits,
                                       "rce_endpoints": [e for e, s, c in editor_hits]}})

    for f in findings:
        ctx.emit({"type": "finding", **f})

    ctx.emit({"type": "module", "name": name, "status": "done",
              "msg": f"xss2shell: {len(findings)} hallazgo(s) de la cadena",
              "findings": [f.get("detail", "") for f in findings][:20]})
