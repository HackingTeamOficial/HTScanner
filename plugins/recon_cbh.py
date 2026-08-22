#!/usr/bin/env python3
"""Plugin recon_cbh: integra el recon SPA-aware de Claude-BugHunter en HTScanner.

Aporta a la fase de recon lo que el crawler de HTScanner no alcanza bien en SPAs:
  * minado de bundles .js (rutas /api, /graphql, /v1..., hosts backend absolutos),
  *escaneo de secretos expuestos en cliente (AWS/Google/OpenAI/Slack/JWT...),
  * sondeo de .well-known / Firebase / OAuth discovery (platform_recon),
  * parseo de OpenAPI/swagger -> endpoints categorizados + auth-enforcement sweep.

El codigo vendored vive en core/cbh_recon.py y core/cbh_scope.py (MIT, con atribucion
en sus headers). Este plugin SOLO orquesta y fusiona en ctx._crawl; el trabajo de red
lo hace el modulo vendored (stdlib, read-only, seguro).

No reemplaza al crawler nativo: corre en paralelo y ENRIQUECE la superficie para que
los plugins de ataque (sqli/xss/lfi/idor...) hereden mas endpoints/params.

Salida:
  * fusiona urls/js_endpoints/apis/params/forms en ctx._crawl
  * emite hallazgos "info-leak" para secretos / plataforma expuesta / auth no forzada
  * emite log con hosts fuera de scope (no tocados)
"""
import re

PLUGIN_NAME = "recon_cbh"
PLUGIN_SEVERITY = "Info"
PLUGIN_DESC = "Recon SPA-aware (Claude-BugHunter vendored): bundles JS, secret-scan, .well-known, OpenAPI"

# modulo vendored (MIT, atribucion en el header del propio archivo)
from core import cbh_recon as recon
from core import cbh_scope as scope_mod


def _make_scope(target):
    """Construye un Scope de CBH a partir del target de HTScanner (apex + subdomains)."""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    host = re.sub(r"^https?://", "", t).split("/")[0].split(":")[0].lower()
    # apex + cualquier subdomain, y el propio host exacto
    in_scope = [host, "*." + host]
    seeds = [t.rstrip("/") if t.startswith("http") else "https://" + t.rstrip("/")]
    return scope_mod.Scope(in_scope=in_scope, out_of_scope=None, seeds=seeds, name="htscan")


def run(ctx):
    try:
        sc = _make_scope(ctx.target)
    except Exception as e:
        ctx.emit({"type": "log", "msg": f"recon_cbh: no pude armar scope ({e})", "level": "warn"})
        ctx.emit({"type": "module", "name": PLUGIN_NAME, "status": "done",
                  "msg": "scope no construido; omitido"})
        return []

    loglines = []
    def log(*a):
        msg = " ".join(str(x) for x in a)
        loglines.append(msg)
        ctx.emit({"type": "log", "msg": "recon_cbh: " + msg})

    crawl = getattr(ctx, "_crawl", {}) or {}
    urls = set(crawl.get("urls", set()) or set())
    js_endpoints = set(crawl.get("js_endpoints", set()) or set())
    apis = set(crawl.get("apis", set()) or set())
    params = set(crawl.get("params", set()) or set())
    forms = list(crawl.get("forms", []) or [])

    findings = []

    # 1) SPA-aware recon (HTML + bundles JS + robots/sitemap) -> endpoints + secretos
    try:
        items, oos = recon.spa_recon(sc, seeds=sc.seeds, max_js=20,
                                     interesting_only=True, log=log)
        for it in items:
            u = it.get("url", "")
            if not u:
                continue
            urls.add(u)
            low = u.lower()
            if re.search(r"/(api|rest|graphql|v\d|gql|internal|webhook|auth|oauth|"
                         r"token|sso|saml|login|admin|proxy|upload|download|search|"
                         r"query|user|users|account|order|invoice|file|files|report)/?$",
                         low):
                apis.add(u)
            if it.get("source") == "form":
                forms.append({"action": u, "method": it.get("method", "POST"),
                              "params": [it["param"]] if it.get("param") else []})
            if it.get("param"):
                params.add(it["param"])
            if it.get("vuln_class") == "info-leak" and it.get("source") == "secret":
                findings.append({"severity": "medium", "module": PLUGIN_NAME,
                                  "detail": "Secreto expuesto en JS cliente: " + it.get("note", ""),
                                  "evidence": {"url": it.get("url", ""),
                                               "redacted": it.get("evidence", "")}})
        for h in oos:
            log(f"host fuera de scope (no tocado): {h}")
    except Exception as e:
        log(f"spa_recon fallo: {e}")

    # 2) platform/.well-known recon (Firebase, OAuth discovery, robots disallow)
    try:
        pitems = recon.platform_recon(sc, log=log)
        for it in pitems:
            u = it.get("url", "")
            if u:
                urls.add(u)
                if it.get("vuln_class") in ("info-leak", "oauth"):
                    findings.append({"severity": "low", "module": PLUGIN_NAME,
                                     "detail": "Plataforma expuesta: " + it.get("note", ""),
                                     "evidence": {"url": u}})
    except Exception as e:
        log(f"platform_recon fallo: {e}")

    # 3) OpenAPI/swagger -> endpoints categorizados + auth-enforcement sweep
    try:
        oitems = recon.openapi_recon(sc, log=log)
        for it in oitems:
            u = it.get("url", "")
            if u:
                urls.add(u)
                apis.add(u)
            if it.get("vuln_class") == "auth-bypass" and "UNAUTH" in (it.get("note", "") or ""):
                findings.append({"severity": "high", "module": PLUGIN_NAME,
                                 "detail": "Auth no forzada en op declarada-securizada: " +
                                           it.get("note", ""),
                                 "evidence": {"url": u, "note": it.get("note", "")}})
    except Exception as e:
        log(f"openapi_recon fallo: {e}")

    # fusionar de vuelta a ctx._crawl (compatible con sqli/xss/lfi/idor/jwt)
    merged = dict(crawl)
    merged["urls"] = set(crawl.get("urls", set()) or set()) | urls
    merged["js_endpoints"] = set(crawl.get("js_endpoints", set()) or set()) | js_endpoints
    merged["apis"] = set(crawl.get("apis", set()) or set()) | apis
    merged["params"] = set(crawl.get("params", set()) or set()) | params
    merged["forms"] = forms
    ctx._crawl = merged

    # emitir hallazgos info-leak como 'finding'
    for f in findings:
        ctx.emit({"type": "finding", "severity": f["severity"], "module": PLUGIN_NAME,
                  "detail": f["detail"], "evidence": f.get("evidence", {})})

    ctx.emit({"type": "module", "name": PLUGIN_NAME, "status": "done",
              "msg": f"recon_cbh: +{len(urls)} URLs, +{len(apis)} APIs, "
                    f"{len(findings)} hallazgo(s) info-leak"})
    return findings
