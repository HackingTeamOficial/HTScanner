#!/usr/bin/env python3
"""core/vulndb.py - Cruce de tecnologias/versiones con CVE / CISA KEV / ExploitDB.

Funciona 100% offline con un JSON local (signatures/vulns.json) y, SI hay
red (en el Kali del usuario), puede enriquecer con APIs publicas:
  * CISA KEV  -> https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  * NVD CVE API -> https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...
    (opcional; requiere red y puede ser lento; se usa solo como mejora)

El JSON local tiene la forma:
{
  "rules": [
    {"tech":"Log4j", "version_regex":"2\\..*", "cve":"CVE-2021-44228",
     "kev":true, "edb":null, "min_version":"2.0", "max_version":"2.14.1",
     "title":"Log4Shell - RCE via JNDI lookup",
     "advice":"Actualizar a 2.17.1+; deshabilitar lookups JNDI."},
    ...
  ]
}

No requiere pip install. El JSON local es la fuente de verdad; la API online
solo anade el flag 'kev' si CISA lo confirma.
"""
import os
import re
import json

SIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "signatures", "vulns.json")

# Cache del JSON local
_VULNS = None


def load_vulns():
    global _VULNS
    if _VULNS is not None:
        return _VULNS
    data = {"rules": []}
    if os.path.exists(SIG_PATH):
        try:
            with open(SIG_PATH) as f:
                data = json.load(f)
        except Exception:
            pass
    _VULNS = data
    return data


def _version_in_range(version, min_v, max_v):
    """Compara versiones semver-ish de forma simple (tupla de ints)."""
    def to_tuple(v):
        parts = re.findall(r"\d+", v or "")
        return tuple(int(x) for x in parts[:4])
    try:
        v = to_tuple(version)
        lo = to_tuple(min_v) if min_v else (0,)
        hi = to_tuple(max_v) if max_v else (9999,)
        return lo <= v <= hi
    except Exception:
        return False


def match_tech(tech, version):
    """Devuelve lista de reglas que aplican a (tech, version)."""
    tech = (tech or "").lower()
    out = []
    for r in load_vulns().get("rules", []):
        if (r.get("tech") or "").lower() != tech:
            continue
        vr = r.get("version_regex")
        if vr:
            if not re.search(vr, version or ""):
                continue
        else:
            # rango explicito
            if version and not _version_in_range(version, r.get("min_version", ""), r.get("max_version", "")):
                continue
        out.append(r)
    return out


def enrich_with_kev(rules):
    """Si hay red, consulta CISA KEV para marcar reglas como confirmadas KEV.
    Silencioso si no hay red (fallback al JSON local)."""
    cves = [r.get("cve") for r in rules if r.get("cve")]
    if not cves:
        return rules
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            headers={"User-Agent": "HT-Scanner"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        kev_set = {v.get("cveID") for v in data.get("vulnerabilities", [])}
        for r in rules:
            if r.get("cve") in kev_set:
                r["kev"] = True
    except Exception:
        # sin red -> dejamos el flag kev del JSON local
        pass
    return rules


def check_findings(fingerprint, online=False):
    """Cruza las versiones de fingerprint con la base de vulnerabilidades.
    Devuelve lista de hallazgos enriquecidos (dict listo para emitir)."""
    versions = (fingerprint or {}).get("versions", {}) or {}
    results = []
    for tech, version in versions.items():
        rules = match_tech(tech, version)
        if online:
            rules = enrich_with_kev(rules)
        for r in rules:
            sev = "critical" if r.get("kev") else "high"
            results.append({
                "severity": sev,
                "module": "vulndb",
                "confidence": "sospechoso",
                "detail": f"{tech} {version} => {r.get('cve','?')}: {r.get('title','')}"
                          + (" [CISA KEV]" if r.get("kev") else ""),
                "evidence": {
                    "tech": tech, "version": version, "cve": r.get("cve"),
                    "kev": bool(r.get("kev")), "edb": r.get("edb"),
                    "advice": r.get("advice", ""),
                },
            })
    return results
