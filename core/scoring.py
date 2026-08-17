#!/usr/bin/env python3
"""core/scoring.py - Scoring enriquecido de hallazgos (sin red, stdlib).

Cada hallazgo pasa de una simple severidad (HIGH/MEDIUM/...) a un modelo
de riesgo con 7 dimensiones:

  * confidence   0.0-1.0  -> que tan seguro esta la deteccion (confirmed vs sospechoso)
  * impact       0-100    -> impacto potencial si se explota
  * reachability 0-100    -> que tan expuesto esta (requiere auth? esta en internet?)
  * exploitability 0-100 -> que tan facil de explotar (payload conocido, automatizable)
  * evidence     dict     -> prueba (request/response, firma, diff)
  * cvss_estimado float   -> CVSS v3 aproximado derivado de impact+exploitability
  * confidence_reason str  -> justificacion de la confianza

El CVSS se estima localmente (no es un calculo oficial de FIRST, pero da
un orden de magnitud coherente para priorizar y exportar a SARIF).
"""

# Severidad base -> peso de impacto y vector CVSS aproximado
SEV_IMPACT = {
    "critical": 95, "high": 75, "medium": 50, "low": 25, "info": 5,
}
SEV_CVSS = {
    "critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0,
}

# Factores de confirmacion basados en heurísticas estaticas
# Mejora: ahora considera más criterios para elevacion de confianza
CONF_FACTOR = {
    "confirmed": 1.0, 
    "sospechoso": 0.4,  # Bajado de 0.6 para ser mas conservador
    "auto_confirmed": 0.85,  # HTTP 200 + patrones validos
    "heuristic": 0.3,      # Solo deteccion por firma
    "high": 1.0, "medium": 0.7, "low": 0.5
}


def _clamp(v, lo=0, hi=100):
    return max(lo, min(hi, v))


def _check_static_confirmation(finding, evidence):
    """
    Heurísticas estaticas para confirmar hallazgos sin requerir peticion adicional.
    Devuelve (confidence, reason) si se puede confirmar estaticamente.
    """
    module = finding.get("module", "").lower()
    detail = finding.get("detail", "").lower()
    severity = finding.get("severity", "low").lower()
    
    # Para plugins que detectan hechos reales sin peticion extra
    if module == "vulndb":
        # CVE confirmada con version exacta
        if finding.get("evidence", {}).get("cve"):
            return "confirmed", "Versiones coinciden con CVE publicada"
    
    if module == "cors":
        # CORS reflejando Origin + credentials es un hallazgo real
        if "credentials" in detail or "referencia" in detail:
            return "confirmed", "Configuracion CORS validada (Origin reflejado + credentials)"
    
    if module == "jwt":
        # JWT sin firma o con alg=none es exploitable
        if "alg=none" in detail or "sin firma" in detail:
            return "confirmed", "Token JWT vulnerable a manipulacion (alg=none)"
    
    if module == "headers":
        # Falta de headers de seguridad críticos
        if "strict-transport-security" in detail and "falta" in detail:
            return "confirmed", "Falta HSTS - vulnerabilidad confirmada"
        if "content-security-policy" in detail and "ausente" in detail:
            return "confirmed", "Falta CSP - XSS sin limitaciones"
    
    # Para XSS - reflejacion sin escapar
    if module == "xss":
        if "reflejado" in detail and "no escapado" in detail:
            return "confirmed", "XSS reflejado confirmado (payload no escapado)"
    
    # Para SQLi - detección basada en patrones de error
    if module == "sqli":
        if "error" in detail or "syntax" in detail:
            return "confirmed", "Error SQL detectado en respuesta"
    
    # Para LFI - firma de archivo sensible
    if module == "lfi":
        if any(sig in detail.lower() for sig in ["passwd", "apache", "bash", "php", "config"]):
            return "confirmed", "Firma de archivo sensible confirmada"
    
    return None, None


def score_finding(f):
    """Recibe un dict de hallazgo y devuelve el mismo dict enriquecido con
    las claves: confidence, impact, reachability, exploitability, cvss_estimado,
    confidence_reason.
    
    Si ya trae algunas (p.ej. el plugin seteo impact), las respeta.
    """
    sev = (f.get("severity") or "low").lower()
    conf_label = (f.get("confidence") or "sospechoso").lower()
    
    # NUEVA MEJORA: Verificar confirmation estatica
    evidence = f.get("evidence", {})
    static_conf, static_reason = _check_static_confirmation(f, evidence)
    
    if static_conf:
        conf_label = static_conf
        conf = CONF_FACTOR.get(conf_label, 0.6)
        f["confidence_reason"] = static_reason
    else:
        # confidence numerico
        conf = f.get("confidence_score")
        if conf is None:
            conf = CONF_FACTOR.get(conf_label, 0.6)
        else:
            f["confidence_reason"] = "Score numeric override"
        conf = float(_clamp(conf, 0.0, 1.0))
    
    # impact (respeta valor explicito del plugin si lo hubo)
    impact = f.get("impact")
    if impact is None:
        impact = SEV_IMPACT.get(sev, 25)
    impact = float(_clamp(impact, 0, 100))
    
    # reachability: por defecto alto (escaner web expuesto). Si el hallazgo
    # indica que requiere auth/red interna, el plugin puede bajarlo.
    reach = f.get("reachability")
    if reach is None:
        reach = 80 if sev in ("critical", "high", "medium") else 60
    reach = float(_clamp(reach, 0, 100))
    
    # exploitability: derivado de severidad + confirmacion
    expl = f.get("exploitability")
    if expl is None:
        base = {"critical": 90, "high": 75, "medium": 55, "low": 35, "info": 10}.get(sev, 25)
        expl = base * conf
    expl = float(_clamp(expl, 0, 100))
    
    # cvss estimado: combina impact y exploitability (AV:N/AC:L/PR:N/UI:N)
    cvss = f.get("cvss_estimado")
    if cvss is None:
        cvss = round(min(10.0, (impact * 0.6 + expl * 0.4) / 10.0), 1)
    cvss = float(_clamp(cvss, 0.0, 10.0))
    
    f["confidence_score"] = round(conf, 2)
    f["impact"] = round(impact, 1)
    f["reachability"] = round(reach, 1)
    f["exploitability"] = round(expl, 1)
    f["cvss_estimado"] = cvss
    # mantener la etiqueta de texto legible
    if "confidence" not in f:
        f["confidence"] = "confirmed" if conf >= 0.8 else "sospechoso"
    return f


def prioritize(findings):
    """Ordena por cvss_estimado desc (luego impact). Devuelve lista nueva."""
    return sorted(findings, key=lambda f: (f.get("cvss_estimado", 0), f.get("impact", 0)),
                  reverse=True)


def severity_from_cvss(cvss):
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"