#!/usr/bin/env python3
"""risk.py - Priorizacion, correlacion y sugerencias (IA local, sin API externa).

  * Ordena los hallazgos por severidad (CRITICAL > HIGH > MEDIUM > LOW > INFO).
  * Correlaciona: combina hallazgos debiles en uno de mayor impacto.
      - XSS + cookie sin HttpOnly  -> robo de sesion (HIGH)
      - CORS * + credentials       -> robo de credenciales (HIGH)
      - LFI/traversal + RCE o XXE  -> lectura/escritura de archivos criticos
      - SQLi + auth en la misma ruta -> acceso a datos de usuarios
  * Sugiere siguientes pasos segun la tecnologia/findings (estilo "IA"):
      - Laravel expuesto          -> probar Debug Mode, APP_KEY, Ignition RCE
      - WordPress                  -> enumerar plugins, xmlrpc, usuarios
      - CORS abierto              -> explicar riesgo y como explotar
      - JWT debil                 -> alg=none, kid injection, fuerza bruta
"""
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def risk_level(findings):
    """Calcula el nivel de riesgo global del escaneo segun los hallazgos."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = (f.get("severity") or "low").lower()
        if s in counts:
            counts[s] += 1
    if counts["critical"] > 0:
        level = "CRITICAL"
    elif counts["high"] > 0:
        level = "HIGH"
    elif counts["medium"] > 0:
        level = "MEDIUM"
    elif counts["low"] > 0:
        level = "LOW"
    else:
        level = "INFO"
    return f"{level} (C:{counts['critical']} H:{counts['high']} M:{counts['medium']} L:{counts['low']})"


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "low"), 9))


def correlate(findings):
    """Devuelve lista de correlaciones (nuevos hallazgos derivados) con
    impacto elevado (no solo detectar). Usa scoring.py para dimensionar."""
    from core.scoring import score_finding
    out = []
    by_mod = {}
    for f in findings:
        by_mod.setdefault(f.get("module", ""), []).append(f)

    # XSS + cookie sin HttpOnly -> session theft
    xss = by_mod.get("xss")
    cookie_nohttp = any("HttpOnly" in f.get("detail", "") and "sin" in f.get("detail", "")
                        for f in by_mod.get("jwt", []) + by_mod.get("cors", []))
    if xss and cookie_nohttp:
        c = score_finding({"severity": "high", "module": "correlation",
            "detail": "CORRELACION: XSS reflejado + cookies sin HttpOnly => robo de sesion del usuario (session hijacking). "
                      "Impacto: toma de control de cuenta.",
            "evidence": {"chain": ["xss", "cookie-sin-httponly"]}, "impact": 85})
        out.append(c)

    # CORS wildcard + credentials
    cors_hits = [f for f in by_mod.get("cors", [])
                 if "credentials" in f.get("detail", "").lower()
                 or "wildcard" in f.get("detail", "").lower()]
    if cors_hits:
        c = score_finding({"severity": "high", "module": "correlation",
            "detail": "CORRELACION: CORS permisivo (wildcard o refleja Origin) => posible robo de credenciales "
                      "si la app envia cookies/auth con cross-origin. Impacto: CSRF avanzado / filtracion de datos.",
            "evidence": {"chain": ["cors"]}, "impact": 70})
        out.append(c)

    # LFI/XXE + RCE presentes -> escalada a critico
    if by_mod.get("lfi") or by_mod.get("xxe"):
        if by_mod.get("rce"):
            c = score_finding({"severity": "critical", "module": "correlation",
                "detail": "CORRELACION: LFI/XXE + RCE coexisten => lectura de archivos sensibles y ejecucion de comandos. "
                          "Impacto: compromiso total del servidor.",
                "evidence": {"chain": ["lfi/xxe", "rce"]}, "impact": 98})
            out.append(c)

    # NUEVAS CADENAS (las que pidio el usuario) -------------------------------
    # 1) JWT + Admin Panel -> privilege escalation
    jwt = by_mod.get("jwt")
    admin = [f for f in findings if "admin" in (f.get("detail", "") + f.get("module", "")).lower()]
    if jwt and admin:
        c = score_finding({"severity": "critical", "module": "correlation",
            "detail": "CORRELACION: JWT debil + Panel de administracion expuesto => posible privilege escalation. "
                      "Un JWT manipulable (alg=none / sin firma fuerte) sobre un panel admin expuesto permite "
                      "forjar una sesion con rol admin. Impacto: control total del panel.",
            "evidence": {"chain": ["jwt", "admin-panel"]}, "impact": 92, "exploitability": 80})
        out.append(c)

    # 2) LFI + Upload -> RCE
    lfi = by_mod.get("lfi")
    upload = [f for f in findings if "upload" in f.get("detail", "").lower()
              or f.get("module") == "upload"]
    # tambien si hay rfi (carga remota) cuenta como vector de subida
    rfi = by_mod.get("rfi")
    if lfi and (upload or rfi):
        c = score_finding({"severity": "critical", "module": "correlation",
            "detail": "CORRELACION: LFI + vector de subida (upload/RFI) => RCE probable. "
                      "Si se puede incluir un archivo subido/remoto via LFI, se alcanza ejecucion de codigo. "
                      "Impacto: compromiso total del servidor.",
            "evidence": {"chain": ["lfi", "upload/rfi"]}, "impact": 95, "exploitability": 75})
        out.append(c)

    # 3) XSS + CSP debil -> impacto mucho mayor
    def _csp_debil(f):
        d = (f.get("detail", "") + f.get("module", "")).lower()
        return ("csp" in d and ("ausente" in d or "falta" in d or "none" in d or "unsafe" in d))
    csp_weak = [f for f in findings if _csp_debil(f) or f.get("module") == "headers"]
    # buscar especificamente falta de CSP en headers
    csp_missing = [f for f in findings if f.get("module") == "headers"
                   and "csp" in f.get("detail", "").lower() and "falta" in f.get("detail", "").lower()]
    if xss and (csp_weak or csp_missing):
        c = score_finding({"severity": "high", "module": "correlation",
            "detail": "CORRELACION: XSS + CSP debil/ausente => impacto mucho mayor. "
                      "Sin Content-Security-Policy (o con directivas unsafe-inline/eval) el XSS es "
                      "exploitable de forma fiable para robo de sesion, defacement o pivote. "
                      "Impacto: escala de XSS a compromiso de cliente/usuario.",
            "evidence": {"chain": ["xss", "csp-debil"]}, "impact": 88, "exploitability": 85})
        out.append(c)

    return out


# Grafo de relaciones: cada arista une dos hallazgos/condiciones en una cadena
# de ataque. Origen -> destino -> ... -> impacto. (Estilo "Risk Engine" de ChatGPT)
CHAIN_RULES = [
    {
        "name": "JWT -> Admin API -> CORS -> CSRF = toma de control",
        "nodes": ["jwt", "graphql", "cors", "csrf"],
        "severity": "critical",
        "impact": "Cadena: JWT debil + API admin expuesta + CORS abierto + falta CSRF => "
                  "forjar token, acceder a API privilegiada y ejecutar acciones en nombre del admin.",
    },
    {
        "name": "XSS -> Cookie sin HttpOnly -> robo de sesion",
        "nodes": ["xss", "cookie-sin-httponly"],
        "severity": "high",
        "impact": "XSS + cookie accesible por JS => robar sesion via document.cookie y secuestrar cuenta.",
    },
    {
        "name": "SQLi -> credenciales -> acceso admin",
        "nodes": ["sqli", "idor"],
        "severity": "high",
        "impact": "SQLi para extraer hashes/claves y IDOR para acceder a recursos de otros usuarios (pivote a admin).",
    },
    {
        "name": "LFI/XXE -> RCE = compromiso total",
        "nodes": ["lfi", "xxe", "rce"],
        "severity": "critical",
        "impact": "Lectura de archivos (LFI/XXE) para robar claves/secrets y alcanzar RCE => control completo.",
    },
    {
        "name": "CORS abierto -> fuga de datos autenticados",
        "nodes": ["cors", "jwt"],
        "severity": "high",
        "impact": "CORS wildcard + JWT en header => un origen malicioso lee respuestas autenticadas del usuario.",
    },
    {
        "name": "JWT -> Admin Panel = privilege escalation",
        "nodes": ["jwt", "admin-panel"],
        "severity": "critical",
        "impact": "JWT manipulable sobre panel admin expuesto => forjar sesion con rol admin y tomar el control.",
    },
    {
        "name": "LFI -> Upload/RFI = RCE",
        "nodes": ["lfi", "upload"],
        "severity": "critical",
        "impact": "Incluir archivo subido/remoto via LFI => ejecucion de codigo => compromiso total.",
    },
    {
        "name": "XSS -> CSP debil = impacto mayor",
        "nodes": ["xss", "csp-debil"],
        "severity": "high",
        "impact": "Sin CSP (o unsafe-inline/eval) el XSS se explota de forma fiable: robo de sesion, defacement, pivote.",
    },
]


def attack_chains(findings, fingerprint=None):
    """Devuelve cadenas de ataque detectadas (grafo de correlacion).
    Busca que todos los nodos de la regla aparezcan como modulos presentes
    (o condiciones derivadas como cookie-sin-httponly)."""
    present = set()
    for f in findings:
        m = (f.get("module") or "").lower()
        present.add(m)
        d = (f.get("detail") or "").lower()
        if m in ("jwt", "cors") and ("sin httponly" in d or "no httponly" in d or "httponly" not in d):
            pass
        # cookie sin httponly se infiere si hay xss y la cabecera set-cookie no trae httponly
        if "sin httponly" in d or "sin HttpOnly" in d:
            present.add("cookie-sin-httponly")
        # nodos derivados para las nuevas cadenas
        if "admin" in d or m == "tech" and "admin" in d:
            present.add("admin-panel")
        if m == "tech" and ("admin" in d or "panel" in d):
            present.add("admin-panel")
        if "upload" in d or m == "rfi":
            present.add("upload")
        if (m == "headers" and "csp" in d and "falta" in d) or "csp debil" in d or "csp" in d and ("ausente" in d or "unsafe" in d):
            present.add("csp-debil")
    chains = []
    for rule in CHAIN_RULES:
        if all(n in present for n in rule["nodes"]):
            chains.append({
                "severity": rule["severity"],
                "module": "chain",
                "detail": f"CADENA DE ATAQUE: {rule['name']}. {rule['impact']}",
                "evidence": {"chain": rule["nodes"]},
            })
    return chains


def suggest(findings, fingerprint=None):
    """Genera sugerencias tipo IA (reglas locales, sin red)."""
    out = []
    tech = (fingerprint or {}).get("tech", []) if fingerprint else []
    text_tech = " ".join(tech).lower()
    details = " ".join(f.get("detail", "").lower() for f in findings)

    def add(trigger, advice):
        out.append({"trigger": trigger, "advice": advice})

    if "laravel" in text_tech or "laravel" in details:
        add("Laravel detectado",
            "Probar: Debug Mode (/_ignition/health-check), APP_KEY conocida => Ignition RCE (CVE-2021-3129), "
            " Sanctum/Livewire, deserializacion de cookies cifradas.")
    if "wordpress" in text_tech or "wordpress" in details:
        add("WordPress detectado",
            "Enumerar plugins/temas desactualizados, xmlrpc.php (brute force), usuarios via /wp-json/wp/v2/users, "
            "y subida de plugins maliciosos si hay credenciales.")
    if "nginx" in text_tech or "apache" in text_tech:
        add("Servidor web expuesto",
            "Revisar version para CVEs conocidos; comprobar listados de directorios y headers de version.")
    if any("cors" in f.get("module", "") for f in findings):
        add("CORS permisivo",
            "Explicacion: si Access-Control-Allow-Credentials=true y el Origin se refleja, un sitio atacante puede "
            "leer respuestas autenticadas de la victima. Explotar con fetch() desde pagina malicious.")
    if any("jwt" in f.get("module", "") for f in findings):
        add("JWT debil",
            "Probar alg=none (sin firma), confusion de algoritmo RS256->HS256, kid injection (../../../../../dev/null) "
            "y fuerza bruta de clave simetrica (rockyou).")
    if any("graphql" in f.get("module", "") for f in findings):
        add("GraphQL expuesto",
            "Usar introspection para mapear el esquema; probar batching/alias abuse para bypass de rate-limit y "
            "query cost attacks. Desactivar introspection en produccion.")
    if any("sqli" in f.get("module", "") for f in findings):
        add("SQLi presente",
            "Confirmar con sqlmap para extraccion de datos; revisar si afecta a tabla de usuarios/credenciales. "
            "Mitigar con consultas parametrizadas/ORM.")
    return out
