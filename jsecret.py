#!/usr/bin/env python3
"""jsecret.py - Analizador de JavaScript: extrae secretos, API keys, tokens.
Busca en los .js del objetivo (alimentado por el crawler):
  * AWS Access Key ID / Secret
  * Google Maps / Firebase / Stripe / Twilio keys
  * JWT
  * Private keys (PEM)
  * Tokens genericos (Bearer, api_key, client_secret, ...)
  * Endpoints / URLs internas
"""
import re
import threading

PATTERNS = [
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    ("AWS_SECRET", r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}"),
    ("GOOGLE_MAPS", r"AIza[0-9A-Za-z\-_]{35}"),
    ("FIREBASE", r"[a-z0-9.-]+\.firebaseio\.com"),
    ("STRIPE", r"sk_live_[0-9a-zA-Z]{24}"),
    ("STRIPE_PUB", r"pk_live_[0-9a-zA-Z]{24}"),
    ("TWILIO", r"SK[0-9a-fA-F]{32}"),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("JWT", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("GENERIC_TOKEN", r"(?i)(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|secret[_-]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    ("BEARER", r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    ("SLACK", r"xox[baprs]-[0-9A-Za-z-]+"),
    ("URL_INTERNAL", r"https?://[a-z0-9.-]+\.(?:com|net|io|dev|cloud|app)[a-z0-9/._-]*"),
]


def analyze_js(ctx, js_files):
    """js_files: set/list de URLs .js. Devuelve lista de secretos encontrados."""
    found = []

    def scan(url):
        if ctx.ctrl("jsecret") in ("stop", "skip"):
            return
        try:
            rr = ctx.req("GET", url, timeout=10)
        except Exception:
            return
        txt = rr.get("body", "") or ""
        if not txt:
            return
        for name, pat in PATTERNS:
            for m in re.findall(pat, txt):
                if isinstance(m, tuple):
                    m = m[0] if m else ""
                snippet = m if isinstance(m, str) else str(m)
                if len(snippet) < 8:
                    continue
                found.append((name, snippet[:60], url))
                ctx.emit({"type": "finding", "severity": "high", "module": "jsecret",
                          "detail": f"{name} expuesto en {url}: {snippet[:40]}...",
                          "evidence": {"url": url, "type": name}})

    # Limitar concurrencia al contexto (evita lanzar N hilos si hay muchos .js)
    sem = threading.Semaphore(ctx.concurrency)
    threads = []
    def _bounded(url):
        with sem:
            scan(url)
    for jf in list(js_files):
        if ctx.ctrl("jsecret") in ("stop", "skip"):
            break
        t = threading.Thread(target=_bounded, args=(jf,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=120)
    return found
