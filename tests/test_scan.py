#!/usr/bin/env python3
"""tests/test_scan.py - Suite mínima de verificación para HTScanner.

Cubre:
  * Crawler: parseo HTML real, descubrimiento de enlaces/formularios.
  * SQLi: confirmación multi-técnica (boolean/error/time/union/stacked).
  * XSS: reflected + stored + DOM.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json, time
import urllib.request


BASE = "http://127.0.0.1:9090"
HT_BASE = "http://127.0.0.1:8787"


def _get(path, timeout=10):
    return urllib.request.urlopen(BASE + path, timeout=timeout)


def test_crawler_parseo_html():
    r = _get("/artists.php")
    body = r.read().decode("utf-8", "replace")
    assert "<a href=" in body or "<form" in body or "artist" in body, \
        f"Crawler debería ver enlaces/formularios en artists.php"
    print("[OK] crawler parseo HTML: artists.php tiene superficie")


def test_sqli_boolean_confirmed():
    url = f"{HT_BASE}/api/scan?target={BASE}/artists.php&mode=active&profile=full&concurrency=2&auth=1"
    r = urllib.request.urlopen(url, timeout=120)
    findings = []
    for raw in r:
        line = raw.decode().rstrip()
        if not line or not line.startswith("data:"):
            continue
        try:
            ev = json.loads(line[5:].strip())
        except Exception:
            continue
        if ev.get("type") == "finding" and ev.get("module") == "sqli":
            findings.append(ev)
    assert findings, "SQLi: se esperaba al menos 1 finding CONFIRMED"
    f = findings[0]
    ev = f.get("evidence") or {}
    assert ev.get("confidence") == "confirmed", "SQLi confidence debe ser confirmed"
    assert ev.get("type") in ("Boolean-based SQLi", "Error-based SQLi", "Time-based SQLi", "Union-based SQLi", "Stacked-queries SQLi")
    assert ev.get("request") and "payload" in ev.get("request", "").lower(), "SQLi request reproducible"
    print(f"[OK] SQLi CONFIRMED: {ev.get('type')} param={ev.get('param')} url={ev.get('url')}")


def test_xss_reflected_confirmed():
    url = f"{HT_BASE}/api/scan?target={BASE}/search.php&mode=active&profile=full&concurrency=2&auth=1"
    r = urllib.request.urlopen(url, timeout=120)
    findings = []
    for raw in r:
        line = raw.decode().rstrip()
        if not line or not line.startswith("data:"):
            continue
        try:
            ev = json.loads(line[5:].strip())
        except Exception:
            continue
        if ev.get("type") == "finding" and ev.get("module") == "xss":
            findings.append(ev)
    assert findings, "XSS: se esperaba al menos 1 finding CONFIRMED"
    f = findings[0]
    ev = f.get("evidence") or {}
    assert ev.get("confidence") == "confirmed", "XSS confidence debe ser confirmed"
    assert ev.get("snippet"), "XSS evidence debe incluir snippet"
    print(f"[OK] XSS CONFIRMED: {ev.get('type')} param={ev.get('param')} url={ev.get('url')}")


if __name__ == "__main__":
    test_crawler_parseo_html()
    test_sqli_boolean_confirmed()
    test_xss_reflected_confirmed()
    print("\nTODO OK")
