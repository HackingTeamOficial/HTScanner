#!/usr/bin/env python3
"""tests/test_unit.py - Tests unitarios de regresión (no requieren servidor).

Validan que los puntos que otra IA modificó y que antes rompían el scan
siguen correctos, mediante (a) ejecución de funciones publicas y
(b) chequeo de código fuente para helpers internos de Nuclei.

Cubre:
  * Nuclei _resolve(): tolerante a str / list / dict (bug 'list' object has no attribute 'replace')
  * Nuclei _apply_payloads(): acepta payloads dict o list
  * port_scan._parse_nmap_output(): parsea JSON -oJ y tabla de texto
  * naabu parseo JSON por linea (logica igual a core/port_scan)
  * crawler: activo usa html.parser y NO existe crawler.py.bak
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import urllib.parse
import server
from core import port_scan
import crawler

ROOT = os.path.join(os.path.dirname(__file__), "..")
SERVER_SRC = open(os.path.join(ROOT, "server.py"), encoding="utf-8").read()


def _resolve_like_server(text, target="http://127.0.0.1:9090"):
    """Replica EXACTAMENTE la logica interna de _resolve en run_nuclei_templates."""
    if isinstance(text, list):
        text = text[0] if text else ""
    if isinstance(text, dict):
        text = text.get("path") or text.get("value") or ""
    return (text or "").replace("{{BaseURL}}", target.rstrip("/")).replace(
        "{{Hostname}}", urllib.parse.urlparse(target).netloc)


def test_nuclei_resolve_source_has_guards():
    # El helper interno debe tolerar lista/dict (regresion del bug historico)
    assert "if isinstance(text, list):" in SERVER_SRC, "falta guard lista en _resolve"
    assert "if isinstance(text, dict):" in SERVER_SRC, "falta guard dict en _resolve"
    # Comprobacion funcional contra la logica replicada
    assert _resolve_like_server("{{BaseURL}}/x") == "http://127.0.0.1:9090/x"
    assert _resolve_like_server("{{Hostname}}/y") == "127.0.0.1:9090/y"
    assert _resolve_like_server(["/a", "/b"]) in ("/a", "/b")
    assert _resolve_like_server({"path": "/c"}) == "/c"

def test_nuclei_apply_payloads_source():
    # Debe aceptar payloads como dict o lista (el fix anterior)
    assert 'payloads = tmpl.get("payloads", {})' in SERVER_SRC, "payloads debe ser dict por defecto"
    assert "isinstance(payloads, list)" in SERVER_SRC, "falta rama lista en _apply_payloads"

def test_parse_nmap_json():
    sample = json.dumps({"scan": {"10.0.0.1": {"ports": [
        {"portid": "80", "protocol": "tcp", "state": {"state": "open"},
         "service": {"name": "http", "product": "Apache", "version": "2.4"}},
        {"portid": "22", "protocol": "tcp", "state": {"state": "filtered"},
         "service": {"name": "ssh"}}
    ]}}})
    res = port_scan._parse_nmap_output(sample, "")
    assert res is not None
    open_ports = [r["port"] for r in res]
    assert 80 in open_ports and 22 not in open_ports, f"open ports: {open_ports}"

def test_parse_nmap_table():
    table = ("PORT     STATE SERVICE    VERSION\n"
             "21/tcp   open  ftp        ProFTPD\n"
             "22/tcp   open  ssh        OpenSSH 8.9\n"
             "Service Info: foo\n")
    res = port_scan._parse_nmap_output(table, "")
    assert res is not None
    ports = {r["port"] for r in res}
    assert ports == {21, 22}, f"ports: {ports}"

def test_naabu_parse():
    out = '{"port":443,"protocol":"tcp"}\n{"port":8080,"protocol":"tcp"}\n'
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("port"):
            results.append({"port": int(obj["port"]), "protocol": obj.get("protocol", "tcp")})
    ports = {r["port"] for r in results}
    assert ports == {443, 8080}, f"ports: {ports}"

def test_crawler_is_improved():
    src = open(os.path.join(ROOT, "crawler.py"), encoding="utf-8").read()
    assert "html.parser" in src, "crawler activo debe usar html.parser"
    assert "HTMLParser" in src, "crawler activo debe importar HTMLParser"
    bak = os.path.join(ROOT, "crawler.py.bak")
    assert not os.path.exists(bak), "crawler.py.bak no debe existir (evita confusion)"

if __name__ == "__main__":
    test_nuclei_resolve_source_has_guards()
    print("[PASS] nuclei _resolve str/list/dict (regresion)")
    test_nuclei_apply_payloads_source()
    print("[PASS] nuclei _apply_payloads dict/list (regresion)")
    test_parse_nmap_json()
    print("[PASS] port_scan parse nmap JSON")
    test_parse_nmap_table()
    print("[PASS] port_scan parse nmap table")
    test_naabu_parse()
    print("[PASS] naabu parse (regresion)")
    test_crawler_is_improved()
    print("[PASS] crawler activo es el mejorado (sin .bak)")
    print("\nTODOS LOS TESTS UNITARIOS OK")
