#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/port_scan.py - Descubrimiento de puertos abiertos con nmap / naabu.

Capas de fallback (graceful degradation):
  1) nmap (CLI)        -> SYN/connect scan + version detection + OSCG/vers.
  2) naabu (CLI)       -> descubrimiento rapido de puertos.
  3) scan_pure_python  -> sondeo TCP connect stdlib (lento, para labs sin nmap/naabu).
  4) Sin herramientas  -> emite un hallazgo INFO y devuelve [] (no bloquea el escaneo).

El resultado se emite como:
  - 1 evento "module" (nombre "nmap") con status "done" + msg de resumen.
  - N eventos "finding" (1 por puerto abierto) con evidencia del servicio.
"""

import subprocess
import json
import ipaddress
import socket
import time
import re
import threading
import math

# ---------------------------------------------------------------------------
# Helpers de ejecucion de CLI
# ---------------------------------------------------------------------------

def _find_tool(name):
    """Devuelve la ruta absoluta al ejecutable, o None si no esta disponible.

    shrows en PATH primero. Para nmap en Windows tambien busca en las
    ubicaciones habituales de instalacion (C:\\Program Files (x86)\\Nmap, etc.).
    """
    from shutil import which
    path = which(name)
    if path:
        return path

    # nmap en Windows suele instalarse fuera de PATH
    if name == "nmap":
        import os
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe",
            os.path.expanduser(r"~\AppData\Local\Programs\Nmap\nmap.exe"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        # Búsqueda recursiva con where.exe
        try:
            r = subprocess.run(
                ["where", "/R", "C:\\", "nmap.exe"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().splitlines()[0]
        except Exception:
            pass
    return None


def _run(cmd, timeout_sec=180):
    """Ejecuta `cmd` (lista) y devuelve (stdout, stderr, returncode).

    errors='replace' evita UnicodeDecodeError en Windows.
    """
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_sec,
        )
        return r.stdout or "", r.stderr or "", r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", f"{cmd[0]} no encontrado", -1
    except Exception as e:
        return "", str(e), -1


def _nmap_top_ports_json(target, ports="1-1000", timing="T4", timeout=180):
    """Ejecuta nmap con -oJ (JSON) para parseo fiable.

    Devuelve lista de dicts con {port, protocol, service, product, version, extra}.
    """
    nmap_exe = _find_tool("nmap")
    if not nmap_exe:
        return None, "nmap no esta instalado (sinopsis: nmap --version)"

    cmd = [
        nmap_exe,
        "-sV",
        "-sC",
        f"-{timing}",
        "-p", ports,
        "--open",
        "-oJ", "-",
        "-Pn",
        target,
    ]
    out, err, rc = _run(cmd, timeout_sec=timeout)
    if rc != 0 and not out:
        return None, err or f"nmap devolvio codigo {rc}"

    # Nmap 7.99+ a veces no soporta -oJ bien; intentamos parsear JSON directo,
    # y si falla usamos parseo de texto plano de la tabla de puertos.
    results = _parse_nmap_output(out, err)
    if results is not None:
        return results, None
    return None, "nmap no pudo parsear (ni JSON ni tabla de puertos)"


def _nmap_version_string(port_info):
    """Une product + version + extra info para el campo `service_extra`."""
    parts = []
    if port_info.get("product"):
        parts.append(port_info["product"])
    if port_info.get("version"):
        parts.append(port_info["version"])
    if port_info.get("extra", {}).get("reason"):
        parts.append(f"[{port_info['extra']['reason']}]")
    return " ".join(parts).strip() or ""


def _naabu_ports(target, top="1000", timeout=120):
    """Ejecuta naabu y devuelve lista de puertos [{port, protocol}]."""
    naabu_exe = _find_tool("naabu")
    if not naabu_exe:
        return None, "naabu no esta instalado"
    cmd = [
        naabu_exe,
        "-top-ports", top,
        "-p", f"1-{top}",
        "-host", target,
        "-json",
        "-silent",
    ]
    out, err, rc = _run(cmd, timeout_sec=timeout)
    if rc != 0 and not out:
        return None, err or f"naabu devolvio codigo {rc}"
    results = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        port = obj.get("port")
        if port:
            results.append({
                "port": int(port),
                "protocol": obj.get("protocol", "tcp"),
                "service": "",
                "product": "",
                "version": "",
                "extra": {},
            })
    return results, None

# ---------------------------------------------------------------------------
# Parseo de salida de nmap (soporta tanto JSON -oJ como texto plano)
# ---------------------------------------------------------------------------

def _parse_nmap_output(out, err):
    """Parsea la salida de nmap (puede ser JSON de -oJ o texto plano de la tabla).

    Devuelve lista de dicts con {port, protocol, service, product, version, extra}
    o None si no se pudo parsear.
    """
    # 1) Intentar JSON directo (nmap -oJ stdout)
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            results = []
            scan = data.get("scan", {})
            for host_key, host_data in scan.items():
                ports_list = host_data.get("ports", [])
                for p in ports_list:
                    state = p.get("state", {}).get("state", "")
                    if state != "open":
                        continue
                    service = p.get("service", {})
                    results.append({
                        "port": int(p.get("portid", 0)),
                        "protocol": p.get("protocol", "tcp"),
                        "state": state,
                        "service": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                        "extra": {
                            "reason": p.get("reason", ""),
                            "reason_ttl": p.get("reason_ttl", ""),
                            "cpe": service.get("cpe", []),
                        },
                    })
            if results:
                return results
    except (json.JSONDecodeError, Exception):
        pass

    # 2) Parseo de texto plano de la tabla de puertos (PORT STATE SERVICE VERSION)
    results = []
    in_ports_section = False
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Detectar inicio de sección de puertos (línea con "PORT    STATE SERVICE")
        if re.match(r'^PORT\s+', line):
            in_ports_section = True
            continue
        # Detectar fin de sección (línea en blanco después de los puertos, o "Service Info:")
        if in_ports_section and line.startswith("Service Info:"):
            break
        if in_ports_section and re.match(r'^\d+/\w+\s+', line):
            # Parsear línea: "135/tcp open  msrpc         Microsoft Windows RPC"
            m = re.match(r'^(\d+)/(\w+)\s+(\w+)\s+(.*)', line)
            if m:
                portid = int(m.group(1))
                protocol = m.group(2)
                state = m.group(3)
                rest = m.group(4).strip()
                if state != "open":
                    continue
                # Separar nombre del servicio de versión/producto
                parts = rest.split(None, 1)  # máximo 2 partes
                service_name = parts[0] if parts else ""
                product_version = parts[1] if len(parts) > 1 else ""
                # El producto suele ser la primera palabra, versión el resto
                if product_version:
                    pv_parts = product_version.split(None, 1)
                    product = pv_parts[0]
                    version = pv_parts[1] if len(pv_parts) > 1 else ""
                else:
                    product = ""
                    version = ""
                results.append({
                    "port": portid,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extra": {},
                })
            continue
        # Si llegamos aquí después de puertos sin más líneas de puertos,
        # probablemente fin de sección
        if in_ports_section and not re.match(r'^\d+/\w+\s+', line):
            # Podría ser líneas de Host script results, Service Info, etc.
            # Si no es un nuevo puerto, asumimos fin aunque haya más contenido
            if line.startswith("Host script") or line.startswith("Service Info"):
                break

    return results if results else None


def _probe_port(host, port, timeout_sec=1):
    """Sondeo TCP connect simple (stdlib). Devuelve True si el puerto acepta conexion."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_sec)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def _resolve_target_host(target):
    """Devuelve (host_ip, host_display) a partir de un target como 'http://x:yy' o 'x' o 'x:yy'."""
    import urllib.parse
    p = urllib.parse.urlparse(target)
    host = p.hostname or target
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ip = host
    return ip, host


SCAN_PURE_MAX_PORTS = 1024   # puertos 1..1024 en modo puro (para no eternizar)


def scan_pure_python(ctx, target, max_ports=SCAN_PURE_MAX_PORTS, concurrency=100):
    """Sondeo TCP connect concurrente puro (stdlib). Devuelve lista de puertos abiertos."""
    host_ip, host_disp = _resolve_target_host(target)
    open_ports = []
    lock = threading.Lock()
    sem = threading.Semaphore(concurrency)

    def probe(port):
        with sem:
            if ctx.ctrl("nmap") in ("stop", "skip"):
                return
            if _probe_port(host_ip, port, timeout_sec=1):
                with lock:
                    open_ports.append(port)

    threads = []
    for p in range(1, max_ports + 1):
        t = threading.Thread(target=probe, args=(p,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=300)
    open_ports.sort()
    return host_ip, host_disp, open_ports


# ---------------------------------------------------------------------------
# Funcion principal del modulo (llamada desde server.py scan_target)
# ---------------------------------------------------------------------------

HOST_DISPLAY_CACHE = {}


def run_port_scan(ctx):
    """Modulo de recon: descubrimiento de puertos con nmap (o naabu o fallback).

    Emite:
      - 1 evento "module" tipo "nmap" con status "done".
      - 1 evento "finding" por puerto abierto (severity: critical>=critical ports,
        high>=1024, medium<1024 no criticos, info=scan sin herramientas).
      - 1 evento "recon" kind="ports" con el listado completo.
    """
    target = ctx.target
    host_ip, host_disp = _resolve_target_host(target)

    # 1) Intentar nmap
    nmap_res, nmap_err = _nmap_top_ports_json(host_disp, ports="1-1000", timeout=180)
    if nmap_res is not None and nmap_res:
        _emit_nmap_results(ctx, host_disp, host_ip, nmap_res, source="nmap")
        return

    # 2) Intentar naabu
    naabu_res, naabu_err = _naabu_ports(host_disp, top="1000", timeout=120)
    if naabu_res is not None and naabu_res:
        _emit_naabu_results(ctx, host_disp, host_ip, naabu_res)
        return

    # 3) Fallback puro Python (solo si el contexto es localhost / lab conocido)
    is_local = host_ip.startswith("127.") or host_ip.startswith("192.168.") or host_ip.startswith("10.")
    if is_local:
        host_ip2, _, pure_ports = scan_pure_python(ctx, target, max_ports=1024, concurrency=ctx.concurrency * 20)
        if pure_ports:
            _emit_pure_results(ctx, host_disp, host_ip2, pure_ports)
            return

    # 4) Sin herramientas disponibles -> emitir hallazgo informativo y continuar
    msg = "nmap/naabu no instalados; escape de puertos no realizado (instala nmap y/o naabu)."
    ctx.emit({
        "type": "module",
        "name": "nmap",
        "status": "done",
        "msg": msg,
    })
    ctx.emit({
        "type": "finding",
        "severity": "info",
        "module": "nmap",
        "confidence": "info",
        "detail": msg,
        "evidence": {"host": host_disp, "ip": host_ip, "ports": []},
    })


def _emit_nmap_results(ctx, host_disp, host_ip, results, source="nmap"):
    """Emite resultados de nmap como hallazgos + evento de modulo + evento recon."""
    HOST_DISPLAY_CACHE[host_ip] = host_disp

    findings = []
    critical_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                       1433, 1521, 3306, 3389, 5432, 5632, 6379, 8080, 8443, 27017}
    for r in results:
        port = r["port"]
        sev = "medium"
        if port in {22, 23, 3389, 5900, 1433, 1521, 3306, 5432, 6379, 27017, 11211}:
            sev = "critical"
        elif port < 1024:
            sev = "high"
        elif port in {8080, 8443, 9000, 9200, 27017}:
            sev = "high"
        else:
            sev = "medium"

        service_extra = _nmap_version_string(r)
        detail = f"Puerto {port}/{r['protocol']} abierto"
        if service_extra:
            detail += f" - {service_extra}"
        elif r["service"]:
            detail += f" - servicio: {r['service']}"

        evidence = {
            "host": host_disp,
            "ip": host_ip,
            "port": port,
            "protocol": r["protocol"],
            "service": r["service"],
            "product": r["product"],
            "version": r["version"],
            "source": source,
            "request": f"nmap -sV -sC --open -p {port} {host_disp}",
        }
        findings.append({
            "severity": sev,
            "module": "nmap",
            "confidence": "confirmed",
            "detail": detail,
            "evidence": evidence,
        })
        ctx.emit({
            "type": "finding",
            "severity": sev,
            "module": "nmap",
            "confidence": "confirmed",
            "detail": detail,
            "evidence": evidence,
        })

    summary_parts = []
    if findings:
        crit = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        med = sum(1 for f in findings if f["severity"] == "medium")
        summary_parts.append(f"{len(findings)} puertos abiertos (C:{crit} H:{high} M:{med})")
        ports_str = ", ".join(str(f["evidence"]["port"]) for f in findings[:30])
        summary_parts.append(f"puertos: {ports_str}")
    else:
        summary_parts.append("ningun puerto abierto detectado (o filtrado)")

    ctx.emit({
        "type": "module",
        "name": "nmap",
        "status": "done",
        "msg": "Nmap: " + " | ".join(summary_parts),
        "findings": [f["detail"] for f in findings],
    })
    # El conteo de progreso lo hace el wrapper run_modules (engine), NO aqui,
    # para evitar contar nmap dos veces y pasarnos de 100%.
    ctx.emit({
        "type": "progress",
        "done": ctx._done_count,
        "total": ctx._total,
    })
    ctx.emit({
        "type": "recon",
        "kind": "ports",
        "data": {
            "host": host_disp,
            "ip": host_ip,
            "ports": [{"port": f["evidence"]["port"], "protocol": f["evidence"]["protocol"],
                       "service": f["evidence"]["service"], "product": f["evidence"]["product"],
                       "version": f["evidence"]["version"],
                       "severity": f["severity"]} for f in findings],
            "source": source,
        },
    })


def _emit_naabu_results(ctx, host_disp, host_ip, results):
    """Emite resultados de naabu (puertos sin servicio)."""
    if not results:
        ctx.emit({"type": "module", "name": "nmap", "status": "done",
                  "msg": "NaaBu: ningun puerto abierto detectado"})
        return

    findings = []
    for r in results:
        port = r["port"]
        sev = "high" if port < 1024 else "medium"
        detail = f"Puerto {port}/{r['protocol']} abierto (detectado por naabu)"
        evidence = {
            "host": host_disp, "ip": host_ip, "port": port,
            "protocol": r["protocol"], "service": r["service"],
            "source": "naabu",
            "request": f"naabu -top-ports 1000 -p 1-1000 -host {host_disp}",
        }
        findings.append({
            "severity": sev, "module": "nmap", "confidence": "confirmed",
            "detail": detail, "evidence": evidence,
        })
        ctx.emit({
            "type": "finding", "severity": sev, "module": "nmap",
            "confidence": "confirmed", "detail": detail, "evidence": evidence,
        })

    summary = f"{len(findings)} puertos (naabu)"
    ctx.emit({"type": "module", "name": "nmap", "status": "done", "msg": "NaaBu: " + summary,
              "findings": [f["detail"] for f in findings]})
    ctx.emit({"type": "progress", "done": ctx.record_progress()[0], "total": ctx._total})
    ctx.emit({"type": "recon", "kind": "ports",
              "data": {"host": host_disp, "ip": host_ip,
                       "ports": [{"port": f["evidence"]["port"], "protocol": f["evidence"]["protocol"],
                                  "service": f["evidence"]["service"], "severity": f["severity"]}
                                 for f in findings],
                       "source": "naabu"}})


def _emit_pure_results(ctx, host_disp, host_ip, ports):
    """Emite resultados del fallback puro Python."""
    findings = []
    for port in ports:
        sev = "high" if port < 1024 else "medium"
        detail = f"Puerto {port}/tcp abierto (sondeo TCP puro - nmap/naabu no disponibles)"
        evidence = {"host": host_disp, "ip": host_ip, "port": port,
                    "protocol": "tcp", "service": "", "source": "pure-python",
                    "request": f"sondeo TCP connect a {host_ip}:{port} (stdlib)"}
        findings.append({"severity": sev, "module": "nmap", "confidence": "sospechoso",
                         "detail": detail, "evidence": evidence})
        ctx.emit({"type": "finding", "severity": sev, "module": "nmap",
                  "confidence": "sospechoso", "detail": detail, "evidence": evidence})

    ctx.emit({"type": "module", "name": "nmap", "status": "done",
              "msg": f"Fallback Python: {len(ports)} puertos ABIERTOS (modo puro - sin nmap/naabu)"})
    ctx.emit({"type": "progress", "done": ctx.record_progress()[0], "total": ctx._total})
    ctx.emit({"type": "recon", "kind": "ports",
              "data": {"host": host_disp, "ip": host_ip,
                       "ports": [{"port": f["evidence"]["port"], "protocol": "tcp",
                                  "service": "", "severity": f["severity"], "source": "pure-python"}
                                 for f in findings],
                       "source": "pure-python"}})
