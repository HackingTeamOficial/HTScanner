#!/usr/bin/env python3
"""exporters.py - Exportacion del reporte en varios formatos (stdlib puro).
  * JSON  (datos crudos, para DefectDojo/Dradis/API)
  * Markdown (lectura humana)
  * HTML  (reporte estilo SOC con graficos)
  * Nuclei templates (un template por finding, para reusar en Nuclei)
  * Burp  (req/res simplificado como base64 en formato legible)
"""
import json
import base64
import html


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False)


def to_markdown(report):
    lines = []
    lines.append(f"# HT Scanner - Reporte de Seguridad")
    lines.append("")
    lines.append(f"- **Objetivo:** {report.get('target','')}")
    lines.append(f"- **Fecha:** {report.get('fecha','')}")
    lines.append(f"- **Modo:** {report.get('mode','')}")
    lines.append(f"- **Modulos:** {report.get('modulos','')}")
    sys = report.get("system", {})
    if sys:
        lines.append(f"- **Servidor:** {sys.get('server','')}")
        lines.append(f"- **Tecnologia:** {sys.get('tech','')}")
        lines.append(f"- **Puertos:** {sys.get('ports','')}")
    lines.append("")
    findings = report.get("findings", [])
    lines.append(f"## Hallazgos ({len(findings)})")
    lines.append("")
    for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","low"),9)):
        lines.append(f"### [{f.get('severity','').upper()}] {f.get('module','')}")
        conf = f.get("confidence")
        if conf:
            lines.append(f"- **Confianza:** {conf}")
        lines.append(f"- {f.get('detail','')}")
        ev = f.get("evidence")
        if ev:
            lines.append(f"- Evidencia: `{json.dumps(ev, ensure_ascii=False)}`")
        lines.append("")
    return "\n".join(lines)


def to_html(report):
    findings = report.get("findings", [])
    sev_count = {}
    for f in findings:
        sev_count[f.get("severity", "low")] = sev_count.get(f.get("severity", "low"), 0) + 1
    rows = ""
    for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","low"),9)):
        conf = f.get("confidence")
        conf_badge = f" <span class='conf'>{html.escape(conf)}</span>" if conf else ""
        rows += (f"<tr><td><span class='sev {f.get('severity','low')}'>{f.get('severity','').upper()}</span></td>"
                 f"<td>{html.escape(f.get('module',''))}</td>"
                 f"<td>{html.escape(f.get('detail',''))}{conf_badge}</td></tr>")
    bars = "".join(
        f"<div class='bar'><span class='lbl'>{k.upper()}</span>"
        f"<span class='val' style='width:{sev_count.get(k,0)*20}px'>{sev_count.get(k,0)}</span></div>"
        for k in ["critical", "high", "medium", "low", "info"])
    return f"""<!doctype html><html><head><meta charset='utf-8'>
<title>HT Scanner Reporte</title>
<style>
 body{{font-family:Segoe UI,Roboto,Arial;background:#0d0d12;color:#e6e6e6;margin:0;padding:20px}}
 h1{{color:#39ff14}} .sev{{padding:2px 6px;border-radius:4px;font-weight:700;color:#000}}
 .critical{{background:#e74c3c}} .high{{background:#e67e22}} .medium{{background:#f1c40f}}
 .low{{background:#2ecc71}} .info{{background:#3498db}}
 table{{width:100%;border-collapse:collapse;margin-top:10px}}
 td,th{{border:1px solid #333;padding:8px;text-align:left}}
 .bar{{margin:4px 0}} .lbl{{display:inline-block;width:80px}} .val{{display:inline-block;background:#39ff14;color:#000;padding:0 6px}}
</style></head><body>
<h1>HT SCANNER — REPORTE</h1>
<p>Objetivo: {html.escape(report.get('target',''))} | Fecha: {report.get('fecha','')} | Modo: {report.get('mode','')}</p>
<h3>Resumen por severidad</h3>{bars}
<h3>Hallazgos ({len(findings)})</h3>
<table><tr><th>Sev</th><th>Modulo</th><th>Detalle</th></tr>{rows}</table>
<p style="margin-top:20px;color:#888">Firmado digitalmente por HT Scanner — hacking team. Uso exclusivo autorizado.</p>
</body></html>"""


def to_nuclei_templates(report):
    """Genera plantillas Nuclei (yaml) a partir de los hallazgos."""
    out = []
    for f in report.get("findings", []):
        ev = f.get("evidence", {}) or {}
        url = ev.get("url") or report.get("target", "")
        name = f"ht-scanner-{f.get('module','')}-{abs(hash(f.get('detail','')))%10000}"
        matchers = ""
        if "root:x:0:0:" in f.get("detail", ""):
            matchers = "matchers:\n      - type: word\n        words:\n          - \"root:x:0:0:\"\n        part: body"
        elif f.get("module") == "cors":
            matchers = "matchers:\n      - type: word\n        words:\n          - \"Access-Control-Allow-Origin\"\n        part: header"
        else:
            matchers = "matchers:\n      - type: status\n        status:\n          - 200"
        tmpl = (f"id: {name}\n"
                f"info:\n  name: {f.get('module','')} via HT Scanner\n"
                f"  severity: {f.get('severity','low')}\n"
                f"  confidence: {f.get('confidence','confirmed')}\n"
                f"requests:\n  - method: GET\n    path:\n      - {url}\n"
                f"    {matchers}\n")
        out.append(tmpl)
    return "\n---\n".join(out)


def to_burp(report):
    """Exportacion simplificada estilo 'copy as HTTP request' por hallazgo."""
    lines = []
    for f in report.get("findings", []):
        ev = f.get("evidence", {}) or {}
        url = ev.get("url") or report.get("target", "")
        req = f"GET {url} HTTP/1.1\nHost: {report.get('target','')}\nUser-Agent: HT-Scanner\n\n"
        b64 = base64.b64encode(req.encode()).decode()
        conf = f.get('confidence','confirmed')
        lines.append(f"# {f.get('module','')} ({f.get('severity','')}) [{conf}]\n# Base64 HTTP request:\n{b64}\n")
    return "\n".join(lines)


def to_sarif(report):
    """Exporta a SARIF 2.1.0 (para GitHub Security / code scanning / DefectDojo).

    Cada hallazgo se convierte en un 'result' con su severidad mapeada a
    level, y las dimensiones de scoring (confidence/impact/reachability/
    exploitability/cvss) como propiedades personalizadas. Los hallazgos que
    traen una URL en evidence apuntan a esa ubicacion.
    """
    SEV_LEVEL = {
        "critical": "error", "high": "error", "medium": "warning",
        "low": "note", "info": "none",
    }
    rules = {}
    results = []
    target = report.get("target", "")
    for f in report.get("findings", []):
        rid = f.get("module") or "generic"
        rule_id = f"ht-scanner-{rid}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"HT Scanner: {rid}",
                "shortDescription": {"text": f"Hallazgo de {rid} detectado por HT Scanner"},
                "fullDescription": {"text": f"Modulo {rid} de HT Scanner (hacking team)."},
                "defaultConfiguration": {"level": SEV_LEVEL.get(
                    (f.get("severity") or "low").lower(), "warning")},
                "properties": {"category": rid},
            }
        ev = f.get("evidence", {}) or {}
        loc = ev.get("url") or target
        props = {
            "confidence": f.get("confidence", "sospechoso"),
            "impact": f.get("impact"),
            "reachability": f.get("reachability"),
            "exploitability": f.get("exploitability"),
            "cvss_estimado": f.get("cvss_estimado"),
            "module": f.get("module"),
        }
        props = {k: v for k, v in props.items() if v is not None}
        results.append({
            "ruleId": rule_id,
            "level": SEV_LEVEL.get((f.get("severity") or "low").lower(), "warning"),
            "message": {"text": f.get("detail", "") or f.get("module", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc},
                }
            }],
            "properties": props,
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "HT Scanner",
                    "informationUri": "https://github.com/hackingteam/ht-scanner",
                    "version": "2.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
