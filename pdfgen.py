#!/usr/bin/env python3
"""pdfgen.py - Generador de PDF profesional en stdlib puro (sin dependencias).
Crea un reporte de escaneo firmado por hacking team con el logo embebido.
Estilo: IGUAL al informe de referencia HTScanner (fondo BLANCO, header oscuro
HT SCANNER + Informe de evaluacion de seguridad, dashboard con graficos de
barras, detalle completo de cada hallazgo con tabla de evidencia tecnica).
El logo se redimensiona para no inflar el tamano del PDF.
"""
import zlib
import struct
import os

LOGO = os.path.join(os.path.dirname(__file__), "assets", "logo_dni.png")

# Paleta del informe de referencia
HEADER_BG = (0.070, 0.106, 0.184)   # azul marino header
WHITE = (1, 1, 1)
BG = (1, 1, 1)                       # fondo blanco
INK = (0.09, 0.10, 0.13)            # texto oscuro
GREY = (0.42, 0.46, 0.52)          # subtitulos
GREY_L = (0.62, 0.65, 0.70)        # pie
LINE = (0.85, 0.87, 0.90)          # lineas claras
CYAN = (0.114, 0.306, 0.847)       # #1D4ED8 azul indigo (alto contraste)
MAGENTA = (0.918, 0.345, 0.047)     # #EA580C naranja (reemplaza magenta neon)

SEV_COLOR = {
    "critical": (0.937, 0.267, 0.267),   # #EF4444
    "high":     (0.976, 0.451, 0.086),   # #F97316
    "medium":   (0.961, 0.620, 0.043),   # #F59E0B
    "low":      (0.133, 0.773, 0.369),   # #22C55E
    "info":     (0.024, 0.714, 0.831),   # #06B6D4
}
SEV_LABEL = {
    "critical": "CRITICA", "high": "ALTA", "medium": "MEDIA",
    "low": "BAJA", "info": "INFORMATIVA",
}
CVSS_BY_SEV = {
    "critical": "9.1", "high": "7.5", "medium": "5.3", "low": "3.1", "info": "0.0",
}


def _read_png(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "no es PNG"
    pos = 8
    width = height = None
    idat = b""
    ct = None
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + ln]
        if typ == b"IHDR":
            width, height, _, ct = struct.unpack(">IIBB", chunk[:10])
        elif typ == b"IDAT":
            idat += chunk
        elif typ == b"IEND":
            break
        pos += 12 + ln
    raw = zlib.decompress(idat)
    if ct not in (2, 6):
        return None
    bpp = 3 if ct == 2 else 4
    stride = width * bpp
    out = bytearray()
    prev = bytearray(stride)
    p = 0
    for y in range(height):
        ftype = raw[p]; p += 1
        line = bytearray(raw[p:p + stride]); p += stride
        if ftype == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                pp = a + b - c
                pa = abs(pp - a); pb = abs(pp - b); pc = abs(pp - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        out += line
        prev = line
    return width, height, bytes(out), bpp


def _png_rgb_resized(path, max_w=240):
    info = _read_png(path)
    if not info:
        return None
    w, h, raw, bpp = info
    scale = min(1.0, max_w / w)
    nw = max(1, int(w * scale)); nh = max(1, int(h * scale))
    out = bytearray()
    for y in range(nh):
        sy = min(h - 1, int(y / scale))
        for x in range(nw):
            sx = min(w - 1, int(x / scale))
            si = (sy * w + sx) * bpp
            out += raw[si:si + 3]
    return nw, nh, bytes(out)


class PDF:
    def __init__(self):
        self.pages = []
        self.objs = []
        self._xobjs = ""
        self._img_count = 0
        self._pending_img = None
        self._f1 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        self._f2 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        self._f3 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    def _add(self, data):
        self.objs.append(data)
        return len(self.objs)

    def add_page_content(self, ops):
        stream = "\n".join(ops).encode("latin-1", "replace")
        cid = self._add(("stream", zlib.compress(stream)))
        pid = self._add(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {self._f1} 0 R /F2 {self._f2} 0 R "
            f"/F3 {self._f3} 0 R >> /XObject << {self._xobjs} >> >> "
            f"/Contents {cid} 0 R >>"
        )
        self.pages.append(pid)

    def embed_image(self, png_path, x, y, max_w=240):
        info = _png_rgb_resized(png_path, max_w)
        if not info:
            return
        w, h, rgb = info
        img_data = zlib.compress(rgb)
        xobj_id = self._add(("imgobj", w, h, img_data))
        self._img_count += 1
        self._xobjs += f"/Im{self._img_count} {xobj_id} 0 R "
        self._pending_img = (w, h, x, y)

    def _finalize_image_ops(self, ops):
        if getattr(self, "_pending_img", None):
            w, h, x, y = self._pending_img
            ops.append(f"q {w} 0 0 {h} {x} {y} cm /Im{self._img_count} Do Q")
            self._pending_img = None

    def save(self, path):
        out = []
        kids = [f"{pid} 0 R" for pid in self.pages]
        pages_id = self._add(f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>")
        catalog_id = self._add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")
        out.append(b"%PDF-1.4\n")
        offsets = []
        pos = len(out[-1])
        for i, obj in enumerate(self.objs, start=1):
            offsets.append(pos)
            if isinstance(obj, tuple) and obj[0] == "stream":
                comp = obj[1]
                body = f"{i} 0 obj\n<< /Length {len(comp)} /Filter /FlateDecode >>\nstream\n".encode() + comp + b"\r\nendstream\nendobj\n"
            elif isinstance(obj, tuple) and obj[0] == "imgobj":
                w, h, data = obj[1], obj[2], obj[3]
                body = (f"{i} 0 obj\n<< /Type /XObject /Subtype /Image /Width {w} "
                        f"/Height {h} /ColorSpace /DeviceRGB /BitsPerComponent 8 "
                        f"/Filter /FlateDecode /Length {len(data)} >>\nstream\n").encode() + data + b"\r\nendstream\nendobj\n"
            else:
                body = f"{i} 0 obj\n{obj}\nendobj\n".encode()
            out.append(body)
            pos += len(body)
        xref_pos = sum(len(b) for b in out)
        n = len(self.objs) + 1
        xref = f"xref\n0 {n}\n0000000000 65535 f \n".encode()
        for off in offsets:
            xref += f"{off:010d} 00000 n \n".encode()
        trailer = f"trailer\n<< /Size {n} /Root {catalog_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
        with open(path, "wb") as f:
            f.write(b"".join(out) + xref + trailer)


# --- helpers de dibujo ---
def _bg(ops, color=BG):
    r, g, b = color
    ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg 0 0 595 842 re f")

def _rect(ops, x, y, w, h, color):
    r, g, b = color
    ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

def _txt(ops, x, y, s, font="F1", size=10, color=INK):
    r, g, b = color
    ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg BT /{font} {size} Tf 1 0 0 1 0 0 Tm {x:.1f} {y:.1f} Td ({s}) Tj ET")

def _line(ops, x, y, w, color=LINE, h=0.6):
    r, g, b = color
    ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

def _polygon(ops, pts, color):
    """Rellena un poligono definido por lista de (x,y)."""
    if len(pts) < 3:
        return
    r, g, b = color
    p = " ".join(f"{x:.1f} {y:.1f}" for x, y in pts)
    ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg {pts[0][0]:.1f} {pts[0][1]:.1f} m " +
               " ".join(f"{x:.1f} {y:.1f} l" for x, y in pts[1:]) + " h f")

def _pie(ops, cx, cy, r, a0, a1, color):
    """Sector circular (porcion de tarta) desde angulo a0 a a1 (radianes)."""
    import math
    steps = max(2, int(abs(a1 - a0) / 0.15))
    pts = [(cx, cy)]
    for i in range(steps + 1):
        a = a0 + (a1 - a0) * i / steps
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    _polygon(ops, pts, color)

def _donut(ops, cx, cy, r_out, r_in, segments):
    """Dibuja un donut. segments = [(fraccion, color), ...] en orden.
    Las fracciones deben sumar ~1."""
    import math
    total = sum(max(s[0], 0) for s in segments) or 1
    a = -math.pi / 2  # arranca arriba
    for frac, color in segments:
        if frac <= 0:
            continue
        span = 2 * math.pi * (frac / total)
        _pie(ops, cx, cy, r_out, a, a + span, color)
        a += span
    # agujero central (color de fondo)
    _circle(ops, cx, cy, r_in, BG)

def _circle(ops, x, y, r, color):
    """Circulo relleno aproximado por poligono de 48 lados."""
    import math
    pts = [(x + r * math.cos(2 * math.pi * i / 48), y + r * math.sin(2 * math.pi * i / 48))
           for i in range(48)]
    _polygon(ops, pts, color)

def _header(ops, page_no):
    """Header oscuro comun (estilo informe de referencia)."""
    _rect(ops, 0, 812, 595, 30, HEADER_BG)
    _txt(ops, 50, 826, "HT SCANNER", "F2", 13, WHITE)
    _txt(ops, 400, 826, "Informe de evaluacion de seguridad", "F1", 10, (0.819, 0.835, 0.855))
    _footer(ops, page_no)

def _footer(ops, page_no):
    _txt(ops, 50, 30, "Uso autorizado - documento tecnico de evaluacion", "F1", 7, GREY_L)
    _txt(ops, 500, 30, f"Pagina {page_no}", "F1", 7, GREY_L)

def _pdf_safe(s):
    if not isinstance(s, str):
        s = str(s)
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

def _wrap(ops, x, y, text, max_chars, font="F1", size=9, color=INK, lh=12):
    words = str(text).split()
    line = ""
    yy = y
    for w in words:
        test = (line + " " + w).strip()
        if len(test) > max_chars and line:
            _txt(ops, x, yy, _pdf_safe(line), font, size, color)
            yy -= lh
            line = w
        else:
            line = test
    if line:
        _txt(ops, x, yy, _pdf_safe(line), font, size, color)
        yy -= lh
    return yy

def _risk_label(findings):
    counts = {}
    for f in findings:
        counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1
    if counts.get("critical"): return "CRITICO"
    if counts.get("high"): return "ALTO"
    if counts.get("medium"): return "MEDIO"
    if counts.get("low"): return "BAJO"
    return "INFORMACIONAL"


# --- API de alto nivel ---
def generate_report(scan_data, out_path):
    pdf = PDF()
    M = 50
    target = scan_data.get("target", "")
    fecha = scan_data.get("fecha", "")
    mode = scan_data.get("mode", "active")
    findings = scan_data.get("findings", [])
    n = len(findings)
    modules_list = scan_data.get("modules_list", [])
    assets = scan_data.get("assets", n)
    page_no = 1

    # ========== PORTADA ==========
    ops = []
    _bg(ops)
    _rect(ops, 0, 812, 595, 30, HEADER_BG)
    _txt(ops, 50, 826, "HT SCANNER", "F2", 14, WHITE)
    _txt(ops, 400, 826, "Informe de evaluacion de seguridad", "F1", 10, (0.819,0.835,0.855))
    _line(ops, 50, 806, 90, CYAN, 2.5)
    pdf.embed_image(LOGO, 50, 700, max_w=70)
    _txt(ops, 150, 752, "HT SCANNER", "F2", 30, INK)
    _txt(ops, 150, 724, "REPORTE DE SEGURIDAD", "F2", 13, CYAN)
    # metadatos
    rows = [
        ("Organizacion evaluada", target),
        ("Objetivo", target),
        ("Fecha", fecha),
        ("Modo", mode),
        ("ID de Evaluacion", scan_data.get("scan_id", "HTSCAN")),
    ]
    y = 660
    for k, v in rows:
        _txt(ops, 50, y, k.upper(), "F1", 9, GREY)
        _txt(ops, 240, y, _pdf_safe(str(v)), "F1", 10, INK)
        y -= 22
    # numero de hallazgos
    _txt(ops, 50, 470, str(n), "F2", 40, CYAN)
    _txt(ops, 135, 478, "HALLAZGOS", "F2", 13, INK)
    _txt(ops, 50, 110, "Uso autorizado - documento tecnico de evaluacion.", "F1", 8, GREY_L)
    _txt(ops, 50, 96, "Generado por HT Scanner - comunidad hacking team.", "F1", 8, GREY_L)
    pdf._finalize_image_ops(ops)
    pdf.add_page_content(ops)

    # ========== 1. RESUMEN EJECUTIVO ==========
    ops = []
    _bg(ops)
    _header(ops, page_no); page_no += 1
    _txt(ops, M, 780, "1. Resumen ejecutivo", "F2", 16, INK)
    _txt(ops, M, 762, "Vista de alto nivel para direccion y responsables de seguridad.", "F1", 9, GREY)
    _line(ops, M, 752, 495)
    # tarjetas metricas
    cards = [
        ("RIESGO GLOBAL", _risk_label(findings), (0.976,0.451,0.086)),
        ("HALLAZGOS", str(n), CYAN),
        ("ACTIVOS", str(assets), MAGENTA),
    ]
    cy = 690; cw = 150; gap = 22; cx = M
    for label, val, bcol in cards:
        _rect(ops, cx, cy-60, cw, 60, (0.95,0.96,0.98))
        _rect(ops, cx, cy-60, 4, 60, bcol)
        _txt(ops, cx+12, cy-22, label, "F1", 8, GREY)
        _txt(ops, cx+12, cy-44, val, "F2", 20, INK)
        cx += cw + gap
    # seccion: sistema analizado
    sy = 612
    _rect(ops, M, sy-58, 445, 58, (0.93,0.95,0.98))
    _rect(ops, M, sy-58, 4, 58, (0.024,0.714,0.831))
    _txt(ops, M+12, sy-10, "SISTEMA ANALIZADO", "F2", 9, (0.024,0.714,0.831))
    sysd = scan_data.get("system", {}) or {}
    host = scan_data.get("host") or sysd.get("host") or target
    ip = scan_data.get("ip") or sysd.get("ip") or "—"
    ports = scan_data.get("puertos") or sysd.get("ports") or "—"
    tech = scan_data.get("tech") or sysd.get("tech") or "—"
    srv = sysd.get("server") or "—"
    s1 = f"Host: {host}"
    s2 = f"IP: {ip}    Puertos: {ports}"
    s3 = f"Tecnologia: {tech}    Server: {srv}"
    _txt(ops, M+12, sy-28, _pdf_safe(s1), "F1", 8, INK)
    _txt(ops, M+12, sy-42, _pdf_safe(s2), "F1", 8, INK)
    _txt(ops, M+12, sy-54, _pdf_safe(s3), "F1", 8, INK)
    # distribucion por severidad
    y = 545
    _txt(ops, M, y, "Distribucion por severidad", "F2", 13, INK)
    y -= 16; _line(ops, M, y, 495)
    y -= 30
    counts = {}
    for f in findings:
        counts[f.get("severity","low")] = counts.get(f.get("severity","low"),0)+1
    sx = M; sw = 95
    for key in ["critical","high","medium","low","info"]:
        bcol = SEV_COLOR.get(key)
        _rect(ops, sx, y-55, sw, 55, (0.95,0.96,0.98))
        _rect(ops, sx, y-55, sw, 4, bcol)
        _txt(ops, sx+10, y-18, SEV_LABEL.get(key,""), "F1", 8, bcol)
        _txt(ops, sx+10, y-40, str(counts.get(key,0)), "F2", 18, INK)
        sx += sw + 5
    # parrafo
    y2 = y - 90
    para = (f"Se evaluo {target} registrando {n} hallazgos. El riesgo global se clasifica como "
            f"{_risk_label(findings)}. Se recomienda priorizar los hallazgos de mayor severidad "
            f"y validar manualmente los casos sospechosos antes de cualquier accion de remediacion.")
    yy = _wrap(ops, M, y2, para, 110, "F1", 9, GREY, 13)
    # interpretacion
    yy -= 10
    _txt(ops, M, yy, "Interpretacion", "F2", 11, INK)
    yy -= 14
    _wrap(ops, M, yy, "Los hallazgos informativos no son vulnerabilidades por si mismos, pero ayudan "
          "a documentar la superficie de ataque. La distribucion por severidad permite a los equipos "
          "de seguridad concentrar esfuerzos donde el impacto es mayor.", 110, "F1", 9, GREY, 13)
    pdf.add_page_content(ops)

    # ========== 2. DASHBOARD DE EXPOSICION (graficos) ==========
    ops = []
    _bg(ops)
    _header(ops, page_no); page_no += 1
    _txt(ops, M, 780, "2. Dashboard de exposicion", "F2", 16, INK)
    _txt(ops, M, 762, "Indicadores visuales para identificar rapidamente donde concentrar la remediacion.", "F1", 9, GREY)
    _line(ops, M, 752, 495)
    # grafico 1: distribucion por severidad (barras)
    _txt(ops, M, 720, "Distribucion por severidad", "F2", 12, INK)
    gy = 400; gh = 260; gx = M; gw = 230
    maxv = max([counts.get(k,0) for k in ["critical","high","medium","low","info"]] + [1])
    by = gy
    for key in ["critical","high","medium","low","info"]:
        v = counts.get(key,0)
        bh = int(gh * (v/maxv)) if maxv else 0
        _rect(ops, gx, by, 36, bh, SEV_COLOR.get(key))
        _txt(ops, gx-2, by-12, str(v), "F2", 9, INK)
        _txt(ops, gx-6, gy-18, SEV_LABEL.get(key,"")[:6], "F1", 7, GREY)
        gx += 46
    # grafico 1b: donut de distribucion por severidad (geometria redonda)
    _txt(ops, M, 350, "Distribucion por severidad (donut)", "F2", 11, INK)
    dcx, dcy, dout, din = 130, 225, 68, 40
    segs = [(counts.get(k,0), SEV_COLOR.get(k)) for k in ["critical","high","medium","low","info"]]
    _donut(ops, dcx, dcy, dout, din, segs)
    # texto central del donut
    _txt(ops, dcx-18, dcy+4, str(n), "F2", 16, INK)
    _txt(ops, dcx-22, dcy-12, "hallazgos", "F1", 7, GREY)
    # leyenda del donut
    lx = 225; ly = 300
    for key in ["critical","high","medium","low","info"]:
        _rect(ops, lx, ly-8, 10, 10, SEV_COLOR.get(key))
        _txt(ops, lx+16, ly, f"{SEV_LABEL.get(key,'')}: {counts.get(key,0)}", "F1", 8, INK)
        ly -= 20
    # grafico 2: hallazgos por modulo (top 8)
    _txt(ops, 320, 720, "Hallazgos por modulo (top 8)", "F2", 12, INK)
    mod_counts = {}
    for f in findings:
        m = f.get("module","?")
        mod_counts[m] = mod_counts.get(m,0)+1
    top = sorted(mod_counts.items(), key=lambda x:-x[1])[:8]
    maxm = max([c for _,c in top] + [1])
    my = gy; mx = 320; mw = 210
    for m,c in top:
        bw = int(mw * (c/maxm)) if maxm else 0
        _rect(ops, mx, my, bw, 18, MAGENTA)
        _txt(ops, mx+bw+4, my+12, f"{m} ({c})", "F1", 7, GREY)
        my -= 26
    pdf.add_page_content(ops)

    # ========== 3. DETALLE DE VULNERABILIDADES ==========
    idx = 0
    for f in findings:
        idx += 1
        sev = f.get("severity","low")
        bcol = SEV_COLOR.get(sev, (0.5,0.5,0.5))
        ops = []
        _bg(ops)
        _header(ops, page_no); page_no += 1
        # titulo hallazgo
        _txt(ops, M, 780, f"{idx}. {SEV_LABEL.get(sev,'')} - {_pdf_safe(str(f.get('module','')).upper())}", "F2", 14, INK)
        _line(ops, M, 752, 495)
        # recuadro severidad
        _rect(ops, M, 700, 90, 40, bcol)
        _txt(ops, M+10, 722, "Severidad", "F1", 8, WHITE)
        _txt(ops, M+10, 708, SEV_LABEL.get(sev,""), "F2", 13, WHITE)
        # datos rapidos
        _txt(ops, 160, 722, "Confianza:", "F1", 9, GREY)
        _txt(ops, 230, 722, _pdf_safe(str(f.get("confidence","confirmed"))), "F1", 9, INK)
        _txt(ops, 160, 708, "CVSS:", "F1", 9, GREY)
        _txt(ops, 230, 708, CVSS_BY_SEV.get(sev,"-"), "F2", 10, INK)
        ev = f.get("evidence", {}) or {}
        if ev.get("url"):
            _txt(ops, 330, 715, "Activo/URL:", "F1", 9, GREY)
            _wrap(ops, 410, 715, ev.get("url",""), 60, "F3", 8, INK, 10)
        # descripcion
        y = 680
        _txt(ops, M, y, "Descripcion / evidencia", "F2", 11, INK)
        y -= 16
        det = f.get("detail","")
        y = _wrap(ops, M, y, det, 110, "F1", 9, INK, 13)
        # tabla de evidencia tecnica
        y -= 14
        _txt(ops, M, y, "Evidencia tecnica", "F2", 11, INK)
        y -= 12; _line(ops, M, y, 495); y -= 18
        evrows = [
            ("url", ev.get("url")),
            ("param", ev.get("param")),
            ("method", ev.get("method")),
            ("type", ev.get("type")),
            ("detail", ev.get("detail") or ev.get("evidence_detail")),
            ("request", ev.get("request")),
            ("template", ev.get("template")),
            ("confidence", ev.get("confidence")),
        ]
        for k,v in evrows:
            if not v: continue
            _txt(ops, M, y, k, "F2", 8, bcol)
            if k in ("request","url","detail"):
                y = _wrap(ops, M+70, y, str(v), 90, "F3", 8, INK, 11)
            else:
                _txt(ops, M+70, y, _pdf_safe(str(v)), "F1", 8, INK)
                y -= 14
            if y < 80:
                pdf.add_page_content(ops)
                ops = []; _bg(ops); _header(ops, page_no); page_no += 1
                y = 800
        pdf.add_page_content(ops)

    # ========== 4. MODULOS EJECUTADOS ==========
    ops = []
    _bg(ops)
    _header(ops, page_no); page_no += 1
    _txt(ops, M, 780, "Modulos ejecutados", "F2", 16, INK)
    _line(ops, M, 752, 495)
    y = 730
    for m in modules_list:
        if y < 80:
            pdf.add_page_content(ops); ops = []; _bg(ops); _header(ops, page_no); page_no+=1; y=780
        ok = m.get("ok")
        bcol = (0.133,0.773,0.369) if ok else (0.937,0.267,0.267)
        _txt(ops, M, y, f"[{'OK' if ok else 'FAIL'}] {_pdf_safe(str(m.get('name','')).upper())}", "F2", 10, bcol)
        _txt(ops, M+140, y, _pdf_safe(str(m.get("msg",""))[:78]), "F1", 8, GREY)
        y -= 18
    pdf.add_page_content(ops)

    # ========== 5. RECOMENDACIONES ==========
    ops = []
    _bg(ops)
    _header(ops, page_no); page_no += 1
    _txt(ops, M, 780, "Recomendaciones", "F2", 16, INK)
    _line(ops, M, 752, 495)
    recs = [
        "Priorizar y remediar los hallazgos de severidad CRITICA y ALTA antes de exponer el activo.",
        "Validar manualmente cada hallazgo confirmado para descartar falsos positivos.",
        "Aplicar cabeceras de seguridad (CSP, X-Frame-Options, HSTS) y endurecer configuraciones.",
        "Mantener dependencias y componentes actualizados; eliminar archivos y endpoints innecesarios.",
        "Realizar pruebas de regresion tras la remediacion y re-escanear para confirmar cierre.",
    ]
    y = 730
    for i, r in enumerate(recs, 1):
        _txt(ops, M, y, f"{i}.", "F2", 10, CYAN)
        y = _wrap(ops, M+20, y, r, 100, "F1", 9, INK, 13)
        y -= 8
    pdf.add_page_content(ops)

    # ========== FIRMA ==========
    ops = []
    _bg(ops)
    _rect(ops, 0, 812, 595, 30, HEADER_BG)
    _txt(ops, 50, 826, "HT SCANNER", "F2", 14, WHITE)
    pdf.embed_image(LOGO, 50, 700, max_w=70)
    _txt(ops, 150, 752, "hacking team", "F2", 22, INK)
    _txt(ops, 150, 724, "Reporte generado por HT Scanner", "F2", 11, CYAN)
    _txt(ops, 150, 704, _pdf_safe(fecha), "F1", 9, GREY)
    _txt(ops, 150, 686, "Herramienta educativa de la comunidad hacking team.", "F1", 8, GREY_L)
    pdf._finalize_image_ops(ops)
    pdf.add_page_content(ops)

    pdf.save(out_path)
    return out_path
