#!/usr/bin/env python3
"""pdfgen.py - Generador de PDF profesional en stdlib puro (sin dependencias).
Crea un reporte de escaneo firmado por hacking team con el logo embebido.
Soporta: portada, tabla de hallazgos, detalle por modulo y firma.
El logo se redimensiona para no inflar el tamaño del PDF.
"""
import zlib
import struct
import datetime
import os

LOGO = os.path.join(os.path.dirname(__file__), "logo.png")


def _read_png(path):
    """Lee un PNG y devuelve (width, height, raw_rgb_bytes)."""
    with open(path, "rb") as f:
        data = f.read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "no es PNG"
    pos = 8
    width = height = None
    idat = b""
    bitd = ct = None
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + ln]
        if typ == b"IHDR":
            width, height, bitd, ct = struct.unpack(">IIBB", chunk[:10])
        elif typ == b"IDAT":
            idat += chunk
        elif typ == b"IEND":
            break
        pos += 12 + ln
    raw = zlib.decompress(idat)
    # Solo soportamos 8-bit RGB (color type 2) o RGBA (6)
    if ct not in (2, 6):
        # convertir grayscale/otros no soportado; devolvemos None para omitir
        return None
    bpp = 3 if ct == 2 else 4
    stride = width * bpp
    # desfiltrar (filtros PNG: 0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth)
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
    """Devuelve (w,h,rgb_bytes) redimensionado por nearest-neighbor a max_w."""
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
        self._fonts = {}
        self._xobjs = ""
        self._pending_img = None
        # IDs de fuentes (se crean ahora para que add_page_content los referencie)
        self._font_f1 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        self._font_f2 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        self._font_f3 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    # --- bajo nivel ---
    def _add(self, data):
        self.objs.append(data)
        return len(self.objs)  # 1-based id

    def add_page_content(self, ops):
        """ops: lista de strings de contenido PDF."""
        stream = "\n".join(ops).encode("latin-1", "replace")
        cid = self._add(("stream", zlib.compress(stream)))
        pid = self._add(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {self._font_f1} 0 R /F2 {self._font_f2} 0 R "
            f"/F3 {self._font_f3} 0 R >> /XObject << {self._xobjs} >> >> "
            f"/Contents {cid} 0 R >>"
        )
        self.pages.append(pid)

    def _setup_fonts(self):
        self._font_f1 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        self._font_f2 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        self._font_f3 = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
        self._xobjs = ""

    def embed_image(self, png_path, x, y, max_w=240):
        info = _png_rgb_resized(png_path, max_w)
        if not info:
            return
        w, h, rgb = info
        # flate-compress los datos de imagen
        img_data = zlib.compress(rgb)
        xobj_id = self._add(("imgobj", w, h, img_data))
        self._img_count = getattr(self, "_img_count", 0) + 1
        self._xobjs += f"/Im{self._img_count} {xobj_id} 0 R "
        self._pending_img = (w, h, x, y)
        self._pending_img = (w, h, x, y)

    def _finalize_image_ops(self, ops):
        if getattr(self, "_pending_img", None):
            w, h, x, y = self._pending_img
            # colocar imagen ocupando w x h puntos (ya redimensionada)
            ops.append(f"q {w} 0 0 {h} {x} {y} cm /Im{self._img_count} Do Q")
            self._pending_img = None

    def save(self, path):
        # Las fuentes ya se crearon en __init__; aqui solo construimos el PDF.
        out = []
        # Catalog y Pages (se crean ahora para tener sus IDs correctos)
        kids = [f"{pid} 0 R" for pid in self.pages]
        pages_id = self._add(
            f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
        )
        catalog_id = self._add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")
        # construir cuerpo
        out.append(b"%PDF-1.4\n")
        offsets = []
        pos = len(out[-1])  # posicion actual tras el header
        for i, obj in enumerate(self.objs, start=1):
            offsets.append(pos)
            body = b""
            if isinstance(obj, tuple) and obj[0] == "stream":
                comp = obj[1]
                body = f"{i} 0 obj\n<< /Length {len(comp)} /Filter /FlateDecode >>\nstream\n".encode() + comp + b"\r\nendstream\nendobj\n"
            elif isinstance(obj, tuple) and obj[0] == "imgobj":
                w, h, data = obj[1], obj[2], obj[3]
                comp = data
                body = (f"{i} 0 obj\n<< /Type /XObject /Subtype /Image /Width {w} "
                        f"/Height {h} /ColorSpace /DeviceRGB /BitsPerComponent 8 "
                        f"/Filter /FlateDecode /Length {len(comp)} >>\nstream\n").encode() + comp + b"\r\nendstream\nendobj\n"
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


# --- API de alto nivel para el reporte ---
SEV_COLOR = {
    "critical": (192, 57, 43),
    "high": (211, 84, 0),
    "medium": (243, 156, 18),
    "low": (39, 174, 96),
    "info": (52, 152, 219),
}


def generate_report(scan_data, out_path):
    """scan_data: dict con target, fecha, modulos, findings, tech, ports..."""
    pdf = PDF()
    W = 595
    M = 50  # margen
    y = 792

    # ---------- PORTADA ----------
    ops = []
    # fondo oscuro
    ops.append("0.05 0.02 0.08 rg 0 0 595 842 re f")
    # franja neón
    ops.append("0.22 1 0.08 rg 0 760 595 4 re f")
    ops.append("0.6 0.2 0.9 rg 0 70 595 3 re f")
    # logo
    pdf.embed_image(LOGO, (W - 240) / 2, 470, max_w=240)
    # titulo
    ops.append("1 1 1 rg BT /F2 26 Tf 1 0 0 1 0 0 Tm 170 760 Td (HT SCANNER) Tj ET")
    ops.append("0.22 1 0.08 rg BT /F2 13 Tf 1 0 0 1 0 0 Tm 150 740 Td (REPORTE DE SEGURIDAD) Tj ET")
    ops.append("0.7 0.7 0.7 rg BT /F1 11 Tf 1 0 0 1 0 0 Tm 60 700 Td (Objetivo: ) Tj ET")
    ops.append("1 1 1 rg BT /F3 11 Tf 1 0 0 1 0 0 Tm 130 700 Td (%s) Tj ET" % _pdf_safe(scan_data.get("target", "")))
    ops.append("0.7 0.7 0.7 rg BT /F1 11 Tf 1 0 0 1 0 0 Tm 60 682 Td (Fecha: ) Tj ET")
    ops.append("1 1 1 rg BT /F1 11 Tf 1 0 0 1 0 0 Tm 110 682 Td (%s) Tj ET" % _pdf_safe(scan_data.get("fecha", "")))
    ops.append("0.7 0.7 0.7 rg BT /F1 11 Tf 1 0 0 1 0 0 Tm 60 664 Td (Modo: ) Tj ET")
    ops.append("1 1 1 rg BT /F1 11 Tf 1 0 0 1 0 0 Tm 110 664 Td (%s) Tj ET" % _pdf_safe(scan_data.get("mode", "active")))
    # resumen de hallazgos
    n = len(scan_data.get("findings", []))
    ops.append("1 1 1 rg BT /F2 30 Tf 1 0 0 1 0 0 Tm 60 600 Td (%d) Tj ET" % n)
    ops.append("0.22 1 0.08 rg BT /F2 13 Tf 1 0 0 1 0 0 Tm 110 600 Td (HALLAZGOS) Tj ET")
    # firma
    ops.append("0.6 0.6 0.6 rg BT /F1 9 Tf 1 0 0 1 0 0 Tm 50 90 Td (Firmado digitalmente por HT Scanner - hacking team) Tj ET")
    ops.append("0.6 0.6 0.6 rg BT /F1 8 Tf 1 0 0 1 0 0 Tm 50 76 Td (Uso exclusivo autorizado. Comunidad hacking team.) Tj ET")
    pdf._finalize_image_ops(ops)
    pdf.add_page_content(ops)

    # ---------- PAGINA DE RESUMEN / SISTEMA ----------
    ops = []
    y = 800
    ops.append("1 1 1 rg BT /F2 16 Tf 1 0 0 1 0 0 Tm %d %d Td (Resumen del Sistema) Tj ET" % (M, y))
    y -= 30
    info = scan_data.get("system", {})
    rows = [
        ("Objetivo", scan_data.get("target", "")),
        ("IP / Host", info.get("host", "n/a")),
        ("Servidor", info.get("server", "n/a")),
        ("Tecnologia", info.get("tech", "n/a")),
        ("Puertos abiertos", info.get("ports", "n/a")),
        ("Modulos ejecutados", str(scan_data.get("modulos", 0))),
        ("Hallazgos", str(n)),
    ]
    for k, v in rows:
        ops.append("0.22 1 0.08 rg BT /F2 10 Tf 1 0 0 1 0 0 Tm %d %d Td (%s:) Tj ET" % (M, y, _pdf_safe(k)))
        ops.append("0.9 0.9 0.9 rg BT /F1 10 Tf 1 0 0 1 0 0 Tm %d %d Td (%s) Tj ET" % (M + 130, y, _pdf_safe(str(v))))
        y -= 20
    # tabla de severidades
    y -= 20
    ops.append("1 1 1 rg BT /F2 14 Tf 1 0 0 1 0 0 Tm %d %d Td (Hallazgos por severidad) Tj ET" % (M, y))
    y -= 24
    counts = {}
    for f in scan_data.get("findings", []):
        counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            r, g, b = SEV_COLOR.get(sev, (100, 100, 100))
            ops.append("%f %f %f rg 30 0 0 re f" % (r / 255, g / 255, b / 255))
            ops.append("%f %f %f rg %d %d %d 8 re f" % (r / 255, g / 255, b / 255, M, y - 8, 10))
            ops.append("1 1 1 rg BT /F2 11 Tf 1 0 0 1 0 0 Tm %d %d Td (%s: %d) Tj ET" % (M + 20, y, sev.upper(), counts[sev]))
            y -= 20
    pdf.add_page_content(ops)

    # ---------- TABLA DE HALLAZGOS ----------
    ops = []
    y = 800
    ops.append("1 1 1 rg BT /F2 16 Tf 1 0 0 1 0 0 Tm %d %d Td (Detalle de vulnerabilidades) Tj ET" % (M, y))
    y -= 26
    ops.append("0.3 0.3 0.3 rg 0.5 %d %d %d re f" % (y + 6, 495, 2))  # linea
    for f in scan_data.get("findings", []):
        if y < 80:
            pdf.add_page_content(ops)
            ops = []
            y = 800
        sev = f.get("severity", "low")
        r, g, b = SEV_COLOR.get(sev, (100, 100, 100))
        ops.append("%f %f %f rg %d %d %d 8 re f" % (r / 255, g / 255, b / 255, M, y - 8, 70))
        ops.append("1 1 1 rg BT /F2 9 Tf 1 0 0 1 0 0 Tm %d %d Td (%s) Tj ET" % (M + 4, y, sev.upper()))
        ops.append("1 1 1 rg BT /F2 10 Tf 1 0 0 1 0 0 Tm %d %d Td (%s) Tj ET" % (M + 80, y, _pdf_safe(f.get("module", "").upper())))
        y -= 16
        ops.append("0.85 0.85 0.85 rg BT /F1 9 Tf 1 0 0 1 0 0 Tm %d %d Td (%s) Tj ET" % (M + 80, y, _pdf_safe(f.get("detail", ""))[:95]))
        y -= 22
    pdf.add_page_content(ops)

    # ---------- MODULOS EJECUTADOS ----------
    ops = []
    y = 800
    ops.append("1 1 1 rg BT /F2 16 Tf 1 0 0 1 0 0 Tm %d %d Td (Modulos ejecutados) Tj ET" % (M, y))
    y -= 26
    for m in scan_data.get("modules_list", []):
        if y < 80:
            pdf.add_page_content(ops); ops = []; y = 800
        status = "OK" if m.get("ok") else "FAIL"
        ops.append("0.22 1 0.08 rg BT /F2 10 Tf 1 0 0 1 0 0 Tm %d %d Td ([%s]) Tj ET" % (M, y, _pdf_safe(m.get("name", "").upper())))
        ops.append("0.8 0.8 0.8 rg BT /F1 9 Tf 1 0 0 1 0 0 Tm %d %d Td (%s) Tj ET" % (M + 90, y, _pdf_safe(m.get("msg", ""))[:80]))
        y -= 18
    pdf.add_page_content(ops)

    # ---------- FIRMA FINAL ----------
    ops = []
    ops.append("0.05 0.02 0.08 rg 0 0 595 842 re f")
    ops.append("0.22 1 0.08 rg 0 760 595 4 re f")
    pdf.embed_image(LOGO, (W - 200) / 2, 430, max_w=200)
    ops.append("1 1 1 rg BT /F2 20 Tf 1 0 0 1 0 0 Tm 200 400 Td (hacking team) Tj ET")
    ops.append("0.22 1 0.08 rg BT /F2 11 Tf 1 0 0 1 0 0 Tm 150 380 Td (Reporte generado por HT Scanner) Tj ET")
    ops.append("0.7 0.7 0.7 rg BT /F1 9 Tf 1 0 0 1 0 0 Tm 120 350 Td (%s) Tj ET" % _pdf_safe(scan_data.get("fecha", "")))
    ops.append("0.6 0.6 0.6 rg BT /F1 8 Tf 1 0 0 1 0 0 Tm 90 320 Td (Herramienta educativa de la comunidad hacking team.) Tj ET")
    pdf._finalize_image_ops(ops)
    pdf.add_page_content(ops)

    pdf.save(out_path)
    return out_path


def _pdf_safe(s):
    if not isinstance(s, str):
        s = str(s)
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
