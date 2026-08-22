#!/usr/bin/env python3
"""core/notify_telegram.py - notificaciones de escaneo por Telegram (stdlib).

Modulo autocontenido: solo usa urllib + hmac (sin pip install). Se suscribe
al EventBus de HTScanner y envia a un chat de Telegram:
  * inicio del scan
  * cada hallazgo (finding) con severidad, modulo y detalle
  * resumen al terminar (done)
  * enlace/estado del reporte (report)
  * errores graves (error)

El token y chat_id NO se escriben en el codigo: se cargan desde
config/telegram.json (creado por el usuario desde telegram.example.json).
Si no hay configuracion, el notificador es un no-op silencioso y el scan
sigue funcionando normalmente.

DOBLE FACTOR (TOTP):
Los bots de Telegram NO admiten el 2FA de la cuenta de usuario (limitacion de
la API). Para dar un segundo factor REAL, esta integracion soporta TOTP
(compatible con Google Authenticator / Authy / FreeOTP) usando solo stdlib.
Si se activa two_factor en la config, el backend exige un codigo TOTP valido
antes de instanciar/enviar el notificador. Asi el envio requiere:
  (1) el token guardado (algo que tienes)  +  (2) el codigo TOTP actual
       de tu movil (algo que tienes en tu movil) = doble factor de verdad.

Uso:
    from core.notify_telegram import TelegramNotifier, totp_verify, totp_uri
    n = TelegramNotifier.from_config()      # lee config/telegram.json
    if n and n.enabled:
        n.notify_start(target, scan_id)
        n.attach(bus)                        # suscribe a finding/done/report/error
"""
import os
import json
import time
import base64
import struct
import hmac
import hashlib
import urllib.request
import urllib.parse
import urllib.error

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "config", "telegram.json")

SEV_EMOJI = {
    "critical": "\U0001F525",   # fire
    "high": "\u26A1",           # zap
    "medium": "\u26A0",         # warning
    "low": "\u2139",            # info
    "info": "\U0001F4E3",       # megaphone
}
SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _esc_md(text):
    """Escapa caracteres reservados de Markdown v1 de Telegram."""
    if text is None:
        return ""
    s = str(text)
    out = []
    for ch in s:
        if ch in "_*[]()~`>#+-=|{}.!":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) en stdlib puro — compatible con Google Authenticator/Authy.
# ---------------------------------------------------------------------------
def totp_generate_secret():
    """Genera un secreto base32 de 160 bits (20 bytes)."""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _b32_decode(secret):
    s = secret.strip().upper().replace(" ", "")
    # base32 valido usa A-Z y 2-7; rellena con '=' hasta multiplo de 8
    pad = (-len(s)) % 8
    s += "=" * pad
    return base64.b32decode(s)


def totp_at(secret, timestamp=None, digits=6, period=30):
    """Calcula el codigo TOTP para un instante dado."""
    if timestamp is None:
        timestamp = int(time.time())
    counter = timestamp // period
    msg = struct.pack(">Q", counter)
    key = _b32_decode(secret)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF)
    return str(code % (10 ** digits)).zfill(digits)


def totp_verify(secret, code, digits=6, period=30, window=1):
    """Verifica un codigo TOTP con ventana de tolerancia +/-window pasos."""
    if not secret or not code:
        return False
    code = str(code).strip()
    now = int(time.time())
    for w in range(-window, window + 1):
        if totp_at(secret, now + w * period, digits, period) == code:
            return True
    return False


def totp_uri(secret, label="HTScanner", issuer="HTScanner"):
    """Devuelve la URI otpauth:// para escanear con la app del movil."""
    s = secret.strip().upper().replace(" ", "")
    return f"otpauth://totp/{urllib.parse.quote(label)}?secret={s}&issuer={urllib.parse.quote(issuer)}"


# ---------------------------------------------------------------------------
# Notificador
# ---------------------------------------------------------------------------
class TelegramNotifier:
    def __init__(self, token, chat_id, enabled=True, min_severity="info",
                 two_factor=False, totp_secret=None):
        self.token = token
        self.chat_id = chat_id
        self.enabled = enabled
        self.min_severity = min_severity
        self.two_factor = two_factor
        self.totp_secret = totp_secret
        self._last_send = 0.0
        self._min_interval = 0.05  # throttle ligero para no disparar 429

    @classmethod
    def from_config(cls, path=None):
        """Carga token/chat_id desde config/telegram.json. None si no existe."""
        cfg = path or CONFIG_PATH
        if not os.path.exists(cfg):
            return None
        try:
            with open(cfg, "r") as f:
                d = json.load(f)
        except Exception:
            return None
        token = d.get("token", "").strip()
        chat_id = str(d.get("chat_id", "")).strip()
        if not token or not chat_id:
            return None
        enabled = bool(d.get("enabled", True))
        min_sev = d.get("min_severity", "info")
        two_factor = bool(d.get("two_factor", False))
        totp_secret = d.get("totp_secret", "") or None
        return cls(token, chat_id, enabled=enabled, min_severity=min_sev,
                   two_factor=two_factor, totp_secret=totp_secret)

    # ---- envio ---------------------------------------------------------
    def send(self, text, parse="Markdown"):
        """Envia un mensaje. Reintenta en fallos y respeta 429 (retry_after).
        Devuelve True/False. Nunca lanza excepciones."""
        if not self.enabled or not self.token or not self.chat_id:
            return False
        # throttle
        now = time.time()
        wait = self._min_interval - (now - self._last_send)
        if wait > 0:
            time.sleep(wait)
        self._last_send = time.time()

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text[:4000],
            "parse_mode": parse,
            "disable_web_page_preview": True,
        }
        data = json.dumps(payload).encode("utf-8")
        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    url, data=data,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status == 200
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    ra = e.headers.get("Retry-After")
                    try:
                        time.sleep(float(ra) if ra else 2.0)
                    except Exception:
                        time.sleep(2.0)
                    continue
                if e.code == 400 and parse == "Markdown":
                    try:
                        return self._send_plain(text)
                    except Exception:
                        return False
                return False
            except Exception:
                time.sleep(1.0)
        return False

    def _send_plain(self, text):
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {"chat_id": self.chat_id,
                   "text": text[:4000],
                   "disable_web_page_preview": True}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200

    # ---- mensajes ------------------------------------------------------
    def notify_start(self, target, scan_id, mode="active", profile="full"):
        msg = ("\U0001F6E1 *HTScanner* \\- iniciando escaneo\n"
               f"\\* Objetivo: `{_esc_md(target)}`\n"
               f"\\* Scan ID: `{_esc_md(scan_id)}`\n"
               f"\\* Modo: {_esc_md(mode)} \\| Perfil: {_esc_md(profile)}\n"
               "\\_ Te avisare cuando encuentre hallazgos\\._")
        return self.send(msg)

    def _fmt_finding(self, ev):
        sev = (ev.get("severity") or "info").lower()
        emoji = SEV_EMOJI.get(sev, "\u26A0")
        module = _esc_md(ev.get("module", "?"))
        detail = _esc_md(ev.get("detail", ""))
        conf = _esc_md(ev.get("confidence", "confirmed"))
        lines = [f"{emoji} *Hallazgo: {sev.upper()}*",
                 f"\\* Modulo: `{module}`",
                 f"\\* Confianza: {conf}",
                 f"\\* Detalle: {detail}"]
        evd = ev.get("evidence") or {}
        if isinstance(evd, dict):
            for k, v in evd.items():
                if v:
                    lines.append(f"  \\- {_esc_md(k)}: `{_esc_md(v)}`")
        return "\n".join(lines)

    def _should_send(self, sev):
        s = (sev or "info").lower()
        return SEV_ORDER.get(s, 1) >= SEV_ORDER.get(self.min_severity, 1)

    def _on_event(self, ev):
        """Handler suscrito al bus. No lanza excepciones."""
        try:
            t = ev.get("type")
            if t == "finding":
                sev = ev.get("severity", "info")
                if self._should_send(sev):
                    self.send(self._fmt_finding(ev))
            elif t == "done":
                target = _esc_md(ev.get("target", ""))
                summary = _esc_md(ev.get("summary", ""))
                msg = ("\u2705 *HTScanner* \\- escaneo completado\n"
                       f"\\* Objetivo: `{target}`\n"
                       f"\\* Resumen: {summary}")
                self.send(msg)
            elif t == "report":
                msg = ("\U0001F4C4 *Reporte generado*\n"
                       f"\\* {_esc_md(ev.get('msg', ''))}\n"
                       f"\\* Formatos: {_esc_md(', '.join(ev.get('formats', [])))}")
                self.send(msg)
            elif t == "error":
                msg = ("\u26D4 *HTScanner* \\- error durante el escaneo\n"
                       f"\\* {_esc_md(ev.get('msg', ''))}")
                self.send(msg)
        except Exception:
            pass

    def attach(self, bus):
        """Suscribe el notificador a los eventos del bus."""
        bus.subscribe("finding", self._on_event)
        bus.subscribe("done", self._on_event)
        bus.subscribe("report", self._on_event)
        bus.subscribe("error", self._on_event)
        return self
