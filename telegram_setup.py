#!/usr/bin/env python3
"""telegram_setup.py - ayuda a configurar las notificaciones de Telegram.

Uso:
    python3 telegram_setup.py init
        Crea config/telegram.json a partir de config/telegram.example.json
        (si no existe) y muestra los datos que tienes que rellenar.

    python3 telegram_setup.py totp
        Genera un secreto TOTP (2FA) y la URI otpauth:// para escanear con
        Google Authenticator / Authy / FreeOTP. Activa two_factor en la config.

    python3 telegram_setup.py test [codigo_totp]
        Verifica que el bot puede enviar un mensaje de prueba al chat.
        Si two_factor esta activo, pasa el codigo TOTP como argumento.

Requisitos:
    - Crear un bot con @BotFather en Telegram y copiar el token.
    - Obtener tu chat_id (enviale /start a @userinfobot o usa @RawDataBot).
    - Pegar ambos en config/telegram.json.
"""
import os
import sys
import json

ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(ROOT, "config", "telegram.json")
EXAMPLE = os.path.join(ROOT, "config", "telegram.example.json")

sys.path.insert(0, ROOT)
from core.notify_telegram import (totp_generate_secret, totp_uri,
                                 totp_verify, TelegramNotifier)


def _load():
    if not os.path.exists(CONFIG):
        print("[!] No existe config/telegram.json. Ejecuta: python3 telegram_setup.py init")
        sys.exit(1)
    return TelegramNotifier.from_config()


def cmd_init():
    os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
    if os.path.exists(CONFIG):
        print(f"[*] Ya existe {CONFIG}. No se sobreescribe.")
        return
    if os.path.exists(EXAMPLE):
        with open(EXAMPLE) as f:
            data = json.load(f)
    else:
        data = {"token": "", "chat_id": "", "enabled": True,
                "min_severity": "info", "two_factor": False, "totp_secret": ""}
    with open(CONFIG, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Creado {CONFIG}")
    print("[*] Editalo y rellena:")
    print("    token   -> el token de @BotFather (ej. 123456789:ABC...def)")
    print("    chat_id -> tu chat_id (pregunta a @userinfobot con /start)")
    print("[*] Opcional: python3 telegram_setup.py totp  (activa doble factor)")


def cmd_totp():
    data = {}
    if os.path.exists(CONFIG):
        with open(CONFIG) as f:
            data = json.load(f)
    secret = totp_generate_secret()
    data["two_factor"] = True
    data["totp_secret"] = secret
    with open(CONFIG, "w") as f:
        json.dump(data, f, indent=2)
    print("[+] Secreto TOTP generado y guardado en config/telegram.json")
    print("[+] two_factor = true activado.")
    print()
    print("Escanea este codigo QR o introduce la URI manualmente en tu app:")
    print("  " + totp_uri(secret))
    print()
    print("Codigo actual de ejemplo:", totp_verify(secret, "", ) or "", "(verifica con tu app)")
    # muestra el codigo actual para que el usuario confirme
    from core.notify_telegram import totp_at
    print("Tu codigo TOTP ahora mismo:", totp_at(secret))


def cmd_test(code=None):
    n = _load()
    if not n:
        sys.exit(1)
    if n.two_factor:
        if not code:
            print("[!] two_factor activo: pasa tu codigo TOTP: python3 telegram_setup.py test 123456")
            sys.exit(1)
        if not totp_verify(n.totp_secret, code):
            print("[!] Codigo TOTP incorrecto. Reintenta.")
            sys.exit(1)
        print("[+] TOTP verificado correctamente.")
    ok = n.send("\U0001F6E1 *HTScanner* \\- prueba de notificacion\\.\n"
                "Si recibes este mensaje, la integracion funciona \u2705")
    print("[+] Mensaje enviado." if ok else "[!] No se pudo enviar. Revisa token/chat_id/conexion.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "init"
    if cmd == "init":
        cmd_init()
    elif cmd == "totp":
        cmd_totp()
    elif cmd == "test":
        cmd_test(sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print(__doc__)
