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

        sys.exit(1)
    return TelegramNotifier.from_config()


def cmd_init():
    os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
    if os.path.exists(CONFIG):

        return
    if os.path.exists(EXAMPLE):
        with open(EXAMPLE) as f:
            data = json.load(f)
    else:
        data = {"token": "", "chat_id": "", "enabled": True,
                "min_severity": "info", "two_factor": False, "totp_secret": ""}
    with open(CONFIG, "w") as f:
        json.dump(data, f, indent=2)





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







    # muestra el codigo actual para que el usuario confirme
    from core.notify_telegram import totp_at

def cmd_test(code=None):
    n = _load()
    if not n:
        sys.exit(1)
    if n.two_factor:
        if not code:

            sys.exit(1)
        if not totp_verify(n.totp_secret, code):

            sys.exit(1)

    ok = n.send("\U0001F6E1 *HTScanner* \\- prueba de notificacion\\.\n"
                "Si recibes este mensaje, la integracion funciona \u2705")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "init"
    if cmd == "init":
        cmd_init()
    elif cmd == "totp":
        cmd_totp()
    elif cmd == "test":
        cmd_test(sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print("Uso: python3 telegram_setup.py [init|totp|test]")
