#!/usr/bin/env bash
# launch.sh - Arranca HT Scanner de hacking team en un comando.
# Uso: bash launch.sh
cd "$(dirname "$0")" || exit 1
echo "⚡ HT Scanner — hacking team"
echo "[*] Iniciando backend en http://127.0.0.1:8787 ..."
if command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  echo "[!] python3 no encontrado. Instalalo primero."
  exit 1
fi
# Arranca el demo target en background (opcional), el control plane y el server
"$PY" demo_target.py >/dev/null 2>&1 &
"$PY" control_plane.py >/dev/null 2>&1 &
"$PY" server.py &
sleep 1.5
echo "[+] Abre en tu navegador: http://127.0.0.1:8787/index.html"
wait
