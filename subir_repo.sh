#!/usr/bin/env bash
# HTScannerPro -> GitHub (HackingTeamOficial/HTScanner)
# Ejecutar en Git Bash / MINGW64 dentro de la carpeta HTScannerPro.
set -u
REPO="HackingTeamOficial/HTScanner"
cd "$(dirname "$0")" || exit 1

echo "===================================================="
echo " HTScannerPro -> GitHub ($REPO)"
echo "===================================================="
echo

echo "[1/5] Comprobando git..."
if ! command -v git >/dev/null 2>&1; then
  echo "  ERROR: git NO esta instalado. Instala https://git-scm.com/download/win"
  exit 1
fi
echo "  git OK: $(git --version)"

echo "[2/5] Comprobando gh..."
if ! command -v gh >/dev/null 2>&1; then
  echo "  ERROR: gh (GitHub CLI) NO esta instalado. Instala https://cli.github.com"
  echo "  Luego: gh auth login"
  exit 1
fi
echo "  gh OK: $(gh --version | head -1)"

echo "[3/5] Comprobando sesion gh..."
if ! gh auth status >/dev/null 2>&1; then
  echo "  ERROR: No has iniciado sesion en gh."
  echo "  Ejecuta: gh auth login   (GitHub.com -> HTTPS -> autoriza navegador)"
  exit 1
fi
echo "  Sesion gh OK."

echo "[4/5] git init / add / commit..."
if [ ! -d .git ]; then
  git init -b main
fi
# identidad (cambiala por tu email real si quieres)
git config user.name "HackingTeam" 2>/dev/null
git config user.email "hackingteam@users.noreply.github.com" 2>/dev/null

git add . || { echo "  ERROR: git add fallo (revisa 'nul' u otros archivos bloqueados)"; exit 1; }
git commit -m "HTScannerPro release" || echo "  (nada nuevo que commitear - continuamos)"

echo "[5/5] remote + push..."
git remote remove origin >/dev/null 2>&1
git remote add origin "https://github.com/${REPO}.git"

if gh repo view "$REPO" >/dev/null 2>&1; then
  echo "  Repo $REPO ya existe -> push..."
  git push -u origin main
else
  echo "  Repo $REPO no existe -> creandolo..."
  gh repo create "$REPO" --public --source=. --remote=origin --push
fi

echo
echo "===================================================="
echo " TERMINADO. Repo: https://github.com/$REPO"
echo "===================================================="
