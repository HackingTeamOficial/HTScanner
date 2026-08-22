@echo off
REM ===================================================================
REM  HTScannerPro — Subir repo a GitHub (HackingTeamOficial/HTScanner)
REM  Version ROBUSTA: no cierra la ventana y muestra el error real.
REM  Requisitos: git y gh instalados + sesion (gh auth login).
REM ===================================================================
setlocal
set REPO=HackingTeamOficial/HTScanner
set ROOT=%~dp0
cd /d "%ROOT%"

echo ====================================================
echo  HTScannerPro -> GitHub (%REPO%)
echo ====================================================
echo.

echo [1/5] Comprobando git...
where git >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: git NO esta instalado.
    echo  Descarga e instala: https://git-scm.com/download/win
    echo  Luego vuelve a ejecutar este .bat
    echo.
    pause
    exit /b
)

echo [2/5] Comprobando gh...
where gh >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: gh (GitHub CLI) NO esta instalado.
    echo  Descarga e instala: https://cli.github.com
    echo  Luego:  gh auth login
    echo  Y vuelve a ejecutar este .bat
    echo.
    pause
    exit /b
)

echo [3/5] Comprobando sesion gh...
gh auth status >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: No has iniciado sesion en gh.
    echo  Ejecuta en esta terminal:  gh auth login
    echo  (elige GitHub.com, HTTPS, y autoriza el navegador)
    echo.
    pause
    exit /b
)
echo  Sesion gh OK.

echo [4/5] git init / add / commit...
if not exist ".git" (
    git init -b main
) else (
    echo  (repo ya inicializado)
)
git add .
git commit -m "HTScannerPro release" || echo  (nada nuevo que commitear - continuamos)

echo [5/5] remote + push...
git remote remove origin >nul 2>&1
git remote add origin https://github.com/%REPO%.git

gh repo view %REPO% >nul 2>&1
if errorlevel 1 (
    echo  Repo %REPO% no existe -> creandolo...
    gh repo create %REPO% --public --source=. --remote=origin --push
) else (
    echo  Repo %REPO% ya existe -> push...
    git push -u origin main
)

echo.
echo ====================================================
echo  TERMINADO. Revisa arriba si hubo errores.
echo  Repo: https://github.com/%REPO%
echo ====================================================
echo.
pause
