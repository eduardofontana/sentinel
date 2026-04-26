@echo off
echo ========================================
echo SentinelFW - Push to GitHub
echo ========================================
echo.

REM Check if git is installed
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo ERRO: Git nao encontrado!
    echo Instale o Git: https://git-scm.com
    pause
    exit /b 1
)

REM Check if gh is installed
where gh >nul 2>&1
if %errorlevel% neq 0 (
    echo AVISO: GitHub CLI (gh) nao encontrado.
    echo continuing with git only...
)

echo.
echo Passos para criar o repositorio no GitHub:
echo.
echo 1. Crie um repositorio em: https://github.com/new
echo    - Nome: sentinelfw
echo    - Descricao: Home Firewall + IDS (Snort-inspired)
echo    - Publico: Sim
echo    - Nao adicione README inicial
echo.
echo 2. Execute os comandos abaixo no terminal:
echo.
echo    echo "# Adicione seu email" 
echo    git config --global user.email "seu@email.com"
echo.
echo    echo "# Adicione seu nome"
echo    git config --global user.name "Seu Nome"
echo.
echo    git add .
echo    git commit -m "Initial commit: SentinelFW v1.0"
echo.
echo    echo "# Copie a URL do seu repositorio abaixo e remova as aspas:"
echo    set REPO_URL="https://github.com/eduardofontana/sentinelfw.git"
echo    git remote add origin %REPO_URL%
echo    git push -u origin main
echo.
pause