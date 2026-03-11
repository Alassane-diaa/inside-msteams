@echo off
REM Script de lancement du serveur HTTPS avec SSLKEYLOGFILE (Windows batch)
REM Ce script configure la variable d'environnement SSLKEYLOGFILE pour capturer les clés TLS

setlocal

REM Configuration
set "KEYLOG_FILE=%~dp0server_keys.log"
set "PYTHON_SCRIPT=%~dp0serveur.py"

echo.
echo ========================================
echo   Lancement du serveur HTTPS TLS
echo ========================================
echo.

echo Configuration:
echo    - Script Python : %PYTHON_SCRIPT%
echo    - Fichier keylog: %KEYLOG_FILE%
echo.

REM Vérifier que le script Python existe
if not exist "%PYTHON_SCRIPT%" (
    echo ERREUR: Le fichier %PYTHON_SCRIPT% n'existe pas!
    exit /b 1
)

REM Définir la variable d'environnement SSLKEYLOGFILE
set "SSLKEYLOGFILE=%KEYLOG_FILE%"
echo Variable SSLKEYLOGFILE definie: %SSLKEYLOGFILE%
echo.

REM Lancer le serveur Python
echo Demarrage du serveur...
echo.
python "%PYTHON_SCRIPT%"

endlocal
