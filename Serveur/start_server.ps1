#!/usr/bin/env pwsh
# Script de lancement du serveur HTTPS avec SSLKEYLOGFILE
# Ce script configure la variable d'environnement SSLKEYLOGFILE pour capturer les clés TLS

$ErrorActionPreference = "Stop"

# Configuration
$KEYLOG_FILE = Join-Path $PSScriptRoot "server_keys.log"
$PYTHON_SCRIPT = Join-Path $PSScriptRoot "serveur.py"

# Afficher les informations
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Lancement du serveur HTTPS TLS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "📝 Configuration:" -ForegroundColor Yellow
Write-Host "   - Script Python : $PYTHON_SCRIPT"
Write-Host "   - Fichier keylog: $KEYLOG_FILE"
Write-Host ""

# Vérifier que le script Python existe
if (-not (Test-Path $PYTHON_SCRIPT)) {
    Write-Host "❌ ERREUR: Le fichier $PYTHON_SCRIPT n'existe pas!" -ForegroundColor Red
    exit 1
}

# Définir la variable d'environnement SSLKEYLOGFILE
$env:SSLKEYLOGFILE = $KEYLOG_FILE
Write-Host "✓ Variable SSLKEYLOGFILE définie: $env:SSLKEYLOGFILE`n" -ForegroundColor Green

# Lancer le serveur Python
try {
    Write-Host "🚀 Démarrage du serveur...`n" -ForegroundColor Green
    python $PYTHON_SCRIPT
}
catch {
    Write-Host "`n❌ Erreur lors du lancement: $_" -ForegroundColor Red
    exit 1
}
finally {
    Write-Host "`n✓ Serveur arrêté." -ForegroundColor Yellow
}
