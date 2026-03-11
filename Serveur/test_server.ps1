#!/usr/bin/env pwsh
# Script de test du serveur HTTPS avec curl et SSLKEYLOGFILE

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test du serveur HTTPS avec curl" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Configuration
$CLIENT_KEYLOG = Join-Path $PSScriptRoot "client_keys.log"
$SERVER_URL = "https://localhost:4443/"

# Supprimer l'ancien fichier keylog s'il existe
if (Test-Path $CLIENT_KEYLOG) {
    Remove-Item $CLIENT_KEYLOG -Force
    Write-Host "🗑️  Ancien fichier client_keys.log supprimé" -ForegroundColor Yellow
}

# Définir SSLKEYLOGFILE pour curl
$env:SSLKEYLOGFILE = $CLIENT_KEYLOG
Write-Host "✓ Variable SSLKEYLOGFILE définie: $CLIENT_KEYLOG`n" -ForegroundColor Green

# Vérifier que curl est disponible
try {
    $curlVersion = curl --version 2>&1 | Select-Object -First 1
    Write-Host "📦 Version de curl:" -ForegroundColor Yellow
    Write-Host "   $curlVersion`n" -ForegroundColor White
}
catch {
    Write-Host "❌ curl n'est pas installé ou accessible" -ForegroundColor Red
    Write-Host "   Installez curl ou utilisez un navigateur pour tester`n" -ForegroundColor Yellow
    exit 1
}

# Faire une requête HTTPS (ignorer le certificat auto-signé)
Write-Host "🌐 Requête vers $SERVER_URL..." -ForegroundColor Green
Write-Host "   (Le certificat auto-signé sera ignoré avec -k)`n" -ForegroundColor Gray

try {
    $response = curl -k -v $SERVER_URL 2>&1
    
    Write-Host "✓ Requête réussie !`n" -ForegroundColor Green
    
    # Afficher les premières lignes de la réponse
    Write-Host "📄 Réponse (extrait):" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    $response | Select-Object -First 20 | ForEach-Object { Write-Host $_ }
    Write-Host "----------------------------------------`n" -ForegroundColor Gray
    
}
catch {
    Write-Host "❌ Erreur lors de la requête: $_`n" -ForegroundColor Red
    Write-Host "Le serveur est-il démarré ? Lancez-le avec ./start_server.ps1`n" -ForegroundColor Yellow
    exit 1
}

# Vérifier que le fichier keylog a été créé
if (Test-Path $CLIENT_KEYLOG) {
    $keylogSize = (Get-Item $CLIENT_KEYLOG).Length
    Write-Host "✓ Fichier de clés TLS créé: $CLIENT_KEYLOG" -ForegroundColor Green
    Write-Host "  Taille: $keylogSize octets`n" -ForegroundColor White
    
    # Afficher le contenu
    Write-Host "🔑 Contenu du fichier keylog:" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Get-Content $CLIENT_KEYLOG | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
    Write-Host "----------------------------------------`n" -ForegroundColor Gray
    
    Write-Host "✅ Test réussi ! Les clés TLS ont été capturées.`n" -ForegroundColor Green
    Write-Host "💡 Vous pouvez utiliser ce fichier dans Wireshark pour déchiffrer le trafic HTTPS." -ForegroundColor Yellow
}
else {
    Write-Host "⚠️  Le fichier keylog n'a pas été créé" -ForegroundColor Yellow
    Write-Host "   Vérifiez que curl supporte SSLKEYLOGFILE`n" -ForegroundColor Gray
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Fin du test" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
