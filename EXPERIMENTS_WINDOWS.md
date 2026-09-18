# Reproduire les expériences sous Windows

Ce document est la procédure de référence pour reproduire les expériences du dépôt. Elle suppose PowerShell et Windows 64 bits. Les commandes sont lancées depuis la racine du dépôt, sauf indication contraire.

## 1. Logiciels nécessaires

Installer ou récupérer :

- Windows 10/11 x64.
- Python 3.10 ou plus récent (`python --version`).
- Visual Studio 2022 Build Tools avec **Développement Desktop en C++**, MSVC, Windows SDK et LLVM/Clang.
- Intel Pin pour Windows x64. Le dossier extrait doit contenir `pin.exe`, `source`, `intel64` et `extras`.
- Wireshark avec l'interface loopback pour les sessions locales.
- OpenSSL pour le serveur de référence contrôlé et la génération du certificat. Le serveur Python utilise les bibliothèques OpenSSL de Python.

Le dépôt contient les exécutables Windows dans `Cible/`. Sinon, fournir des exécutables x64 compatibles `curl.exe`, `curl_openssl.exe` ou `curl_schannel.exe`. La cible OpenSSL doit utiliser les noms de DLL indiqués dans `Scripts/pin_config.ini`, ou le filtre doit être adapté.

## 2. Préparer les chemins

Depuis PowerShell, se placer à la racine du dépôt. Les pintools écrivent leurs résultats par défaut dans `Data/log`.

```powershell
Set-Location "C:\chemin\vers\inside-msteams"
$env:PIN_ROOT = "C:\outils\pin-external-4.0-99633-g5ca9893f2-clang-windows"
```

`PIN_ROOT` est le seul chemin absolu spécifique au poste qui est nécessaire. Si Clang n'est pas présent dans `PATH`, définir également :

```powershell
$env:CLANG_CL = "C:\Program Files\LLVM\bin\clang-cl.exe"
$env:LLD_LINK = "C:\Program Files\LLVM\bin\lld-link.exe"
```

Il est recommandé d'utiliser **Developer PowerShell for VS 2022**, car cette console prépare `INCLUDE`, `LIB` et le Windows SDK. Vérifier la configuration :

```powershell
Test-Path "$env:PIN_ROOT\pin.exe"
Get-Command clang-cl.exe
Get-Command lld-link.exe
python --version
```

## 3. Compiler les pintools

Les sources sont versionnées directement dans le dossier réel `Pintools/` :

```powershell
Set-Location Pintools
.\build.bat TraceBuilder TraceBuilder_Delayed TraceBuilder_FuncEntry PinGetName Backtracer
Set-Location ..
```

Pour compiler toutes les cibles disponibles :

```powershell
Set-Location Pintools
.\build.bat
Set-Location ..
```

Les DLL sont écrites dans `Pintools/obj-intel64/`. Les principales cibles sont :

- `TraceBuilder` : trace complète des instructions.
- `TraceBuilder_Delayed` : fenêtre limitée d'instructions.
- `TraceBuilder_FuncEntry` : premières instructions de chaque fonction.
- `TraceBuilder_PerFunctionSplit` : séparation de la trace par fonction.
- `TraceBuilder_ArgTracker` et `TraceBuilder_StructTracker` : suivi des arguments et structures.
- `PinGetName` et `PinGetName_StructTracker` : résolution de l'instruction candidate.
- `Backtracer` et `Backtracer_StructTracker` : capture de la pile d'appels et des octets extraits.
- `Extracteur` et `LibraryFunctions` : outils auxiliaires.

En cas d'erreur de compilation concernant des headers ou bibliothèques, vérifier que la console est une Developer PowerShell et que `PIN_ROOT` pointe vers la racine du kit Pin, et non vers `pin.exe`.

## 4. Configurer le TraceBuilder filtré par fonction

Modifier `Scripts/pin_config.ini` pour choisir les DLL cibles, les registres, la taille mémoire et les filtres. Les chemins de `[INPUT FILES]` et `[OUTPUT FILES]` sont relatifs à la racine du dépôt. Conserver `MODE = whitelist` autant que possible : une trace sans filtre peut atteindre plusieurs gigaoctets.

`FILTER_FUNCTION` contient les fonctions à exclure et `TARGET_LIB` limite l'instrumentation aux DLL TLS. Cette configuration est comprise par `TraceBuilder`, `TraceBuilder_Delayed`, `TraceBuilder_FuncEntry` et `TraceBuilder_PerFunctionSplit`.

```ini
[FILTERS]
MODE = whitelist
FILTER_FUNCTION = printf, sprintf, puts, SSL_sendfile
TARGET_LIB = libssl-3-x64.dll, libcrypto-3-x64.dll
```

Pour un premier essai, utiliser `TraceBuilder_FuncEntry.dll` avec `MAX_INS_PER_FUNC`. Si la candidate n'est pas trouvée, utiliser `TraceBuilder_PerFunctionSplit.dll`, puis `TraceBuilder.dll` avec un filtre plus large.

La pipeline est la suivante :

1. Exécuter un TraceBuilder filtré et produire `Data/log/trace.binary`.
2. Exécuter `Analyseur/main.py` et relever la DLL candidate et le delta.
3. Exécuter `PinGetName.dll` avec la même cible et la même configuration.
4. Exécuter `Backtracer.dll` sur l'instruction candidate.
5. Comparer les octets extraits avec le keylog de référence du serveur.

Exemple avec OpenSSL :

```powershell
& "$env:PIN_ROOT\pin.exe" `
  -t "Pintools/obj-intel64/TraceBuilder.dll" `
  -config "Scripts/pin_config.ini" `
  -- "Cible/curl_openssl.exe" https://www.google.com
```

Exemple avec SChannel :

```powershell
& "$env:PIN_ROOT\pin.exe" `
  -t "Pintools/obj-intel64/TraceBuilder.dll" `
  -config "Scripts/pin_config.ini" `
  -- "Cible/curl_schannel.exe" -k https://localhost:4443
```

Remplacer `TraceBuilder.dll` par `TraceBuilder_Delayed.dll`, `TraceBuilder_FuncEntry.dll` ou `TraceBuilder_PerFunctionSplit.dll` pour comparer les variantes. Pour Delayed, ajouter `SKIP_INSTRUCTIONS` et `MAX_INSTRUCTIONS` dans `[GENERAL]`. Pour FuncEntry, ajouter `MAX_INS_PER_FUNC`.

Supprimer les anciens résultats avant une nouvelle expérience :

```powershell
Remove-Item Data/log/trace.binary, Data/log/trace.log -ErrorAction SilentlyContinue
```

## 5. Analyser la trace

```powershell
python Analyseur/main.py -c Scripts/pin_config.ini
Get-Content Data/log/analyse.log
```

Noter la DLL candidate, le registre ou fragment mémoire et le delta. Les résultats peuvent changer selon l'exécutable cible, la version de la DLL TLS et le filtre utilisé. Les deltas historiques ne sont pas universels.

## 6. Résoudre l'instruction et capturer la backtrace

```powershell
& "$env:PIN_ROOT\pin.exe" `
  -t "Pintools/obj-intel64/PinGetName.dll" `
  -config "Scripts/pin_config.ini" `
  -- "Cible/curl_openssl.exe" https://www.google.com

Get-Content Data/log/getName.log
```

Après vérification de la DLL et du delta dans `getName.log` :

```powershell
& "$env:PIN_ROOT\pin.exe" `
  -t "Pintools/obj-intel64/Backtracer.dll" `
  -config "Scripts/pin_config.ini" `
  -- "Cible/curl_openssl.exe" https://www.google.com
```

Le Backtracer écrit `Data/log/Backtrace.log` et `Data/log/backtrace_leaks.log`. Pour SChannel, utiliser `curl_schannel.exe -k https://localhost:4443` et `Scripts/reconstruct_keylog_schannel.py`.

## 7. Keylog de référence côté serveur OpenSSL

Le client Windows utilisé pour l'extraction ne fournit pas de `SSLKEYLOGFILE` exploitable : SChannel ne propose pas d'équivalent client dans ce montage. Pour la phase d'apprentissage, contrôler le serveur HTTPS à la place. La variable `SSLKEYLOGFILE` doit être définie dans le terminal PowerShell **du serveur**, pas dans celui du client.

Dans une deuxième console PowerShell, depuis la racine du dépôt :

```powershell
$env:SSLKEYLOGFILE = "$PWD/Data/server-ssl-key.log"
python Serveur/serveur.py
```

Lancer ensuite la requête côté client, directement ou avec la pipeline TraceBuilder filtrée. Après la requête, récupérer `Data/server-ssl-key.log` comme keylog de référence.

Pour apprendre `Data/secret_leak_map.json`, utiliser les leaks et le Client Random de cette même requête :

```powershell
python Scripts/reconstruct_keylog.py `
  -i Data/log/backtrace_leaks.log `
  -k Data/server-ssl-key.log `
  -r <CLIENT_RANDOM_HEX_64_CARACTERES> `
  -o Data/decryption-key.log `
  -v
```

Ne jamais utiliser un keylog provenant d'une autre session TLS : la carte est apprise avec les octets extraits et les secrets de la même requête.

## 8. Expérience SChannel avec le serveur HTTPS local

Dans une console séparée, depuis la racine du dépôt :

```powershell
python Serveur/serveur.py
```

Il est aussi possible d'utiliser `Serveur/start_server.ps1` si les certificats sont déjà configurés. Le certificat local étant auto-signé, l'option `-k` est nécessaire.

Dans Wireshark, capturer l'interface loopback et utiliser le filtre `tls.handshake.type == 1`. Ouvrir le Client Hello et copier `TLS > Handshake Protocol: Client Hello > Random` sous la forme de 64 caractères hexadécimaux. Reconstruire les secrets applicatifs :

```powershell
python Scripts/reconstruct_keylog_schannel.py `
  -i Data/log/backtrace_leaks.log `
  -r <CLIENT_RANDOM_HEX_64_CARACTERES> `
  -o Data/decryption-key.log `
  -v
```

Le workflow SChannel récupère normalement les secrets du trafic applicatif uniquement. Les limites et la candidate historique sont décrites dans `SCHANNEL_PROCESS.md`.

## 9. Reconstruction OpenSSL et Wireshark

Pour une exécution OpenSSL, récupérer le Client Random dans la capture Wireshark correspondante puis exécuter :

```powershell
python Scripts/reconstruct_keylog.py `
  -i Data/log/backtrace_leaks.log `
  -r <CLIENT_RANDOM_HEX_64_CARACTERES> `
  -o Data/decryption-key.log `
  -v
```

En phase d'apprentissage, fournir le keylog de référence avec `-k` et mettre à jour `Data/secret_leak_map.json`. Ne jamais committer de clés privées, keylogs ou captures contenant des données sensibles.

Dans Wireshark, ouvrir `Edit > Preferences > Protocols > TLS`, sélectionner `(Pre)-Master-Secret log filename`, choisir `Data/decryption-key.log`, puis rouvrir la capture si nécessaire.

## 10. Informations à conserver

Pour chaque expérience, noter :

- les versions de Windows, Python, Pin et du compilateur ;
- le nom et le hash de la cible (`Get-FileHash Cible/curl_openssl.exe`) ;
- les versions des DLL TLS et le contenu exact de `Scripts/pin_config.ini` ;
- la variante TraceBuilder et ses limites ;
- la commande curl, les logs candidats, le Client Random et le résultat de reconstruction ;
- le protocole utilisé, OpenSSL ou SChannel, et l'interface Wireshark.

Ne pas committer les résultats générés dans `Data/`, les certificats privés, les keylogs ou les captures. Utiliser des chemins relatifs dans la documentation et des variables comme `PIN_ROOT` pour les outils externes.
