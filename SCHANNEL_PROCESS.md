# Extraction des Secrets TLS — curl SChannel (bcryptprimitives.dll)

> ⚠️ Ce document décrit le process pour **curl_schannel.exe** (implémentation Windows
> native via SChannel / `bcryptprimitives.dll`).  
> Pour **curl + OpenSSL** (`libcrypto-3-x64.dll`) → voir `RESUME_EXTRACTION_SECRETS_TLS.md`
> et `commandes.txt`.

---

## 📋 Objectif

Extraire les secrets TLS 1.3 d'une session `curl_schannel.exe` **sans** `SSLKEYLOGFILE`,
afin de déchiffrer le trafic réseau dans Wireshark.

---

## 🔑 Candidat Validé (SChannel)

| Propriété    | Valeur |
|--------------|--------|
| DLL          | `bcryptprimitives.dll` (DLL système Windows) |
| Fonction     | `.text` — symbole interne non exporté (proche de `GetHashInterface`) |
| Delta        | **41714** (`0xA2F2`) |
| Instruction  | `movdqu xmm0, [rcx+rax*8]` |
| Hook         | `IPOINT_BEFORE` — lit la clé **avant** le XOR HMAC ipad |

### Secrets capturés

| Secret | Disponible |
|--------|-----------|
| `SERVER_TRAFFIC_SECRET_0` | ✅ |
| `CLIENT_TRAFFIC_SECRET_0` | ✅ |
| `EXPORTER_SECRET` | ✅ |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET` | ❌ (chemin HKDF différent) |
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | ❌ (chemin HKDF différent) |

> **Note :** Les 3 secrets APPLICATION suffisent pour déchiffrer le contenu HTTP
> dans Wireshark. Les secrets HANDSHAKE ne sont pas disponibles à cette instruction
> (chemin HKDF distinct dans `bcryptprimitives.dll`).


---

## 📦 Prérequis

- **Pin** : `C:\Users\diala\Downloads\pin-external-4.0-99633-g5ca9893f2-clang-windows`
- **Cible** : `Cible/curl_schannel.exe` (curl compilé avec SChannel, pas OpenSSL)
- **Serveur HTTPS local** : `Serveur/serveur.py` sur `https://localhost:4443`
  (certificat auto-signé → flag `-k` nécessaire)
- **`pin_config.ini`** configuré pour SChannel (voir ci-dessous)
- **Pintools compilés** : `Pintools/MyPintool/obj-intel64/*.dll`

---

## ⚙️ Configuration pin_config.ini (mode SChannel)

Vérifier / mettre à jour `Scripts/pin_config.ini` :

```ini
[filter]
MODE=blacklist
LIBRARIES=ntdll.dll

[target]
LIBRARY=bcryptprimitives.dll
DELTA=41714

[output]
COMMAND=SERVER_TRAFFIC_SECRET_0
```

> Le mode `blacklist` sur `ntdll.dll` est indispensable : instrumenter les RET/CALL
> de `ntdll` provoque des crashs NtContinue lors de l'utilisation de SChannel.

---

## 🚀 Procédure Complète

### Étape 0 : Compiler les Pintools

```powershell
cd Pintools/MyPintool
.\build.bat
cd ../..
```

---

### Étape 1 : Démarrer le serveur HTTPS local

Dans un terminal séparé :

```powershell
python Serveur/serveur.py
```

Le serveur écoute sur `https://localhost:4443` avec le certificat
`Serveur/openssl.cnf`. Laisser ce terminal ouvert pour toute la session.

---

### Étape 2 : Lancer TraceBuilder

```powershell
$PIN_TOOL = "C:\Users\diala\Downloads\pin-external-4.0-99633-g5ca9893f2-clang-windows"
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\TraceBuilder.dll" `
    -config Scripts/pin_config.ini `
    -- Cible/curl_schannel.exe -k https://localhost:4443
```

Résultat : `Data/log/trace.binary` + `Data/log/trace.txt`

---

### Étape 3 : Analyser la trace (identifier le candidat)

```powershell
python Analyseur/main.py -c Scripts/pin_config.ini
```

Résultat attendu dans `Data/log/analyse.log` :

```
Reg: MEMORY32 Lib: bcryptprimitives.dll Delta: 41714
```

> Si le candidat est différent, mettre à jour `DELTA` dans `pin_config.ini`.

---

### Étape 4 : PinGetName (obtenir le nom de l'instruction)

```powershell
$PIN_TOOL = "C:\Users\diala\Downloads\pin-external-4.0-99633-g5ca9893f2-clang-windows"
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\PinGetName.dll" `
    -config Scripts/pin_config.ini `
    -- Cible/curl_schannel.exe -k https://localhost:4443
```

Résultat dans `Data/log/getName.log` — exemple :

```
Librairie: bcryptprimitives.dll
Delta: 41714
Adresse: 0x7fff6318a2f2
Fonction: `.text`
Instruction: movdqu xmm0, xmmword ptr [rcx+rax*8]
```

> La fonction affiche `.text` car le symbole est **interne et non exporté** dans
> `bcryptprimitives.dll`. C'est attendu — la fonction HKDF utilisée par SChannel
> n'est pas dans la table d'export de la DLL.

---

### Étape 5 : Backtracer (capturer les secrets)

```powershell
$PIN_TOOL = "C:\Users\diala\Downloads\pin-external-4.0-99633-g5ca9893f2-clang-windows"
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\Backtracer.dll" `
    -config Scripts/pin_config.ini `
    -- Cible/curl_schannel.exe -k https://localhost:4443
```

Résultats :
- `Data/log/Backtrace.log` — pile d'appels au moment de la capture
- `Data/log/backtrace_leaks.log` — octets extraits (secrets bruts)

Exemple de ligne dans `backtrace_leaks.log` :
```
[Backtracer] DEBUG: Leaked bytes: 0b 21 e2 1c 3f a4 ... (48 octets)
```

Chaque secret apparaît plusieurs fois (même adresse accédée en boucle) —
le script de reconstruction déduplique automatiquement.

---

### Étape 6 : Lancer Wireshark et capturer le trafic

Lancer Wireshark et démarrer une capture sur l'interface loopback (`lo` / `Loopback`),
**puis** relancer `curl_schannel.exe` (sans Pin cette fois) pour générer la session
dont on veut récupérer le Client Random :

```powershell
Cible/curl_schannel.exe -k https://localhost:4443
```

> Cette étape est uniquement nécessaire pour obtenir le Client Random de la session
> à déchiffrer. Elle est **indépendante** des étapes d'apprentissage (2-5).

---

### Étape 7 : Récupérer le Client Random (Wireshark)

1. Filtre Wireshark : `tls.handshake.type == 1`
2. Clic sur le paquet **Client Hello** de la session à déchiffrer
3. Naviguer vers : `TLS → Handshake Protocol: Client Hello → Random`
4. Clic droit → **Copy → As Hex Stream**
5. Copier les 64 caractères hex (32 bytes)

---

### Étape 8 : Reconstruire le fichier ssl-key.log (sur la session Backtracer)

```powershell
python Scripts/reconstruct_keylog_schannel.py `
    -i Data/log/backtrace_leaks.log `
    -r <CLIENT_RANDOM_HEX_64_CHARS> `
    -o Data/decryption-key.log `
    -v
```

Exemple :
```powershell
python Scripts/reconstruct_keylog_schannel.py `
    -i Data/log/backtrace_leaks.log `
    -r 17148a11b23c4d5e6f7a8b9c0d1e2f30a1b2c3d4e5f60718293a4b5c6d7e8f9 `
    -o Data/decryption-key.log `
    -v
```

Le fichier `Data/decryption-key.log` contient les 3 secrets au format NSS :
```
SERVER_TRAFFIC_SECRET_0 <client_random> <48_bytes_hex>
CLIENT_TRAFFIC_SECRET_0 <client_random> <48_bytes_hex>
EXPORTER_SECRET         <client_random> <48_bytes_hex>
```

---

### Étape 9 : Déchiffrer dans Wireshark

1. `Edit → Preferences → Protocols → TLS`
2. `(Pre)-Master-Secret log filename` → sélectionner `Data/decryption-key.log`
3. Cliquer sur **OK**
4. Le contenu HTTP de la session est maintenant visible 🔓

> **Attention :** Seul le trafic **application** est déchiffré. Les messages
> `Client Hello` / `Server Hello` restent chiffrés dans Wireshark (secrets
> HANDSHAKE non capturés).

---

## 🔄 Workflow Résumé (Pour une démo)

```powershell
# Terminal 1 — serveur HTTPS
python Serveur/serveur.py

# Terminal 2 — dans le répertoire du projet
$PIN_TOOL = "C:\Users\diala\Downloads\pin-external-4.0-99633-g5ca9893f2-clang-windows"

# 1. Backtracer (capture les secrets)
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\Backtracer.dll" `
    -config Scripts/pin_config.ini `
    -- Cible/curl_schannel.exe -k https://localhost:4443

# 2. Lancer Wireshark (capture loopback) + curl_schannel.exe sans Pin pour la session à déchiffrer
#    → récupérer Client Random : tls.handshake.type == 1 → ClientHello → Random

# 3. Reconstruire ssl-key.log
python Scripts/reconstruct_keylog_schannel.py `
    -i Data/log/backtrace_leaks.log `
    -r <CLIENT_RANDOM> `
    -o Data/decryption-key.log

# 4. Configurer Wireshark avec Data/decryption-key.log
```

---

## 📌 Points Clés (Différences avec OpenSSL)

| Critère | curl + OpenSSL | curl + SChannel |
|---------|---------------|-----------------|
| DLL cible | `libcrypto-3-x64.dll` | `bcryptprimitives.dll` |
| Fonction | `SHA384_Final` (exportée) | `.text` **(interne, non exportée)** |
| Delta | 3656159 (0x37C9DF) | **41714 (0xA2F2)** |
| Instruction | `mov rcx, [rdi]` | `movdqu xmm0, [rcx+rax*8]` |
| Secrets capturés | 5 (dont HANDSHAKE) | **3 (APPLICATION seulement)** |
| Positions fixes | Oui (11, 30, 36, 39, 53) | **Non (déduplication par contenu)** |
| Config blacklist | Optionnelle | **Obligatoire (ntdll.dll)** |
| Cible | `curl.exe https://www.google.com` | `curl_schannel.exe -k https://localhost:4443` |
| Script reconstitution | `reconstruct_keylog.py` | **`reconstruct_keylog_schannel.py`** |

---

## Date de Rédaction

Mars 2026
