# Résumé : Extraction des Secrets TLS via Pin Instrumentation

## 📋 Objectif

Extraire les secrets TLS (TLS 1.3) d'une application utilisant OpenSSL **sans** avoir accès à la variable d'environnement `SSLKEYLOGFILE`, afin de pouvoir déchiffrer le trafic réseau dans Wireshark.

---

## 🔍 Phase 1 : Vérification de l'Endianness

### Problème Initial
Les secrets dans `ssl-key.log` (générés par `SSLKEYLOGFILE`) ne correspondaient pas directement aux leaks capturés par le Backtracer.

### Découverte
Les secrets TLS dans `ssl-key.log` sont stockés en **little-endian par blocs de 8 octets**, tandis que nos leaks (capturés via `SHA384_Final`) sont en **big-endian**.

### Exemple de Conversion
```
Secret ssl-key.log (little-endian 8 bytes):
e11edc30ddb070eb 962f87c47e9d292f b093d72386677d38 ...

Leak capturé (big-endian):
eb70b0dd30dc1ee1 2f299d7ec4872f96 387d678623d793b0 ...
```

### Fonction de Conversion (PowerShell)
```powershell
function Conv($h) {
    $r = ""
    for ($i = 0; $i -lt $h.Length; $i += 16) {
        $b = $h.Substring($i, 16)
        $v = ""
        for ($j = 14; $j -ge 0; $j -= 2) {
            $v += $b.Substring($j, 2)
        }
        $r += $v
    }
    return $r
}
```

---

## 🎯 Phase 2 : Identification du Candidat

### Candidats Analysés
L'analyseur (`python analyseur/main.py`) a identifié deux candidats :

| Candidat | DLL | Delta | Fonction | Verdict |
|----------|-----|-------|----------|---------|
| 1 | libcrypto-3-x64.dll | 3656159 (0x37C9DF) | SHA384_Final | ✅ **BON** |
| 2 | libssl-3-x64.dll | 196544 (0x2FFC0) | SSLKEYLOGFILE logging | ❌ Inutile sans SSLKEYLOGFILE |

### Candidat Retenu
```
Reg: MEMORY32 Lib: C:\WINDOWS\SYSTEM32\libcrypto-3-x64.dll Delta: 3656159
```

**Instruction instrumentée** : `mov rcx, qword ptr [rdi]` dans `SHA384_Final`

Cette instruction lit 8 octets du secret depuis la mémoire. Le Backtracer capture 48 octets (taille d'un secret TLS 1.3 avec SHA-384).

---

## 📊 Phase 3 : Analyse des Captures

### Méthodologie
1. Lancer le Backtracer **avec** `SSLKEYLOGFILE` activé
2. Comparer les secrets de `ssl-key.log` avec les leaks de `backtrace_leaks.log`
3. Identifier les positions des 5 secrets TLS

### Résultats des 3 Captures de Validation

| Capture | Total Leaks | Positions Identiques |
|---------|-------------|---------------------|
| 1 | 61 | ✅ |
| 2 | 61 | ✅ |
| 3 | 61 | ✅ |

### Positions Stables Identifiées

| Position | Secret TLS |
|----------|------------|
| **11** | SERVER_HANDSHAKE_TRAFFIC_SECRET |
| **30** | SERVER_TRAFFIC_SECRET_0 |
| **36** | EXPORTER_SECRET |
| **39** | CLIENT_HANDSHAKE_TRAFFIC_SECRET |
| **53** | CLIENT_TRAFFIC_SECRET_0 |

**Conclusion** : Les positions sont **100% stables** d'une exécution à l'autre pour curl + OpenSSL 3.x + TLS 1.3.

---

## 🔧 Phase 4 : Script de Reconstruction

### Script Créé : `Scripts/reconstruct_keylog.py`

Ce script reconstruit automatiquement un fichier `ssl-key.log` à partir des leaks, **sans** avoir besoin de `SSLKEYLOGFILE`.

### Usage
```bash
# Reconstruction basique (Client Random = placeholder)
python Scripts/reconstruct_keylog.py -i Data/log/backtrace_leaks.log -o Data/reconstructed-ssl-key.log

# Avec Client Random (récupéré depuis Wireshark)
python Scripts/reconstruct_keylog.py -i Data/log/backtrace_leaks.log -r <CLIENT_RANDOM_HEX> -v
```

### Fonctionnement
1. Parse `backtrace_leaks.log` et extrait tous les leaks
2. Récupère les leaks aux positions 11, 30, 36, 39, 53
3. Convertit de big-endian vers little-endian (blocs de 8 octets)
4. Génère le fichier au format `SSLKEYLOGFILE`

### Validation
Les secrets reconstruits correspondent **exactement** aux secrets originaux :

```
=== ORIGINAL ===
SERVER_HANDSHAKE_TRAFFIC_SECRET: 7521f7e2bf5253f71b16b2300a9df963...
SERVER_TRAFFIC_SECRET_0: 0f359e2c836a1c987925ae99e3d99722...
EXPORTER_SECRET: 0ed7b1bebc62a598303b9654ac1f2547...
CLIENT_HANDSHAKE_TRAFFIC_SECRET: f80ae34b45b6d3848a5949d4288f3a7b...
CLIENT_TRAFFIC_SECRET_0: 4919d8810884492d579393b3858a497e...

=== RECONSTRUIT ===
SERVER_HANDSHAKE_TRAFFIC_SECRET: 7521f7e2bf5253f71b16b2300a9df963... ✅
SERVER_TRAFFIC_SECRET_0: 0f359e2c836a1c987925ae99e3d99722... ✅
EXPORTER_SECRET: 0ed7b1bebc62a598303b9654ac1f2547... ✅
CLIENT_HANDSHAKE_TRAFFIC_SECRET: f80ae34b45b6d3848a5949d4288f3a7b... ✅
CLIENT_TRAFFIC_SECRET_0: 4919d8810884492d579393b3858a497e... ✅
```

---

## Workflow Final (Sans SSLKEYLOGFILE)

### Étape 1 : Capture du Trafic
```bash
# Lancer Wireshark et capturer sur l'interface réseau
```

### Étape 2 : Lancer le Backtracer
```powershell
$PIN_TOOL = "C:\Users\diala\Downloads\pin-external-4.0-99633-g5ca9893f2-clang-windows"
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\Backtracer.dll" -- Cible/curl.exe -k https://localhost:4443
```

### Étape 3 : Extraire le Client Random
Dans Wireshark :
1. Filtre : `tls.handshake.type == 1`
2. Aller dans : `TLS → Handshake Protocol: Client Hello → Random`
3. Copier les 32 bytes (64 caractères hex)

### Étape 4 : Reconstruire ssl-key.log
```bash
python Scripts/reconstruct_keylog.py -i Data/log/backtrace_leaks.log -r <CLIENT_RANDOM> -o Data/decryption-key.log
```

### Étape 5 : Déchiffrer dans Wireshark
1. `Edit → Preferences → Protocols → TLS`
2. `(Pre)-Master-Secret log filename` → sélectionner `decryption-key.log`
3. Le trafic TLS est maintenant déchiffré ! 🔓

---

## Structure des Fichiers

```
inside-msteams/
├── Analyseur/              # Analyseur de traces
│   └── main.py
├── Cible/
│   └── curl.exe            # Application cible (OpenSSL)
├── Data/
│   └── log/                # Logs générés (vide après nettoyage)
├── Pintools/
│   ├── Backtracer.cpp
│   ├── PinGetName.cpp
│   ├── TraceBuilder.cpp
│   └── MyPintool/obj-intel64/   # DLLs compilées
├── Scripts/
│   ├── pin_config.ini
│   ├── reconstruct_keylog.py    # Script de reconstruction
│   └── https_server.py          # Serveur HTTPS de test
└── commandes.txt                # Procédure d'exécution
```

---

## Points Clés

1. **Candidat** : `libcrypto-3-x64.dll` delta `3656159` (SHA384_Final)
2. **Endianness** : ssl-key.log = little-endian 8 bytes, leaks = big-endian
3. **Positions stables** : 11, 30, 36, 39, 53 (sur 61 leaks)
4. **Client Random** : Récupérable en clair dans le ClientHello (Wireshark)
5. **5 secrets TLS 1.3** : SERVER_HANDSHAKE, CLIENT_HANDSHAKE, SERVER_TRAFFIC_0, CLIENT_TRAFFIC_0, EXPORTER

---


## Date de Rédaction
22 janvier 2026
