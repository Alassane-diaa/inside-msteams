# Guide d'utilisation du serveur HTTPS avec SSLKEYLOGFILE

Le serveur est le point de controle de reference sous OpenSSL pour Windows.
Le client, notamment `curl_schannel.exe`, n'a pas besoin de definir
`SSLKEYLOGFILE`; on definit cette variable dans le terminal qui lance le
serveur, puis on recupere le fichier de cles apres la requete.

## 📋 Prérequis

- Python 3.8+ avec OpenSSL 1.1.1+
- OpenSSL installé (pour la génération de certificats)

## 🚀 Démarrage rapide

### Option 1: Utiliser le script PowerShell (recommandé)
```powershell
.\start_server.ps1
```

### Option 2: Utiliser le script Batch
```cmd
start_server.bat
```

### Option 3: Lancement manuel
```powershell
# Définir la variable d'environnement dans le terminal du serveur
$env:SSLKEYLOGFILE = "$PWD\server_keys.log"

# Lancer le serveur
python serveur.py
```

## 📁 Fichiers générés

- **server.crt** - Certificat SSL auto-signé (valide 365 jours)
- **server.key** - Clé privée du serveur
- **server_keys.log** - Fichier de log contenant les clés TLS/SSL (format SSLKEYLOGFILE)
- **openssl.cnf** - Configuration OpenSSL pour la génération de certificats

## 🔍 Tester le serveur

### Avec curl (capture des clés TLS)
```powershell
# Définir SSLKEYLOGFILE pour curl
$env:SSLKEYLOGFILE = "client_keys.log"

# Faire une requête (ignorer le certificat auto-signé)
curl -k https://localhost:4443/
```

### Avec un navigateur
1. Ouvrir https://localhost:4443 dans votre navigateur
2. Accepter l'avertissement de sécurité (certificat auto-signé)
3. Les clés TLS seront enregistrées dans `server_keys.log`

## 🔐 Analyse des clés TLS

Le fichier `server_keys.log` contient les clés de session TLS au format compatible avec Wireshark.

### Utiliser avec Wireshark
1. Capturer le trafic réseau avec Wireshark
2. Aller dans: Edit → Preferences → Protocols → TLS
3. Dans "(Pre)-Master-Secret log filename", spécifier le chemin vers `server_keys.log`
4. Le trafic HTTPS sera déchiffré automatiquement

### Format du fichier
```
CLIENT_RANDOM <client_random> <master_secret>
```

## 🔧 Régénérer les certificats

Si vous devez régénérer les certificats:

```powershell
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -config openssl.cnf
```

## ⚙️ Configuration

### Modifier le port du serveur
Éditer [serveur.py](serveur.py) et changer la valeur de `SERVER_PORT`:
```python
SERVER_PORT = 4443  # Changez cette valeur
```

### Modifier le fichier de log
Éditer [serveur.py](serveur.py) et changer la valeur de `KEYLOG_FILE`:
```python
KEYLOG_FILE = "server_keys.log"  # Changez cette valeur
```

## 🐛 Dépannage

### Python ne supporte pas keylog_filename
Vérifiez votre version de Python et OpenSSL:
```powershell
python --version
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

Vous avez besoin de:
- Python 3.8+
- OpenSSL 1.1.1+

### Erreur "certificats manquants"
Régénérez les certificats avec la commande ci-dessus.

### Port déjà utilisé
Changez `SERVER_PORT` dans [serveur.py](serveur.py) ou arrêtez le processus utilisant le port 4443:
```powershell
netstat -ano | findstr :4443
```

## 📝 Notes

- Le certificat est auto-signé, les navigateurs afficheront un avertissement de sécurité (normal)
- Les clés TLS sont écrites en temps réel dans `server_keys.log`
- Le serveur sert les fichiers du répertoire courant
- Compatible avec l'analyse de trafic TLS dans Wireshark
