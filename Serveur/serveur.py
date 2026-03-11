import ssl
import http.server
import os
import sys
from pathlib import Path

# 1. Configuration du fichier de log des clés
KEYLOG_FILE = "server_keys.log"
SERVER_CERT = "server.crt"
SERVER_KEY = "server.key"
SERVER_PORT = 4443

def main():
    # Vérifier que les certificats existent
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print(f"ERREUR: Les fichiers {SERVER_CERT} ou {SERVER_KEY} n'existent pas!")
        print("Générez-les avec: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -config openssl.cnf")
        sys.exit(1)
    
    # 2. Configuration du contexte SSL
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    
    # Support des anciennes versions de TLS pour la compatibilité
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Activer le keylog pour capturer les clés TLS
    if hasattr(context, "keylog_filename"):
        context.keylog_filename = KEYLOG_FILE
        print(f"✓ SSLKEYLOGFILE activé: {KEYLOG_FILE}")
    else:
        print("⚠ Votre version de Python/OpenSSL ne supporte pas keylog_filename.")
        print("  Vous avez besoin de Python 3.8+ avec OpenSSL 1.1.1+")
    
    # Vérifier également la variable d'environnement SSLKEYLOGFILE
    env_keylog = os.environ.get('SSLKEYLOGFILE')
    if env_keylog:
        print(f"✓ Variable d'environnement SSLKEYLOGFILE définie: {env_keylog}")
    
    # 3. Lancement d'un serveur HTTP simple
    server_address = ('localhost', SERVER_PORT)
    
    try:
        httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        
        print("\n" + "="*60)
        print(f"🔒 Serveur HTTPS démarré sur https://localhost:{SERVER_PORT}")
        print(f"📁 Répertoire servi: {Path.cwd()}")
        print(f"🔑 Clés TLS écrites dans: {Path(KEYLOG_FILE).absolute()}")
        print("="*60)
        print("\nAppuyez sur Ctrl+C pour arrêter le serveur\n")
        
        httpd.serve_forever()
        
    except KeyboardInterrupt:
        print("\n\n🛑 Arrêt du serveur...")
        httpd.shutdown()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()