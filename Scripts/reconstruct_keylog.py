#!/usr/bin/env python3
"""
reconstruct_keylog.py — curl + OpenSSL 3.x UNIQUEMENT
======================================================
Reconstruit ssl-key.log à partir de backtrace_leaks.log SANS avoir besoin
de SSLKEYLOGFILE.

⚠️  Ce script est SPÉCIFIQUE à curl compilé avec OpenSSL 3.x (libcrypto-3-x64.dll).
    Pour curl SChannel (bcryptprimitives.dll), utiliser reconstruct_keylog_schannel.py.

Hypothèses OpenSSL 3.x + TLS 1.3 :
  - Candidat : libcrypto-3-x64.dll delta 3656159 (SHA384_Final)
  - Les leaks sont en big-endian → conversion little-endian par blocs de 8 octets
  - Les positions des secrets sont FIXES sur 61 leaks :
      Position 11 → SERVER_HANDSHAKE_TRAFFIC_SECRET
      Position 30 → SERVER_TRAFFIC_SECRET_0
      Position 36 → EXPORTER_SECRET
      Position 39 → CLIENT_HANDSHAKE_TRAFFIC_SECRET
      Position 53 → CLIENT_TRAFFIC_SECRET_0

Usage:
  python reconstruct_keylog.py -i Data/log/backtrace_leaks.log -o Data/reconstructed.log
  python reconstruct_keylog.py -i Data/log/backtrace_leaks.log -r <CLIENT_RANDOM_HEX>
"""

import sys
import re
import argparse
from pathlib import Path

# Positions fixes des secrets TLS (1-indexed) - déterminées empiriquement
SECRET_POSITIONS = {
    11: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    30: "SERVER_TRAFFIC_SECRET_0",
    36: "EXPORTER_SECRET",
    39: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    53: "CLIENT_TRAFFIC_SECRET_0",
}

def convert_big_to_little_endian_8(hex_str: str) -> str:
    """
    Convertit un secret de big-endian vers little-endian par blocs de 8 octets.
    Les leaks sont en big-endian, ssl-key.log attend du little-endian.
    """
    result = ""
    for i in range(0, len(hex_str), 16):
        block = hex_str[i:i+16]
        reversed_block = "".join(block[j:j+2] for j in range(len(block)-2, -1, -2))
        result += reversed_block
    return result

def extract_leaks(leaks_file: Path) -> list:
    """Extrait tous les leaks du fichier backtrace_leaks.log"""
    leaks = []
    pattern = re.compile(r"Leaked bytes:\s*(.+)")
    
    with open(leaks_file, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                hex_value = match.group(1).strip().replace(" ", "")
                leaks.append(hex_value)
    
    return leaks

def reconstruct_ssl_keylog(leaks: list, client_random: str = None) -> list:
    """
    Reconstruit les lignes du ssl-key.log à partir des leaks.
    """
    if client_random is None:
        client_random = "0" * 64
        print("WARNING: Client Random non fourni, utilisant placeholder!", file=sys.stderr)
    
    lines = []
    for position, secret_name in sorted(SECRET_POSITIONS.items()):
        if position <= len(leaks):
            big_endian_secret = leaks[position - 1]
            little_endian_secret = convert_big_to_little_endian_8(big_endian_secret)
            lines.append(f"{secret_name} {client_random} {little_endian_secret}")
        else:
            print(f"WARNING: Position {position} hors limites", file=sys.stderr)
    
    return lines

def main():
    parser = argparse.ArgumentParser(
        description="Reconstruit ssl-key.log à partir des leaks (curl + OpenSSL 3.x uniquement)"
    )
    parser.add_argument("-i", "--input", type=Path, default=Path("Data/log/backtrace_leaks.log"))
    parser.add_argument("-o", "--output", type=Path, default=Path("Data/reconstructed-ssl-key.log"))
    parser.add_argument("-r", "--client-random", type=str, default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()
    
    if not args.input.exists():
        print(f"ERREUR: {args.input} introuvable", file=sys.stderr)
        sys.exit(1)
    
    leaks = extract_leaks(args.input)
    print(f"Leaks extraits: {len(leaks)}")
    
    lines = reconstruct_ssl_keylog(leaks, args.client_random)
    
    with open(args.output, 'w') as f:
        f.write("\n".join(lines) + "\n")
    
    print(f"Fichier créé: {args.output}")
    
    if args.verbose:
        print("\n=== Secrets reconstruits ===")
        for line in lines:
            parts = line.split()
            print(f"  {parts[0]}: {parts[2][:32]}...")

if __name__ == "__main__":
    main()
