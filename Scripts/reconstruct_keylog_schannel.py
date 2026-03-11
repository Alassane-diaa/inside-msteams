#!/usr/bin/env python3
"""
reconstruct_keylog_schannel.py — curl SChannel / bcryptprimitives.dll UNIQUEMENT
=================================================================================
Reconstruit un fichier ssl-key.log (format NSS SSLKEYLOGFILE) à partir de
backtrace_leaks.log capturé via Backtracer sur curl_schannel.exe.

⚠️  Ce script est SPÉCIFIQUE à curl compilé avec SChannel (bcryptprimitives.dll).
    Pour curl OpenSSL (libcrypto-3-x64.dll), utiliser reconstruct_keylog.py.

Hypothèses SChannel + TLS 1.3 :
  - Candidat : bcryptprimitives.dll delta 41714 (0xA2F2)
  - Instruction : movdqu xmm0, [rcx+rax*8]  (hook IPOINT_BEFORE)
  - Les octets capturés sont RAW = secrets réels (pas de conversion endian)
    → l'instruction XOR (HMAC ipad 0x36) se fait APRÈS le hook
  - Seuls les secrets APPLICATION sont capturés ici (pas les secrets HANDSHAKE) :
      1er secret unique → SERVER_TRAFFIC_SECRET_0
      2ème secret unique → CLIENT_TRAFFIC_SECRET_0
      3ème secret unique → EXPORTER_SECRET
  - Chaque secret apparaît plusieurs fois dans le log (même adresse accédée
    plusieurs fois) → déduplication par contenu (premier occurrence conservée)

Usage:
  python Scripts/reconstruct_keylog_schannel.py \\
      -i Data/log/backtrace_leaks.log \\
      -r <CLIENT_RANDOM_HEX> \\
      -o Data/decryption-key.log

  Le Client Random (64 hex chars) se récupère dans Wireshark :
    Filtre : tls.handshake.type == 1
    TLS → Handshake Protocol: Client Hello → Random
"""

import sys
import re
import argparse
from pathlib import Path

# Mapping position (ordre d'apparition) → nom du secret
SECRET_ORDER = [
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
]


def extract_leaks(leaks_file: Path, verbose: bool = False) -> list:
    """
    Extrait et déduplique les leaks depuis backtrace_leaks.log.

    Chaque ligne pertinente ressemble à :
        [Backtracer] DEBUG: Leaked bytes: xx xx xx ...

    Retourne une liste ordonnée de secrets hex uniques (sans espaces),
    dans l'ordre de première apparition.
    """
    pattern = re.compile(r"Leaked bytes:\s*(.+)")
    seen = {}     # hex_str → index d'insertion (pour conserver l'ordre)
    ordered = []  # liste ordonnée par première apparition

    with open(leaks_file, "r") as f:
        for lineno, line in enumerate(f, 1):
            m = pattern.search(line)
            if not m:
                continue
            # Normalise : retire les espaces, met en minuscules
            raw = m.group(1).strip()
            hex_str = raw.replace(" ", "").lower()
            if not hex_str:
                continue
            if hex_str not in seen:
                seen[hex_str] = len(ordered)
                ordered.append(hex_str)
                if verbose:
                    print(f"  [+] Nouveau secret #{len(ordered)} (ligne {lineno}): "
                          f"{hex_str[:16]}...", file=sys.stderr)
            else:
                if verbose:
                    print(f"  [dup] Ligne {lineno} → doublon du secret #{seen[hex_str] + 1}",
                          file=sys.stderr)

    return ordered


def reconstruct_ssl_keylog(secrets: list, client_random: str) -> list:
    """
    Génère les lignes au format NSS SSLKEYLOGFILE.
    Pas de conversion endian : les octets bruts sont les secrets réels.
    """
    lines = []
    for i, name in enumerate(SECRET_ORDER):
        if i < len(secrets):
            lines.append(f"{name} {client_random} {secrets[i]}")
        else:
            print(f"WARNING: secret #{i + 1} ({name}) absent du fichier de leaks",
                  file=sys.stderr)
    return lines


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Reconstruit ssl-key.log à partir des leaks "
            "(curl SChannel / bcryptprimitives.dll uniquement)"
        )
    )
    parser.add_argument(
        "-i", "--input",
        type=Path,
        default=Path("Data/log/backtrace_leaks.log"),
        help="Fichier backtrace_leaks.log (défaut: Data/log/backtrace_leaks.log)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("Data/decryption-key.log"),
        help="Fichier de sortie (défaut: Data/decryption-key.log)",
    )
    parser.add_argument(
        "-r", "--client-random",
        type=str,
        default=None,
        help="Client Random TLS (64 hex chars, depuis Wireshark ClientHello)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Affiche les détails de l'extraction",
    )

    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERREUR: {args.input} introuvable", file=sys.stderr)
        sys.exit(1)

    if args.client_random is None:
        args.client_random = "0" * 64
        print("AVERTISSEMENT: --client-random non fourni, utilisation d'un placeholder.",
              file=sys.stderr)
        print("  → Récupérer le Client Random dans Wireshark :",
              file=sys.stderr)
        print("    Filtre : tls.handshake.type == 1",
              file=sys.stderr)
        print("    TLS → Handshake Protocol: Client Hello → Random",
              file=sys.stderr)
    else:
        # Normalise les éventuels espaces / majuscules
        args.client_random = args.client_random.replace(" ", "").lower()
        if len(args.client_random) != 64:
            print(f"ERREUR: Client Random doit faire 64 caractères hex "
                  f"(reçu : {len(args.client_random)})", file=sys.stderr)
            sys.exit(1)

    # --- Extraction ---
    if args.verbose:
        print(f"Lecture de {args.input} ...", file=sys.stderr)

    secrets = extract_leaks(args.input, verbose=args.verbose)

    print(f"Secrets uniques extraits : {len(secrets)}")
    if len(secrets) < len(SECRET_ORDER):
        print(f"AVERTISSEMENT: attendu {len(SECRET_ORDER)} secrets, "
              f"seulement {len(secrets)} trouvés.", file=sys.stderr)

    # --- Reconstruction ---
    lines = reconstruct_ssl_keylog(secrets, args.client_random)

    # --- Écriture ---
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Fichier créé : {args.output}")

    if args.verbose:
        print("\n=== Secrets reconstruits (SChannel) ===")
        for line in lines:
            parts = line.split()
            print(f"  {parts[0]:40s}: {parts[2][:32]}...")
        print()
        print("Note : aucune conversion endian effectuée — les octets bruts "
              "sont les secrets réels.")


if __name__ == "__main__":
    main()
