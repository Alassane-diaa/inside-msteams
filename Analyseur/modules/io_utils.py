# io_utils.py
import numpy as np
import logging
import os
import sys
import re

from .config_utils import get_register_size

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Lecture et transformation de la trace binaire
# -----------------------------------------------------------------------------

def load_binary_trace(file_path, register_list, size=1024):
    """
    Lit un fichier binaire et renvoie un array numpy d’octets non signés.
    En cas d’erreur ou de fichier vide, termine le programme.
    """
    total_bytes = sum(get_register_size(r) for r in register_list)
    logger.debug(f"[BQ] Taille totale des registres : {total_bytes} octets")

    file_size = os.path.getsize(file_path)
    frag_size = size * total_bytes
    logger.debug(f"[BQ] Taille du fichier : {file_size} octets")
    logger.debug(f"[BQ] Taille des fragments (chunk) : {frag_size} octets")

    mm = np.memmap(file_path, dtype=np.ubyte, mode='r')
    num_chunks = len(mm) // frag_size
    logger.info(f"[BQ] Nombre de chunks disponibles : {num_chunks}")

    for i in range(0, len(mm), frag_size):
        yield mm[i:i+frag_size]

# -----------------------------------------------------------------------------
# Gestion des bibliothèques
# -----------------------------------------------------------------------------

def parse_loaded_libraries(logfile="Data/log/trace.log"):
    """
    Parse un log Pin pour extraire les modules chargés.
    Retourne [(nom_module, adresse_base), ...].
    """
    libs =[]
    with open(logfile, encoding='utf-8') as f:
        for line in f:
            match = re.match(rf"Module chargé\s*:\s*(.+?)\s+Adresse de base\s*:\s*(0x[0-9a-fA-F]+)", line)
            if match:
                lib_name = match.group(1)
                base_addr = int(match.group(2), 16)
                libs.append((lib_name,base_addr))
                logger.debug(f"[recover_lib] Module chargé: {lib_name}, 0x{base_addr:016x}")
    return libs

def locate_library(address, libs):
    """
    Pour une adresse donnée, retourne la bibliothèque la plus proche
    en base et le décalage (delta).
    """
    closest_lib = (None, float('inf'))
    for name, base in libs:
        delta = int(address) - int(base)
        if 0 <= delta < closest_lib[1]:
            closest_lib = (name, delta)
    return closest_lib   