# config_utils.py
import argparse
import configparser
import numpy as np
import subprocess
import logging
import os
import re

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Fonctions de configuration des tailles de registre
# -----------------------------------------------------------------------------
def get_register_size(reg_name: str) -> int:
    """
    Retourne la taille en octets pour un registre ou une zone MEMORY.
    Exemples :
      REG_RAX       → 8
      REG_XMM0      → 16
      REG_YMM3      → 32
      REG_ZMM7      → 64
      MEMORY8       → 8
      MEMORY32      → 32
    """
    if reg_name.startswith("REG_ZMM"):
        return 64
    if reg_name.startswith("REG_YMM"):
        return 32
    if reg_name.startswith("REG_XMM"):
        return 16
    if reg_name.startswith("REG_"):
        # tout autre REG_* (RAX, RBX, RIP…) → 8 octets
        return 8
    m = re.match(r"MEMORY(\d+)", reg_name)
    if m:
        return int(m.group(1))
    raise ValueError(f"Taille inconnue pour le registre/zone '{reg_name}'")

# -----------------------------------------------------------------------------
# Fonctions de configuration et d’entrée
# -----------------------------------------------------------------------------
def create_parser():
    parser = argparse.ArgumentParser(description="Analyse binaire d'un fichier de trace pour retrouver une séquence secrète.")
    parser.add_argument("-c", "--config-file", type=str, help="Chemin du fichier de configuration (config.ini)")
    parser.add_argument("-bf", "--binary-file", type=str, help="Chemin du fichier binaire")
    parser.add_argument("-k", "--key-file", type=str, help="Chemin du fichier contenat la clef")
    parser.add_argument("-cs", "--chunk-size", type=int, help="Taille des fragments (en octets)")
    parser.add_argument("-m", "--memory", type=int, help="Taille en mémoire à lire")
    parser.add_argument("-reg", "--registers", nargs="+", help="Liste des registres à analyser")
    parser.add_argument("-e", "--endianness", type=str, choices=["little", "big"], help="Choix de l'endianness (little ou big)")
    parser.add_argument("-co", "--command", nargs="+", help="Algorithme utilisé pour généré la clef")
    parser.add_argument("-p", "--pin-log", type=str, help="Chemin du fichier log Pin")
    parser.add_argument("-res", "--result-log", type=str, help="Chemin du fichier log result")
    parser.add_argument("-v", "--verbose", action="store_true", help="Activer les logs détaillés")
    parser.add_argument("-fm", "--filter-method", type=str, help="Mode de filtrage des candidats")
    parser.add_argument("-fo", "--filter-option", type=str, help="Option de filtrage (ex: adresse cible)")

    return parser

def load_config_file(config_path):
    """
    Lit un INI et renvoie un dict des valeurs utiles
    (GENERAL, INPUT FILES, OUTPUT FILES).
    """
    config_values = {}
    if config_path and os.path.exists(config_path):
        config = configparser.ConfigParser(interpolation=None)
        config.read(config_path)

        if "GENERAL" in config:
            general = config["GENERAL"]
            config_values["chunk_size"] = general.getint("CHUNK_SIZE", fallback=None)
            config_values["registers"] = general.get("REGISTERS", None)
            config_values["memory"] = general.get("MEMORY", None)
            config_values["endianness"] = general.get("ENDIANNESS", fallback="little")
            config_values["command"] = general.get("COMMAND", None)
            config_values["verbose"] = general.getboolean("VERBOSE", fallback=False)

        if "FILTERS" in config:
            filters = config["FILTERS"]
            config_values["filter_function"] = filters.get("FILTER_FUNCTION", None)
            config_values["filter_method"] = filters.get("FILTER_METHOD", fallback="min_fragments")
            config_values["filter_option"] = filters.get("FILTER_OPTION", None)

        if "INPUT FILES" in config:
            input_files = config["INPUT FILES"]
            config_values["binary_file"] = input_files.get("BINARY_FILE", None)
            config_values["pin_log"] = input_files.get("PIN_LOG", None)
            config_values["key_file"] = input_files.get("KEY_FILE", None)

        if "OUTPUT FILES" in config:
            output_files = config["OUTPUT FILES"]
            config_values["result_log"] = output_files.get("RESULT_LOG", None)

        logger.info("Fichier de configuration chargé avec succès.")
    return config_values

def merge_args_with_config(args, config_values):
    """
    Combine args CLI et cfg INI, avec priorité CLI.
    Remplit les valeurs par défaut si nécessaire.
    """
    return argparse.Namespace(
        binary_file=args.binary_file        or config_values.get("binary_file"),
        chunk_size=args.chunk_size          or config_values.get("chunk_size") or 8,
        registers=args.registers            or (config_values.get("registers").split() if config_values.get("registers") else None),
        memory=args.memory                  or config_values.get("memory") or 0,
        endianness=args.endianness          or config_values.get("endianness", "little"),
        command=args.command                or config_values.get("command"),
        key_file=args.key_file              or config_values.get("key_file"),
        pin_log=args.pin_log                or config_values.get("pin_log") or "data/log/trace.log",
        result_log=args.result_log          or config_values.get("result_log") or "data/log/analyse.log",
        verbose=args.verbose                or config_values.get("verbose", False),
        filter_method=args.filter_method    or config_values.get("filter_method") or "min_fragments",
        filter_option=args.filter_option    or config_values.get("filter_option"),
        config_file=args.config_file
    )

def parse_arguments():
    parser = create_parser()
    args, _ = parser.parse_known_args()
    config_values = load_config_file(args.config_file)
    final_args = merge_args_with_config(args, config_values)

    if not final_args.binary_file or not final_args.registers or not final_args.key_file:
        parser.error("Les arguments 'binary-file', 'registers' et 'key-file' sont obligatoires (via config ou CLI).")

    if final_args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Mode DEBUG activé")

    logger.debug("Paramètres finaux fusionnés :")
    logger.debug(f"    binary_file : {final_args.binary_file}")
    logger.debug(f"    chunk_size  : {final_args.chunk_size}")
    logger.debug(f"    registers   : {final_args.registers}")
    logger.debug(f"    memory      : {final_args.memory}")
    logger.debug(f"    command     : {final_args.command}")
    logger.debug(f"    key_file    : {final_args.key_file}")
    logger.debug(f"    pin_log     : {final_args.pin_log}")
    logger.debug(f"    result_log  : {final_args.result_log}")
    logger.debug(f"    verbose     : {final_args.verbose}")
    logger.debug(f"    filter_method : {final_args.filter_method}")
    logger.debug(f"    filter_option : {final_args.filter_option}")

    return final_args


# -----------------------------------------------------------------------------
# Fonctions d'initialisation
# -----------------------------------------------------------------------------
def init_registers(register_in_args, memory_size):
    register_list = register_in_args
    if memory_size == 8:
        register_list.append("MEMORY8")
    elif memory_size == 16:
        register_list.append("MEMORY16")
    elif memory_size == 32:
        register_list.append("MEMORY32")
    elif memory_size == 64:
        register_list.append("MEMORY64")

    return register_list


def init_secret(cmd, endianness, chunk_size=8):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"[init_secret] Erreur dans la commande : {e.stderr.decode()}")
        return None

    raw_output = result.stdout

    # Cas 1 : sortie texte hexadécimale (ex : via xxd ou hexdump)
    try:
        decoded = raw_output.decode().strip()
        # Enlève tous les caractères non-hex (espace, \n, :)
        hex_str = re.sub(r'[^0-9A-Fa-f]', '', decoded)
        if len(hex_str) % 2 == 0 and len(hex_str) >= 32:
            secret_bytes = bytes.fromhex(hex_str)
            logger.debug("[init_secret] Interprété comme chaîne hexadécimale.")
        else:
            raise ValueError("Pas une chaîne hex valide.")
    except Exception:
        # Cas 2 : sortie binaire brute (ex : openssl pkeyutl -derive)
        secret_bytes = raw_output
        logger.debug("[init_secret] Interprété comme binaire brut.")

    secret_array = np.frombuffer(secret_bytes, dtype=np.ubyte)

    # Le secret SSL est en big endian (format standard crypto)
    # La trace x86 est en little endian
    # Si l'utilisateur spécifie "little", on convertit le secret de big vers little endian
    if endianness == "little":
        # Inverser chaque chunk pour convertir de big endian vers little endian (format trace x86)
        remainder = len(secret_array) % chunk_size
        if remainder != 0:
            padding = chunk_size - remainder
            secret_array = np.pad(secret_array, (0, padding), mode='constant', constant_values=0)
        secret_array = secret_array.reshape(-1, chunk_size)
        secret_array = np.flip(secret_array, axis=1)
        secret_array = secret_array.flatten()

    logger.debug(f"[init_secret] Secret final ({len(secret_array)} octets):\n {secret_array}")

    return np.ascontiguousarray(secret_array)

def init_const(args):
    binary_file_path = args.binary_file
    pinlog_file_path = args.pin_log
    key_file_path = args.key_file
    result_log_path = args.result_log
    chunk_size = args.chunk_size
    register_list = args.registers
    memory_size = int(args.memory)
    register_list = init_registers(args.registers,memory_size)
    nb_registers = len(register_list)
    endian = args.endianness
    cmd = args.command
    filter_method = args.filter_method
    filter_option = args.filter_option

    logger.debug("Variables globales initialisées :")
    logger.debug(f"    binary_file_path : {binary_file_path}")
    logger.debug(f"    pinlog_file_path : {pinlog_file_path}")
    logger.debug(f"    result_log_path  : {result_log_path}")
    logger.debug(f"    chunk_size       : {chunk_size}")
    logger.debug(f"    register_list    : {register_list}")
    logger.debug(f"    nb_registers     : {nb_registers}")
    logger.debug(f"    memory_size      : {memory_size}")
    logger.debug(f"    CMD              : {cmd}")
    logger.debug(f"    endian           : {endian}")
    logger.debug(f"    filter_method    : {filter_method}")
    logger.debug(f"    filter_option    : {filter_option}")
    logger.info("Chargement des paramètres globaux effectué avec succès.")

    return binary_file_path, pinlog_file_path, key_file_path, result_log_path, chunk_size, register_list,endian, cmd, filter_method, filter_option
