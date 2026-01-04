import numpy as np
import logging
import sys
import re

from modules.candidates import find_candidates, indices_to_dict_OBG
from modules.config_utils import parse_arguments, init_const, init_secret
from modules.io_utils import load_binary_trace, parse_loaded_libraries, locate_library
from modules.trace_analysis import built_quadruple

# -----------------------------------------------------------------------------
# Préparation du logger (structure seulement, le niveau sera ajusté plus tard)
# -----------------------------------------------------------------------------

RESET       = "\x1b[0m"
COLOR_DEBUG = "\x1b[36m"
COLOR_INFO  = "\x1b[32m"
COLOR_WARN  = "\x1b[33m"
COLOR_ERROR = "\x1b[31m"
COLOR_CRIT  = "\x1b[41m"

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        color = {
            logging.DEBUG: COLOR_DEBUG,
            logging.INFO: COLOR_INFO,
            logging.WARNING: COLOR_WARN,
            logging.ERROR: COLOR_ERROR,
            logging.CRITICAL: COLOR_CRIT
        }.get(record.levelno, RESET)
        record.levelname = f"{color}{record.levelname}{RESET}"
        return super().format(record)

# Handlers
console_handler = logging.StreamHandler(sys.stdout)
console_formatter = ColoredFormatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler.setFormatter(console_formatter)

file_handler = logging.FileHandler("data/log/debug.log", mode="w", encoding="utf-8")
file_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(file_formatter)

# Logger principal
root_logger = logging.getLogger()
root_logger.handlers.clear()
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Fonction principale
# -----------------------------------------------------------------------------

def main():
    args = parse_arguments()

    # 🔧 Configuration dynamique du niveau de log
    if args.verbose:
        root_logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
        file_handler.setLevel(logging.DEBUG)
        logger.debug("Mode DEBUG activé")
    else:
        root_logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)
        file_handler.setLevel(logging.INFO)

    # Initialisation des constantes
    binary_file_path, pinlog_file_path, _, result_log_path, chunk_size, register_list, endian, cmd, filter_method, filter_option = init_const(args)
    
    # This is to make sure that REG_RIp is in the register_list and in the first position, even if it needs to be added
    if "REG_RIP" in register_list and register_list[0] != "REG_RIP":
        register_list.remove("REG_RIP")
        register_list = ["REG_RIP"] + register_list
    elif not "REG_RIP" in register_list:
        register_list = ["REG_RIP"] + register_list

    secret = init_secret(cmd, endian)
    logger.debug(f"[MAIN] Secret ({len(secret)} o):\n {secret}")

    logger.info(f"Analyse du fichier {binary_file_path}...")
    trace = load_binary_trace(binary_file_path, register_list)

    quadruplets = []
    for i, chunk in enumerate(trace):
        logger.debug(f"[MAIN] Traitement du chunk {i}")
        quads = built_quadruple(chunk, secret, register_list, chunk_size)
        quadruplets.extend(quads)
    
    OBG = indices_to_dict_OBG(quadruplets, register_list, chunk_size)
    best_candidate = find_candidates(OBG, secret, chunk_size, filter_method, filter_option, pinlog_file_path = pinlog_file_path)

    if best_candidate and best_candidate[0]:
        (rip, reg), frags = best_candidate
        lib_name, delta = locate_library(rip, parse_loaded_libraries(pinlog_file_path))
        print("")
        logger.info(f"Candidat retenu:")
        logger.info(f"RIP: {hex(rip)}, Registre: {reg}, \nFragments: {frags}")
        logger.info(f"--> Lib: {lib_name}, Delta: {delta}")

        with open(result_log_path, "a") as file:
            reg_name = re.match(r"^[^\[]+", reg).group(0)
            file.write(f"Reg: {reg_name} Lib: {lib_name} Delta: {delta}\n")
    else:
        logger.warning("Aucun candidat valide trouvé.")

    print()
    logger.info(f"Analyse terminée. Données écrites dans {result_log_path}")


if __name__ == "__main__":
    main()
