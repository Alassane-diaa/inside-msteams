# trace_analysis.py
import numpy as np
import logging
import pprint

from .config_utils import get_register_size
from .constants import SIZE_TO_TYPE

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Recherche des fragments correspondant au secret
# -----------------------------------------------------------------------------

def find_matching_fragments(trace, secrets, common_type):
    """
    Trouve les fragments communs (i1, i2) tels que trace[i1] == secret[i2].
    """

    trace_chunks = trace.view(common_type)
    secret_chunks = secrets.view(common_type)

    match_matrix = trace_chunks[:,np.newaxis] == secret_chunks
    matching_indices = np.argwhere(match_matrix).astype(common_type)

    logger.debug("[FMF] Indices communs :\n" + pprint.pformat(matching_indices))

    return trace_chunks, matching_indices

def built_quadruple(trace, secrets, register_list, chunk_size):
    """
    Construit les quadruplets sous la forme (adress, registre, frag, ligne)
    """

    # Détermination du type commun
    common_type = SIZE_TO_TYPE[chunk_size]
    logger.debug(f"[BQ] Type commun : {common_type}")

    # Construction des indices communs
    t8, matching_indices = find_matching_fragments(trace, secrets, common_type)

    # Calcul de la taille (en chunks) du fragment complet
    total_bytes = sum(get_register_size(r) for r in register_list)
    frag_size = total_bytes // chunk_size
    logger.debug(f"[BQ] frag size : {frag_size}")

    position2register = dict()
    position = 0
    for r in register_list:
        size = get_register_size(r)
        for offset in range(0, size, chunk_size):
            position2register[position] = f"{r}[{offset},{offset+chunk_size}]"
            position += 1

    logger.debug("[BQ] position2register : \n" + pprint.pformat(position2register))

    results = []
    for trace_index, secret_index in matching_indices:
        reg_index = trace_index % frag_size
        reg_name = position2register[reg_index]
        # print(f"trace_index = {trace_index}, reg_name = {reg_name}, reg_index = {reg_index}")
        address = t8[trace_index - reg_index]
        results.append((int(address), reg_name, int(secret_index), int(trace_index // frag_size)*1024))
    logger.debug(f"{len(results)} fragments communs trouvés")

    logger.debug("[BQ]\n" + pprint.pformat(results))

    return results
