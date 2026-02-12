# modules/filter_modes.py
import logging
from typing import Dict, Tuple, List

from .constants import SIZE_TO_TYPE
from .io_utils import locate_library, parse_loaded_libraries

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Helpers de parsing d'options de filtrage
# -----------------------------------------------------------------------------

def parse_reg_priority(option: str) -> Dict[str, int]:
    """
    Extrait un dict {registre: score} depuis une chaîne "R1:1,R2:5,...".
    """
    d: Dict[str, int] = {}
    if not option:
        return d
    for pair in option.split(','):
        pair = pair.strip()
        if not pair:
            continue
        if ':' in pair:
            reg, score = pair.split(':', 1)
            try:
                d[reg.strip()] = int(score.strip(), 0)
            except ValueError:
                logger.warning(f"Impossible de parser le score pour '{pair}'")
    return d


def parse_target_addr(option: str) -> int:
    """
    Convertit une chaîne hexadécimale ou décimale en int.
    """
    if not option:
        return 0
    try:
        return int(option, 0)
    except ValueError:
        logger.warning(f"Option d'adresse invalide : '{option}'")
        return 0

# -----------------------------------------------------------------------------
# Méthodes de filtrage des candidats
# -----------------------------------------------------------------------------

def filter_min_fragments(candidates, secret, chunk_size, pinlog_file_path = None):
    """
    Choisit parmi les candidats celui couvrant tous les fragments
    du secret avec le moins de redondance (critère de taille).
    """
    best = (None, None, float('inf'))
    required_indices = set(range(len(secret.view(SIZE_TO_TYPE[chunk_size])))) # Ensemble des indices attendus pour couvrir le secret

    logger.debug(f"{len(required_indices)} fragments à couvrir")

    for (rip, reg), values in candidates.items():
        indices = {i for i, _ in values}
        if not required_indices.issubset(indices):
            # Si le candidat n'a pas tous les fragment contenus dans le secret, on l'ignore
            continue

        fragment_count = len(values)
        #logger.info(f"Bon candidat : ({rip}, {reg}) : {values}")
        if pinlog_file_path != None:
            lib_name, delta = locate_library(rip, parse_loaded_libraries(pinlog_file_path))
            if lib_name != None:
                logger.info(f"Bon candidat : ({hex(rip)}, {reg}), lib : {lib_name}, delta : {hex(delta)}")
            else:
                logger.info(f"Bon candidat : ({hex(rip)}, {reg})")
        else:
            logger.info(f"Bon candidat : ({hex(rip)}, {reg})")

        if fragment_count < best[2]:
            best = ((rip, reg), values, fragment_count)

    return best[0], best[1]

def filter_max_fragments(candidates, secret, chunk_size, pinlog_file_path = None):
    """
    Choisit parmi les candidats celui couvrant tous les fragments
    du secret avec le plus de redondance (critère de taille).
    """
    best = (None, None, 0)
    required_indices = set(range(len(secret.view(SIZE_TO_TYPE[chunk_size])))) # Ensemble des indices attendus pour couvrir le secret

    logger.debug(f"{len(required_indices)} fragments à couvrir")

    for (rip, reg), values in candidates.items():
        indices = {i for i, _ in values}
        if not required_indices.issubset(indices):
            # Si le candidat n'a pas tous les fragment contenus dans le secret, on l'ignore
            continue

        fragment_count = len(values)
        #logger.info(f"Bon candidat : ({rip}, {reg}) : {values}")
        if pinlog_file_path != None:
            lib_name, delta = locate_library(rip, parse_loaded_libraries(pinlog_file_path))
            logger.info(f"Bon candidat : ({hex(rip)}, {reg}), lib : {lib_name}, delta : {hex(delta)}")
        else:
            logger.info(f"Bon candidat : ({hex(rip)}, {reg})")

        if fragment_count > best[2]:
            best = ((rip, reg), values, fragment_count)

    return best[0], best[1]

def filter_max_contiguous(candidates, secret, chunk_size, pinlog_file_path = None):
    """
    Choisit parmi les candidats celui couvrant tous les fragments
    et ayant le plus de fragments contigus
    """
    best = (None, None, -1)

    required_indices = set(range(len(secret.view(SIZE_TO_TYPE[chunk_size])))) # Ensemble des indices attendus pour couvrir le secret

    for (rip, reg), values in candidates.items():
        frags = [i for i, _ in values]
        lines  = [l for _, l in values]

        if not required_indices.issubset(frags):
            # Si le candidat n'a pas tous les fragment contenus dans le secret, on l'ignore
            continue

        max_current = 1
        current = 1
        for a, b in zip(frags, frags[1:]):
            if b == a + 1:
                current += 1
                max_current = max(max_current, current)
            else:
                current = 1

        if max_current > best[2]:
            best = ((rip, reg), values, max_current)

    return best[0], best[1]

def filter_by_register_priority(candidates, secret, chunk_size, reg_priority:Dict[str, int], pinlog_file_path = None):
    best = (None, None, float('inf'))

    required_indices = set(range(len(secret.view(SIZE_TO_TYPE[chunk_size])))) # Ensemble des indices attendus pour couvrir le secret

    for (rip, reg), values in candidates.items():
        sorted_pairs = sorted(values, key=lambda p: p[0])
        frags = [i for i, _ in sorted_pairs]

        if not required_indices.issubset(frags):
            # Si le candidat n'a pas tous les fragment contenus dans le secret, on l'ignore
            continue

        score = reg_priority.get(reg, 100)

        if score < best[2]:
            best = ((rip,reg), values, score)

    return best[0], best[1]

def filter_closest_address(candidates, secret, chunk_size, target_addr, pinlog_file_path = None):
    best = (None, None, float('inf'))

    required_indices = set(range(len(secret.view(SIZE_TO_TYPE[chunk_size])))) # Ensemble des indices attendus pour couvrir le secret

    for (rip, reg), values in candidates.items():
        sorted_pairs = sorted(values, key=lambda p: p[0])
        frags = [i for i, _ in sorted_pairs]

        if not required_indices.issubset(frags):
            # Si le candidat n'a pas tous les fragment contenus dans le secret, on l'ignore
            continue

        dist = abs(rip - target_addr)
        if dist < best[2]:
            best = ((rip,reg), values, dist)

    return best[0], best[1]

def filter_min_pattern(candidates, secret, chunk_size, pinlog_file_path = None):
    best = (None, None, float('inf'))
    min_dist = float('inf')

    required_indices = set(range(len(secret.view(SIZE_TO_TYPE[chunk_size])))) # Ensemble des indices attendus pour couvrir le secret

    for (rip, reg), values in candidates.items():
        sorted_pairs = sorted(values, key=lambda p: p[0])
        frags = [i for i, _ in sorted_pairs]
        lines  = [l for _, l in sorted_pairs]

        print(lines)

        if not required_indices.issubset(frags):
            # Si le candidat n'a pas tous les fragment contenus dans le secret, on l'ignore
            continue

        line1 = min(lines)
        line2 = max(lines)
        dist = abs(line2 - line1)

        if dist < min_dist:
            min_dist = dist
            best = ((rip, reg), values, dist)
        
    return best[0], best[1]

def filter_first_completion(candidates, secret, chunk_size, pinlog_file_path = None):
    """
    Choisit le candidat dont la couverture complète du secret apparaît
    le plus tôt (ligne minimale du dernier fragment requis).
    """
    best = (None, None, float('inf'))
    required_indices = set(range(len(secret.view(SIZE_TO_TYPE[chunk_size]))))

    for (rip, reg), values in candidates.items():
        # Tri par index de fragment pour respecter l'ordre
        sorted_pairs = sorted(values, key=lambda p: p[0])
        frags = [i for i, _ in sorted_pairs]
        lines = [l for _, l in sorted_pairs]

        # On n'étudie que les candidats couvrant tous les fragments
        if not required_indices.issubset(frags):
            continue

        # La complétion effective a lieu à la ligne max(lines)
        completion_line = max(lines)
        if completion_line < best[2]:
            best = ((rip, reg), values, completion_line)

        logger.info(f"Candidat ({hex(rip)}, {reg}) complété à la ligne {completion_line}")

    return best[0], best[1]

def filter_partial(candidates, secret, chunk_size, min_chunks=1, pinlog_file_path=None):
    """
    Retourne tous les candidats ayant au moins min_chunks fragments du secret.
    Trie par nombre de fragments décroissant.
    """
    required_count = len(secret) // chunk_size
    results = []

    for (rip, reg), values in candidates.items():
        indices = {i for i, _ in values}
        count = len(indices)
        
        if count >= min_chunks:
            if pinlog_file_path:
                lib_name, delta = locate_library(rip, parse_loaded_libraries(pinlog_file_path))
                if lib_name:
                    logger.info(f"Candidat partiel : ({hex(rip)}, {reg}), {count}/{required_count} fragments, lib: {lib_name}, delta: {hex(delta)}")
                else:
                    logger.info(f"Candidat partiel : ({hex(rip)}, {reg}), {count}/{required_count} fragments")
            else:
                logger.info(f"Candidat partiel : ({hex(rip)}, {reg}), {count}/{required_count} fragments")
            results.append(((rip, reg), values, count))
    
    if not results:
        return None, None
    
    # Trier par nombre de fragments décroissant et retourner le meilleur
    results.sort(key=lambda x: x[2], reverse=True)
    best = results[0]
    return best[0], best[1]

# -----------------------------------------------------------------------------
# Mapping des différentes méthodes de filtrage des candidats
# -----------------------------------------------------------------------------
MODES = {
    "min_fragments":        filter_min_fragments,
    "max_fragments":        filter_max_fragments,
    "max_contiguous":       filter_max_contiguous,
    "reg_priority":         filter_by_register_priority,
    "closest_address":      filter_closest_address,
    "min_pattern":          filter_min_pattern,
    "first_completion":     filter_first_completion,
    "partial":              filter_partial,
}

def get_filter(mode: str):
    if mode not in MODES:
        raise ValueError(f"Mode inconnu : {mode}")
    return MODES[mode]

# -----------------------------------------------------------------------------
# Fonction principale de filtrage des candidats
# -----------------------------------------------------------------------------

def filter_candidates(candidates, secret, chunk_size, filter_method, filter_option=None, pinlog_file_path = None):
    print(filter_method)
    filter_func = get_filter(filter_method)

    if filter_method == "reg_priority":
        reg_pri = parse_reg_priority(filter_option or "")
        return filter_func(candidates, secret, chunk_size, reg_pri, pinlog_file_path = pinlog_file_path)
    elif filter_method == "closest_address":
        addr = parse_target_addr(filter_option or "0")
        return filter_func(candidates, secret, chunk_size, addr, pinlog_file_path = pinlog_file_path)
    elif filter_method == "partial":
        min_chunks = int(filter_option) if filter_option else 1
        return filter_func(candidates, secret, chunk_size, min_chunks, pinlog_file_path = pinlog_file_path)
    else:
        return filter_func(candidates, secret, chunk_size, pinlog_file_path = pinlog_file_path)
