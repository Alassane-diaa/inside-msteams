# candidates.py
import re
import itertools
import logging

from .config_utils import get_register_size
from .filters import filter_candidates

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Regroupement et dictionnaire des candidats
# -----------------------------------------------------------------------------

def insert_in_map(d, k, v):
    if k not in d:
        d[k] = list()
    if v not in d[k]:
        d[k].append(v)

def group_mem_frags(candidates, chunk_size, target_size, base_chunck_size = -1, reg_name : str = "MEMORY"):
    """
    Regroupe récursivement les fragments MEMORY de taille `chunk_size`
    en fragments de taille doublée, jusqu'à atteindre `target_size`.
    - candidates : dict[(rip, reg)] = [(idx_secret, ligne), ...]
    - chunk_size : taille des morceaux actuels (en octets)
    - target_size: taille finale désirée (en octets)
    """
    # Si on atteint la taille cible, alors
    # on ne peut plus grouper de fragments
    # for k in sorted(candidates):
    #     print(f"key = {hex(k[0]), k[1]}, val = {candidates[k]}")
    if chunk_size > target_size:
        return candidates

    if reg_name == "MEMORY":
        reg_name = f"MEMORY{target_size}"
    if base_chunck_size == -1:
        base_chunck_size = chunk_size

    new_candidates = candidates.copy()

    # On récupère tous les candidats dans MEMORY
    keys = [(rip, reg) for (rip, reg) in candidates if reg.startswith(f"{reg_name}[")]

    # Pour chaque paire de candidats MEMORY, on essaye de fusionner 
    # les paires adjacents
    for rip, group in itertools.groupby(sorted(keys), key=lambda x: x[0]):
        regs = [reg for (_rip, reg) in group]
        regs.sort(key=lambda r: int(r[r.find('[') + 1:r.find(',')]))

        for i, reg1 in enumerate(regs):
            start1, end1 = map(int, re.findall(r"\[(\d+),(\d+)\]", reg1)[0])
            for reg2 in regs[i+1:]:
                start2, end2 = map(int, re.findall(r"\[(\d+),(\d+)\]", reg2)[0])
                if start2 == end1 and ((start1 + chunk_size) == end1 or (start2 + chunk_size) == end2):
                    # Si oui, on construit le nouveau candidat
                    new_reg = f"{reg_name}[{start1},{end2}]"
                    key1 = (rip, reg1)
                    key2 = (rip, reg2)

                    for frag1, line1 in candidates[key1]:
                            for frag2, line2 in candidates[key2]:
                                if line1 == line2:
                                    # On ne garde ques les lignes identiques
                                    insert_in_map(new_candidates,(rip,new_reg), (frag1,line1))
                                    insert_in_map(new_candidates,(rip,new_reg), (frag2,line2))

    return group_mem_frags(new_candidates, chunk_size + base_chunck_size, target_size, base_chunck_size = base_chunck_size)

def indices_to_dict_OBG(quadruplets, register_list : list[str], chunk_size):
    """
    Transforme la liste de quadruplets en dictionnaire :
    clé = (RIP, registre) → liste de (index_frag_secret, ligne).
    """
    OBG = dict()
    for rip, reg, frags_num, line in quadruplets:
        insert_in_map(OBG,(rip,reg), (frags_num,line))
    
    logger.debug(f"Dictionnaire de candidats construit avec {len(OBG)} clés :")
    #logger.debug("\n" + pprint.pformat(OBG))
    #print(f"register_list = {register_list}")
    for register in register_list: 

        if get_register_size(register) > chunk_size:  # Vérifie si l'élément correspond au motif MEMORY suivi d'un chiffre
            mem_size = get_register_size(register)  # Extrait la taille mémoire
            OBG = group_mem_frags(OBG, chunk_size, mem_size)
    
    logger.debug(f"Nouveau dictionnaire de candidats construit avec {len(OBG)} clés :")
    #logger.debug("\n" + pprint.pformat(OBG))
    return OBG

# -----------------------------------------------------------------------------
# Recherche de candidats
# -----------------------------------------------------------------------------

def find_candidates(candidates,secret, chunk_size, filter_method, filter_option=None, pinlog_file_path = None):
    """
    Lance le filtrage des candidats et renvoie un dictionnaire.
    Si aucun candidat n'est trouvé, retourne un dict vide et logguer un avertissement.
    """
    result = filter_candidates(candidates, secret, chunk_size, filter_method, filter_option, pinlog_file_path = pinlog_file_path)
    if not result:
        logger.warning("Aucun candidat trouvé avec la méthode '%s'", filter_method)
        return None
    
    # J'affiche le candidat
    # logger.info(f"(RIP, Registre) : {list(result.keys())}, Fragments: {list(result.values())}")
    return result
