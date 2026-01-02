# modules/constants.py
import numpy as np

# -----------------------------------------------------------------------------
# Constantes
# -----------------------------------------------------------------------------
# Pour convertir un nombre d’octets en type numpy
SIZE_TO_TYPE = {
    4: np.uint32,
    8: np.uint64
}