#!/usr/bin/env python3
"""
Analyse tous les candidats pour trouver le meilleur point d'instrumentation.
Compare les candidats par:
- Nombre de fragments du secret couverts
- Nombre total de hits (moins = moins de faux positifs)
- Bibliothèque source (libssl vs libcrypto)
"""

import sys
sys.path.insert(0, 'Analyseur')

import numpy as np
from modules.config_utils import init_secret
from modules.trace_analysis import built_quadruple
from modules.io_utils import load_binary_trace, parse_loaded_libraries, locate_library
from modules.candidates import indices_to_dict_OBG
from collections import defaultdict

def main():
    # Config
    register_list = ['REG_RIP', 'REG_RAX', 'REG_RSI', 'REG_RDI', 'MEMORY32']
    chunk_size = 8

    # Secret (6 fragments de 8 bytes = 48 bytes)
    secret = init_secret('type data\\key.log', 'little', chunk_size)
    num_frags = len(secret) // chunk_size
    print(f'Secret: {len(secret)} bytes = {num_frags} fragments')

    # Charger les libs
    libs = parse_loaded_libraries('data/log/trace.log')

    # Charger la trace
    print('Chargement de la trace...')
    trace = load_binary_trace('data/log/trace.binary', register_list)

    # Analyser
    print('Analyse des quadruplets...')
    quadruplets = []
    for i, chunk in enumerate(trace):
        quads = built_quadruple(chunk, secret, register_list, chunk_size)
        quadruplets.extend(quads)
        if i % 10000 == 0 and i > 0:
            print(f'  Chunk {i}... ({len(quadruplets)} quads)')

    print(f'Total quadruplets: {len(quadruplets)}')

    # Construire OBG
    OBG = indices_to_dict_OBG(quadruplets, register_list, chunk_size)
    print(f'Candidats uniques (RIP, reg): {len(OBG)}')

    # Compter les fragments par candidat
    stats = []
    for (rip, reg), values in OBG.items():
        frags = set(i for i, _ in values)
        lib_name, delta = locate_library(rip, libs)
        lib_short = lib_name.split('\\')[-1] if lib_name else 'unknown'
        stats.append({
            'rip': rip,
            'reg': reg,
            'lib': lib_short,
            'delta': delta,
            'frag_count': len(frags),
            'total_hits': len(values),
            'frags': sorted(frags)
        })

    # Trier par nombre de fragments (décroissant) puis par hits (croissant = moins de bruit)
    stats.sort(key=lambda x: (-x['frag_count'], x['total_hits']))

    print(f'\n{"="*80}')
    print(f'=== Top 30 candidats (par couverture du secret) ===')
    print(f'{"="*80}')
    print(f'Frags  Hits   Delta        Lib                         Reg')
    print('-' * 80)
    for s in stats[:30]:
        print(f"{s['frag_count']}/{num_frags}    {s['total_hits']:4d}   0x{s['delta']:08x}   {s['lib'][:27]:27}   {s['reg']}")

    # Chercher les candidats dans libssl (pas libcrypto)
    print(f'\n{"="*80}')
    print(f'=== Candidats dans libssl (plus specifiques TLS) ===')
    print(f'{"="*80}')
    ssl_stats = [s for s in stats if 'libssl' in s['lib'].lower()]
    if ssl_stats:
        for s in ssl_stats[:15]:
            print(f"{s['frag_count']}/{num_frags}    {s['total_hits']:4d}   0x{s['delta']:08x}   {s['lib'][:27]:27}   {s['reg']}")
    else:
        print('Aucun candidat dans libssl')

    # Candidats avec couverture complete et peu de hits
    print(f'\n{"="*80}')
    print(f'=== Candidats complets ({num_frags}/{num_frags}) avec le moins de hits ===')
    print(f'{"="*80}')
    complete = [s for s in stats if s['frag_count'] == num_frags]
    complete.sort(key=lambda x: x['total_hits'])
    if complete:
        for s in complete[:10]:
            print(f"Hits: {s['total_hits']:4d}   Delta: 0x{s['delta']:08x}   {s['lib'][:30]}   {s['reg']}")
    else:
        print(f'Aucun candidat avec {num_frags}/{num_frags} fragments')
        # Montrer les meilleurs partiels
        print(f'\nMeilleurs partiels:')
        for s in stats[:5]:
            print(f"Frags: {s['frag_count']}/{num_frags}  Hits: {s['total_hits']:4d}   Delta: 0x{s['delta']:08x}   {s['lib']}")

    # Sauvegarder les stats
    with open('data/log/candidates_analysis.log', 'w') as f:
        f.write(f'# Analyse des candidats\n')
        f.write(f'# Secret: {len(secret)} bytes = {num_frags} fragments\n')
        f.write(f'# Total candidats: {len(stats)}\n\n')
        for s in stats:
            f.write(f"Frags={s['frag_count']}/{num_frags} Hits={s['total_hits']} Delta=0x{s['delta']:x} Lib={s['lib']} Reg={s['reg']}\n")
    print(f'\nStats sauvegardées dans data/log/candidates_analysis.log')

if __name__ == '__main__':
    main()
