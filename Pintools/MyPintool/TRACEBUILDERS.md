# TraceBuilder : Fonctionnement et Variantes

## 1. TraceBuilder.cpp — Version originale

### Principe

Le TraceBuilder original instrumente **chaque instruction** exécutée par le programme cible (hors instructions de contrôle de flux et fonctions/bibliothèques filtrées). Pour chaque instruction, il enregistre dans un fichier binaire (`trace.binary`) :

| Champ | Taille | Contenu |
|-------|--------|---------|
| RIP (adresse de l'instruction) | 8 octets | `uint64_t` |
| Registres configurés | variable | RAX, RSI, RDI… (8 o chacun), XMM (16 o), YMM (32 o), ZMM (64 o) |
| Zone mémoire lue | 0, 8, 16, 32 ou 64 octets | Contenu pointé par le 1er opérande mémoire en lecture, ou zéros |

### Flux d'exécution

```
main()
  ├── Lit pin_config.ini  →  registres, taille mémoire, filtres
  ├── Ouvre trace.binary + trace.log
  └── PIN_StartProgram()
        │
        ├── ImageLoad()           →  log chaque DLL chargée
        │
        └── Instructions(ins)     →  pour CHAQUE instruction du programme :
              ├── Vérifie filtres (whitelist/blacklist, fonctions)
              ├── Ignore les instructions de contrôle de flux
              └── Insère record_fragment() ou record_register()
                    → écrit [RIP | registres | mémoire] dans trace.binary
```

### Problème

Toute instruction non filtrée est tracée → **la trace peut devenir énorme** (plusieurs Go) si le programme exécute beaucoup d'instructions avant/après la partie TLS intéressante.

---

## 2. TraceBuilder_Delayed.cpp — Traçage différé par fenêtre d'instructions

### Objectif

Réduire la trace en ne traçant qu'une **fenêtre** d'instructions : on saute les N premières instructions, puis on trace les M suivantes.

### Nouveaux paramètres (dans `[GENERAL]` de `pin_config.ini`)

| Paramètre | Par défaut | Description |
|-----------|-----------|-------------|
| `SKIP_INSTRUCTIONS` | 0 | Nombre d'instructions à ignorer au début |
| `MAX_INSTRUCTIONS` | 0 (illimité) | Nombre max d'instructions à tracer après le skip |

### Exemple de configuration

```ini
[GENERAL]
CHUNK_SIZE = 8
REGISTERS = REG_RIP REG_RAX REG_RSI REG_RDI
MEMORY = 32

# Sauter le démarrage (1 million d'instructions) pour arriver au handshake TLS
SKIP_INSTRUCTIONS = 1000000
# Tracer seulement 500 000 instructions à partir de là
MAX_INSTRUCTIONS = 500000
```

### Comment ça marche

```
Instruction n° :  0 ──────── SKIP ──────── 1 000 000 ──── TRACE ──── 1 500 000 ──── STOP
                  │                            │                          │
                  └─ record_fragment()         └─ écrit dans trace       └─ return immédiat
                     fait return immédiat
```

1. Un **compteur atomique global** (`global_ins_counter`) est incrémenté à chaque appel de `record_fragment()` / `record_register()`.
2. Si `counter < SKIP_INSTRUCTIONS` → on retourne immédiatement (rien n'est écrit).
3. Si `counter >= SKIP_INSTRUCTIONS` et `counter < SKIP + MAX` → on écrit normalement dans la trace.
4. Si `counter >= SKIP + MAX` → on retourne immédiatement et on affiche un message d'arrêt.

### Conception

- L'instrumentation (`Instructions()`) est **identique** au TraceBuilder original — on insère les callbacks sur les mêmes instructions.
- Le filtrage se fait **à l'exécution** dans les callbacks `record_*`, pas à l'instrumentation. Cela évite de modifier la logique de filtrage de bibliothèques.
- Le compteur est `std::atomic<uint64_t>` pour être thread-safe.
- Les statistiques finales affichent le nombre total d'instructions vues, sautées et tracées.

### Résultat attendu

Si le programme exécute 10 millions d'instructions et qu'on configure `SKIP=1000000, MAX=500000`, la trace ne contiendra que 500 000 lignes au lieu de 10 millions → **réduction d'un facteur ~20**.

---

## 3. TraceBuilder_FuncEntry.cpp — Traçage limité aux premières instructions de chaque fonction

### Objectif

Réduire la trace en ne traçant que les **N premières instructions** de chaque appel de fonction. L'intuition est que les secrets TLS sont souvent manipulés en début de fonction (paramètres dans les registres, copie en mémoire locale) et rarement au milieu de longues boucles.

### Nouveau paramètre (dans `[GENERAL]` de `pin_config.ini`)

| Paramètre | Par défaut | Description |
|-----------|-----------|-------------|
| `MAX_INS_PER_FUNC` | 10 | Nombre max d'instructions tracées par appel de fonction |

### Exemple de configuration

```ini
[GENERAL]
CHUNK_SIZE = 8
REGISTERS = REG_RIP REG_RAX REG_RSI REG_RDI
MEMORY = 32

# Tracer seulement les 15 premières instructions de chaque fonction
MAX_INS_PER_FUNC = 15
```

### Comment ça marche

```
Appel de fonction foo():
  instruction 1  ✓ tracée (budget=15 → 14)
  instruction 2  ✓ tracée (budget=14 → 13)
  ...
  instruction 15 ✓ tracée (budget=1 → 0)
  instruction 16 ✗ ignorée (budget=0)
  instruction 17 ✗ ignorée
  ...

Appel de fonction bar():     ← budget rechargé à 15
  instruction 1  ✓ tracée
  ...
```

1. **Instrumentation au niveau routine** (`RTN_AddInstrumentFunction`) : pour chaque fonction, on insère un callback `on_function_entry()` à l'entrée qui réinitialise un **budget par thread** à `MAX_INS_PER_FUNC`.
2. **À chaque instruction** dans cette routine, les callbacks `record_fragment()` / `record_register()` vérifient le budget restant :
   - Si budget > 0 → on écrit, on décrémente.
   - Si budget = 0 → on retourne immédiatement.
3. Le budget est **par thread** (`std::map<THREADID, uint64_t>`) protégé par un mutex.

### Conception

- Contrairement aux deux autres variantes, celle-ci utilise `RTN_AddInstrumentFunction` au lieu de `INS_AddInstrumentFunction`. Cela permet d'itérer sur les instructions **à l'intérieur de chaque routine** et d'insérer le callback de reset à l'entrée.
- Requiert `PIN_InitSymbols()` pour que Pin puisse résoudre les symboles de fonctions (déjà appelé dans le main original).
- Les callbacks d'enregistrement prennent un paramètre supplémentaire `IARG_THREAD_ID` pour identifier le thread courant.
- Les statistiques finales montrent le **ratio de traçage** (instructions tracées / vues), ce qui permet de juger l'efficacité de la réduction.

### Résultat attendu

Si une fonction typique fait ~100 instructions et qu'on trace les 10 premières → **réduction d'un facteur ~10**. Pour des fonctions de boucle avec des milliers d'itérations, la réduction peut être de l'ordre de **100x ou plus**.

---

## Comparaison

| Critère | Original | Delayed | FuncEntry |
|---------|----------|---------|-----------|
| Instructions tracées | Toutes | Fenêtre [SKIP, SKIP+MAX] | N premières par fonction |
| Config supplémentaire | — | `SKIP_INSTRUCTIONS`, `MAX_INSTRUCTIONS` | `MAX_INS_PER_FUNC` |
| Granularité de la réduction | — | Grossière (plage temporelle) | Fine (par fonction) |
| Risque de rater le secret | — | Si la fenêtre est mal placée | Faible (les secrets transitent souvent en début de fonction) |
| Compatibilité analyseur | ✓ | ✓ (même format binaire) | ✓ (même format binaire) |
| API Pin utilisée | `INS_AddInstrumentFunction` | `INS_AddInstrumentFunction` | `RTN_AddInstrumentFunction` |

Les trois variantes produisent le **même format de trace binaire** → l'analyseur Python (`main.py`) fonctionne sans modification.

---

## Utilisation

### Pipeline recommandée avec filtre par fonction

Pour Windows, la pipeline reproductible est la suivante :

1. Définir `SSLKEYLOGFILE` dans le terminal du serveur HTTPS OpenSSL contrôlé,
  puis lancer `Serveur/serveur.py`. Le client SChannel ne fournit pas cette
  variable ; la clé de référence est donc récupérée côté serveur.
2. Configurer `[FILTERS]` dans `Scripts/pin_config.ini`, notamment
  `FILTER_FUNCTION` pour exclure les fonctions non pertinentes et
  `TARGET_LIB` pour limiter les DLL TLS.
3. Compiler et exécuter un TraceBuilder (`TraceBuilder_FuncEntry` est le point
  de départ recommandé, puis `TraceBuilder_PerFunctionSplit` ou
  `TraceBuilder` si le candidat est manqué).
4. Analyser `Data/log/trace.binary`, puis exécuter `PinGetName` et
  `Backtracer` avec la même cible et la même configuration.
5. Comparer `Data/log/backtrace_leaks.log` avec le keylog serveur de la même
  session pour apprendre ou appliquer la carte des secrets.

Le keylog serveur et les leaks doivent correspondre à la même requête TLS ; un
keylog provenant d'une autre session ne permet pas d'apprendre correctement la
correspondance.

### Compilation

Le script `build.bat` / `build.ps1` accepte en paramètre le nom de la cible à compiler. On ne recompile que ce qui est nécessaire.

```bat
:: Compiler uniquement le TraceBuilder original
.\build.bat TraceBuilder

:: Compiler uniquement la variante Delayed
.\build.bat TraceBuilder_Delayed

:: Compiler uniquement la variante FuncEntry
.\build.bat TraceBuilder_FuncEntry

:: Compiler plusieurs cibles en une seule commande
.\build.bat TraceBuilder TraceBuilder_Delayed

:: Compiler tout (aucun argument = tous les outils)
.\build.bat
```

Cibles disponibles : `TraceBuilder`, `TraceBuilder_Delayed`, `TraceBuilder_FuncEntry`, `TraceBuilder_PerFunctionSplit`, `TraceBuilder_StructTracker`, `TraceBuilder_ArgTracker`, `PinGetName`, `PinGetName_StructTracker`, `Backtracer`, `Backtracer_StructTracker`, `Extracteur`, `LibraryFunctions`.

Chaque cible produit sa propre DLL dans `obj-intel64/` (ex: `TraceBuilder_Delayed.dll`).

### Exécution

Pointer Pin vers la DLL de la variante souhaitée :

```powershell
$PIN_TOOL = $env:PIN_ROOT

# Version originale
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\TraceBuilder.dll" `
    -config Scripts/pin_config.ini `
    -- Cible/curl_schannel.exe -k https://localhost:4443

# Version Delayed
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\TraceBuilder_Delayed.dll" `
    -config Scripts/pin_config.ini `
    -- Cible/curl_schannel.exe -k https://localhost:4443

# Version FuncEntry
& "$PIN_TOOL\pin.exe" -t "Pintools\MyPintool\obj-intel64\TraceBuilder_FuncEntry.dll" `
    -config Scripts/pin_config.ini `
    -- Cible/curl_schannel.exe -k https://localhost:4443
```

Puis lancer l'analyse normalement :

```powershell
cd Analyseur
python main.py -c ..\Scripts\pin_config.ini
```
