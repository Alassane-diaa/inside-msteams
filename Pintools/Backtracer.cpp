/**
 * @file Backtracer.cpp
 * @brief Outil PIN pour capturer une backtrace au point d’une instruction cible.
 *
 * Cet outil lit au démarrage un fichier d’analyse (« data/log/getName.log ») qui décrit :
 *  - la librairie cible,
 *  - le décalage (delta),
 *  - l’adresse (hexadécimale) de l’instruction,
 *  - le nom de la fonction et de l’instruction.
 *
 * Lorsqu’une image est chargée, si elle correspond à la librairie ciblée, on recalcule
 * l’adresse absolue de l’instruction. On instrumente chaque appel/retour pour maintenir
 * une pile d’appels (thread-local), et lorsqu’on atteint l’instruction cible, on produit
 * une backtrace complète (nom des fonctions appelantes + quelques registres et lectures
 * mémoire) une seule fois, dans « data/log/Backtrace.log ».
 */

#include <atomic>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "pin.H"

/** Flux tampon global pour accumuler les lignes de log avant écriture finale. */
static std::stringstream key_out;
static std::stringstream log_out;
/** Nom de la bibliothèque ciblée, tel que lu dans getName.log. */
static std::string libName;

/** Nom de la fonction cible (pour info). */
static std::string funName;

/** Nom de l’instruction cible (pour info). */
static std::string insName;

/** Adresse absolue de l’instruction cible. */
static ADDRINT insAddress = 0;

/** Décalage (delta) appliqué à l’entrée de la librairie pour obtenir insAddress. */
static ADDRINT delta = 0;

/** Flag atomique pour n’enregistrer la backtrace qu’une seule fois. */
static std::atomic<bool> logged{false};

/** TLS key pour stocker une pile d’appels par thread. */
static TLS_KEY tlsKey;

/** Verrou PIN pour la sortie (serialisation des écritures). */
static PIN_LOCK ioLock;

static const ADDRINT RANGE_BEFORE = 0x80; // 32 octets avant
static const ADDRINT RANGE_AFTER = 0x20;  // 32 octets après
static std::vector<char *> gInstList;

static const int SECRET_LEN = 48;
static std::vector<uint8_t> gLeakedBytes;

/**
 * @struct Frame
 * @brief Informations capturées pour chaque appel de fonction.
 */
struct Frame
{
    std::string funcName; /**< Nom de la fonction appelée. */
    std::string libName;  /**< Nom de la librairie contenant la fonction. */
    ADDRINT regs[7];      /**< Valeurs des registres RDI, RSI, RDX, RCX, R8, R9, R10. */
};

/**
 * @struct CallStack
 * @brief Représente une pile d’appels (LIFO) pour un thread donné.
 */
struct CallStack
{
    std::vector<Frame> stack;
};

/**
 * @brief Récupère le CallStack associé au thread donné.
 * @param tid Identifiant du thread.
 * @return Pointeur vers le CallStack du thread.
 */
static CallStack *GetTlsStack(THREADID tid)
{
    return static_cast<CallStack *>(PIN_GetThreadData(tlsKey, tid));
}

/**
 * @brief Callback PIN appelé à la création d’un thread.
 *        Alloue et initialise la pile d’appels.
 */
VOID ThreadStart(THREADID tid, CONTEXT *, INT32, VOID *)
{
    CallStack *cs = new CallStack();
    PIN_SetThreadData(tlsKey, cs, tid);
}

/**
 * @brief Callback PIN appelé à la terminaison d’un thread.
 *        Libère la pile d’appels.
 */
VOID ThreadFini(THREADID tid, const CONTEXT *, INT32, VOID *)
{
    CallStack *cs = static_cast<CallStack *>(PIN_GetThreadData(tlsKey, tid));
    delete cs;
}

/**
 * @brief Lit le fichier d’analyse pour initialiser libName, delta, insAddress, funName, insName.
 * @param filename Nom du fichier à lire.
 */
void LoadResultAnalyse(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        log_out << "[Backtracer] ERROR: Impossible d'ouvrir " << filename << std::endl;
        return;
    }

    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(file, line))
    {
        auto pos = line.find(':');
        if (pos == std::string::npos)
            continue;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);
        // Trim leading spaces
        val.erase(0, val.find_first_not_of(" \t"));
        kv[key] = val;
    }

    libName = kv["Librairie"];
    funName = kv["Fonction"];
    insName = kv["Instruction"];

    // try {
    // Check if keys exist before trying to convert
    if (kv.count("Delta"))
    {
        delta = std::stoull(kv["Delta"], nullptr, 10);
    }
    else
    {
        log_out << "[Backtracer] ERROR: 'Delta' key not found in " << filename << std::endl;
    }

    if (kv.count("Adresse"))
    {
        insAddress = std::stoull(kv["Adresse"], nullptr, 16);
    }
    else
    {
        log_out << "[Backtracer] ERROR: 'Adresse' key not found in " << filename << std::endl;
    }

    // } catch (const std::invalid_argument& e) {
    //     log_out << "[Backtracer] ERROR: std::invalid_argument in stoull: " << e.what() << std::endl;
    //     log_out << "[Backtracer] Problematic values: Delta='" << kv["Delta"] << "', Adresse='" << kv["Adresse"] << "'" << std::endl;
    //     PIN_ExitProcess(1); // Exit PIN if parsing fails
    // } catch (const std::out_of_range& e) {
    //     log_out << "[Backtracer] ERROR: std::out_of_range in stoull: " << e.what() << std::endl;
    //     log_out << "[Backtracer] Problematic values: Delta='" << kv["Delta"] << "', Adresse='" << kv["Adresse"] << "'" << std::endl;
    //     PIN_ExitProcess(1); // Exit PIN if parsing fails
    // }

    log_out
        << "[Backtracer] libName=" << libName
        << " delta=" << delta
        << " insAddress=0x" << std::hex << insAddress << std::dec
        << " funName=" << funName
        << " insName=" << insName
        << std::endl;
    file.close();
}

/**
 * @brief Callback PIN appelé à chaque chargement d’image (exe ou lib).
 *        Si c’est la librairie ciblée, on met à jour insAddress = base + delta.
 */
VOID ImageLoad(IMG img, VOID *)
{
    // log_out << "[Backtracer] " << __func__ << std::endl;
    const std::string imgName = IMG_Name(img);
    if (imgName.find(libName) != std::string::npos)
    {
        insAddress = IMG_LowAddress(img) + delta;
        log_out << "[Backtracer] Librairie chargée: " << imgName << std::endl;
        log_out << "[Backtracer] Adresse de base: 0x" << std::hex << IMG_LowAddress(img) << std::endl;
        log_out << "[Backtracer] Adresse cible: 0x" << std::hex << insAddress << std::dec << std::endl;
    }
}

/**
 * @brief Sauvegarde dans @p out la valeur de type T lue à l’adresse @p addr.
 * @tparam T Type à lire (uint32_t, uint64_t, etc.).
 * @param addr Adresse mémoire à lire.
 * @param out Référence où stocker la valeur lue.
 * @return true si la lecture a réussi.
 */
template <typename T>
bool ReadMem(ADDRINT addr, T &out)
{
    // PIN_SafeCopy retourne le nombre d'octets copiés
    UINT32 copied = PIN_SafeCopy(&out, reinterpret_cast<VOID *>(addr), sizeof(T));
    return (copied == sizeof(T));
}

/**
 * @brief Callback d’instrumentation de chaque appel de fonction.
 *        Pousse un Frame sur la pile locale du thread.
 */
VOID OnCall(ADDRINT target, THREADID tid, CONTEXT *ctx)
{
    // log_out << "[Backtracer] " << __func__ << " tid=" << tid << std::endl;
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(target);
    IMG img = IMG_FindByAddress(target);

    Frame f;
    f.funcName = RTN_Valid(rtn) ? RTN_Name(rtn) : "<unknown>";
    f.libName = IMG_Valid(img) ? IMG_Name(img) : "<unknown>";
    PIN_UnlockClient();

    // RDI, RSI, RDX, RCX, R8, R9, R10
    f.regs[0] = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI);
    f.regs[1] = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI);
    f.regs[2] = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX);
    f.regs[3] = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX);
    f.regs[4] = PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8);
    f.regs[5] = PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9);
    f.regs[6] = PIN_GetContextReg(ctx, LEVEL_BASE::REG_R10);

    GetTlsStack(tid)->stack.push_back(f);
}

/**
 * @brief Callback d’instrumentation d’un retour de fonction.
 *        Dépile la dernière frame.
 */
VOID OnRet(THREADID tid)
{
    // log_out << "[Backtracer] " << __func__ << " tid=" << tid << std::endl;
    CallStack *stk = GetTlsStack(tid);
    if (!stk)
    {
        return;
    }
    if (!stk->stack.empty())
    {
        stk->stack.pop_back();
    }
}

/**
 * @brief Lorsqu’on atteint l’instruction cible, génère la backtrace complète une seule fois.
 * @param ip   Adresse de l’instruction instrumentée.
 * @param tid  Identifiant du thread.
 * @param dis  Pointeur vers la chaîne désassemblée (libérée à la fin).
 */
VOID Backtrace(ADDRINT ip, THREADID tid, std::vector<char *> *instList)
{
    // log_out << "[Backtracer] " << __func__ << " tid=" << tid << std::endl;
    bool expected = false;
    if (!logged.compare_exchange_strong(expected, true))
    {
        for (auto p : *instList)
        {
            free(p);
        }
        instList->clear();
        return; // déjà loggé
    }

    PIN_GetLock(&ioLock, 1);

    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(ip);
    std::string currentFunc = RTN_Valid(rtn) ? RTN_Name(rtn) : "<unknown>";
    PIN_UnlockClient();

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << "Adresse : 0x" << std::setw(16) << ip << "\n"
        << "Fonction : `" << currentFunc << "`\n";

    oss << "===     Fuite    ===\n";
    for (auto b : gLeakedBytes)
    {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << uint32_t(b);
    }
    oss << std::dec << "\n";

    oss << "=== Instructions ===\n";
    for (auto disasm_cstr : *instList)
    {
        if (disasm_cstr == insName)
        {
            oss << "[!] " << disasm_cstr << "\n";
        }
        else
        {
            oss << "\t" << disasm_cstr << "\n";
        }
    }

    oss << "=== Appelant(s)  ===\n";

    auto &stack = GetTlsStack(tid)->stack;
    for (int i = int(stack.size()) - 1; i >= 0; --i)
    {
        const Frame &f = stack[i];
        oss << "  -> " << f.funcName << "\n"
            << "\tBibliothèque : " << f.libName << "\n"
            << "\tArguments : \n"
            << "\tRDI = 0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[0] << "\n"
            << "\tRSI = 0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[1] << "\n"
            << "\tRDX = 0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[2] << "\n"
            << "\tRCX = 0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[3] << "\n"
            << "\tR8  = 0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[4] << "\n"
            << "\tR9  = 0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[5] << "\n"
            << "\tR10  = 0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[6] << "\n";

        // On ne fait ça que si vous voulez vraiment lire un uint64_t
        uint32_t valRDI = 0, valRSI = 0;

        // Tente de lire 8 octets à *l’adresse* f.rdi
        if (ReadMem<uint32_t>(f.regs[0], valRDI))
        {
            oss << "\tValeur 32-bits à l'adresse RDI (0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[0]
                << ") : 0x" << std::hex << std::setw(16) << std::setfill('0') << valRDI << "\n";
        }
        else
        {
            oss << "\t[Erreur] impossible de lire à l'adresse RDI 0x"
                << std::hex << f.regs[0] << "\n";
        }

        // Même chose pour RSI
        if (ReadMem<uint32_t>(f.regs[1], valRSI))
        {
            oss << "\tValeur 32-bits à l'adresse RSI (0x" << std::hex << std::setw(16) << std::setfill('0') << f.regs[1]
                << ") : 0x" << std::hex << std::setw(16) << std::setfill('0') << valRSI << "\n";
        }
        else
        {
            oss << "\t[Erreur] impossible de lire à l'adresse RSI 0x"
                << std::hex << f.regs[1] << "\n";
        }
        oss << "\n";
    }

    if (stack.empty() || stack.front().funcName != "main")
    {
        oss << "  -> main\n";
    }

    key_out << oss.str();
    PIN_ReleaseLock(&ioLock);

    for (auto p : *instList)
    {
        free(p);
    }
    instList->clear();
}

/**
 * @brief Fonction d’instrumentation pour lire un octet à l’adresse effective.
 * @param ea Adresse effective de l’octet à lire.
 * @param tid Identifiant du thread.
 */
VOID LeakSecret(void *ea, THREADID tid)
{
    uint8_t buffer[SECRET_LEN];
    log_out << "[Backtracer] DEBUG: Address effective: 0x" << std::hex << reinterpret_cast<ADDRINT>(ea) << std::dec << std::endl;
    UINT32 copied = PIN_SafeCopy(buffer, ea, SECRET_LEN);
    if (copied == SECRET_LEN)
    {
        gLeakedBytes.insert(gLeakedBytes.end(), buffer, buffer + SECRET_LEN);
        log_out << "[Backtracer] DEBUG: Leaked bytes: ";
        for (int i = 0; i < SECRET_LEN; i++)
        {
            log_out << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        }
        log_out << std::endl;
    }
    else
    {
        log_out << "[Backtracer] ERROR: PIN_SafeCopy failed to copy all bytes. Copied: " << copied << " bytes." << std::endl;
        memset(buffer, 0, SECRET_LEN);
        gLeakedBytes.insert(gLeakedBytes.end(), buffer, buffer + SECRET_LEN);
    }
}

/**
 * @brief Fonction d’instrumentation générique appelée pour chaque instruction.
 *        - INS_IsCall  → OnCall
 *        - INS_IsRet   → OnRet
 *        - INS_Address == insAddress → Backtrace
 */
VOID Instruction(INS ins, VOID *)
{
    ADDRINT addr = INS_Address(ins);

    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnCall,
                       IARG_BRANCH_TARGET_ADDR, IARG_THREAD_ID,
                       IARG_CONTEXT, IARG_END);
    }
    else if (INS_IsRet(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnRet,
                       IARG_THREAD_ID, IARG_END);
    }

    // --- hook de la fuite d’octet ---
    if (addr == insAddress && gLeakedBytes.size() < SECRET_LEN)
    {
        log_out << "[Backtracer] DEBUG: Inserting LeakSecret call at address: 0x" << std::hex << addr << std::dec << std::endl;
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, AFUNPTR(LeakSecret),
            IARG_MEMORYREAD_EA,
            IARG_THREAD_ID,
            IARG_END);
    }

    // --- hook de l’instruction cible ---
    if (addr >= insAddress - RANGE_BEFORE && addr <= insAddress + RANGE_AFTER)
    {
        char *disasm_cstr = strdup(INS_Disassemble(ins).c_str());
        gInstList.push_back(disasm_cstr);

        if (addr == insAddress)
        {
            // On a atteint l'instruction cible
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Backtrace,
                           IARG_INST_PTR, IARG_THREAD_ID,
                           IARG_PTR, &gInstList,
                           IARG_END);
        }
    }
}

/**
 * @brief Callback PIN à la fin du programme : écrit le log dans « log/Backtrace.log ».
 */
VOID Fini(INT32 code, VOID *v)
{
    std::ofstream file("data/log/Backtrace.log", std::ios::out | std::ios::trunc);
    if (!file.is_open())
    {
        std::cerr << "Erreur lors de l'ouverture du fichier data/log/Backtrace.log" << std::endl;
        return;
    }
    file << key_out.str();
    file.close();

    std::ofstream output("data/log/backtrace_leaks.log", std::ios::out | std::ios::trunc);
    if (!output.is_open())
    {
        std::cerr << "Erreur lors de l'ouverture du fichier data/log/backtrace_leaks.log" << std::endl;
        return;
    }
    output << log_out.str();
    output.close();
}

/**
 * @brief Point d’entrée du tool.
 * @param argc Nombre d’arguments.
 * @param argv Tableau d’arguments.
 * @return -1 en cas d’échec d’initialisation, sinon 0 (le programme PIN démarre l’exécution appliquée).
 */
int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return -1;
    }

    tlsKey = PIN_CreateThreadDataKey(nullptr);

    PIN_InitLock(&ioLock);

    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);

    LoadResultAnalyse("data/log/getName.log");

    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
