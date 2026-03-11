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
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "pin.H"

//------------------------------------------------------------------------------
// Config KNOB
//------------------------------------------------------------------------------
KNOB<std::string> KnobConfigFile(KNOB_MODE_WRITEONCE, "pintool",
                                 "config", "pin_config.ini",
                                 "Path to the PIN tool configuration file");

//------------------------------------------------------------------------------
// Filtering globals
//------------------------------------------------------------------------------
static std::vector<std::string> skip_libs;
static std::vector<std::string> target_libs;
static std::string filter_mode = "blacklist"; // défaut sûr

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------
static std::string bt_trim(const std::string &s)
{
    const auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string bt_get_filename(const std::string &path)
{
    auto pos = path.find_last_of("\\/");
    std::string f = (pos == std::string::npos) ? path : path.substr(pos + 1);
    for (auto &c : f) c = std::tolower(c);
    return f;
}

/** Charge MODE, FILTER_LIB et TARGET_LIB depuis la section [FILTERS] du config. */
static void load_filter_config_backtracer(const std::string &filename)
{
    std::ifstream cfg(filename);
    if (!cfg) return;
    std::string line;
    bool in_filters = false;
    while (std::getline(cfg, line))
    {
        auto p = line.find('#');
        if (p != std::string::npos) line = line.substr(0, p);
        line = bt_trim(line);
        if (line.empty()) continue;
        if (line == "[FILTERS]") { in_filters = true; continue; }
        if (line.front() == '[' && line.back() == ']') { in_filters = false; continue; }
        if (!in_filters) continue;
        if (line.rfind("MODE", 0) == 0)
        {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string mode = bt_trim(line.substr(eq + 1));
            for (auto &c : mode) c = std::tolower(c);
            if (mode == "whitelist" || mode == "blacklist" || mode == "none")
                filter_mode = mode;
        }
        if (line.rfind("FILTER_LIB", 0) == 0)
        {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::istringstream ss(bt_trim(line.substr(eq + 1)));
            std::string lib;
            while (std::getline(ss, lib, ','))
                skip_libs.push_back(bt_trim(lib));
        }
        if (line.rfind("TARGET_LIB", 0) == 0)
        {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::istringstream ss(bt_trim(line.substr(eq + 1)));
            std::string lib;
            while (std::getline(ss, lib, ','))
                target_libs.push_back(bt_trim(lib));
        }
    }
    std::cout << "[Backtracer] Mode de filtrage : " << filter_mode;
    if (filter_mode == "blacklist") std::cout << " -> " << skip_libs.size() << " libs ignorées";
    else if (filter_mode == "whitelist") { std::cout << " -> libs: "; for (size_t i=0;i<target_libs.size();++i){if(i)std::cout<<", ";std::cout<<target_libs[i];} }
    std::cout << std::endl;
}

/** Forward decl – défini plus bas dans le fichier. */
static std::string libName;

/**
 * @brief Retourne true si l'image doit être ignorée pour le suivi call/ret.
 *        La lib cible (libName) est toujours instrumentée.
 */
static bool should_skip_img(const std::string &imgName)
{
    std::string fname = bt_get_filename(imgName);
    // Toujours instrumenter la lib cible
    std::string target_fname = bt_get_filename(libName);
    if (!target_fname.empty() && fname.find(target_fname) != std::string::npos)
        return false;
    if (filter_mode == "whitelist")
    {
        for (auto &t : target_libs)
        {
            std::string tl = t; for (auto &c : tl) c = std::tolower(c);
            if (fname == tl || fname.find(tl) != std::string::npos) return false;
        }
        return true;
    }
    if (filter_mode == "blacklist")
    {
        for (auto &s : skip_libs)
        {
            std::string sl = s; for (auto &c : sl) c = std::tolower(c);
            if (fname == sl || fname.find(sl) != std::string::npos) return true;
        }
    }
    return false;
}

/** Flux tampon global pour accumuler les lignes de log avant écriture finale. */
static std::stringstream key_out;
static std::stringstream log_out;
// libName est déclaré dans le bloc de filtrage plus haut

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


/** Verrou PIN pour la sortie (serialisation des écritures). */
static PIN_LOCK ioLock;

static const ADDRINT RANGE_BEFORE = 0x80; // 32 octets avant
static const ADDRINT RANGE_AFTER = 0x20;  // 32 octets après
static std::vector<char *> gInstList;

static const int SECRET_LEN = 48;
static std::vector<uint8_t> gLeakedBytes;


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

 * @brief At target instruction: dump registers, leaked bytes, disasm window,

 *        and walk the stack via RSP to find callers.

 * @param ip       Address of the target instruction.

 * @param tid      Thread id.

 * @param instList Disassembly window around the target (freed here).

 * @param ctx      Snapshot context (IARG_CONST_CONTEXT).

 */

VOID Backtrace(ADDRINT ip, THREADID tid, std::vector<char *> *instList, const CONTEXT *ctx)

{

    bool expected = false;

    if (!logged.compare_exchange_strong(expected, true))

    {

        for (auto p : *instList) free(p);

        instList->clear();

        return;

    }



    PIN_GetLock(&ioLock, 1);



    ADDRINT rdi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI);

    ADDRINT rsi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI);

    ADDRINT rdx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX);

    ADDRINT rcx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX);

    ADDRINT r8  = PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8);

    ADDRINT r9  = PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9);

    ADDRINT rsp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP);




    PIN_LockClient();

    RTN rtn_cur = RTN_FindByAddress(ip);

    std::string currentFunc = RTN_Valid(rtn_cur) ? RTN_Name(rtn_cur) : "<unknown>";

    PIN_UnlockClient();



    std::ostringstream oss;

    oss << std::hex << std::setfill('0')

        << "Adresse : 0x" << std::setw(16) << ip << "\n"

        << "Fonction : `" << currentFunc << "`\n"

        << "=== Registres au point cible ===\n"

        << "\tRDI = 0x" << std::setw(16) << rdi << "\n"

        << "\tRSI = 0x" << std::setw(16) << rsi << "\n"

        << "\tRDX = 0x" << std::setw(16) << rdx << "\n"

        << "\tRCX = 0x" << std::setw(16) << rcx << "\n"

        << "\tR8  = 0x" << std::setw(16) << r8  << "\n"

        << "\tR9  = 0x" << std::setw(16) << r9  << "\n";



    oss << "===     Fuite    ===\n";

    for (auto b : gLeakedBytes)

        oss << std::hex << std::setw(2) << std::setfill('0') << uint32_t(b);

    oss << std::dec << "\n";




    oss << "=== Instructions ===\n";

    for (auto disasm_cstr : *instList)

    {

        if (disasm_cstr == insName)

            oss << "[!] " << disasm_cstr << "\n";

        else

            oss << "\t" << disasm_cstr << "\n";

    }



    oss << "=== Appelant(s) (stack walk) ===\n";

    PIN_LockClient();

    int frames = 0;

    for (ADDRINT offset = 0; offset < 4096 && frames < 32; offset += 8)

    {

        ADDRINT candidate = 0;

        if (PIN_SafeCopy(&candidate, reinterpret_cast<void *>(rsp + offset), 8) != 8) break;

        if (!candidate) continue;

        IMG img = IMG_FindByAddress(candidate);

        if (!IMG_Valid(img)) continue;

        RTN frame_rtn = RTN_FindByAddress(candidate);

        oss << "  [" << std::dec << frames << "] "

            << (RTN_Valid(frame_rtn) ? RTN_Name(frame_rtn) : "<unknown>")

            << " @ 0x" << std::hex << std::setw(16) << std::setfill('0') << candidate

            << "\n\t" << IMG_Name(img) << "\n";

        frames++;

    }

    if (frames == 0) oss << "  (aucun appelant trouve dans la fenetre de stack)\n";

    PIN_UnlockClient();



    key_out << oss.str();

    PIN_ReleaseLock(&ioLock);



    for (auto p : *instList) free(p);

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
/**

 * @brief Instrument each instruction: collect disasm window around target,

 *        insert LeakSecret and Backtrace hooks at insAddress.

 *        No CALL/RET tracking -- avoids NtContinue crashes with SChannel.

 */

VOID Instruction(INS ins, VOID *)

{

    ADDRINT addr = INS_Address(ins);



    // Leak the secret bytes at the target address

    if (addr == insAddress && gLeakedBytes.size() < (size_t)SECRET_LEN)

    {

        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(LeakSecret),

                                 IARG_MEMORYREAD_EA, IARG_THREAD_ID, IARG_END);

    }



    // Collect disasm window and fire Backtrace once

    if (insAddress > 0 &&

        addr >= insAddress - RANGE_BEFORE &&

        addr <= insAddress + RANGE_AFTER)

    {

        char *disasm_cstr = strdup(INS_Disassemble(ins).c_str());

        gInstList.push_back(disasm_cstr);



        if (addr == insAddress)

        {

            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Backtrace,

                           IARG_INST_PTR, IARG_THREAD_ID,

                           IARG_PTR, &gInstList,

                           IARG_CONST_CONTEXT,
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

    PIN_InitLock(&ioLock);

    LoadResultAnalyse("data/log/getName.log");
    load_filter_config_backtracer(KnobConfigFile.Value());

    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
