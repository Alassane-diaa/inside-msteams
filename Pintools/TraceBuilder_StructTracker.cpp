#include "pin.H"
#include <iostream>
#include <fstream>
#include <mutex>
#include <vector>
#include <iomanip>

extern "C" {
    __declspec(dllimport) int __stdcall CreateDirectoryA(const char* lpPathName, void* lpSecurityAttributes);
}

// -----------------------------------------------------------------------------
// Format de sortie Binaire : (Type, Taille, Valeur)
// -----------------------------------------------------------------------------
enum RecordType : uint8_t {
    TYPE_IP = 0,
    TYPE_ARG_RCX = 1,
    TYPE_ARG_RDX = 2,
    TYPE_ARG_R8 = 3,
    TYPE_ARG_R9 = 4,
    TYPE_RAW_DATA = 5,
    TYPE_RECORD_END = 255
};

#pragma pack(push, 1)
struct RecordHeader {
    uint8_t type;
    uint32_t size;
};
#pragma pack(pop)

static std::ofstream trace_file;
static std::ofstream log_file;
static std::mutex trace_mutex;

// -----------------------------------------------------------------------------
// Helper d'écriture binaire (Thread-safe)
// -----------------------------------------------------------------------------
inline void WriteBinary(uint8_t type, const void* data, uint32_t size) {
    RecordHeader header = { type, size };
    std::lock_guard<std::mutex> lock(trace_mutex);
    trace_file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (size > 0 && data != nullptr) {
        trace_file.write(reinterpret_cast<const char*>(data), size);
    }
}

// -----------------------------------------------------------------------------
// Borne de lecture pour ssl_connection_st.
// -----------------------------------------------------------------------------
static constexpr size_t STRUCT_SSL_READ_SIZE = 512;

VOID AnalyzeArgument(uint8_t base_type, ADDRINT val) {
    // Un pointeur user-space Windows valide est généralement supérieur à 0x10000 (64 Ko)
    // Cela nous permet d'ignorer tout de suite les petits nombres (flags, tailles, etc.)
    if (val < 0x10000) {
        return;
    }

    // Ensuite, on tente de lire la mémoire. Si c'est un faux pointeur, PIN_SafeCopy échouera proprement.
    UINT8 raw_buffer[STRUCT_SSL_READ_SIZE] = {0};
    size_t raw_copied = PIN_SafeCopy(raw_buffer, reinterpret_cast<const void*>(val), STRUCT_SSL_READ_SIZE);

    // Si on a réussi à lire des données, c'est la preuve que c'est un VRAI pointeur accessible
    if (raw_copied > 0) {
        // On écrit le registre (RCX)
        WriteBinary(base_type, &val, sizeof(ADDRINT));
        // On écrit la donnée ciblée par le pointeur
        WriteBinary(TYPE_RAW_DATA, raw_buffer, static_cast<uint32_t>(raw_copied));
    }
}

// -----------------------------------------------------------------------------
// Callback d'analyse : appelé à l'entrée de chaque fonction
// -----------------------------------------------------------------------------
VOID OnFunctionEntry(ADDRINT ip, const CONTEXT* ctx, THREADID tid) {
    WriteBinary(TYPE_IP, &ip, sizeof(ADDRINT));

    // Selon votre directive: on ne regarde QUE RCX
    ADDRINT rcx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX);

    AnalyzeArgument(TYPE_ARG_RCX, rcx);

    WriteBinary(TYPE_RECORD_END, nullptr, 0);
}

// -----------------------------------------------------------------------------
// Instrumentation des Routines (Fonctions)
// -----------------------------------------------------------------------------
VOID RoutineInstrumentation(RTN rtn, VOID* v) {
    if (!RTN_Valid(rtn)) return;

    RTN_Open(rtn);

    // Entrée de Fonction (pas de filtrage, on trace TOUT)
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)OnFunctionEntry,
                   IARG_INST_PTR,        // Adresse de la fonction (IP)
                   IARG_CONST_CONTEXT,   // Contexte des registres
                   IARG_THREAD_ID,
                   IARG_END);

    RTN_Close(rtn);
}

// -----------------------------------------------------------------------------
// Log loaded modules (Indispensable pour contourner l'ASLR)
// -----------------------------------------------------------------------------
VOID ImageLoad(IMG img, VOID* v) {
    if(log_file.is_open()) {
        log_file << "Module chargé : " << IMG_Name(img)
                 << " Adresse de base : 0x" << std::hex << std::setw(16)
                 << std::setfill('0') << IMG_LowAddress(img) << std::endl;
    }
}

// -----------------------------------------------------------------------------
// Gestion propre de fin de programme
// -----------------------------------------------------------------------------
VOID Fini(INT32 code, VOID* v) {
    if (trace_file.is_open()) trace_file.close();
    if (log_file.is_open()) log_file.close();
    std::cout << "[StructTracker] Analyse terminee et fichiers sauvegardes." << std::endl;
}

// -----------------------------------------------------------------------------
// Point d'entrée
// -----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        std::cerr << "L'initialisation de PIN a echoue." << std::endl;
        return -1;
    }

    CreateDirectoryA("data", NULL);
    CreateDirectoryA("data\\log", NULL);

    log_file.open("data\\log\\trace.log");
    if (!log_file) {
        std::cerr << "Erreur: impossible d'ouvrir data/log/trace.log." << std::endl;
        return -1;
    }

    trace_file.open("data\\log\\trace.binary", std::ios::binary);
    if (!trace_file) {
        std::cerr << "Erreur: impossible d'ouvrir data/log/trace.binary." << std::endl;
        return -1;
    }

    // Capture des DLLs pour l'ASLR
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // On utilise l'instrumentation au niveau routine
    RTN_AddInstrumentFunction(RoutineInstrumentation, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}