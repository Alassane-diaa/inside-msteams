#include "pin.H"
#include <iostream>
#include <fstream>
#include <mutex>
#include <vector>
#include <iomanip>
#include <algorithm>

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
    TYPE_EXIT_IP = 6,
    TYPE_XMM_DATA = 7,
    TYPE_MEM_ACCESS = 8,
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
// Analyseur récursif de pointeurs (jusqu'à 3 niveaux de profondeur)
// -----------------------------------------------------------------------------
#define MAX_DEREF_DEPTH 10
#define RAW_DATA_READ_SIZE 64 // Combien d'octets lire quand c'est une donnée brute (augmenté à 64)

VOID AnalyzeArgument(uint8_t base_type, ADDRINT val, int depth = 0) {
    // Si la valeur est nulle (pointeur NULL) ou profondeur max atteinte
    if (val == 0 || depth >= MAX_DEREF_DEPTH) {
        return;
    }

    // Hypothèse 1 : val est un pointeur vers un autre pointeur
    ADDRINT next_val = 0;
    size_t copied = PIN_SafeCopy(&next_val, reinterpret_cast<const void*>(val), sizeof(ADDRINT));

    if (copied == sizeof(ADDRINT) && next_val != 0) {
        // C'est potentiellement un pointeur valide vers un autre pointeur,
        // on enregistre l'adresse courante puis on cherche plus profond
        WriteBinary(base_type, &val, sizeof(ADDRINT));
        
        // On vérifie tout de même si next_val est une adresse (heuristique simple > 0x10000)
        // pour ne pas confondre un gros entier avec une adresse.
        if (next_val > 0x10000) {
            AnalyzeArgument(base_type, next_val, depth + 1);
            return;
        }
    } 

    // Hypothèse 2 : val pointe vers de la donnée brute / fin de chaîne
    UINT8 raw_buffer[RAW_DATA_READ_SIZE] = {0};
    size_t raw_copied = PIN_SafeCopy(raw_buffer, reinterpret_cast<const void*>(val), RAW_DATA_READ_SIZE);

    if (raw_copied > 0) {
        // On a trouvé de la donnée brute à cette adresse mémoire
        WriteBinary(TYPE_RAW_DATA, raw_buffer, static_cast<uint32_t>(raw_copied));
    } else if (depth == 0) {
        // Ce n'était pas un pointeur, c'est juste la valeur immédiate du registre
        WriteBinary(base_type, &val, sizeof(ADDRINT));
    }
}

// -----------------------------------------------------------------------------
// Callbacks d'analyse (Entrée et Sortie de fonction)
// -----------------------------------------------------------------------------
VOID OnFunctionEntry(ADDRINT ip, const CONTEXT* ctx, THREADID tid) {
    WriteBinary(TYPE_IP, &ip, sizeof(ADDRINT));
    ADDRINT rcx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX);
    ADDRINT rdx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX);
    ADDRINT r8  = PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8);
    ADDRINT r9  = PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9);

    AnalyzeArgument(TYPE_ARG_RCX, rcx);
    AnalyzeArgument(TYPE_ARG_RDX, rdx);
    AnalyzeArgument(TYPE_ARG_R8, r8);
    AnalyzeArgument(TYPE_ARG_R9, r9);
    WriteBinary(TYPE_RECORD_END, nullptr, 0);
}

// -----------------------------------------------------------------------------
// Instrumentation des Routines (Fonctions)
// -----------------------------------------------------------------------------
VOID RoutineInstrumentation(RTN rtn, VOID* v) {
    if (!RTN_Valid(rtn)) return;

    RTN_Open(rtn);

    // Entrée de Fonction
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
    std::cout << "[TraceTracker] Analyse terminee et fichiers sauvegardes." << std::endl;
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