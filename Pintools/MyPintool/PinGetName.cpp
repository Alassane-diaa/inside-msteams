#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <set>
#include "pin.H"

// Flux global pour accumuler les messages avant écriture finale
static std::stringstream key_out;

// Adresse cible de l’instruction à instrumenter et décalage calculé
ADDRINT insAddress = 0;
ADDRINT delta = 0;

// Nom de la librairie et du registre / type mémoire à lire
std::string libName = "";
std::string regName = "";
static bool gHeaderWritten = false;
static bool gResolvedFromImage = false;

// Mapping entre nom de registre (string) et enum PIN REG
static std::map<std::string, REG> String2Reg{
    {"REG_RIP", LEVEL_BASE::REG_RIP},
    {"REG_RAX", LEVEL_BASE::REG_RAX},
    {"REG_RBX", LEVEL_BASE::REG_RBX},
    {"REG_RCX", LEVEL_BASE::REG_RCX},
    {"REG_RDX", LEVEL_BASE::REG_RDX},
    {"REG_RSI", LEVEL_BASE::REG_RSI},
    {"REG_RDI", LEVEL_BASE::REG_RDI},
    {"REG_R8", LEVEL_BASE::REG_R8},
    {"REG_R9", LEVEL_BASE::REG_R9},
    {"REG_XMM0", LEVEL_BASE::REG_XMM0},
    {"REG_XMM1", LEVEL_BASE::REG_XMM1},
    {"REG_XMM2", LEVEL_BASE::REG_XMM2},
    {"REG_XMM3", LEVEL_BASE::REG_XMM3},
    {"REG_XMM4", LEVEL_BASE::REG_XMM4},
    {"REG_XMM5", LEVEL_BASE::REG_XMM5},
    {"REG_XMM6", LEVEL_BASE::REG_XMM6},
    {"REG_XMM7", LEVEL_BASE::REG_XMM7},
    {"REG_YMM0", LEVEL_BASE::REG_YMM0},
    {"REG_YMM1", LEVEL_BASE::REG_YMM1},
    {"REG_YMM2", LEVEL_BASE::REG_YMM2},
    {"REG_YMM3", LEVEL_BASE::REG_YMM3},
    {"REG_YMM4", LEVEL_BASE::REG_YMM4},
    {"REG_YMM5", LEVEL_BASE::REG_YMM5},
    {"REG_YMM6", LEVEL_BASE::REG_YMM6},
    {"REG_YMM7", LEVEL_BASE::REG_YMM7},
};

// Lit le fichier d’analyse pour récupérer Reg:, Lib: et Delta:
void LoadResultAnalyse(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file)
    {
        std::cerr << "[PV] Impossible d'ouvrir " << filename << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line))
    {
        ADDRINT d;
        std::istringstream iss(line);
        std::string regLabel, r, libLabel, l, deltaLabel;

        if (iss >> regLabel >> r >> libLabel >> l >> deltaLabel >> d)
        {
            if (regLabel == "Reg:" && libLabel == "Lib:" && deltaLabel == "Delta:")
            {
                regName = r;
                delta = d;
                libName = l;
            }
        }
    }
}

// Callback appelé à chaque chargement d’image (bibliothèque ou exécutable)
VOID ImageLoad(IMG img, VOID *v)
{
    // Si l’image correspond à la librairie ciblée, calcule l’adresse cible
    std::string s = IMG_Name(img);
    if (s.find(libName) != std::string::npos)
    {
        ADDRINT libAddress = IMG_LowAddress(img);
        printf("[PV] Librairie chargée: %s\n", s.c_str());
        printf("[PV] Adresse de la librairie: 0x%lx\n", libAddress);
        insAddress = libAddress + delta;
        printf("[PV] Adresse de l'instruction ciblée: 0x%lx\n", insAddress);

        if (!gHeaderWritten)
        {
            std::ostringstream oss;
            oss << "Librairie: " << libName << std::endl;
            oss << "Delta: " << delta << std::endl;
            oss << "Adresse: 0x"
                << std::hex << std::setw(16) << std::setfill('0') << insAddress
                << std::endl;
            std::string output = oss.str();
            key_out.write(output.c_str(), output.size());
            gHeaderWritten = true;
        }

        // Resolve function+instruction statically from the target image/address,
        // so we do not depend on execution reaching this exact instruction.
        if (!gResolvedFromImage)
        {
            for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
            {
                for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
                {
                    RTN_Open(rtn);
                    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
                    {
                        if (INS_Address(ins) == insAddress)
                        {
                            std::ostringstream oss;
                            oss << "Fonction: `" << RTN_Name(rtn) << "`" << std::endl;
                            oss << "Instruction: " << INS_Disassemble(ins) << std::endl;
                            std::string output = oss.str();
                            key_out.write(output.c_str(), output.size());
                            gResolvedFromImage = true;
                            break;
                        }
                    }
                    RTN_Close(rtn);
                    if (gResolvedFromImage)
                        break;
                }
                if (gResolvedFromImage)
                    break;
            }
        }
    }
}

// Instrumentation des instructions : on intercepte uniquement l’adresse cible
VOID Instruction(INS ins, VOID *v)
{
    // On ignore les isntructions de contrôle de flux
    if (INS_IsControlFlow(ins))
        return;

    // On vérifie si l'adresse de l'instruction correspond à celle ciblée
    if (INS_Address(ins) == insAddress)
    {
        printf("[PV] Adresse cible atteinte : 0x%lx\n", insAddress);
        std::string current_disasm = INS_Disassemble(ins);

        RTN rtn = RTN_FindByAddress(insAddress);
        std::string funcName = RTN_Valid(rtn) ? RTN_Name(rtn) : "<unknown>";

        // On construit le message d'en-tête
        std::ostringstream oss;
        oss << "Adresse: 0x"
            << std::hex << std::setw(16) << std::setfill('0') << insAddress
            << "\nFonction: `" << funcName << "`"
            << "\nInstruction: " << current_disasm << std::endl;

        std::string output = oss.str();
        key_out.write(output.c_str(), output.size());
    }
}

VOID Fini(INT32 code, VOID *v)
{
    if (key_out.str().empty())
    {
        key_out << "PINGETNAME_V2: no-data" << std::endl;
    }

    if (gHeaderWritten && !gResolvedFromImage)
    {
        std::ostringstream oss;
        oss << "Fonction: `<unknown>`" << std::endl;
        oss << "Instruction: <not-resolved-from-image>" << std::endl;
        std::string output = oss.str();
        key_out.write(output.c_str(), output.size());
    }

    std::ofstream file("data/log/getName.log", std::ios::out | std::ios::trunc);
    if (!file.is_open())
    {
        std::cerr << "Erreur lors de l'ouverture du fichier data/log/getName.log" << std::endl;
        return;
    }
    file << key_out.str();
    file.close();
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
        return -1;

    LoadResultAnalyse("data/log/analyse.log");

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
