#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <map>
#include "pin.H"

static std::stringstream key_out;

ADDRINT insAddress = 0;
ADDRINT delta = 0;
std::string libName = "";
std::string regName = "";

void LoadResultAnalyse(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file) return;

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

VOID ImageLoad(IMG img, VOID *v)
{
    std::string s = IMG_Name(img);
    if (s.find(libName) != std::string::npos)
    {
        ADDRINT libAddress = IMG_LowAddress(img);
        insAddress = libAddress + delta;

        std::ostringstream oss;
        oss << "Librairie: " << libName << std::endl;
        oss << "Delta: " << delta << std::endl;
        oss << "Adresse: 0x" << std::hex << std::setw(16) << std::setfill('0') << insAddress << std::endl;

        // On cherche la routine par adresse immédiatement
        RTN rtn = RTN_FindByAddress(insAddress);
        std::string funcName = RTN_Valid(rtn) ? RTN_Name(rtn) : "<unknown>";
        oss << "Fonction: `" << funcName << "`" << std::endl;
        oss << "Instruction: (Trouvée à l'entrée de la routine par StructTracker)" << std::endl;

        std::string output = oss.str();
        key_out.write(output.c_str(), output.size());
    }
}

VOID Fini(INT32 code, VOID *v)
{
    std::ofstream file("data/log/getName.log", std::ios::out | std::ios::trunc);
    file << key_out.str();
    file.close();
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return -1;
    LoadResultAnalyse("data/log/analyse.log");
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}