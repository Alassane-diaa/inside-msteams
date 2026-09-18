#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>

// Fichier de sortie
std::ofstream outFile;

// Fonction appelée quand une nouvelle image (DLL/EXE) est chargée
VOID ImageLoad(IMG img, VOID *v)
{
    // Nom de l'image
    std::string imgName = IMG_Name(img);
    
    // Parcourir toutes les sections
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // Parcourir toutes les routines dans cette section
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            std::string rtnName = RTN_Name(rtn);
            ADDRINT rtnAddr = RTN_Address(rtn);
            
            outFile << imgName << " | " << rtnName 
                    << " @ 0x" << std::hex << rtnAddr << std::dec
                    << std::endl;
        }
    }
    
    // Aussi parcourir les symboles
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
    {
        std::string symName = SYM_Name(sym);
        ADDRINT symAddr = SYM_Address(sym);
        
        outFile << imgName << " | " << symName 
                << " @ 0x" << std::hex << symAddr << std::dec
                << std::endl;
    }
    
    outFile.flush();
}

// Fonction appelée à la fin de l'exécution
VOID Fini(INT32 code, VOID *v)
{
    outFile.close();
}

// Affichage de l'aide
INT32 Usage()
{
    std::cerr << "This tool lists all loaded libraries and their functions." << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

// Point d'entrée principal
int main(int argc, char *argv[])
{
    // Initialiser Pin
    PIN_InitSymbols();
    
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    
    // Ouvrir le fichier de sortie
    outFile.open("library_functions.txt");
    
    if (!outFile.is_open())
    {
        std::cerr << "Error: Could not open output file 'library_functions.txt'" << std::endl;
        return -1;
    }
    
    // Enregistrer la callback pour le chargement d'images
    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    // Enregistrer la callback de fin
    PIN_AddFiniFunction(Fini, 0);
    
    // Démarrer le programme
    PIN_StartProgram();
    
    return 0;
}
