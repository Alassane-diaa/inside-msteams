#include "pin.H"
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
    __declspec(dllimport) int __stdcall CreateDirectoryA(const char* lpPathName, void* lpSecurityAttributes);
}

//------------------------------------------------------------------------------
// Command line switches
//------------------------------------------------------------------------------
KNOB<std::string> KnobConfigFile(KNOB_MODE_WRITEONCE,
                                 "pintool",        // namespace pour vos knobs
                                 "config",         // option --config
                                 "pin_config.ini", // valeur par défaut
                                 "Path to your PIN tool configuration file");

//------------------------------------------------------------------------------
// Global logging and tracing streams
//------------------------------------------------------------------------------
static std::ofstream trace_file;
static std::ofstream log_file;
static std::mutex trace_mutex; // Protège l'écriture du fichier trace

//------------------------------------------------------------------------------
// Configured registers and memory-read size (in bytes)
//------------------------------------------------------------------------------
std::vector<REG> configured_regs;
static size_t memory_size_to_read;

//------------------------------------------------------------------------------
// Liste des instructions à ignorer
// -----------------------------------------------------------------------------
static std::vector<std::string> skip_functions;
static std::vector<std::string> skip_libs;
static std::vector<std::string> target_libs;  // Mode whitelist: SEULEMENT ces libs
static std::vector<std::string> not_skip_libs;

//------------------------------------------------------------------------------
// Map from string names in config to PIN REG identifiers
//------------------------------------------------------------------------------
static std::map<std::string, REG> String2Reg = {
    {"REG_RIP", LEVEL_BASE::REG_RIP}, 
    {"REG_RAX", LEVEL_BASE::REG_RAX}, 
    {"REG_RBX", LEVEL_BASE::REG_RBX}, 
    {"REG_RCX", LEVEL_BASE::REG_RCX}, 
    {"REG_RDX", LEVEL_BASE::REG_RDX}, 
    {"REG_RSI", LEVEL_BASE::REG_RSI}, 
    {"REG_RDI", LEVEL_BASE::REG_RDI}, 
    {"REG_R8", LEVEL_BASE::REG_R8}, 
    {"REG_R9", LEVEL_BASE::REG_R9}, 
    {"REG_R10", LEVEL_BASE::REG_R10}, 
    {"REG_R11", LEVEL_BASE::REG_R11}, 
    {"REG_R12", LEVEL_BASE::REG_R12}, 
    {"REG_R13", LEVEL_BASE::REG_R13}, {"REG_R14", LEVEL_BASE::REG_R14}, {"REG_R15", LEVEL_BASE::REG_R15}, {"REG_XMM0", LEVEL_BASE::REG_XMM0}, {"REG_XMM1", LEVEL_BASE::REG_XMM1}, {"REG_XMM2", LEVEL_BASE::REG_XMM2}, {"REG_XMM3", LEVEL_BASE::REG_XMM3}, {"REG_XMM4", LEVEL_BASE::REG_XMM4}, {"REG_XMM5", LEVEL_BASE::REG_XMM5}, {"REG_XMM6", LEVEL_BASE::REG_XMM6}, {"REG_XMM7", LEVEL_BASE::REG_XMM7},

    {"REG_YMM0", LEVEL_BASE::REG_YMM0},
    {"REG_YMM1", LEVEL_BASE::REG_YMM1},
    {"REG_YMM2", LEVEL_BASE::REG_YMM2},
    {"REG_YMM3", LEVEL_BASE::REG_YMM3},
    {"REG_YMM4", LEVEL_BASE::REG_YMM4},
    {"REG_YMM5", LEVEL_BASE::REG_YMM5},
    {"REG_YMM6", LEVEL_BASE::REG_YMM6},
    {"REG_YMM7", LEVEL_BASE::REG_YMM7},

    {"REG_ZMM0", LEVEL_BASE::REG_ZMM0},
    {"REG_ZMM1", LEVEL_BASE::REG_ZMM1},
    {"REG_ZMM2", LEVEL_BASE::REG_ZMM2},
    {"REG_ZMM3", LEVEL_BASE::REG_ZMM3},
    {"REG_ZMM4", LEVEL_BASE::REG_ZMM4},
    {"REG_ZMM5", LEVEL_BASE::REG_ZMM5},
    {"REG_ZMM6", LEVEL_BASE::REG_ZMM6},
    {"REG_ZMM7", LEVEL_BASE::REG_ZMM7}};

//------------------------------------------------------------------------------
// Helper: extract filename from full path (case-insensitive matching)
//------------------------------------------------------------------------------
static std::string get_filename(const std::string &path)
{
  auto pos = path.find_last_of("\\/");
  std::string filename = (pos == std::string::npos) ? path : path.substr(pos + 1);
  // Convertir en minuscules pour comparaison insensible à la casse
  for (auto &c : filename) c = std::tolower(c);
  return filename;
}

//------------------------------------------------------------------------------
// Helper: trim whitespace from both ends of a string
//------------------------------------------------------------------------------
static std::string trim(const std::string &s)
{
  const auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos)
    return {};
  const auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

//------------------------------------------------------------------------------
// Load register list and memory-size from INI-style config
// Returns true if at least one register was configured
//------------------------------------------------------------------------------
bool load_register_config(const std::string &filename)
{
  std::ifstream config(filename);
  if (!config)
  {
    std::cerr << "Erreur : impossible d'ouvrir le fichier de configuration '"
              << filename << "'." << std::endl;
    return false;
  }

  std::string line;
  bool in_general_section = false;

  memory_size_to_read = 0;
  while (std::getline(config, line))
  {
    // Supprimer les commentaires
    auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos)
      line = line.substr(0, comment_pos);

    // Supprimer les espaces en début/fin
    line = trim(line);
    if (line.empty())
      continue;

    if (line.empty())
      continue;

    // Détection de section
    if (line == "[GENERAL]")
    {
      in_general_section = true;
      continue;
    }
    else if (!line.empty() && line.front() == '[' && line.back() == ']')
    {
      in_general_section = false;
      continue;
    }

    if (!in_general_section)
      continue;

    // Lire la ligne REGISTERS =
    if (line.rfind("REGISTERS", 0) == 0)
    {
      auto equal_pos = line.find('=');
      if (equal_pos == std::string::npos)
        continue;

      std::string reg_list = line.substr(equal_pos + 1);
      std::istringstream ss(reg_list);
      std::string reg_name;

      while (ss >> reg_name)
      {
        auto it = String2Reg.find(reg_name);
        if (it != String2Reg.end() && it->first != "REG_RIP")
        {
          configured_regs.push_back(it->second);
        }
        else
        {
          std::cerr << "Avertissement : registre inconnu ou ignoré '"
                    << reg_name << "'" << std::endl;
        }
      }
    }

    if (line.rfind("MEMORY", 0) == 0)
    {
      auto equal_pos = line.find('=');
      if (equal_pos == std::string::npos)
        continue;

      std::string memory_size_str = line.substr(equal_pos + 1);

      // Conversion de la taille de la mémoire en entier
      int memory_size = std::stoi(memory_size_str);

      // Vérifier que la taille de la mémoire est 0, 8, 16, ou 32
      if (memory_size == 0 || memory_size == 8 || memory_size == 16 ||
          memory_size == 32 || memory_size == 64)
      {
        // std::cout << "Taille de mémoire configurée : " << memory_size << "
        // octets" << std::endl;
        memory_size_to_read = memory_size;
      }
      else
      {
        std::cerr << "Avertissement : taille de mémoire invalide '"
                  << memory_size
                  << "'. Les valeurs autorisées sont 8, 16, 32 ou 64."
                  << std::endl;
        continue;
      }

      // On peut sortir après avoir lu la ligne de la mémoire
      break;
    }
  }

  return !configured_regs.empty();
}

bool load_filter_config(const std::string &filename)
{
  fprintf(stderr, ">>> load_filter_config START: %s\n", filename.c_str());
  fflush(stderr);
  
  std::ifstream config(filename);
  if (!config)
  {
    fprintf(stderr, ">>> FAILED to open config!\n");
    fflush(stderr);
    return false;
  }
  fprintf(stderr, ">>> Config opened OK\n");
  fflush(stderr);

  std::string line;
  bool in_filters = false;
  while (std::getline(config, line))
  {
    // strip comments et espaces
    auto p = line.find('#');
    if (p != std::string::npos)
      line = line.substr(0, p);
    line = trim(line);
    if (line.empty())
      continue;

    if (line == "[FILTERS]")
    {
      in_filters = true;
      continue;
    }
    else if (line.front() == '[' && line.back() == ']')
    {
      in_filters = false;
      continue;
    }

    if (!in_filters)
      continue;

    std::cerr << ">>> FILTER LINE: " << line << std::endl;

    if (line.rfind("FILTER_FUNCTION", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq == std::string::npos)
        continue;
      std::string list = trim(line.substr(eq + 1));
      std::istringstream ss(list);
      std::string fn;
      while (std::getline(ss, fn, ','))
      {
        skip_functions.push_back(trim(fn));
      }
    }

    if (line.rfind("FILTER_LIB", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq == std::string::npos)
        continue;
      std::string list = trim(line.substr(eq + 1));
      std::istringstream ss(list);
      std::string lib;
      while (std::getline(ss, lib, ','))
      {
        skip_libs.push_back(trim(lib));
      }
    }

    // Mode whitelist: SEULEMENT ces libs sont instrumentées
    if (line.rfind("TARGET_LIB", 0) == 0)
    {
      std::cout << "DEBUG: Found TARGET_LIB line: " << line << std::endl;
      auto eq = line.find('=');
      if (eq == std::string::npos)
        continue;
      std::string list = trim(line.substr(eq + 1));
      std::cout << "DEBUG: TARGET_LIB list = " << list << std::endl;
      std::istringstream ss(list);
      std::string lib;
      while (std::getline(ss, lib, ','))
      {
        std::cout << "DEBUG: Adding target lib: " << trim(lib) << std::endl;
        target_libs.push_back(trim(lib));
      }
    }
  }
  std::cout << std::endl
            << "Librairies ignorées (" << skip_libs.size() << ") | Target libs: " << target_libs.size() << std::endl;
  for (auto lib_name : skip_libs)
  {
    std::cout << "\t" << lib_name << std::endl;
  }
  if (!target_libs.empty())
  {
    std::cout << std::endl
              << "Mode WHITELIST actif - SEULEMENT ces libs:" << std::endl;
    for (auto lib_name : target_libs)
    {
      std::cout << "\t" << lib_name << std::endl;
    }
  }
  std::cerr << ">>> target_libs count: " << target_libs.size() << std::endl;
  return true;
}

//------------------------------------------------------------------------------
// Thread-safe write to trace_file
//------------------------------------------------------------------------------
inline void WriteData(const char *data, size_t size)
{
  std::lock_guard<std::mutex> lock(trace_mutex);
  trace_file.write(data, size);
}

//------------------------------------------------------------------------------
// Record register contents (including XMM/YMM) to trace
//------------------------------------------------------------------------------
const uint64_t zero = 0;

VOID record_data(const CONTEXT *ctx)
{
  // Écriture des valeurs en registre
  for (REG reg : configured_regs)
  {
    if (REG_is_zmm(reg))
    {
      UINT8 zmm_val[64];
      PIN_GetContextRegval(ctx, reg, zmm_val);
      // std::cout << "ZMM" << std::endl;
      WriteData((const char *)zmm_val, 64);
    }
    else if (REG_is_ymm(reg))
    {
      UINT8 ymm_val[32];
      PIN_GetContextRegval(ctx, reg, ymm_val);
      // std::cout << "YMM" << std::endl;
      WriteData((const char *)ymm_val, 32);
    }
    else if (REG_is_xmm(reg))
    {
      UINT8 xmm_val[16];
      PIN_GetContextRegval(ctx, reg, xmm_val);
      // std::cout << "XMM" << std::endl;
      WriteData((const char *)xmm_val, 16);
    }
    else
    {
      uint64_t val = PIN_GetContextReg(ctx, reg);
      WriteData((const char *)&val, 8);
    }
  }
}

//------------------------------------------------------------------------------
// Record instruction pointer and register/memory snapshot
//------------------------------------------------------------------------------
VOID record_fragment(uint64_t ip, const CONTEXT *ctx, void *memory_ea)
{
  // Écriture de l'adresse d'instruction (IP) : 8 octets
  WriteData((const char *)&ip, 8);

  // Enregistrement de l'état des registres (taille fixe si configured_regs est
  // constant)
  record_data(ctx);

  // Enregistrement d'une zone mémoire de taille fixe : memory_size_to_read
  // octets On alloue un tampon de taille fixe (la taille est fixée par
  // memory_size_to_read)
  UINT8 buffer[64] = {0};

  if (memory_ea && memory_size_to_read > 0)
  {
    // On lit directement dans buffer
    PIN_SafeCopy(buffer, memory_ea, memory_size_to_read);
  }
  // On écrit exactement memory_size_to_read octets (les restants sont à zéro)
  WriteData((const char *)buffer, memory_size_to_read);
}

VOID record_register(uint64_t ip, const CONTEXT *ctx)
{
  // Écriture de l'adresse d'instruction (IP) : 8 octets
  WriteData((const char *)&ip, 8);
  record_data(ctx);
}

//------------------------------------------------------------------------------
// Instrumentation callback: choose appropriate recorder per instruction
//------------------------------------------------------------------------------
VOID Instructions(INS ins, VOID *v)
{
  // On ignore les instructions présentes dans la liste de filtrage
  if (INS_IsCall(ins))
  {
    RTN rtn = RTN_FindByAddress(INS_Address(ins));
    if (RTN_Valid(rtn))
    {
      std::string rtn_name = RTN_Name(rtn);
      for (auto &skip : skip_functions)
      {
        if (rtn_name == skip)
        {
          return;
        }
      }
    }
  }
  {
    PIN_LockClient();
    IMG img = IMG_FindByAddress(INS_Address(ins));
    PIN_UnlockClient();
    if (IMG_Valid(img))
    {
      std::string img_name = IMG_Name(img);
      std::string img_filename = get_filename(img_name);
      
      // MODE WHITELIST: Si target_libs est défini, on n'instrumente QUE ces libs
      if (!target_libs.empty())
      {
        bool is_target = false;
        for (auto &target : target_libs)
        {
          std::string target_lower = target;
          for (auto &c : target_lower) c = std::tolower(c);
          if (img_filename == target_lower || img_filename.find(target_lower) != std::string::npos)
          {
            is_target = true;
            break;
          }
        }
        if (!is_target)
        {
          return;  // Ignorer tout ce qui n'est pas dans target_libs
        }
      }
      else
      {
        // Mode blacklist classique (FILTER_LIB)
        for (auto &skip : skip_libs)
        {
          std::string skip_lower = skip;
          for (auto &c : skip_lower) c = std::tolower(c);
          if (img_filename == skip_lower || img_filename.find(skip_lower) != std::string::npos)
          {
            return;
          }
        }
      }
      
      bool already_skipped = false;
      for (auto &skip : not_skip_libs)
      {
        if (img_name == skip)
        {
          already_skipped = true;
        }
      }
      if (!already_skipped)
      {
        not_skip_libs.push_back(img_name);
      }
    }
    else
    {
      // Image invalide et mode whitelist actif => ignorer
      if (!target_libs.empty())
      {
        return;
      }
    }
  }
  // On ignore les instructions de contrôle de flux
  if (INS_IsControlFlow(ins))
    return;

  if (memory_size_to_read > 0)
  {
    // Si l'instruction a un opérande mémoire en lecture, on passe l'adresse
    // réelle
    if (INS_MemoryOperandCount(ins) > 0 && INS_MemoryOperandIsRead(ins, 0))
    {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_fragment,
                     IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYOP_EA, 0,
                     IARG_END);
    }
    else
    {
      // Sinon, on passe un pointeur nul pour forcer l'utilisation d'un buffer
      // de zéros
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_fragment,
                     IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT,
                     (ADDRINT) nullptr, IARG_END);
    }
  }
  else
  {
    // Pas d'enregistrement mémoire : uniquement IP et registre
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_register, IARG_INST_PTR,
                   IARG_CONST_CONTEXT, IARG_END);
  }
}

//------------------------------------------------------------------------------
// Log loaded modules
//------------------------------------------------------------------------------
VOID ImageLoad(IMG img, VOID *v)
{
  log_file << "Module chargé : " << IMG_Name(img) << " Adresse de base : 0x"
           << std::hex << std::setw(16) << std::setfill('0')
           << IMG_LowAddress(img) << std::endl;
}

//------------------------------------------------------------------------------
// Finalization: close files
//------------------------------------------------------------------------------
VOID Fini(INT32 code, VOID *v)
{
  if (trace_file.is_open())
    trace_file.close();
  if (log_file.is_open())
    log_file.close();
  std::cout << std::endl
            << "Librairies non ignorées :" << std::endl;
  for (auto lib_name : not_skip_libs)
  {
    std::cout << "\t" << lib_name << std::endl;
  }
}

int main(int argc, char *argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
  {
    std::cerr << "L'initialisation du PIN a échoué." << std::endl;
    return -1;
  }

  // On s'assure que le dossier log existe (on le crée sinon)
  CreateDirectoryA("data", NULL);
  CreateDirectoryA("data\\log", NULL);
  const char* log_path = "data\\log\\trace.log";
  const char* trace_path = "data\\log\\trace.binary";
  
  // Ouverture du fichier log et de la trace
  log_file.open(log_path);
  if (!log_file)
  {
    std::cerr << "Erreur: impossible d'ouvrir data/log/trace.log." << std::endl;
    return -1;
  }

  trace_file.open(trace_path, std::ios::binary);
  if (!trace_file)
  {
    std::cerr << "Erreur: impossible d'ouvrir data/log/trace.binary." << std::endl;
    return -1;
  }

  // Lecture du fichier de configuration
  std::string cfg = KnobConfigFile.Value();
  if (!load_register_config(cfg) || !load_filter_config(cfg))
  {
    std::cerr << "Erreur: échec du chargement de " << cfg << std::endl;
    return -1;
  }

  IMG_AddInstrumentFunction(ImageLoad, 0);
  INS_AddInstrumentFunction(Instructions, 0);
  PIN_AddFiniFunction(Fini, 0);

  PIN_StartProgram();
  return 0;
}
