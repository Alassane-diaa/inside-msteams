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
#include <atomic>

extern "C" {
    __declspec(dllimport) int __stdcall CreateDirectoryA(const char* lpPathName, void* lpSecurityAttributes);
}

//------------------------------------------------------------------------------
// Command line switches
//------------------------------------------------------------------------------
KNOB<std::string> KnobConfigFile(KNOB_MODE_WRITEONCE,
                                 "pintool",
                                 "config",
                                 "pin_config.ini",
                                 "Path to your PIN tool configuration file");

//------------------------------------------------------------------------------
// Global logging and tracing streams
//------------------------------------------------------------------------------
static std::ofstream trace_file;
static std::ofstream log_file;
static std::mutex trace_mutex;

//------------------------------------------------------------------------------
// Configured registers and memory-read size (in bytes)
//------------------------------------------------------------------------------
std::vector<REG> configured_regs;
static size_t memory_size_to_read;

//------------------------------------------------------------------------------
// Function-entry tracing parameters
//------------------------------------------------------------------------------
static uint64_t max_ins_per_function = 10; // from config: MAX_INS_PER_FUNC (0 = illimité, default 10)

// Per-thread tracking of how deep we are into the current function
// Key = thread id, Value = remaining instructions to trace in current function
static std::map<THREADID, uint64_t> thread_budget;
static std::mutex budget_mutex;

// Statistics
static std::atomic<uint64_t> total_ins_seen{0};
static std::atomic<uint64_t> total_ins_traced{0};

//------------------------------------------------------------------------------
// Filter lists
//------------------------------------------------------------------------------
static std::vector<std::string> skip_functions;
static std::vector<std::string> skip_libs;
static std::vector<std::string> target_libs;
static std::vector<std::string> not_skip_libs;
static std::string filter_mode = "none";

//------------------------------------------------------------------------------
// Register name -> PIN REG identifier
//------------------------------------------------------------------------------
static std::map<std::string, REG> String2Reg = {
    {"REG_RIP", LEVEL_BASE::REG_RIP},
    {"REG_RAX", LEVEL_BASE::REG_RAX},
    {"REG_RBX", LEVEL_BASE::REG_RBX},
    {"REG_RCX", LEVEL_BASE::REG_RCX},
    {"REG_RDX", LEVEL_BASE::REG_RDX},
    {"REG_RSI", LEVEL_BASE::REG_RSI},
    {"REG_RDI", LEVEL_BASE::REG_RDI},
    {"REG_R8",  LEVEL_BASE::REG_R8},
    {"REG_R9",  LEVEL_BASE::REG_R9},
    {"REG_R10", LEVEL_BASE::REG_R10},
    {"REG_R11", LEVEL_BASE::REG_R11},
    {"REG_R12", LEVEL_BASE::REG_R12},
    {"REG_R13", LEVEL_BASE::REG_R13},
    {"REG_R14", LEVEL_BASE::REG_R14},
    {"REG_R15", LEVEL_BASE::REG_R15},
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
    {"REG_ZMM0", LEVEL_BASE::REG_ZMM0},
    {"REG_ZMM1", LEVEL_BASE::REG_ZMM1},
    {"REG_ZMM2", LEVEL_BASE::REG_ZMM2},
    {"REG_ZMM3", LEVEL_BASE::REG_ZMM3},
    {"REG_ZMM4", LEVEL_BASE::REG_ZMM4},
    {"REG_ZMM5", LEVEL_BASE::REG_ZMM5},
    {"REG_ZMM6", LEVEL_BASE::REG_ZMM6},
    {"REG_ZMM7", LEVEL_BASE::REG_ZMM7}
};

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------
static std::string get_filename(const std::string &path)
{
  auto pos = path.find_last_of("\\/");
  std::string filename = (pos == std::string::npos) ? path : path.substr(pos + 1);
  for (auto &c : filename) c = std::tolower(c);
  return filename;
}

static std::string trim(const std::string &s)
{
  const auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return {};
  const auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

//------------------------------------------------------------------------------
// Load [GENERAL] config + function-entry parameters
//------------------------------------------------------------------------------
bool load_register_config(const std::string &filename)
{
  std::ifstream config(filename);
  if (!config)
  {
    std::cerr << "Erreur : impossible d'ouvrir '" << filename << "'." << std::endl;
    return false;
  }

  std::string line;
  bool in_general = false;
  memory_size_to_read = 0;

  while (std::getline(config, line))
  {
    auto cp = line.find('#');
    if (cp != std::string::npos) line = line.substr(0, cp);
    line = trim(line);
    if (line.empty()) continue;

    if (line == "[GENERAL]") { in_general = true; continue; }
    else if (line.front() == '[' && line.back() == ']') { in_general = false; continue; }
    if (!in_general) continue;

    if (line.rfind("REGISTERS", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      std::istringstream ss(line.substr(eq + 1));
      std::string rn;
      while (ss >> rn)
      {
        auto it = String2Reg.find(rn);
        if (it != String2Reg.end() && it->first != "REG_RIP")
          configured_regs.push_back(it->second);
        else
          std::cerr << "Avertissement : registre inconnu ou ignoré '" << rn << "'" << std::endl;
      }
    }
    else if (line.rfind("MEMORY", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      int ms = std::stoi(trim(line.substr(eq + 1)));
      if (ms == 0 || ms == 8 || ms == 16 || ms == 32 || ms == 64)
        memory_size_to_read = ms;
      else
        std::cerr << "Avertissement : taille mémoire invalide " << ms << std::endl;
    }
    else if (line.rfind("MAX_INS_PER_FUNC", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq != std::string::npos)
        max_ins_per_function = std::stoull(trim(line.substr(eq + 1)));
    }
  }
  return !configured_regs.empty();
}

bool load_filter_config(const std::string &filename)
{
  std::ifstream config(filename);
  if (!config) return false;

  std::string line;
  bool in_filters = false;
  while (std::getline(config, line))
  {
    auto p = line.find('#');
    if (p != std::string::npos) line = line.substr(0, p);
    line = trim(line);
    if (line.empty()) continue;

    if (line == "[FILTERS]") { in_filters = true; continue; }
    else if (line.front() == '[' && line.back() == ']') { in_filters = false; continue; }
    if (!in_filters) continue;

    if (line.rfind("MODE", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq != std::string::npos)
      {
        std::string mode = trim(line.substr(eq + 1));
        for (auto &c : mode) c = std::tolower(c);
        if (mode == "whitelist" || mode == "blacklist" || mode == "none")
          filter_mode = mode;
      }
    }
    else if (line.rfind("FILTER_FUNCTION", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      std::istringstream ss(trim(line.substr(eq + 1)));
      std::string fn;
      while (std::getline(ss, fn, ',')) skip_functions.push_back(trim(fn));
    }
    else if (line.rfind("FILTER_LIB", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      std::istringstream ss(trim(line.substr(eq + 1)));
      std::string lib;
      while (std::getline(ss, lib, ',')) skip_libs.push_back(trim(lib));
    }
    else if (line.rfind("TARGET_LIB", 0) == 0)
    {
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      std::istringstream ss(trim(line.substr(eq + 1)));
      std::string lib;
      while (std::getline(ss, lib, ',')) target_libs.push_back(trim(lib));
    }
  }

  std::cout << "[TraceBuilder_FuncEntry] Mode filtrage : " << filter_mode << std::endl;
  return true;
}

//------------------------------------------------------------------------------
// Thread-safe write
//------------------------------------------------------------------------------
inline void WriteData(const char *data, size_t size)
{
  std::lock_guard<std::mutex> lock(trace_mutex);
  trace_file.write(data, size);
}

//------------------------------------------------------------------------------
// Record register contents
//------------------------------------------------------------------------------
const uint64_t zero = 0;

VOID record_data(const CONTEXT *ctx)
{
  for (REG reg : configured_regs)
  {
    if (REG_is_zmm(reg))
    {
      UINT8 val[64];
      PIN_GetContextRegval(ctx, reg, val);
      WriteData((const char *)val, 64);
    }
    else if (REG_is_ymm(reg))
    {
      UINT8 val[32];
      PIN_GetContextRegval(ctx, reg, val);
      WriteData((const char *)val, 32);
    }
    else if (REG_is_xmm(reg))
    {
      UINT8 val[16];
      PIN_GetContextRegval(ctx, reg, val);
      WriteData((const char *)val, 16);
    }
    else
    {
      uint64_t val = PIN_GetContextReg(ctx, reg);
      WriteData((const char *)&val, 8);
    }
  }
}

//------------------------------------------------------------------------------
// Analysis callback: called when a function is entered (CALL target)
// Resets the per-thread instruction budget
//------------------------------------------------------------------------------
VOID on_function_entry(THREADID tid)
{
  if (max_ins_per_function == 0) return; // illimité : pas de budget à gérer
  std::lock_guard<std::mutex> lock(budget_mutex);
  thread_budget[tid] = max_ins_per_function;
}

//------------------------------------------------------------------------------
// Record with memory operand (guarded by budget)
//------------------------------------------------------------------------------
VOID record_fragment(uint64_t ip, const CONTEXT *ctx, void *memory_ea, THREADID tid)
{
  total_ins_seen.fetch_add(1, std::memory_order_relaxed);

  if (max_ins_per_function > 0)
  {
    std::lock_guard<std::mutex> lock(budget_mutex);
    auto it = thread_budget.find(tid);
    if (it == thread_budget.end() || it->second == 0)
      return; // no budget left
    it->second--;
  }

  total_ins_traced.fetch_add(1, std::memory_order_relaxed);

  WriteData((const char *)&ip, 8);
  record_data(ctx);

  UINT8 buffer[64] = {0};
  if (memory_ea && memory_size_to_read > 0)
    PIN_SafeCopy(buffer, memory_ea, memory_size_to_read);
  WriteData((const char *)buffer, memory_size_to_read);
}

//------------------------------------------------------------------------------
// Record without memory operand (guarded by budget)
//------------------------------------------------------------------------------
VOID record_register(uint64_t ip, const CONTEXT *ctx, THREADID tid)
{
  total_ins_seen.fetch_add(1, std::memory_order_relaxed);

  if (max_ins_per_function > 0)
  {
    std::lock_guard<std::mutex> lock(budget_mutex);
    auto it = thread_budget.find(tid);
    if (it == thread_budget.end() || it->second == 0)
      return;
    it->second--;
  }

  total_ins_traced.fetch_add(1, std::memory_order_relaxed);

  WriteData((const char *)&ip, 8);
  record_data(ctx);
}

//------------------------------------------------------------------------------
// Should this image be instrumented ?
//------------------------------------------------------------------------------
static bool should_instrument_image(const std::string &img_name)
{
  std::string img_filename = get_filename(img_name);

  if (filter_mode == "whitelist")
  {
    for (auto &target : target_libs)
    {
      std::string tl = target;
      for (auto &c : tl) c = std::tolower(c);
      if (img_filename == tl || img_filename.find(tl) != std::string::npos)
        return true;
    }
    return false;
  }
  else if (filter_mode == "blacklist")
  {
    for (auto &skip : skip_libs)
    {
      std::string sl = skip;
      for (auto &c : sl) c = std::tolower(c);
      if (img_filename == sl || img_filename.find(sl) != std::string::npos)
        return false;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
// Routine-level instrumentation: insert budget reset at each function entry
//------------------------------------------------------------------------------
VOID RoutineInstrumentation(RTN rtn, VOID *v)
{
  if (!RTN_Valid(rtn)) return;

  // Check skip_functions
  std::string rtn_name = RTN_Name(rtn);
  for (auto &skip : skip_functions)
    if (rtn_name == skip) return;

  // Check image filter
  SEC sec = RTN_Sec(rtn);
  if (SEC_Valid(sec))
  {
    IMG img = SEC_Img(sec);
    if (IMG_Valid(img))
    {
      if (!should_instrument_image(IMG_Name(img))) return;

      // Track non-skipped libs
      std::string img_name = IMG_Name(img);
      bool already = false;
      for (auto &s : not_skip_libs) if (img_name == s) { already = true; break; }
      if (!already) not_skip_libs.push_back(img_name);
    }
    else if (filter_mode == "whitelist") return;
  }

  RTN_Open(rtn);

  // Insert call to reset budget at function entry
  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)on_function_entry,
                 IARG_THREAD_ID, IARG_END);

  // Instrument each instruction in the routine
  for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
  {
    if (INS_IsControlFlow(ins)) continue;

    if (memory_size_to_read > 0)
    {
      if (INS_MemoryOperandCount(ins) > 0 && INS_MemoryOperandIsRead(ins, 0))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_fragment,
                       IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYOP_EA, 0,
                       IARG_THREAD_ID, IARG_END);
      else
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_fragment,
                       IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, (ADDRINT)nullptr,
                       IARG_THREAD_ID, IARG_END);
    }
    else
    {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_register,
                     IARG_INST_PTR, IARG_CONST_CONTEXT,
                     IARG_THREAD_ID, IARG_END);
    }
  }

  RTN_Close(rtn);
}

//------------------------------------------------------------------------------
// Log loaded modules
//------------------------------------------------------------------------------
VOID ImageLoad(IMG img, VOID *v)
{
  log_file << "Module chargé : " << IMG_Name(img)
           << " Adresse de base : 0x" << std::hex << std::setw(16)
           << std::setfill('0') << IMG_LowAddress(img) << std::endl;
}

//------------------------------------------------------------------------------
// Finalization
//------------------------------------------------------------------------------
VOID Fini(INT32 code, VOID *v)
{
  if (trace_file.is_open()) trace_file.close();
  if (log_file.is_open()) log_file.close();

  std::cout << std::endl << "[TraceBuilder_FuncEntry] Statistiques:" << std::endl;
  std::cout << "  Instructions vues    : " << total_ins_seen.load() << std::endl;
  std::cout << "  Instructions tracees : " << total_ins_traced.load() << std::endl;
  double ratio = total_ins_seen.load() > 0
    ? 100.0 * total_ins_traced.load() / total_ins_seen.load()
    : 0.0;
  std::cout << "  Ratio de tracage     : " << ratio << " %" << std::endl;
  std::cout << "  Max par fonction     : " << (max_ins_per_function ? std::to_string(max_ins_per_function) : "illimite") << std::endl;

  std::cout << std::endl << "Librairies non ignorees :" << std::endl;
  for (auto &lib : not_skip_libs)
    std::cout << "\t" << lib << std::endl;
}

int main(int argc, char *argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
  {
    std::cerr << "L'initialisation de PIN a echoue." << std::endl;
    return -1;
  }

  CreateDirectoryA("data", NULL);
  CreateDirectoryA("data\\log", NULL);

  log_file.open("data\\log\\trace.log");
  if (!log_file)
  {
    std::cerr << "Erreur: impossible d'ouvrir data/log/trace.log." << std::endl;
    return -1;
  }

  trace_file.open("data\\log\\trace.binary", std::ios::binary);
  if (!trace_file)
  {
    std::cerr << "Erreur: impossible d'ouvrir data/log/trace.binary." << std::endl;
    return -1;
  }

  std::string cfg = KnobConfigFile.Value();
  if (!load_register_config(cfg) || !load_filter_config(cfg))
  {
    std::cerr << "Erreur: echec du chargement de " << cfg << std::endl;
    return -1;
  }

  std::cout << "[TraceBuilder_FuncEntry] MAX_INS_PER_FUNC = " << max_ins_per_function << std::endl;

  IMG_AddInstrumentFunction(ImageLoad, 0);
  RTN_AddInstrumentFunction(RoutineInstrumentation, 0);
  PIN_AddFiniFunction(Fini, 0);

  PIN_StartProgram();
  return 0;
}
