#include "pin.H"
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
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
																 "pintool",
																 "config",
																 "pin_config.ini",
																 "Path to your PIN tool configuration file");

//------------------------------------------------------------------------------
// Global logging and tracing streams
//------------------------------------------------------------------------------
static std::ofstream log_file;
static std::mutex trace_mutex;

struct FunctionTrace
{
	std::string display_name;
	std::string file_path;
	std::ofstream stream;
	bool activated = false;
};

static std::map<std::string, FunctionTrace> function_traces;

// For single-function-per-run mode: track already-skipped functions and the current traced function
static std::set<std::string> already_skipped_functions;
static std::string current_traced_function;
static std::string current_traced_file_path;
static bool function_traced = false;

//------------------------------------------------------------------------------
// Configured registers and memory-read size (in bytes)
//------------------------------------------------------------------------------
std::vector<REG> configured_regs;
static size_t memory_size_to_read;

//------------------------------------------------------------------------------
// Liste des instructions à ignorer
//------------------------------------------------------------------------------
static std::vector<std::string> skip_functions;
static std::vector<std::string> skip_libs;
static std::vector<std::string> target_libs;
static std::vector<std::string> not_skip_libs;

// Mode de filtrage : "whitelist", "blacklist", "none"
static std::string filter_mode = "none";

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
// Helper: extract filename from full path (case-insensitive matching)
//------------------------------------------------------------------------------
static std::string get_filename(const std::string &path)
{
	auto pos = path.find_last_of("\\/");
	std::string filename = (pos == std::string::npos) ? path : path.substr(pos + 1);
	for (auto &c : filename) c = std::tolower(static_cast<unsigned char>(c));
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
// Helper: sanitize a string so it can be used in a filename
//------------------------------------------------------------------------------
static std::string sanitize_for_filename(const std::string &value)
{
	std::string result;
	result.reserve(value.size());

	for (unsigned char ch : value)
	{
		if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.')
			result.push_back(static_cast<char>(ch));
		else
			result.push_back('_');
	}

	while (!result.empty() && result.back() == '_')
		result.pop_back();

	if (result.size() > 80)
		result.resize(80);

	while (!result.empty() && result.back() == '_')
		result.pop_back();

	if (result.empty())
		result = "unknown";

	return result;
}

//------------------------------------------------------------------------------
// Helper: stable hash for file disambiguation
//------------------------------------------------------------------------------
static uint64_t fnv1a64(const std::string &value)
{
	uint64_t hash = 1469598103934665603ULL;
	for (unsigned char ch : value)
	{
		hash ^= ch;
		hash *= 1099511628211ULL;
	}
	return hash;
}

//------------------------------------------------------------------------------
// Helper: load already-skipped functions from functions_skipped.txt
//------------------------------------------------------------------------------
static void load_skipped_functions()
{
	std::string skipped_path = "data\\log\\per_function_traces\\functions_skipped.txt";
	std::ifstream skip_file(skipped_path);
	if (!skip_file)
	{
		// File doesn't exist yet, no skipped functions
		return;
	}

	std::string line;
	while (std::getline(skip_file, line))
	{
		line = trim(line);
		if (!line.empty() && line[0] != '#')
			already_skipped_functions.insert(line);
	}
	skip_file.close();
	std::cout << "[TraceBuilder_PerFunctionSplit] Loaded " << already_skipped_functions.size() 
						<< " already-skipped functions." << std::endl;
}

//------------------------------------------------------------------------------
// Helper: write a manifest entry in memory (will write to file in Fini)
//------------------------------------------------------------------------------
static void register_trace_manifest_entry(const std::string &display_name,
																					const std::string &file_path)
{
	// Store active traced function in memory to be written later in Fini (append mode)
	current_traced_function = display_name;
	current_traced_file_path = file_path;
}

static std::string get_trace_output_dir()
{
	return "data\\log\\per_function_traces";
}

//------------------------------------------------------------------------------
// Helper: get or create the binary trace stream for a routine
//------------------------------------------------------------------------------
static FunctionTrace *get_or_create_function_trace(const std::string &img_name,
																									 const std::string &rtn_name)
{
	std::string key = img_name + "!" + rtn_name;
	auto it = function_traces.find(key);
	if (it != function_traces.end())
		return &it->second;

	FunctionTrace trace_info;
	trace_info.display_name = key;

	std::string img_stem = sanitize_for_filename(get_filename(img_name));
	std::string rtn_stem = sanitize_for_filename(rtn_name);
	uint64_t hash = fnv1a64(key);

	std::ostringstream file_name;
	file_name << get_trace_output_dir() << "\\trace_" << img_stem << "__" << rtn_stem << "__"
						<< std::hex << std::setw(16) << std::setfill('0') << hash << ".binary";
	trace_info.file_path = file_name.str();

	auto insert_result = function_traces.emplace(key, std::move(trace_info));
	return &insert_result.first->second;
}

//------------------------------------------------------------------------------
// Activate tracing lazily on the first actually-called function.
// Returns true only for the active function selected in this execution.
//------------------------------------------------------------------------------
static bool activate_trace_if_needed(FunctionTrace *trace_info)
{
	if (trace_info == nullptr)
		return false;

	std::lock_guard<std::mutex> lock(trace_mutex);

	if (!function_traced)
	{
		trace_info->stream.open(trace_info->file_path, std::ios::binary);
		if (!trace_info->stream)
		{
			std::cerr << "Erreur: impossible d'ouvrir " << trace_info->file_path
								<< " pour la fonction " << trace_info->display_name << std::endl;
			return false;
		}

		trace_info->activated = true;
		function_traced = true;
		register_trace_manifest_entry(trace_info->display_name, trace_info->file_path);
		std::cout << "[TraceBuilder_PerFunctionSplit] Tracing called function: "
						<< trace_info->display_name << std::endl;
		return true;
	}

	if (!trace_info->activated)
		return false;

	if (!trace_info->stream.is_open())
		return false;

	return true;
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
		auto comment_pos = line.find('#');
		if (comment_pos != std::string::npos)
			line = line.substr(0, comment_pos);

		line = trim(line);
		if (line.empty())
			continue;

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
					configured_regs.push_back(it->second);
				else
					std::cerr << "Avertissement : registre inconnu ou ignoré '"
										<< reg_name << "'" << std::endl;
			}
		}

		if (line.rfind("MEMORY", 0) == 0)
		{
			auto equal_pos = line.find('=');
			if (equal_pos == std::string::npos)
				continue;

			std::string memory_size_str = line.substr(equal_pos + 1);
			int memory_size = std::stoi(memory_size_str);

			if (memory_size == 0 || memory_size == 8 || memory_size == 16 ||
					memory_size == 32 || memory_size == 64)
			{
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

			break;
		}
	}

	return !configured_regs.empty();
}

bool load_filter_config(const std::string &filename)
{
	std::ifstream config(filename);
	if (!config)
	{
		std::cerr << "Erreur : impossible d'ouvrir le fichier de configuration '" << filename << "'." << std::endl;
		return false;
	}

	std::string line;
	bool in_filters = false;
	while (std::getline(config, line))
	{
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

		if (line.rfind("MODE", 0) == 0)
		{
			auto eq = line.find('=');
			if (eq != std::string::npos)
			{
				std::string mode = trim(line.substr(eq + 1));
				for (auto &c : mode) c = std::tolower(static_cast<unsigned char>(c));
				if (mode == "whitelist" || mode == "blacklist" || mode == "none")
					filter_mode = mode;
				else
					std::cerr << "Avertissement : mode de filtrage invalide '" << mode
										<< "'. Valeurs autorisées : whitelist, blacklist, none." << std::endl;
			}
		}

		if (line.rfind("FILTER_FUNCTION", 0) == 0)
		{
			auto eq = line.find('=');
			if (eq == std::string::npos)
				continue;
			std::string list = trim(line.substr(eq + 1));
			std::istringstream ss(list);
			std::string fn;
			while (std::getline(ss, fn, ','))
				skip_functions.push_back(trim(fn));
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
				skip_libs.push_back(trim(lib));
		}

		if (line.rfind("TARGET_LIB", 0) == 0)
		{
			auto eq = line.find('=');
			if (eq == std::string::npos)
				continue;
			std::string list = trim(line.substr(eq + 1));
			std::istringstream ss(list);
			std::string lib;
			while (std::getline(ss, lib, ','))
				target_libs.push_back(trim(lib));
		}
	}

	std::cout << "[TraceBuilder_PerFunctionSplit] Mode de filtrage : " << filter_mode;
	if (filter_mode == "whitelist")
	{
		std::cout << " -> libs: ";
		for (size_t i = 0; i < target_libs.size(); ++i)
		{
			if (i) std::cout << ", ";
			std::cout << target_libs[i];
		}
	}
	else if (filter_mode == "blacklist")
	{
		std::cout << " -> " << skip_libs.size() << " libs ignorées";
	}
	std::cout << std::endl;
	return true;
}

//------------------------------------------------------------------------------
// Thread-safe write to one routine-specific trace file
//------------------------------------------------------------------------------
inline void WriteData(FunctionTrace *trace_info, const char *data, size_t size)
{
	if (trace_info != nullptr && trace_info->stream.is_open() && size > 0)
		trace_info->stream.write(data, size);
}

//------------------------------------------------------------------------------
// Record register contents (including XMM/YMM) to trace
//------------------------------------------------------------------------------
VOID record_data(const CONTEXT *ctx, FunctionTrace *trace_info)
{
	for (REG reg : configured_regs)
	{
		if (REG_is_zmm(reg))
		{
			UINT8 zmm_val[64];
			PIN_GetContextRegval(ctx, reg, zmm_val);
			WriteData(trace_info, (const char *)zmm_val, 64);
		}
		else if (REG_is_ymm(reg))
		{
			UINT8 ymm_val[32];
			PIN_GetContextRegval(ctx, reg, ymm_val);
			WriteData(trace_info, (const char *)ymm_val, 32);
		}
		else if (REG_is_xmm(reg))
		{
			UINT8 xmm_val[16];
			PIN_GetContextRegval(ctx, reg, xmm_val);
			WriteData(trace_info, (const char *)xmm_val, 16);
		}
		else
		{
			uint64_t val = PIN_GetContextReg(ctx, reg);
			WriteData(trace_info, (const char *)&val, 8);
		}
	}
}

//------------------------------------------------------------------------------
// Record instruction pointer and register/memory snapshot
//------------------------------------------------------------------------------
VOID record_fragment(uint64_t ip, const CONTEXT *ctx, void *memory_ea, FunctionTrace *trace_info)
{
	if (!activate_trace_if_needed(trace_info))
		return;

	WriteData(trace_info, (const char *)&ip, 8);
	record_data(ctx, trace_info);

	UINT8 buffer[64] = {0};
	if (memory_ea && memory_size_to_read > 0)
		PIN_SafeCopy(buffer, memory_ea, memory_size_to_read);
	WriteData(trace_info, (const char *)buffer, memory_size_to_read);
}

VOID record_register(uint64_t ip, const CONTEXT *ctx, FunctionTrace *trace_info)
{
	if (!activate_trace_if_needed(trace_info))
		return;

	WriteData(trace_info, (const char *)&ip, 8);
	record_data(ctx, trace_info);
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
			std::string target_lower = target;
			for (auto &c : target_lower) c = std::tolower(static_cast<unsigned char>(c));
			if (img_filename == target_lower || img_filename.find(target_lower) != std::string::npos)
				return true;
		}
		return false;
	}

	if (filter_mode == "blacklist")
	{
		for (auto &skip : skip_libs)
		{
			std::string skip_lower = skip;
			for (auto &c : skip_lower) c = std::tolower(static_cast<unsigned char>(c));
			if (img_filename == skip_lower || img_filename.find(skip_lower) != std::string::npos)
				return false;
		}
	}

	return true;
}

//------------------------------------------------------------------------------
// Routine-level instrumentation: ONE trace file per execution
//------------------------------------------------------------------------------
VOID RoutineInstrumentation(RTN rtn, VOID *v)
{
	if (!RTN_Valid(rtn))
		return;

	std::string rtn_name = RTN_Name(rtn);
	
	// Skip if in skip_functions list
	for (auto &skip : skip_functions)
	{
		if (rtn_name == skip)
			return;
	}

	// Skip if already skipped in previous runs
	if (already_skipped_functions.count(rtn_name) > 0)
		return;

	SEC sec = RTN_Sec(rtn);
	if (!SEC_Valid(sec))
		return;

	IMG img = SEC_Img(sec);
	if (!IMG_Valid(img))
	{
		if (filter_mode == "whitelist")
			return;
	}
	else
	{
		std::string img_name = IMG_Name(img);
		std::string routine_key = img_name + "!" + rtn_name;
		
		// Skip if in skip_functions list (by name or by routine_key)
		for (auto &skip : skip_functions)
		{
			if (rtn_name == skip || routine_key == skip)
				return;
		}
		
		// Skip if already skipped
		if (already_skipped_functions.count(rtn_name) > 0 || 
				already_skipped_functions.count(routine_key) > 0)
			return;

		// Skip if image should not be instrumented
		if (!should_instrument_image(img_name))
			return;

		bool already_seen = false;
		for (auto &known_lib : not_skip_libs)
		{
			if (img_name == known_lib)
			{
				already_seen = true;
				break;
			}
		}
		if (!already_seen)
			not_skip_libs.push_back(img_name);

		if (rtn_name.empty())
			rtn_name = "<unnamed>";

		FunctionTrace *trace_info = get_or_create_function_trace(img_name, rtn_name);
		if (trace_info == nullptr)
			return;

		RTN_Open(rtn);
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
		{
			if (INS_IsControlFlow(ins))
				continue;

			if (memory_size_to_read > 0)
			{
				if (INS_MemoryOperandCount(ins) > 0 && INS_MemoryOperandIsRead(ins, 0))
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_fragment,
												 IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYOP_EA, 0,
												 IARG_PTR, trace_info, IARG_END);
				else
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_fragment,
												 IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, (ADDRINT)nullptr,
												 IARG_PTR, trace_info, IARG_END);
			}
			else
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_register,
											 IARG_INST_PTR, IARG_CONST_CONTEXT,
											 IARG_PTR, trace_info, IARG_END);
			}
		}
		RTN_Close(rtn);
		return;
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
// Finalization: close files and write manifest entry
//------------------------------------------------------------------------------
VOID Fini(INT32 code, VOID *v)
{
	for (auto &entry : function_traces)
	{
		if (entry.second.stream.is_open())
			entry.second.stream.close();
	}

	// Write manifest entry (append mode) if a function was traced
	if (function_traced && !current_traced_function.empty())
	{
		std::string manifest_path = "data\\log\\per_function_traces\\trace_manifest.txt";
		std::ofstream manifest_file(manifest_path, std::ios::app);
		if (manifest_file.is_open())
		{
			manifest_file << current_traced_function << " -> " << current_traced_file_path << std::endl;
			manifest_file.close();
			std::cout << "[TraceBuilder_PerFunctionSplit] Manifest entry added: " 
						<< current_traced_function << std::endl;
		}
		else
		{
			std::cerr << "Erreur: impossible d'ouvrir manifest pour append: " << manifest_path << std::endl;
		}
	}

	if (log_file.is_open())
		log_file.close();

	std::cout << std::endl
						<< "Fonctions tracees dans cette execution: " << function_traces.size() << std::endl;
	if (function_traced)
		std::cout << "Fonction enregistree: " << current_traced_function << std::endl;
	std::cout << std::endl
						<< "Librairies non ignorées :" << std::endl;
	for (auto lib_name : not_skip_libs)
		std::cout << "\t" << lib_name << std::endl;
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();
	if (PIN_Init(argc, argv))
	{
		std::cerr << "L'initialisation du PIN a échoué." << std::endl;
		return -1;
	}

	CreateDirectoryA("data", NULL);
	CreateDirectoryA("data\\log", NULL);
	CreateDirectoryA("data\\log\\per_function_traces", NULL);
	const char* log_path = "data\\log\\trace.log";

	log_file.open(log_path);
	if (!log_file)
	{
		std::cerr << "Erreur: impossible d'ouvrir data/log/trace.log." << std::endl;
		return -1;
	}

	// Load already-skipped functions for this run
	load_skipped_functions();

	std::string cfg = KnobConfigFile.Value();
	if (!load_register_config(cfg) || !load_filter_config(cfg))
	{
		std::cerr << "Erreur: échec du chargement de " << cfg << std::endl;
		return -1;
	}

	IMG_AddInstrumentFunction(ImageLoad, 0);
	RTN_AddInstrumentFunction(RoutineInstrumentation, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
	return 0;
}
