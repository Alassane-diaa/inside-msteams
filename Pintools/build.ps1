param(
    [Parameter(Position=0)]
    [string[]]$Targets,
    [string]$PinRoot = $env:PIN_ROOT,
    [string]$ClangPath = $env:CLANG_CL,
    [string]$LinkerPath = $env:LLD_LINK
)

# Resolve all build inputs from the environment or command-line parameters.
# This script must work on machines where Pin and Visual Studio are installed
# in different directories.
Set-Location $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($PinRoot) -or !(Test-Path $PinRoot)) {
    throw "PIN_ROOT must point to the extracted Intel Pin kit. Example: `$env:PIN_ROOT = 'C:\tools\pin'"
}

if ([string]::IsNullOrWhiteSpace($ClangPath)) {
    $clangCommand = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
    if ($clangCommand) { $ClangPath = $clangCommand.Source }
}
if ([string]::IsNullOrWhiteSpace($LinkerPath)) {
    $linkerCommand = Get-Command lld-link.exe -ErrorAction SilentlyContinue
    if ($linkerCommand) { $LinkerPath = $linkerCommand.Source }
}
if ([string]::IsNullOrWhiteSpace($ClangPath) -or !(Test-Path $ClangPath)) {
    throw "clang-cl.exe was not found. Run from a Visual Studio Developer PowerShell or set CLANG_CL."
}
if ([string]::IsNullOrWhiteSpace($LinkerPath) -or !(Test-Path $LinkerPath)) {
    throw "lld-link.exe was not found. Run from a Visual Studio Developer PowerShell or set LLD_LINK."
}

$pin_root = (Resolve-Path $PinRoot).Path
$clang = (Resolve-Path $ClangPath).Path
$linker = (Resolve-Path $LinkerPath).Path

if (!(Test-Path "obj-intel64")) { mkdir "obj-intel64" }

# Get Clang Resource Dir for stddef.h etc.
$resource_dir = (& $clang -print-resource-dir).Trim()
Write-Host "Clang Resource Dir: $resource_dir"

# Includes
$includes = @(
    "-I$pin_root/source/include/pin",
    "-I$pin_root/source/include/pin/gen",
    "-I$pin_root/intel64/pinrt/include/adaptor",
    "-I$pin_root/extras/components/include",
    "-I$pin_root/extras/xed-intel64/include/xed",
    "-I$pin_root/source/tools/Utils",
    "-I$pin_root/intel64/pinrt/include",
    "-I$pin_root/intel64/pinrt/include/pinos",
    "-I$pin_root/intel64/pinrt/include/c++",
    "-I$resource_dir/include"
)

# System Includes (from INCLUDE env var)
$sys_includes = ($env:INCLUDE -split ';') | Where-Object { $_ -ne "" } | ForEach-Object { "-I`"$_`"" }

# Defines
$defines = @(
    "-DTARGET_IA32E", "-DHOST_IA32E", "-D__x86_64__", "-DTARGET_WINDOWS",
    "-DPIN_CRT=1", "-DPIN_RT", "-D_arch_long=long long",
    "-D_LIBCPP_HAS_MUSL_LIBC", "-D_LIBCPP_NO_VCRUNTIME", "-D_LIBCPP_DISABLE_AVAILABILITY", "-D_GNU_SOURCE",
    "-D__DEFINED_max_align_t"
)

# Flags
$flags = @(
    "-nologo", "-m64", "-fno-builtin", "-nostdinc", "-MD", "-O2",
    "/GR-", "/Zc:threadSafeInit-", "/wd5208",
    "/GS-", "/EHa-", "/EHs-", "/EHc-", "/Oi-", "/Gy", "/wd4530",
    "-Wno-non-c-typedef-for-linkage", "-Wno-microsoft-include", "-Wno-unicode", "-Wno-macro-redefined"
)

# Link libraries and paths
$libs = @(
    "$pin_root/intel64/pinrt/lib/crtbeginS.obj",
    "$pin_root/intel64/pinrt/lib/stdlib_new_delete.obj",
    "pin.lib", "pinrt-adaptor-static.lib", "xed.lib", "kernel32.lib", "ntdll.lib",
    "c++.lib", "pincrt4.lib"
)
$libpaths = @(
    "/LIBPATH:$pin_root/intel64/lib",
    "/LIBPATH:$pin_root/intel64/pinrt/lib",
    "/LIBPATH:$pin_root/extras/xed-intel64/lib"
)
$link_flags = @(
    "/DLL", "/EXPORT:main", "/INCREMENTAL:NO", "/IGNORE:4210", "/IGNORE:4049",
    "/DYNAMICBASE", "/NXCOMPAT", "/OPT:REF", "/NODEFAULTLIB",
    "/SAFESEH:NO", "/SUBSYSTEM:CONSOLE"
)

# ─── Known tools and their source files ──────────────────────────────────────
# Key = target name, Value = source .cpp path (relative to Pintools/)
$known_tools = [ordered]@{
    "TraceBuilder"          = "TraceBuilder.cpp"
    "TraceBuilder_PerFunctionSplit" = "TraceBuilder_PerFunctionSplit.cpp"
    "TraceBuilder_Delayed"  = "TraceBuilder_Delayed.cpp"
    "TraceBuilder_FuncEntry"= "TraceBuilder_FuncEntry.cpp"
    "TraceBuilder_ArgTracker"= "TraceBuilder_ArgTracker.cpp"
    "TraceBuilder_StructTracker"= "TraceBuilder_StructTracker.cpp"
    "PinGetName"            = "PinGetName.cpp"
    "PinGetName_StructTracker"= "PinGetName_StructTracker.cpp"
    "Backtracer"            = "Backtracer.cpp"
    "Backtracer_StructTracker"= "Backtracer_StructTracker.cpp"
    "LibraryFunctions"      = "LibraryFunctions.cpp"
    "Extracteur"            = "Extracteur.cpp"
    "Extracteur_WIN"        = "Extracteur_WIN.cpp"
}

# ─── Helper: compile and link one tool ───────────────────────────────────────
function Invoke-ToolBuild {
    param([string]$Name, [string]$Source)

    $obj = "obj-intel64/$Name.obj"
    $dll = "obj-intel64/$Name.dll"

    Write-Host "`n=== Building $Name ===" -ForegroundColor Cyan

    # Compile
    $compile_args = $flags + $defines + $includes + $sys_includes + @("-c", "-Fo$obj", $Source)
    Write-Host "  Compiling $Source ..."
    & $clang $compile_args
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERREUR: compilation de $Name echouee." -ForegroundColor Red
        exit 1
    }

    # Link
    Write-Host "  Linking $dll ..."
    & $linker $link_flags "-out:$dll" $obj $libpaths $libs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERREUR: link de $Name echoue." -ForegroundColor Red
        exit 1
    }

    Write-Host "  $Name OK" -ForegroundColor Green
}

# ─── Main: determine what to build ──────────────────────────────────────────
if (-not $Targets -or $Targets.Count -eq 0) {
    # No arguments: build everything
    Write-Host "Aucune cible specifiee -> compilation de tous les outils" -ForegroundColor Yellow
    foreach ($name in $known_tools.Keys) {
        $src = $known_tools[$name]
        if (Test-Path $src) {
            Invoke-ToolBuild -Name $name -Source $src
        } else {
            Write-Host "  SKIP $name : $src introuvable" -ForegroundColor DarkYellow
        }
    }
} else {
    foreach ($t in $Targets) {
        if ($known_tools.Contains($t)) {
            Invoke-ToolBuild -Name $t -Source $known_tools[$t]
        } else {
            Write-Host "Cible inconnue: '$t'" -ForegroundColor Red
            Write-Host "Cibles disponibles: $($known_tools.Keys -join ', ')" -ForegroundColor Yellow
            exit 1
        }
    }
}

Write-Host "`nBuild Complete." -ForegroundColor Green
