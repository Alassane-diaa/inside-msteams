@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist obj-intel64 mkdir obj-intel64

echo Compiling...
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang-cl.exe" /c /MT /O2 /GS- /D_WINDOWS /DTARGET_WINDOWS /D__PIN__ /D_CRT_SECURE_NO_DEPRECATE /D_SECURE_SCL=0 /DTARGET_IA32E /DHOST_IA32E ^
 /D_arch_long="long long" /DPIN_CRT=1 /DPIN_RT /D__x86_64__ ^
 /D_LIBCPP_HAS_MUSL_LIBC /D_LIBCPP_NO_VCRUNTIME /D_LIBCPP_DISABLE_AVAILABILITY /D_GNU_SOURCE ^
 /Dfseeko=fseek /Dftello=ftell /GR- ^
 /X ^
 /I..\..\..\intel64\pinrt\include\c++ ^
 /I..\..\..\intel64\pinrt\include ^
 /I..\..\..\source\include\pin ^
 /I..\..\..\source\include\pin\gen ^
 /I..\..\..\extras\components\include ^
 /I..\..\..\extras\xed-intel64\include\xed ^
 /I..\..\..\intel64\pinrt\include\adaptor ^
 /I..\..\..\intel64\pinrt\include\pinos ^
 KeyStealer.cpp /Foobj-intel64\KeyStealer.obj

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)

echo Linking...
link /DLL /OUT:obj-intel64\KeyStealer.dll /LIBPATH:..\..\..\intel64\lib /LIBPATH:..\..\..\extras\xed-intel64\lib /LIBPATH:..\..\..\intel64\pinrt\lib ^
 crtbeginS.obj ^
 pin.lib pinrt-adaptor-static.lib xed.lib c++.lib pincrt4.lib compiler-rt.lib stdlib_new_delete.obj kernel32.lib user32.lib ^
 /EXPORT:main /DYNAMICBASE /NXCOMPAT /IGNORE:4210 /IGNORE:4049 /NODEFAULTLIB ^
 obj-intel64\KeyStealer.obj

if %ERRORLEVEL% NEQ 0 (
    echo Linking failed!
    exit /b %ERRORLEVEL%
)

echo Build successful!