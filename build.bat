cmake -G "Visual Studio 17 2022" -A Win32 -S . -B "x86"
cmake -G "Visual Studio 17 2022" -A x64 -S . -B "x64"
cmake --build x86 --config Debug
cmake --build x86 --config Release
cmake --build x64 --config Debug
cmake --build x64 --config Release