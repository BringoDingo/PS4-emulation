// psemu: crash diagnostics for the native GNM backend.
//
// An exception that is not a std::exception (or one that escapes a noexcept function) reaches
// std::terminate and the process dies with a bare "Aborted". This installs a terminate handler
// (per thread on MSVC, so it is installed lazily from every entry point) and a SIGABRT handler
// that print the pending exception's message and a symbolized native stack to stderr first.
// dbghelp.dll is loaded dynamically so no extra link libraries are needed; symbols come from the
// gnm_native.pdb next to the DLL.
#include <windows.h>

#include <csignal>
#include <cstdio>
#include <exception>
#include <string>

#include <dbghelp.h>

#include "gnm_internal.h"

namespace psemu {
namespace {

using SymInitializeFn = BOOL(WINAPI*)(HANDLE, PCSTR, BOOL);
using SymSetOptionsFn = DWORD(WINAPI*)(DWORD);
using SymFromAddrFn = BOOL(WINAPI*)(HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO);
using SymGetLineFn = BOOL(WINAPI*)(HANDLE, DWORD64, PDWORD, PIMAGEHLP_LINE64);

std::string DllDir() {
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&DllDir), &self);
    char path[MAX_PATH] = {};
    GetModuleFileNameA(self, path, MAX_PATH);
    std::string p = path;
    auto slash = p.find_last_of("\\/");
    return slash == std::string::npos ? std::string{} : p.substr(0, slash);
}

void DumpStack(const char* why) {
    std::fprintf(stderr, "\n[gnm-crash] %s\n", why);
    void* frames[48];
    const USHORT n = CaptureStackBackTrace(1, 48, frames, nullptr);
    HMODULE dbg = LoadLibraryA("dbghelp.dll");
    auto init = dbg ? reinterpret_cast<SymInitializeFn>(GetProcAddress(dbg, "SymInitialize")) : nullptr;
    auto opts = dbg ? reinterpret_cast<SymSetOptionsFn>(GetProcAddress(dbg, "SymSetOptions")) : nullptr;
    auto fromaddr = dbg ? reinterpret_cast<SymFromAddrFn>(GetProcAddress(dbg, "SymFromAddr")) : nullptr;
    auto getline = dbg ? reinterpret_cast<SymGetLineFn>(GetProcAddress(dbg, "SymGetLineFromAddr64")) : nullptr;
    const HANDLE proc = GetCurrentProcess();
    bool symbols = false;
    if (init && fromaddr) {
        if (opts) {
            opts(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);
        }
        const std::string dir = DllDir();
        symbols = init(proc, dir.c_str(), TRUE) != FALSE;
    }
    for (USHORT i = 0; i < n; ++i) {
        const auto addr = reinterpret_cast<DWORD64>(frames[i]);
        HMODULE mod = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(frames[i]), &mod);
        char modname[MAX_PATH] = {};
        if (mod) {
            GetModuleFileNameA(mod, modname, MAX_PATH);
        }
        const char* base = modname;
        for (const char* c = modname; *c; ++c) {
            if (*c == '\\' || *c == '/') {
                base = c + 1;
            }
        }
        char buf[sizeof(SYMBOL_INFO) + 256] = {};
        auto* sym = reinterpret_cast<SYMBOL_INFO*>(buf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = 255;
        DWORD64 disp = 0;
        const char* name = "?";
        if (symbols && fromaddr(proc, addr, &disp, sym)) {
            name = sym->Name;
        }
        std::string where;
        if (symbols && getline) {
            IMAGEHLP_LINE64 line{};
            line.SizeOfStruct = sizeof(line);
            DWORD ldisp = 0;
            if (getline(proc, addr, &ldisp, &line)) {
                where = std::string("  ") + line.FileName + ":" + std::to_string(line.LineNumber);
            }
        }
        std::fprintf(stderr, "  #%02u %s!%s+0x%llx%s\n", i, base, name,
                     static_cast<unsigned long long>(disp), where.c_str());
    }
    std::fflush(stderr);
}

[[noreturn]] void OnTerminate() {
    std::string why = "std::terminate: ";
    try {
        if (auto p = std::current_exception()) {
            std::rethrow_exception(p);
        }
        why += "no active exception (noexcept violation / double fault / pure virtual call)";
    } catch (const std::exception& e) {
        why += std::string("uncaught std::exception: ") + e.what();
    } catch (...) {
        why += "uncaught exception of a type that is not std::exception";
    }
    DumpStack(why.c_str());
    std::abort();
}

void OnAbort(int) {
    static bool in_handler = false;
    if (!in_handler) {
        in_handler = true;
        DumpStack("SIGABRT (abort() called)");
    }
    std::signal(SIGABRT, SIG_DFL);
    std::abort();
}

} // namespace

void InstallCrashHandlers() {
    static thread_local bool done = false;
    if (done) {
        return;
    }
    done = true;
    std::set_terminate(OnTerminate);
    static const bool once = (std::signal(SIGABRT, OnAbort), true);
    (void)once;
}

} // namespace psemu
