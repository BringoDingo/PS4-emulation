"""Build psemu's native GNM backend with MSVC (no CMake needed).

    python psemu/gnm/native/build.py            # release build
    python psemu/gnm/native/build.py --debug
    python psemu/gnm/native/build.py --deps D:/path/to/shadPS4/externals

Outputs go to psemu/gnm/native/build/: gnm_recompiler.lib (shadPS4's shader
recompiler + sirit), gnm_native.dll (C API used from Python) and
gnm_run.exe (command-line runner).

Third-party libraries (sirit, SPIRV-Headers, Boost, fmt, magic_enum,
Vulkan-Headers) are read from --deps, by default the shadPS4 checkout's
externals/ folder next to the psemu package.
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys

TOOLS = {}

HERE = os.path.dirname(os.path.abspath(__file__))
SHAD = os.path.join(HERE, "third_party", "shadps4", "src")
DEFAULT_DEPS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "psemu_deps",
                                             "shadPS4", "externals"))
VCVARS_CANDIDATES = [
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
]


def msvc_env():
    for bat in VCVARS_CANDIDATES:
        if os.path.exists(bat):
            out = subprocess.run('cmd /s /c ""%s" >nul 2>&1 && set"' % bat,
                                 capture_output=True, text=True, shell=True).stdout
            env = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
            if "INCLUDE" in env:
                path = env.get("PATH") or env.get("Path") or ""
                for tool in ("cl", "lib", "link"):
                    TOOLS[tool] = shutil.which(tool, path=path) or tool
                return env
    sys.exit("MSVC not found: install Visual Studio 2022 with 'Desktop development with C++'")


def newer(src_files, target):
    if not os.path.exists(target):
        return True
    t = os.path.getmtime(target)
    return any(os.path.getmtime(s) > t for s in src_files)


def run(cmd, env, cwd):
    print("  $", " ".join(cmd[:6]), "..." if len(cmd) > 6 else "")
    r = subprocess.run(cmd, env=env, cwd=cwd)
    if r.returncode:
        sys.exit("build failed (%s)" % cmd[0])


def headers_under(*roots):
    out = []
    for r in roots:
        out += glob.glob(os.path.join(r, "**", "*.h"), recursive=True)
        out += glob.glob(os.path.join(r, "**", "*.inc"), recursive=True)
    return out


def compile_group(name, sources, includes, defines, flags, objdir, env, extra_deps=()):
    """Compile sources into objdir; only stale objects are rebuilt."""
    os.makedirs(objdir, exist_ok=True)
    stale = []
    for s in sources:
        rel = os.path.splitext(os.path.relpath(s, os.path.commonpath(sources)))[0]
        obj = os.path.join(objdir, rel.replace(os.sep, "_") + ".obj")
        if newer([s, *extra_deps], obj):
            stale.append((s, obj))
    objs = [os.path.join(objdir, os.path.splitext(os.path.relpath(
        s, os.path.commonpath(sources)))[0].replace(os.sep, "_") + ".obj") for s in sources]
    if stale:
        print("[%s] compiling %d of %d files" % (name, len(stale), len(sources)))
        # cl /MP compiles in parallel; /Fo<dir>\ needs unique basenames, so
        # compile per-object in batches through response files instead.
        batch = []
        for s, obj in stale:
            batch.append((s, obj))
        procs = []
        maxjobs = os.cpu_count() or 4
        failed = False
        for s, obj in batch:
            cmd = [TOOLS["cl"], "/nologo", "/c", *flags, *["/I" + i for i in includes],
                   *["/D" + d for d in defines], s, "/Fo" + obj]
            procs.append((s, subprocess.Popen(cmd, env=env, cwd=objdir,
                                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                              text=True)))
            if len(procs) >= maxjobs:
                failed |= _drain(procs.pop(0))
        for p in procs:
            failed |= _drain(p)
        if failed:
            sys.exit("[%s] compile errors" % name)
    return objs


def _drain(item):
    src, p = item
    out, _ = p.communicate()
    lines = [l for l in out.splitlines() if l.strip() and l.strip() != os.path.basename(src)]
    if p.returncode:
        print("---- %s" % src)
        print("\n".join(lines[:60]))
        return True
    warn = [l for l in lines if "warning" in l]
    if warn:
        print("  %s: %d warning(s)" % (os.path.basename(src), len(warn)))
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps", default=DEFAULT_DEPS)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--only", choices=["recompiler", "native", "all"], default="all")
    a = ap.parse_args()
    deps = a.deps
    for need in ("sirit", "ext-boost", "fmt", "magic_enum", "vulkan-headers"):
        if not os.path.isdir(os.path.join(deps, need)):
            sys.exit("missing dependency %s under %s" % (need, deps))

    env = msvc_env()
    build = os.path.join(HERE, "build", "debug" if a.debug else "release")
    os.makedirs(build, exist_ok=True)
    opt = ["/Od", "/Zi", "/MDd"] if a.debug else ["/O2", "/Zi", "/MD", "/DNDEBUG"]
    flags = ["/std:c++latest", "/EHa", "/permissive-", "/Zc:preprocessor", "/Zc:__cplusplus",
             "/bigobj", "/utf-8", "/W3", "/wd4244", "/wd4267", "/wd4146", "/wd4305",
             "/wd4068", "/wd4996", "/wd5030", "/FS", *opt]
    includes = [
        SHAD, os.path.dirname(SHAD), os.path.join(HERE, "shim"), os.path.join(HERE, "src"),
        os.path.join(deps, "fmt", "include"),
        os.path.join(deps, "magic_enum", "include"),
        os.path.join(deps, "magic_enum", "include", "magic_enum"),
        os.path.join(deps, "ext-boost"),
        os.path.join(deps, "sirit", "include"),
        os.path.join(deps, "sirit", "src"),
        os.path.join(deps, "sirit", "externals", "SPIRV-Headers", "include"),
        os.path.join(deps, "vulkan-headers", "include"),
    ]
    defines = ["FMT_HEADER_ONLY", "NOMINMAX", "WIN32_LEAN_AND_MEAN", "_CRT_SECURE_NO_WARNINGS",
               "_CRT_NONSTDC_NO_DEPRECATE", "_SCL_SECURE_NO_WARNINGS",
               "BOOST_ASIO_DISABLE_CONCEPTS", "_WIN32_WINNT=0x0A00", "WINVER=0x0A00"]
    hdrs = headers_under(SHAD, os.path.join(HERE, "shim"))

    # --- sirit (SPIR-V builder) + shadPS4 shader recompiler -> static lib
    sirit_src = sorted(glob.glob(os.path.join(deps, "sirit", "src", "**", "*.cpp"), recursive=True))
    shad_src = sorted(glob.glob(os.path.join(SHAD, "shader_recompiler", "**", "*.cpp"),
                                recursive=True))
    shad_src += [os.path.join(SHAD, "video_core", "amdgpu", f)
                 for f in ("pixel_format.cpp", "tiling.cpp", "regs.cpp")]
    shim_src = sorted(glob.glob(os.path.join(HERE, "shim", "**", "*.cpp"), recursive=True))
    objs = compile_group("sirit", sirit_src, includes, defines, flags,
                         os.path.join(build, "obj", "sirit"), env)
    objs += compile_group("recompiler", shad_src, includes, defines, flags,
                          os.path.join(build, "obj", "shadps4"), env, hdrs)
    objs += compile_group("shim", shim_src, includes, defines, flags,
                          os.path.join(build, "obj", "shim"), env, hdrs)
    lib = os.path.join(build, "gnm_recompiler.lib")
    if newer(objs, lib):
        run([TOOLS["lib"], "/nologo", "/OUT:" + lib, *objs], env, build)
    print("ok:", lib)
    if a.only == "recompiler":
        return

    # --- psemu native layer: Vulkan runner + C API
    own = sorted(glob.glob(os.path.join(HERE, "src", "*.cpp")))
    if not own:
        return
    lib_objs = compile_group("native", own, includes, defines + ["VK_NO_PROTOTYPES"], flags,
                             os.path.join(build, "obj", "native"), env,
                             hdrs + headers_under(os.path.join(HERE, "src")))
    main_obj = [o for o in lib_objs if o.endswith("gnm_run.obj")]
    core = [o for o in lib_objs if o not in main_obj]
    dll = os.path.join(build, "gnm_native.dll")
    if newer(core + [lib], dll):
        run([TOOLS["link"], "/nologo", "/DLL", "/DEBUG", "/OUT:" + dll, *core, lib, "user32.lib"],
            env, build)
    if main_obj:
        exe = os.path.join(build, "gnm_run.exe")
        if newer(main_obj + core + [lib], exe):
            run([TOOLS["link"], "/nologo", "/DEBUG", "/OUT:" + exe, *main_obj, *core, lib,
                 "user32.lib"], env, build)
    print("ok:", build)


if __name__ == "__main__":
    main()
