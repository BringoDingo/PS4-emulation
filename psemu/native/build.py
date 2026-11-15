"""Build psemu's native CPU hook (psemu/native/build/psemu_cpu.dll) with MSVC.

    python psemu/native/build.py

Without the DLL psemu falls back to its Python per-instruction hook (slow).
"""
import importlib.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "build")


def _gnm_build():
    path = os.path.join(HERE, "..", "gnm", "native", "build.py")
    spec = importlib.util.spec_from_file_location("gnm_build", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build(force=False):
    srcs = [os.path.join(HERE, f) for f in ("cpuhook.c", "vex.c")]
    deps = srcs + [os.path.join(HERE, "vex.h")]
    dll = os.path.join(OUT, "psemu_cpu.dll")
    if not force and os.path.exists(dll) and all(
            os.path.getmtime(dll) >= os.path.getmtime(s) for s in deps):
        return dll
    os.makedirs(OUT, exist_ok=True)
    gb = _gnm_build()
    env = gb.msvc_env()
    import unicorn
    uc_dir = os.path.dirname(unicorn.__file__)
    cmd = [gb.TOOLS["cl"], "/nologo", "/O2", "/LD", "/W3", "/fp:precise",
           "/I" + os.path.join(uc_dir, "include"), *srcs,
           "/Fo" + OUT + os.sep, "/Fe" + dll]
    r = subprocess.run(cmd, env=env, cwd=OUT)
    if r.returncode:
        sys.exit("psemu_cpu.dll build failed")
    return dll


if __name__ == "__main__":
    print(build(force="--force" in sys.argv))
