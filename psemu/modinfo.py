"""Module analyzer / triage tool.

Classifies a PS4 firmware ELF and reports whether psemu can run it:

  * static ET_EXEC modules (mini-syscore, SceSysAvControl) are self-contained
    and run under psemu's CPU + syscall layer.
  * SCE_DYNAMIC modules (SceSysCore, SceShellCore, GnmCompositor, the shell/UI)
    are dynamically linked against the PS4 shared-library ecosystem and need a
    dynamic linker (ld-elf.so.1) plus those .prx/.sprx libraries before any of
    their code can run.

Usage:
    python -m psemu.modinfo path/to/module.elf
    python -m psemu.modinfo --dir path/to/firmware     # triage a whole tree
"""
import argparse
import os

from .loader import Elf64, ET_EXEC, ET_SCE_DYNAMIC

ET_NAMES = {ET_EXEC: "ET_EXEC", ET_SCE_DYNAMIC: "SCE_DYNAMIC", 0x03: "ET_DYN",
            0xFE00: "SCE_EXEC", 0xFE18: "SCE_DYNEXEC", 0xFE04: "SCE_EXEC_ASLR"}


def analyze(path):
    try:
        elf = Elf64(path)
    except Exception as e:
        return {"path": path, "error": str(e)}
    needed = elf.needed_libraries() if elf.is_dynamic else []
    return {
        "path": path,
        "type": ET_NAMES.get(elf.e_type, f"0x{elf.e_type:x}"),
        "entry": elf.entry,
        "dynamic": elf.is_dynamic,
        "interp": elf.interp,
        "needed": needed,
        "runnable": not elf.is_dynamic,
    }


def print_one(info, verbose=True):
    if "error" in info:
        print(f"  {os.path.basename(info['path'])}: not loadable ({info['error']})")
        return
    tag = "RUN " if info["runnable"] else "DYN "
    print(f"{tag} {os.path.basename(info['path']):<28} {info['type']:<12} "
          f"entry=0x{info['entry']:x}"
          + (f"  needs {len(info['needed'])} libs" if info["dynamic"] else ""))
    if verbose and info["dynamic"]:
        if info["interp"]:
            print(f"      interp: {info['interp']}")
        for lib in info["needed"]:
            print(f"        - {lib}")


def main():
    ap = argparse.ArgumentParser(description="Classify PS4 firmware modules for psemu.")
    ap.add_argument("path", help="an ELF file, or a directory with --dir")
    ap.add_argument("--dir", action="store_true", help="recurse a firmware tree")
    args = ap.parse_args()

    if args.dir:
        print("RUN = static, runnable in psemu   DYN = dynamic, needs linker+libs\n")
        for root, _d, files in sorted(os.walk(args.path)):
            for f in sorted(files):
                if f.lower().endswith(".elf"):
                    print_one(analyze(os.path.join(root, f)), verbose=False)
    else:
        print_one(analyze(args.path), verbose=True)


if __name__ == "__main__":
    main()
