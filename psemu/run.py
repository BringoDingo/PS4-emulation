"""CLI entry point for the psemu scaffold.

    python -m psemu.run path/to/mini-syscore.elf
    python -m psemu.run mini-syscore.elf --trace --max 500
    python -m psemu.run mini-syscore.elf --start 0x400080

Run untrusted modules with `python -I -m psemu.run ...` so the interpreter does
not import stray modules from the firmware's directory.
"""
import argparse
from .emulator import Emulator


def main():
    ap = argparse.ArgumentParser(description="Sandboxed PS4/FreeBSD ELF emulator (scaffold).")
    ap.add_argument("file")
    ap.add_argument("--trace", action="store_true",
                    help="print every instruction and every syscall")
    ap.add_argument("--max", type=int, default=2_000_000,
                    help="instruction budget before forced stop (default 2e6)")
    ap.add_argument("--start", default=None,
                    help="override start address (hex, e.g. 0x400080)")
    ap.add_argument("--fw-root", default=None,
                    help="firmware root for resolving execve() paths "
                         "(default: the directory of the first module)")
    ap.add_argument("--max-modules", type=int, default=8,
                    help="stop after chain-loading this many modules")
    ap.add_argument("--spawn-mode", default=None,
                    help="process-spawn policy for execve() from an rfork'd child: "
                         "'follow' (default, chain-load/replace the image), 'stay' "
                         "(keep running the parent, retire spawned children), 'spawn' (whp: run them as real concurrent processes), or a "
                         "path substring to follow only matching children (e.g. NPXS20001)")
    ap.add_argument("--no-gpu", action="store_true",
                    help="accept /dev/gc submits without running them on the host GPU")
    ap.add_argument("--frames", default=None,
                    help="save displayed frames (VideoOut flips) as PNGs in this directory")
    ap.add_argument("--frame-every", type=int, default=60,
                    help="with --frames: save every Nth flip (default 60, and the first)")
    ap.add_argument("--backend", choices=("unicorn", "whp"), default=None,
                    help="CPU engine: 'unicorn' (default, deterministic, instruction-counted) or "
                         "'whp' (hardware virtualization via the Windows Hypervisor Platform)")
    ap.add_argument("--max-seconds", type=float, default=None,
                    help="wall-clock budget; the stop condition on --backend whp, where there "
                         "is no instruction count")
    ap.add_argument("--then", default=None, metavar="APP_EBOOT",
                    help="whp: after the first process (SceSysCore) has initialized its core "
                         "services, chain-load this app (e.g. .../NPXS20001/eboot.bin)")
    ap.add_argument("--then-settle", type=float, default=5.0,
                    help="seconds the core gets after its last service is up (default 5)")
    ap.add_argument("--gpu-profile", action="store_true",
                    help="log per-phase GPU executor time after every /dev/gc submit")
    args = ap.parse_args()

    start = int(args.start, 0) if args.start else None
    emu = Emulator(args.file, trace=args.trace, max_insns=args.max,
                   fw_root=args.fw_root, backend=args.backend)
    emu.max_seconds = args.max_seconds
    emu.then_path = args.then
    emu.then_settle = args.then_settle
    emu.max_modules = args.max_modules
    emu.spawn_mode = args.spawn_mode
    emu.gpu_enabled = not args.no_gpu
    emu.gpu_profile = args.gpu_profile
    if args.frames:
        emu.frame_dir = args.frames
        emu.frame_every = max(1, args.frame_every)
    if args.spawn_mode == "spawn":
        # real multi-process: an execve from an rfork'd child starts a new process (own address space)
        # next to the parent; they share one WHP machine/vCPU and the kernel's named objects
        from .process import ProcessManager
        pm = ProcessManager()
        pm.add(emu, start)
        pm.run()
    else:
        emu.run(start=start)


if __name__ == "__main__":
    main()
