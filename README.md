First of all, this is almost entirely driven by Claude AI. I'm fairly certain
that I could achoeve the same results using a different LLM,
or by reverse engineering the binaries myself.
i just dont want to. 

the aim of this project is to run the PS4 on my pc, no tricks.
i would like to open the program, and have a ps4 fire up using my hardware.
it most certainly only benefits me, but if youd like you can try it. 
you can import your own firmware and binaries, or you can wait for me to
finish everything, and ill compile it all under one umbrella
as best as i can.









# PS4-emulation (psemu)

An experimental PlayStation 4 (firmware 5.05) system emulator written in Python,
using [Unicorn](https://www.unicorn-engine.org/) for x86-64 CPU emulation plus a
small native acceleration layer, with a GNM → Vulkan GPU backend. The long-term
goal is to boot the PS4 system software far enough to reach the main menu on a PC.

This is a research / reverse-engineering project, not a product. It will not run
games and is nowhere near a usable emulator.

## Status

- Boots `SceSysAvControl` through HDMI/AV setup (`set_mode done`).
- Dynamic linker maps and relocates the firmware module graph (50+ modules).
- `SceShellCore.elf` (the system-menu backend) boots through its init: IPMI/IPC,
  AppMgr, UserService, ModuleLoader, SQLite, the NP/PSN stack, AppDb,
  SystemStateMgr (`State Change: WORKING`), CloudConnectMgr, and more.
- GNM command processing renders to Vulkan (compute, RectList, depth/stencil,
  tiling, fetch shaders) and passes the `cs-test` / `depth-test` checks.

See [`psemu/README.md`](psemu/README.md) for the architecture writeup and
[`psemu/ROADMAP.md`](psemu/ROADMAP.md) for the plan and open problems.

## You must supply your own firmware

**No PlayStation firmware, keys, or console dumps are included in this repository,
and they never will be** — that material is copyrighted by Sony. You can only run
this with decrypted 5.05 firmware modules that you have legally obtained from your
own console, placed in a directory you point `--fw-root` at. The `.gitignore` is
set up to keep firmware (`*.sprx`, `*.elf`, dumps, etc.) out of the repo.

## Running

Requires Python 3.12, `unicorn`, and the Python deps the code imports. The native
CPU helper and the GNM/Vulkan backend are built from source (see
`psemu/native/build.py` and `psemu/gnm/native/`). Build outputs are not committed.

Run from the directory that contains the `psemu/` package:

```bash
python -m psemu.run <path-to-module>.elf --fw-root <your-firmware-root> --max 50000000
```

Regression checks:

```bash
python -m psemu.gnm cs-test
python -m psemu.gnm depth-test
python -m psemu.tools_synctest
```

## License and third-party code

This project reuses code from [shadPS4](https://github.com/shadps4-emu/shadPS4)
(notably in the GNM/Vulkan backend under `psemu/gnm/native/`), which is licensed
**GPL-2.0-or-later**. Accordingly this repository is distributed under
**GPL-2.0-or-later** (see [`LICENSE`](LICENSE)). The vendored shadPS4 checkout
itself is a build-time dependency and is not included here — fetch it separately.

If you believe a file needs clearer attribution or you want a different license
arrangement, that is yours to adjust — this scaffolding was set up to be
GPL-compliant by default given the shadPS4 reuse.
