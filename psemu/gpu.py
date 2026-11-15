"""Host GPU detection and VRAM budgeting.

IMPORTANT — what this is and is NOT
-----------------------------------
This module detects the PC's graphics card and computes a VRAM budget, reserving
a share for the host OS. That is ALL it does. It is **not** a bridge from the
PS4 GPU to your card.

The PS4 GPU is AMD "Liverpool" (GCN), driven by Sony's proprietary GNM API:
command buffers are GNM/PM4 packets and shaders are PSSL compiled for GCN. A PC
GPU speaks Vulkan/Direct3D with a different command language and shader ISA.
Running PS4 graphics on a host card requires a GNM/PM4 command translator and a
PSSL->SPIR-V/DXIL shader recompiler feeding Vulkan/D3D12 — i.e. a full graphics
emulation layer. No device "link" or memory reservation substitutes for that.

So this file provides the *budget*; it does not render anything. Rendering is
done by `psemu.gnm` (shadPS4's shader recompiler + a Vulkan runner, see
`gnm/native/README.md`).

Usage:
    python -m psemu.gpu                 # print detected GPU + budget
"""
import re
import shutil
import subprocess


HOST_RESERVE = 0.30   # fraction of VRAM kept for the host OS/compositor


class GpuInfo:
    def __init__(self, name, vram_bytes, source, reserve=HOST_RESERVE):
        self.name = name
        self.vram_bytes = vram_bytes
        self.source = source            # where the figure came from
        self.reserve = reserve

    @property
    def host_reserved_bytes(self):
        return int(self.vram_bytes * self.reserve)

    @property
    def guest_budget_bytes(self):
        return self.vram_bytes - self.host_reserved_bytes

    @staticmethod
    def _gib(n):
        return n / (1024 ** 3)

    def describe(self):
        return (f"host GPU : {self.name}\n"
                f"  VRAM        : {self._gib(self.vram_bytes):.2f} GiB "
                f"({self.vram_bytes} bytes, via {self.source})\n"
                f"  host reserve: {self.reserve*100:.0f}%  "
                f"({self._gib(self.host_reserved_bytes):.2f} GiB)\n"
                f"  guest budget: {self._gib(self.guest_budget_bytes):.2f} GiB  "
                f"(what a GNM backend could allocate)")


def _powershell(cmd):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return ""
    try:
        return subprocess.run([exe, "-NoProfile", "-Command", cmd],
                              capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return ""


def _vram_from_registry():
    """The accurate figure. WMI's AdapterRAM is a uint32 and caps at ~4 GiB,
    so prefer the driver's HardwareInformation.qwMemorySize."""
    cmd = (r"Get-ItemProperty -Path "
           r"'HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*' "
           r"-ErrorAction SilentlyContinue | "
           r"Where-Object { $_.'HardwareInformation.qwMemorySize' } | "
           r"ForEach-Object { '{0}|{1}' -f $_.DriverDesc, $_.'HardwareInformation.qwMemorySize' }")
    out = _powershell(cmd)
    for line in out.splitlines():
        if "|" in line:
            name, size = line.rsplit("|", 1)
            try:
                return name.strip(), int(size.strip())
            except ValueError:
                continue
    return None, None


def _vram_from_wmi():
    cmd = ("Get-CimInstance Win32_VideoController | "
           "ForEach-Object { '{0}|{1}' -f $_.Name, $_.AdapterRAM }")
    out = _powershell(cmd)
    for line in out.splitlines():
        if "|" in line:
            name, size = line.rsplit("|", 1)
            try:
                return name.strip(), int(size.strip())
            except ValueError:
                continue
    return None, None


def detect(reserve=HOST_RESERVE):
    """Auto-detect the host GPU and VRAM. Registry first (accurate), then WMI
    (VRAM capped at ~4 GiB). Returns a GpuInfo, or None if nothing detected."""
    name, vram = _vram_from_registry()
    source = "registry qwMemorySize"
    if not vram:
        name, vram = _vram_from_wmi()
        source = "WMI AdapterRAM (uint32-capped)"
    if not vram:
        return None
    return GpuInfo(name or "unknown GPU", vram, source, reserve)


class HostGpuBackend:
    """Placeholder for a future GNM->Vulkan/D3D backend. It carries the budget
    but cannot render: PS4 GNM command/PSSL-shader translation is unimplemented."""
    def __init__(self, info: GpuInfo):
        self.info = info

    def submit(self, *_a, **_k):
        raise NotImplementedError(
            "HostGpuBackend only carries the VRAM budget; draw through "
            "psemu.gnm.backend (GCN->SPIR-V recompiler + Vulkan) instead.")


def main():
    info = detect()
    if info is None:
        print("no host GPU detected")
        return
    print(info.describe())
    print("\nnote: this is device info + a VRAM budget only. PS4 shaders run "
          "through psemu.gnm (python -m psemu.gnm --help).")


if __name__ == "__main__":
    main()
