"""psemu - a minimal high-level emulator for PS4 (FreeBSD/ORBIS x86-64) ELF
modules, running them in a sandboxed Unicorn CPU on Windows x64.

This is a *starting scaffold*: it loads the ELF, sets up a stack + TLS, runs
the native x86-64 code inside Unicorn, and traps FreeBSD/SCE `syscall`
instructions into Python handlers. Most syscalls are stubbed and logged; the
point is to get the module executing and to see exactly what kernel services
it reaches for, so they can be implemented one at a time.
"""
__version__ = "0.1.0"
