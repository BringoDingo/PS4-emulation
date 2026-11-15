// SPDX-License-Identifier: GPL-2.0-or-later
// psemu stand-in for shadPS4's emulator settings: only the switches the
// shader recompiler reads.
#pragma once

struct PsemuRecompilerSettings {
    bool dump_shaders = false;
    bool direct_memory_access = false;
    bool IsDumpShaders() const {
        return dump_shaders;
    }
    bool IsDirectMemoryAccessEnabled() const {
        return direct_memory_access;
    }
};

inline PsemuRecompilerSettings EmulatorSettings{};
