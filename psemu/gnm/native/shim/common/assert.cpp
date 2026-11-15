// SPDX-License-Identifier: GPL-2.0-or-later
// psemu: failed recompiler asserts throw instead of breaking into a debugger,
// so one unsupported shader does not take the whole Python process down. The
// C API catches the exception and reports the recompiler's own message.
#include <stdexcept>
#include <string>
#include "common/assert.h"

namespace {
std::string Reason(const char* what) {
    std::string msg = ::Common::Log::g_last_critical;
    // the recompiler's messages start with "Assertion Failed!\n" / "Unreachable code!\n"
    if (const auto nl = msg.find('\n'); nl != std::string::npos) {
        msg = msg.substr(nl + 1);
    }
    return msg.empty() || msg == "Assertion Failed!" || msg == "Unreachable code!"
               ? std::string(what)
               : std::string(what) + ": " + msg;
}
} // namespace

void assert_fail_impl() {
    throw std::runtime_error(Reason("recompiler assertion"));
}

[[noreturn]] void unreachable_impl() {
    throw std::runtime_error(Reason("recompiler unreachable"));
}
