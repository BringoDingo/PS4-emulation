// SPDX-License-Identifier: GPL-2.0-or-later
// psemu stand-in for shadPS4's logging backend: same LOG_* macros, printed to
// stderr through fmt. Level is set with psemu_gnm_set_log_level().
#pragma once

#include <cstdio>
#include <string>
#include <fmt/format.h>

namespace Common::Log {
// 0 trace, 1 debug, 2 info, 3 warning, 4 error, 5 critical
inline int g_level = 3;
// Last critical message on this thread; assert failures report it.
inline thread_local std::string g_last_critical;
inline void Emit(int level, const char* cls, const char* file, int line, const std::string& msg) {
    static const char* names[] = {"Trace", "Debug", "Info", "Warning", "Error", "Critical"};
    if (level >= 5) {
        g_last_critical = msg;
    }
    if (level < g_level) {
        return;
    }
    const char* base = file;
    for (const char* p = file; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            base = p + 1;
        }
    }
    std::fprintf(stderr, "[%s] <%s> %s:%d %s\n", cls, names[level], base, line, msg.c_str());
}
} // namespace Common::Log

#define PSEMU_LOG(level, log_class, ...)                                                          \
    do {                                                                                           \
        if ((level) >= ::Common::Log::g_level || (level) >= 5) {                                   \
            ::Common::Log::Emit(level, #log_class, __FILE__, __LINE__, fmt::format(__VA_ARGS__));  \
        }                                                                                          \
    } while (false)

#define LOG_TRACE(log_class, ...) (void(0))
#define LOG_DEBUG(log_class, ...) PSEMU_LOG(1, log_class, __VA_ARGS__)
#define LOG_INFO(log_class, ...) PSEMU_LOG(2, log_class, __VA_ARGS__)
#define LOG_WARNING(log_class, ...) PSEMU_LOG(3, log_class, __VA_ARGS__)
#define LOG_ERROR(log_class, ...) PSEMU_LOG(4, log_class, __VA_ARGS__)
#define LOG_CRITICAL(log_class, ...) PSEMU_LOG(5, log_class, __VA_ARGS__)
