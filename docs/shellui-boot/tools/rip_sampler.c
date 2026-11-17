/* Native stack sampler for cpu_sampler.py (Windows x64).
 *
 * A sampler thread suspends the target thread, captures its RIP plus up to DEPTH caller
 * frames (RtlVirtualUnwind, so no dbghelp/Python needed while the thread is stopped), and
 * resumes it. Python resolves the addresses afterwards. Doing this without Python between
 * suspend and resume matters: suspending a thread that holds Python's GIL while the sampler
 * needs the GIL deadlocks.
 *
 *   cl /nologo /O2 /LD rip_sampler.c /Fe:rip_sampler.dll
 */
#include <windows.h>
#include <stdint.h>

#define DEPTH 24

static volatile LONG g_stop;
static HANDLE g_thread;
static HANDLE g_target;
static uint64_t *g_buf;            /* cap * DEPTH addresses */
static uint32_t g_cap;
static volatile uint32_t g_n;
static DWORD g_interval_ms;

static void unwind(CONTEXT *ctx, uint64_t *out) {
    int i;
    for (i = 0; i < DEPTH; i++) {
        out[i] = ctx->Rip;
        DWORD64 base;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx->Rip, &base, NULL);
        if (!rf) {                                   /* leaf without unwind data */
            if (!ctx->Rsp) break;
            ctx->Rip = *(DWORD64 *)ctx->Rsp;
            ctx->Rsp += 8;
        } else {
            PVOID handler_data;
            DWORD64 frame;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, ctx->Rip, rf, ctx, &handler_data, &frame, NULL);
        }
        if (!ctx->Rip) { i++; break; }
    }
    for (; i < DEPTH; i++) out[i] = 0;
}

static DWORD WINAPI run(LPVOID unused) {
    (void)unused;
    __declspec(align(16)) CONTEXT ctx;
    while (!g_stop && g_n < g_cap) {
        if (SuspendThread(g_target) != (DWORD)-1) {
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (GetThreadContext(g_target, &ctx)) {
                unwind(&ctx, g_buf + (size_t)g_n * DEPTH);
                g_n++;
            }
            ResumeThread(g_target);
        }
        Sleep(g_interval_ms);
    }
    return 0;
}

__declspec(dllexport) int sampler_depth(void) { return DEPTH; }

__declspec(dllexport) int sampler_start(DWORD target_tid, uint64_t *buf, uint32_t cap, DWORD interval_ms) {
    g_target = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                          FALSE, target_tid);
    if (!g_target) return 0;
    g_buf = buf; g_cap = cap; g_n = 0; g_stop = 0; g_interval_ms = interval_ms ? interval_ms : 1;
    g_thread = CreateThread(NULL, 0, run, NULL, 0, NULL);
    return g_thread != NULL;
}

__declspec(dllexport) uint32_t sampler_stop(void) {
    g_stop = 1;
    if (g_thread) { WaitForSingleObject(g_thread, 5000); CloseHandle(g_thread); g_thread = NULL; }
    if (g_target) { CloseHandle(g_target); g_target = NULL; }
    return g_n;
}
