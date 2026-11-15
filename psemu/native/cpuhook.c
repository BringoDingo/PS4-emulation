/* psemu's per-instruction hook in native code.
 *
 * Unicorn calls a UC_HOOK_CODE callback before every guest instruction. A
 * Python callback costs microseconds; this one costs nanoseconds. It counts
 * instructions and stops the CPU (before the instruction runs) only when
 * Python has work to do:
 *
 *   LIMIT  the instruction budget / thread time slice is used up
 *   TRAP   the address is in the trap set and needs Python: an HLE
 *          function entry, or a VEX instruction vex.c does not handle
 *          (VEX instructions it does handle run right here; see vex.c)
 *   PAGE   first instruction executed on a code page Python has not scanned
 *          for VEX candidates yet
 *
 * The run loop reads the reason, handles it and restarts at RIP. `skip` lets
 * one execution of a trapped address through (HLE 'fixup' hooks, VEX
 * instructions QEMU runs correctly after all).
 *
 * Unicorn functions come from the unicorn.dll the Python package loaded.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <unicorn/unicorn.h>

#include "vex.h"

uc_err (*p_uc_reg_read)(uc_engine *, int, void *);
uc_err (*p_uc_reg_write)(uc_engine *, int, const void *);
uc_err (*p_uc_mem_read)(uc_engine *, uint64_t, void *, uint64_t);
uc_err (*p_uc_mem_write)(uc_engine *, uint64_t, const void *, uint64_t);

#define EXPORT __declspec(dllexport)

enum { R_NONE = 0, R_LIMIT = 1, R_TRAP = 2, R_PAGE = 3 };
#define RING 32

typedef int (*emu_stop_fn)(void *uc);

typedef struct {
    uint64_t count;        /* instructions executed */
    uint64_t limit;        /* stop before executing when count reaches it */
    uint64_t last;         /* address of the last hooked instruction */
    uint64_t stop_addr;    /* address the CPU stopped before */
    uint64_t skip;         /* let this address through once (0 = none) */
    uint32_t reason;
    uint32_t ring_pos;
    uint64_t ring[RING];   /* recent instruction addresses */
    emu_stop_fn emu_stop;
    uint64_t vex_native;   /* VEX instructions executed by vex.c */
    uint64_t vex_passed;   /* VEX addresses left to QEMU */
    uint64_t clock_ns;     /* virtual time skipped while all threads slept */
    uint64_t tsc_mul, tsc_div;   /* TSC ticks per ns, as a fraction */
} CpuState;

static CpuState g;

/* ---- open-addressing u64 set (keys have bit 63 set; 0 = empty, 1 = dead) */
typedef struct {
    uint64_t *keys;
    uint64_t cap;          /* power of two */
    uint64_t used;         /* live + dead */
    uint64_t live;
} Set;

#define EMPTY 0ull
#define DEAD 1ull
#define TAG (1ull << 63)

static uint64_t mix(uint64_t k) { return (k * 0x9E3779B97F4A7C15ull) >> 20; }

static void set_init(Set *s, uint64_t cap) {
    s->keys = (uint64_t *)calloc(cap, sizeof(uint64_t));
    s->cap = cap;
    s->used = s->live = 0;
}

static int set_has(const Set *s, uint64_t k) {
    uint64_t m = s->cap - 1, i = mix(k) & m;
    for (;;) {
        uint64_t v = s->keys[i];
        if (v == k) return 1;
        if (v == EMPTY) return 0;
        i = (i + 1) & m;
    }
}

static void set_insert_raw(Set *s, uint64_t k) {
    uint64_t m = s->cap - 1, i = mix(k) & m;
    while (s->keys[i] != EMPTY && s->keys[i] != DEAD) i = (i + 1) & m;
    if (s->keys[i] == EMPTY) s->used++;
    s->keys[i] = k;
    s->live++;
}

static void set_rehash(Set *s, uint64_t cap) {
    Set n;
    set_init(&n, cap);
    for (uint64_t i = 0; i < s->cap; i++)
        if (s->keys[i] > DEAD) set_insert_raw(&n, s->keys[i]);
    free(s->keys);
    *s = n;
}

static int set_add(Set *s, uint64_t k) {
    if (set_has(s, k)) return 0;
    if ((s->used + 1) * 2 > s->cap) set_rehash(s, s->live * 4 > s->cap ? s->cap * 2 : s->cap);
    set_insert_raw(s, k);
    return 1;
}

static int set_remove(Set *s, uint64_t k) {
    uint64_t m = s->cap - 1, i = mix(k) & m;
    for (;;) {
        uint64_t v = s->keys[i];
        if (v == k) { s->keys[i] = DEAD; s->live--; return 1; }
        if (v == EMPTY) return 0;
        i = (i + 1) & m;
    }
}

static void set_clear(Set *s) {
    memset(s->keys, 0, s->cap * sizeof(uint64_t));
    s->used = s->live = 0;
}

static Set traps, pages, hle;
static int vex_enabled = 1;    /* 0: every VEX trap goes to Python (debugging) */

/* decoded VEX instructions by address */
typedef struct { uint64_t key; Dec d; } DEnt;
static DEnt *dc;
static uint64_t dc_cap, dc_used;
static uint64_t vstat[4][256], vfirst[4][256];

static void dc_clear(void) {
    if (dc) memset(dc, 0, dc_cap * sizeof *dc);
    dc_used = 0;
}

static Dec *dc_get(void *uc, uint64_t addr) {
    if (!dc || (dc_used + 1) * 2 > dc_cap) {
        uint64_t ncap = dc ? dc_cap * 2 : 4096;
        DEnt *n = (DEnt *)calloc(ncap, sizeof *n);
        for (uint64_t i = 0; dc && i < dc_cap; i++)
            if (dc[i].key) {
                uint64_t j = mix(dc[i].key) & (ncap - 1);
                while (n[j].key) j = (j + 1) & (ncap - 1);
                n[j] = dc[i];
            }
        free(dc);
        dc = n;
        dc_cap = ncap;
    }
    uint64_t k = addr | TAG, m = dc_cap - 1, i = mix(k) & m;
    while (dc[i].key) {
        if (dc[i].key == k) return &dc[i].d;
        i = (i + 1) & m;
    }
    dc[i].key = k;
    dc_used++;
    vex_decode((uc_engine *)uc, addr, &dc[i].d);
    return &dc[i].d;
}
/* quick reject before the hash lookup: one bit per hashed address */
#define FILTER_BITS 18
static uint64_t filter[(1u << FILTER_BITS) / 64];
static uint64_t cur_page = ~0ull;    /* last page known to be scanned */

static uint32_t fidx(uint64_t addr) {
    return (uint32_t)((addr * 0x9E3779B97F4A7C15ull) >> (64 - FILTER_BITS));
}

/* ---- the hook ---------------------------------------------------------- */
static void stop(void *uc, uint64_t addr, uint32_t why) {
    g.reason = why;
    g.stop_addr = addr;
    g.emu_stop(uc);
}

EXPORT void cpu_code_hook(void *uc, uint64_t addr, uint32_t size, void *user) {
    (void)size; (void)user;
    g.last = addr;
    g.ring[g.ring_pos++ & (RING - 1)] = addr;
    if (g.count >= g.limit) { stop(uc, addr, R_LIMIT); return; }
    uint64_t page = addr >> 12;
    if (page != cur_page) {
        if (!set_has(&pages, page | TAG)) { stop(uc, addr, R_PAGE); return; }
        cur_page = page;
    }
    uint32_t f = fidx(addr);
    if ((filter[f >> 6] >> (f & 63)) & 1) {
        if (addr == g.skip) {
            g.skip = 0;
        } else if (set_has(&traps, addr | TAG)) {
            if (set_has(&hle, addr | TAG)) { stop(uc, addr, R_TRAP); return; }
            Dec *d = dc_get(uc, addr);
            if (!vex_enabled) { stop(uc, addr, R_TRAP); return; }
            if (d->kind == V_EMU && vex_exec((uc_engine *)uc, d, addr)) {
                /* done: resume after it (a PC write from a hook restarts the
                   CPU there without running this instruction) */
                uint64_t next = addr + d->len;
                uc_reg_write((uc_engine *)uc, UC_X86_REG_RIP, &next);
                g.vex_native++;
                if (!vstat[d->map][d->op]++) vfirst[d->map][d->op] = addr;
                g.count++;
                return;
            }
            if (d->kind == V_PASS) {
                set_remove(&traps, addr | TAG);
                g.vex_passed++;
            } else {
                stop(uc, addr, R_TRAP);
                return;
            }
        }
    }
    g.count++;
}

/* ---- API used from Python (ctypes) ------------------------------------- */
EXPORT CpuState *cpu_state(void) { return &g; }

EXPORT void *cpu_hook_ptr(void) { return (void *)&cpu_code_hook; }

EXPORT int cpu_init(void *emu_stop) {
    g.emu_stop = (emu_stop_fn)emu_stop;
    HMODULE h = GetModuleHandleA("unicorn.dll");
    if (!h) return 0;
    *(FARPROC *)&p_uc_reg_read = GetProcAddress(h, "uc_reg_read");
    *(FARPROC *)&p_uc_reg_write = GetProcAddress(h, "uc_reg_write");
    *(FARPROC *)&p_uc_mem_read = GetProcAddress(h, "uc_mem_read");
    *(FARPROC *)&p_uc_mem_write = GetProcAddress(h, "uc_mem_write");
    if (!p_uc_reg_read || !p_uc_reg_write || !p_uc_mem_read || !p_uc_mem_write) return 0;
    if (!traps.keys) { set_init(&traps, 1024); set_init(&pages, 4096); set_init(&hle, 256); }
    return 1;
}

/* forget traps and scanned pages (a new address space); keeps the count */
EXPORT void cpu_reset(void) {
    set_clear(&traps);
    set_clear(&pages);
    set_clear(&hle);
    dc_clear();
    memset(filter, 0, sizeof filter);
    cur_page = ~0ull;
    g.skip = 0;
    g.reason = R_NONE;
}

EXPORT int cpu_trap_add(uint64_t addr) {
    uint32_t f = fidx(addr);
    filter[f >> 6] |= 1ull << (f & 63);
    return set_add(&traps, addr | TAG);
}

EXPORT void cpu_set_vex(int on) { vex_enabled = on; }

/* an HLE function entry: always handled in Python */
EXPORT int cpu_hle_add(uint64_t addr) {
    set_add(&hle, addr | TAG);
    return cpu_trap_add(addr);
}

EXPORT int cpu_trap_remove(uint64_t addr) {
    return set_remove(&traps, addr | TAG);   /* filter bit stays: harmless */
}

EXPORT void cpu_page_scanned(uint64_t addr) {
    set_add(&pages, (addr >> 12) | TAG);
}

/* code in [lo, hi) changed (module mapped over it): rescan on next execution */
EXPORT void cpu_pages_forget(uint64_t lo, uint64_t hi) {
    for (uint64_t p = lo >> 12; p < (hi + 0xFFF) >> 12; p++) set_remove(&pages, p | TAG);
    cur_page = ~0ull;
    dc_clear();
}

/* rdtsc/rdtscp (UC_HOOK_INSN): the TSC follows psemu's virtual clock
   (1 ns per instruction plus skipped idle time), so guest timing agrees with
   clock_gettime/nanosleep and runs are deterministic. Returning 1 skips the
   real instruction. */
static int tsc_common(void *uc) {
    uint64_t ns = g.count + g.clock_ns;
    uint64_t tsc = g.tsc_div ? ns / g.tsc_div * g.tsc_mul + ns % g.tsc_div * g.tsc_mul / g.tsc_div
                             : ns;
    uint64_t lo = (uint32_t)tsc, hi = tsc >> 32;
    uc_reg_write((uc_engine *)uc, UC_X86_REG_RAX, &lo);
    uc_reg_write((uc_engine *)uc, UC_X86_REG_RDX, &hi);
    return 1;
}

EXPORT int cpu_rdtsc_hook(void *uc, void *user) { (void)user; return tsc_common(uc); }

EXPORT int cpu_rdtscp_hook(void *uc, void *user) {
    uint64_t aux = 0;                       /* TSC_AUX: cpu 0 */
    (void)user;
    uc_reg_write((uc_engine *)uc, UC_X86_REG_RCX, &aux);
    return tsc_common(uc);
}

EXPORT void *cpu_rdtsc_ptr(void) { return (void *)&cpu_rdtsc_hook; }
EXPORT void *cpu_rdtscp_ptr(void) { return (void *)&cpu_rdtscp_hook; }

/* per-opcode counts of natively executed VEX instructions: [map][op], plus
   the first address each was seen at (for naming them) */
EXPORT uint64_t *cpu_vex_stats(void) { return &vstat[0][0]; }
EXPORT uint64_t *cpu_vex_first(void) { return &vfirst[0][0]; }

/* test hook: decode + execute one instruction outside of emulation */
EXPORT int cpu_vex_run(void *uc, uint64_t addr, int *len) {
    Dec d;
    int kind = vex_decode((uc_engine *)uc, addr, &d);
    *len = d.len;
    if (kind != V_EMU) return kind == V_PASS ? 2 : 0;
    return vex_exec((uc_engine *)uc, &d, addr) ? 1 : -1;
}
