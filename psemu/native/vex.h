#pragma once
#include <stdint.h>
#include <unicorn/unicorn.h>

enum { V_PY = 0, V_EMU = 1, V_PASS = 2 };

typedef struct {
    uint8_t len, map, op, pp, L, W, mod, reg, regf, rm, vvvv, imm, scale, kind;
    int8_t base, index;          /* -1 = none, 16 = RIP-relative */
    int32_t disp;
} Dec;

/* Unicorn entry points, resolved from the loaded unicorn.dll by cpu_init()
   (the Python package ships a static unicorn.lib, not an import library) */
extern uc_err (*p_uc_reg_read)(uc_engine *, int, void *);
extern uc_err (*p_uc_reg_write)(uc_engine *, int, const void *);
extern uc_err (*p_uc_mem_read)(uc_engine *, uint64_t, void *, uint64_t);
extern uc_err (*p_uc_mem_write)(uc_engine *, uint64_t, const void *, uint64_t);
#define uc_reg_read p_uc_reg_read
#define uc_reg_write p_uc_reg_write
#define uc_mem_read p_uc_mem_read
#define uc_mem_write p_uc_mem_write

int vex_decode(uc_engine *uc, uint64_t addr, Dec *d);
int vex_exec(uc_engine *uc, const Dec *d, uint64_t addr);
