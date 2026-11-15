/* Native execution of VEX-encoded SSE/AVX instructions.
 *
 * Unicorn's QEMU 5 core has no AVX: VEX.128 instructions run as their legacy
 * SSE forms (ignoring the extra source register VEX.vvvv) and VEX.256 ones
 * are invalid. psemu traps every VEX instruction (see cpuhook.c); this file
 * decodes it once per address and executes the common ones here, directly
 * on Unicorn's YMM register file and guest memory. The result is one of
 *
 *   V_EMU   executed here; the caller moves RIP past it
 *   V_PASS  QEMU runs it correctly (two-operand VEX.128 form): untrap it
 *   V_PY    not handled natively: the Python AVX shim decides
 *
 * Semantics follow the hardware (scalar forms keep src1's upper elements,
 * VEX.128 results clear bits 128..255).
 */
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

#include "vex.h"

typedef union {
    uint8_t b[32]; int8_t sb[32];
    uint16_t w[16]; int16_t sw[16];
    uint32_t d[8]; int32_t sd[8];
    uint64_t q[4]; int64_t sq[4];
    float f[8]; double g[4];
} V;

static const int GPR[16] = {
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
};

#define NOREG (-1)
#define RIPREL 16

/* ---- decode ------------------------------------------------------------ */
static int needs_imm(int map, int op) {
    if (map == 3) return 1;
    if (map == 1) return op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6 ||
                         (op >= 0x70 && op <= 0x73);
    return 0;
}

static int classify(const Dec *d);

int vex_decode(uc_engine *uc, uint64_t addr, Dec *d) {
    uint8_t c[16];
    memset(d, 0, sizeof *d);
    d->kind = V_PY;
    if (uc_mem_read(uc, addr, c, 15) != UC_ERR_OK &&
        uc_mem_read(uc, addr, c, 8) != UC_ERR_OK)
        return V_PY;
    int i, R, X = 0, B = 0;
    if (c[0] == 0xC5) {
        R = !(c[1] & 0x80);
        d->vvvv = (~c[1] >> 3) & 15;
        d->L = (c[1] >> 2) & 1;
        d->pp = c[1] & 3;
        d->map = 1;
        i = 2;
    } else if (c[0] == 0xC4) {
        R = !(c[1] & 0x80);
        X = !(c[1] & 0x40);
        B = !(c[1] & 0x20);
        d->map = c[1] & 0x1F;
        d->W = c[2] >> 7;
        d->vvvv = (~c[2] >> 3) & 15;
        d->L = (c[2] >> 2) & 1;
        d->pp = c[2] & 3;
        i = 3;
    } else {
        return V_PY;
    }
    if (d->map < 1 || d->map > 3) return V_PY;
    d->op = c[i++];
    if (d->map == 1 && d->op == 0x77) {          /* vzeroupper/vzeroall: no ModRM */
        d->mod = 3;
        d->len = (uint8_t)i;
        d->kind = (uint8_t)classify(d);
        return d->kind;
    }
    uint8_t modrm = c[i++];
    d->mod = modrm >> 6;
    d->reg = ((modrm >> 3) & 7) | (R << 3);
    d->regf = (modrm >> 3) & 7;
    int rm = modrm & 7;
    d->base = d->index = NOREG;
    if (d->mod == 3) {
        d->rm = rm | (B << 3);
    } else {
        int disp32 = 0;
        if (rm == 4) {
            uint8_t sib = c[i++];
            d->scale = sib >> 6;
            int idx = ((sib >> 3) & 7) | (X << 3);
            if (idx != 4) d->index = idx;
            int b = sib & 7;
            if (b == 5 && d->mod == 0) disp32 = 1;
            else d->base = b | (B << 3);
        } else if (rm == 5 && d->mod == 0) {
            d->base = RIPREL;
            disp32 = 1;
        } else {
            d->base = rm | (B << 3);
        }
        if (d->mod == 1) { d->disp = (int8_t)c[i]; i += 1; }
        else if (d->mod == 2 || disp32) { int32_t v; memcpy(&v, c + i, 4); d->disp = v; i += 4; }
    }
    if (needs_imm(d->map, d->op)) d->imm = c[i++];
    if (i > 15) return V_PY;
    d->len = (uint8_t)i;
    d->kind = (uint8_t)classify(d);
    return d->kind;
}

/* ---- operand access ---------------------------------------------------- */
static uint64_t gpr(uc_engine *uc, int n) {
    uint64_t v = 0;
    uc_reg_read(uc, GPR[n], &v);
    return v;
}

static uint64_t ea(uc_engine *uc, const Dec *d, uint64_t addr) {
    uint64_t a = (uint64_t)(int64_t)d->disp;
    if (d->base == RIPREL) a += addr + d->len;
    else if (d->base != NOREG) a += gpr(uc, d->base);
    if (d->index != NOREG) a += gpr(uc, d->index) << d->scale;
    return a;
}

static void vread(uc_engine *uc, int r, V *v) { uc_reg_read(uc, UC_X86_REG_YMM0 + r, v); }

static void vwrite(uc_engine *uc, int r, V *v, int w) {
    if (w == 16) memset(v->b + 16, 0, 16);
    uc_reg_write(uc, UC_X86_REG_YMM0 + r, v);
}

/* the r/m operand as a vector: register, or `size` bytes of memory (zero-extended) */
static int rmread(uc_engine *uc, const Dec *d, uint64_t addr, V *v, int size) {
    if (d->mod == 3) { vread(uc, d->rm, v); return 1; }
    memset(v, 0, sizeof *v);
    return uc_mem_read(uc, ea(uc, d, addr), v, size) == UC_ERR_OK;
}

/* the r/m operand as an integer (GPR or memory) */
static int rmint(uc_engine *uc, const Dec *d, uint64_t addr, uint64_t *out, int size) {
    if (d->mod == 3) { *out = gpr(uc, d->rm); return 1; }
    *out = 0;
    return uc_mem_read(uc, ea(uc, d, addr), out, size) == UC_ERR_OK;
}

/* ---- helpers ------------------------------------------------------------ */
static int8_t ss8(int v) { return (int8_t)(v < -128 ? -128 : v > 127 ? 127 : v); }
static uint8_t us8(int v) { return (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v); }
static int16_t ss16(int v) { return (int16_t)(v < -32768 ? -32768 : v > 32767 ? 32767 : v); }
static uint16_t us16(int v) { return (uint16_t)(v < 0 ? 0 : v > 65535 ? 65535 : v); }

static void unpack(V *r, const V *a, const V *b, int e, int high, int w) {
    for (int l = 0; l < w / 16; l++) {
        const uint8_t *pa = a->b + 16 * l, *pb = b->b + 16 * l;
        uint8_t *pr = r->b + 16 * l;
        int n = 16 / e, h = high ? n / 2 : 0;
        for (int j = 0; j < n / 2; j++) {
            memcpy(pr + (2 * j) * e, pa + (h + j) * e, e);
            memcpy(pr + (2 * j + 1) * e, pb + (h + j) * e, e);
        }
    }
}

static int fcmp(double a, double b, int p) {
    int un = isnan(a) || isnan(b);
    switch (p & 15) {
    case 0: return !un && a == b;
    case 1: return !un && a < b;
    case 2: return !un && a <= b;
    case 3: return un;
    case 4: return un || a != b;
    case 5: return un || !(a < b);
    case 6: return un || !(a <= b);
    case 7: return !un;
    case 8: return un || a == b;
    case 9: return un || !(a >= b);
    case 10: return un || !(a > b);
    case 11: return 0;
    case 12: return !un && a != b;
    case 13: return !un && a >= b;
    case 14: return !un && a > b;
    default: return 1;
    }
}

static float fop32(int op, float a, float b) {
    switch (op) {
    case 0x58: return a + b;
    case 0x59: return a * b;
    case 0x5C: return a - b;
    case 0x5D: return a < b ? a : b;
    case 0x5E: return a / b;
    default: return a > b ? a : b;   /* 0x5F */
    }
}

static double fop64(int op, double a, double b) {
    switch (op) {
    case 0x58: return a + b;
    case 0x59: return a * b;
    case 0x5C: return a - b;
    case 0x5D: return a < b ? a : b;
    case 0x5E: return a / b;
    default: return a > b ? a : b;
    }
}

static double rnd(double x, int imm) {
    switch ((imm & 4) ? 0 : (imm & 3)) {
    case 0: return nearbyint(x);
    case 1: return floor(x);
    case 2: return ceil(x);
    default: return trunc(x);
    }
}

/* ---- which instructions are handled ------------------------------------ */
static int is_int_binop(int op) {
    switch (op) {
    case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
    case 0x68: case 0x69: case 0x6A: case 0x6B: case 0x6C: case 0x6D:
    case 0x74: case 0x75: case 0x76:
    case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5: case 0xD8: case 0xD9: case 0xDA:
    case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5: case 0xE8: case 0xE9:
    case 0xEA: case 0xEB: case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF1: case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6: case 0xF8: case 0xF9:
    case 0xFA: case 0xFB: case 0xFC: case 0xFD: case 0xFE:
        return 1;
    }
    return 0;
}

static int is_map2_binop(int op) {
    switch (op) {
    case 0x00: case 0x08: case 0x09: case 0x0A: case 0x28: case 0x29: case 0x2B: case 0x37:
    case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D: case 0x3E: case 0x3F:
    case 0x40:
        return 1;
    }
    return 0;
}

static int classify_emu(const Dec *d);

/* dst == src1, VEX.128, no immediate: the legacy two-operand form QEMU runs
   computes the same thing (as the Python shim always assumed), so leave it
   to QEMU and avoid a translation-block exit per execution */
static int same_as_legacy(const Dec *d) {
    if (d->L || d->vvvv != d->reg || needs_imm(d->map, d->op)) return 0;
    if (d->map == 1) {
        switch (d->op) {
        case 0x10: case 0x11: case 0x28: case 0x29: case 0x6F: case 0x7F: case 0x77:
            return 0;
        }
        return 1;
    }
    return d->map == 2 && d->op != 0x18 && d->op != 0x19 && d->op != 0x1A;
}

static int classify(const Dec *d) {
    int k = classify_emu(d);
    return k == V_EMU && same_as_legacy(d) ? V_PASS : k;
}

static int classify_emu(const Dec *d) {
    int op = d->op, pp = d->pp, mem = d->mod != 3;
    if (d->map == 1) {
        switch (op) {
        case 0x58: case 0x59: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        case 0xC2:
            return V_EMU;
        case 0x51:
            return pp >= 2 || d->L ? V_EMU : V_PASS;
        case 0x54: case 0x55: case 0x56: case 0x57: case 0x14: case 0x15: case 0xC6:
            return pp <= 1 ? V_EMU : V_PY;
        case 0x2A: case 0x5A:
            return pp >= 2 ? V_EMU : (d->L ? V_PY : V_PASS);
        case 0x10: case 0x11:
            if (pp >= 2) return mem ? V_PASS : V_EMU;
            return d->L ? V_EMU : V_PASS;
        case 0x28: case 0x29:
            return pp <= 1 ? (d->L ? V_EMU : V_PASS) : V_PY;
        case 0x6F: case 0x7F:
            return pp == 1 || pp == 2 ? (d->L ? V_EMU : V_PASS) : V_PY;
        case 0x12: case 0x16:
            return pp <= 1 && !d->L ? V_EMU : V_PY;
        case 0x13: case 0x17:
            return d->L ? V_PY : V_PASS;
        case 0x77:
            return pp == 0 ? V_EMU : V_PY;
        case 0x71: case 0x72: case 0x73:
            if (pp != 1 || mem) return V_PY;
            if (op == 0x73) return d->regf == 2 || d->regf == 3 || d->regf == 6 || d->regf == 7
                                   ? V_EMU : V_PY;
            return d->regf == 2 || d->regf == 4 || d->regf == 6 ? V_EMU : V_PY;
        case 0xC4:
            return pp == 1 && !d->L ? V_EMU : V_PY;
        }
        if (pp == 1 && is_int_binop(op)) return V_EMU;
        return V_PY;
    }
    if (d->map == 2) {
        if (op >= 0xF0) return V_PASS;                       /* BMI1/BMI2: QEMU has them */
        if (pp == 1 && is_map2_binop(op)) return V_EMU;
        if (pp == 1 && (op == 0x18 || (d->L && (op == 0x19 || (op == 0x1A && mem)))))
            return V_EMU;                                     /* broadcasts */
        return V_PY;
    }
    /* map 3 */
    if (op == 0xF0) return V_PASS;                            /* rorx */
    if (pp != 1) return V_PY;
    switch (op) {
    case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x0E: case 0x0F:
    case 0x20: case 0x22: case 0x4A: case 0x4B: case 0x4C:
        return V_EMU;
    case 0x21:
        return d->L ? V_PY : V_EMU;
    case 0x06: case 0x18: case 0x19:
        return d->L ? V_EMU : V_PY;
    case 0x14: case 0x15: case 0x16: case 0x17:
        return d->L ? V_PY : V_PASS;
    }
    return V_PY;
}

/* ---- execution ----------------------------------------------------------- */
static int exec_int(int op, V *r, const V *a, const V *b, int w) {
    int n8 = w, n16 = w / 2, n32 = w / 4, n64 = w / 8, k;
    switch (op) {
    case 0x60: unpack(r, a, b, 1, 0, w); break;
    case 0x61: unpack(r, a, b, 2, 0, w); break;
    case 0x62: unpack(r, a, b, 4, 0, w); break;
    case 0x6C: unpack(r, a, b, 8, 0, w); break;
    case 0x68: unpack(r, a, b, 1, 1, w); break;
    case 0x69: unpack(r, a, b, 2, 1, w); break;
    case 0x6A: unpack(r, a, b, 4, 1, w); break;
    case 0x6D: unpack(r, a, b, 8, 1, w); break;
    case 0x63: case 0x67: case 0x6B:
        for (int l = 0; l < w / 16; l++) {
            if (op == 0x6B) {
                for (k = 0; k < 4; k++) {
                    r->sw[8 * l + k] = ss16(a->sd[4 * l + k]);
                    r->sw[8 * l + 4 + k] = ss16(b->sd[4 * l + k]);
                }
            } else {
                for (k = 0; k < 8; k++) {
                    int x = a->sw[8 * l + k], y = b->sw[8 * l + k];
                    if (op == 0x63) { r->sb[16 * l + k] = ss8(x); r->sb[16 * l + 8 + k] = ss8(y); }
                    else { r->b[16 * l + k] = us8(x); r->b[16 * l + 8 + k] = us8(y); }
                }
            }
        }
        break;
    case 0x64: for (k = 0; k < n8; k++) r->b[k] = a->sb[k] > b->sb[k] ? 0xFF : 0; break;
    case 0x65: for (k = 0; k < n16; k++) r->w[k] = a->sw[k] > b->sw[k] ? 0xFFFF : 0; break;
    case 0x66: for (k = 0; k < n32; k++) r->d[k] = a->sd[k] > b->sd[k] ? ~0u : 0; break;
    case 0x74: for (k = 0; k < n8; k++) r->b[k] = a->b[k] == b->b[k] ? 0xFF : 0; break;
    case 0x75: for (k = 0; k < n16; k++) r->w[k] = a->w[k] == b->w[k] ? 0xFFFF : 0; break;
    case 0x76: for (k = 0; k < n32; k++) r->d[k] = a->d[k] == b->d[k] ? ~0u : 0; break;
    case 0xD4: for (k = 0; k < n64; k++) r->q[k] = a->q[k] + b->q[k]; break;
    case 0xD5: for (k = 0; k < n16; k++) r->w[k] = (uint16_t)(a->w[k] * b->w[k]); break;
    case 0xD8: for (k = 0; k < n8; k++) r->b[k] = us8(a->b[k] - b->b[k]); break;
    case 0xD9: for (k = 0; k < n16; k++) r->w[k] = us16(a->w[k] - b->w[k]); break;
    case 0xDA: for (k = 0; k < n8; k++) r->b[k] = a->b[k] < b->b[k] ? a->b[k] : b->b[k]; break;
    case 0xDB: for (k = 0; k < n64; k++) r->q[k] = a->q[k] & b->q[k]; break;
    case 0xDC: for (k = 0; k < n8; k++) r->b[k] = us8(a->b[k] + b->b[k]); break;
    case 0xDD: for (k = 0; k < n16; k++) r->w[k] = us16(a->w[k] + b->w[k]); break;
    case 0xDE: for (k = 0; k < n8; k++) r->b[k] = a->b[k] > b->b[k] ? a->b[k] : b->b[k]; break;
    case 0xDF: for (k = 0; k < n64; k++) r->q[k] = ~a->q[k] & b->q[k]; break;
    case 0xE0: for (k = 0; k < n8; k++) r->b[k] = (uint8_t)((a->b[k] + b->b[k] + 1) >> 1); break;
    case 0xE3: for (k = 0; k < n16; k++) r->w[k] = (uint16_t)((a->w[k] + b->w[k] + 1) >> 1); break;
    case 0xE4: for (k = 0; k < n16; k++) r->w[k] = (uint16_t)(((uint32_t)a->w[k] * b->w[k]) >> 16); break;
    case 0xE5: for (k = 0; k < n16; k++) r->sw[k] = (int16_t)((a->sw[k] * b->sw[k]) >> 16); break;
    case 0xE8: for (k = 0; k < n8; k++) r->sb[k] = ss8(a->sb[k] - b->sb[k]); break;
    case 0xE9: for (k = 0; k < n16; k++) r->sw[k] = ss16(a->sw[k] - b->sw[k]); break;
    case 0xEA: for (k = 0; k < n16; k++) r->sw[k] = a->sw[k] < b->sw[k] ? a->sw[k] : b->sw[k]; break;
    case 0xEB: for (k = 0; k < n64; k++) r->q[k] = a->q[k] | b->q[k]; break;
    case 0xEC: for (k = 0; k < n8; k++) r->sb[k] = ss8(a->sb[k] + b->sb[k]); break;
    case 0xED: for (k = 0; k < n16; k++) r->sw[k] = ss16(a->sw[k] + b->sw[k]); break;
    case 0xEE: for (k = 0; k < n16; k++) r->sw[k] = a->sw[k] > b->sw[k] ? a->sw[k] : b->sw[k]; break;
    case 0xEF: for (k = 0; k < n64; k++) r->q[k] = a->q[k] ^ b->q[k]; break;
    case 0xF4: for (k = 0; k < n64; k++) r->q[k] = (uint64_t)a->d[2 * k] * b->d[2 * k]; break;
    case 0xF5:
        for (k = 0; k < n32; k++)
            r->sd[k] = (int32_t)((int64_t)a->sw[2 * k] * b->sw[2 * k] +
                                 (int64_t)a->sw[2 * k + 1] * b->sw[2 * k + 1]);
        break;
    case 0xF6:
        for (k = 0; k < n64; k++) {
            uint64_t s = 0;
            for (int j = 0; j < 8; j++) s += (uint64_t)abs(a->b[8 * k + j] - b->b[8 * k + j]);
            r->q[k] = s;
        }
        break;
    case 0xF8: for (k = 0; k < n8; k++) r->b[k] = (uint8_t)(a->b[k] - b->b[k]); break;
    case 0xF9: for (k = 0; k < n16; k++) r->w[k] = (uint16_t)(a->w[k] - b->w[k]); break;
    case 0xFA: for (k = 0; k < n32; k++) r->d[k] = a->d[k] - b->d[k]; break;
    case 0xFB: for (k = 0; k < n64; k++) r->q[k] = a->q[k] - b->q[k]; break;
    case 0xFC: for (k = 0; k < n8; k++) r->b[k] = (uint8_t)(a->b[k] + b->b[k]); break;
    case 0xFD: for (k = 0; k < n16; k++) r->w[k] = (uint16_t)(a->w[k] + b->w[k]); break;
    case 0xFE: for (k = 0; k < n32; k++) r->d[k] = a->d[k] + b->d[k]; break;
    default: {
        /* shifts by the count in b's low quadword */
        uint64_t c = b->q[0];
        switch (op) {
        case 0xD1: for (k = 0; k < n16; k++) r->w[k] = c >= 16 ? 0 : (uint16_t)(a->w[k] >> c); break;
        case 0xD2: for (k = 0; k < n32; k++) r->d[k] = c >= 32 ? 0 : a->d[k] >> c; break;
        case 0xD3: for (k = 0; k < n64; k++) r->q[k] = c >= 64 ? 0 : a->q[k] >> c; break;
        case 0xF1: for (k = 0; k < n16; k++) r->w[k] = c >= 16 ? 0 : (uint16_t)(a->w[k] << c); break;
        case 0xF2: for (k = 0; k < n32; k++) r->d[k] = c >= 32 ? 0 : a->d[k] << c; break;
        case 0xF3: for (k = 0; k < n64; k++) r->q[k] = c >= 64 ? 0 : a->q[k] << c; break;
        case 0xE1: for (k = 0; k < n16; k++) r->sw[k] = (int16_t)(a->sw[k] >> (c > 15 ? 15 : c)); break;
        case 0xE2: for (k = 0; k < n32; k++) r->sd[k] = a->sd[k] >> (c > 31 ? 31 : c); break;
        default: return 0;
        }
    }
    }
    return 1;
}

static int exec_map2(int op, V *r, const V *a, const V *b, int w) {
    int n8 = w, n16 = w / 2, n32 = w / 4, n64 = w / 8, k;
    switch (op) {
    case 0x00:
        for (int l = 0; l < w / 16; l++)
            for (k = 0; k < 16; k++) {
                uint8_t m = b->b[16 * l + k];
                r->b[16 * l + k] = (m & 0x80) ? 0 : a->b[16 * l + (m & 15)];
            }
        break;
    case 0x08: for (k = 0; k < n8; k++) r->sb[k] = b->sb[k] < 0 ? (int8_t)-a->sb[k] : b->sb[k] ? a->sb[k] : 0; break;
    case 0x09: for (k = 0; k < n16; k++) r->sw[k] = b->sw[k] < 0 ? (int16_t)-a->sw[k] : b->sw[k] ? a->sw[k] : 0; break;
    case 0x0A: for (k = 0; k < n32; k++) r->sd[k] = b->sd[k] < 0 ? (int32_t)(0u - a->d[k]) : b->sd[k] ? a->sd[k] : 0; break;
    case 0x28: for (k = 0; k < n64; k++) r->sq[k] = (int64_t)a->sd[2 * k] * b->sd[2 * k]; break;
    case 0x29: for (k = 0; k < n64; k++) r->q[k] = a->q[k] == b->q[k] ? ~0ull : 0; break;
    case 0x2B:
        for (int l = 0; l < w / 16; l++)
            for (k = 0; k < 4; k++) {
                r->w[8 * l + k] = us16(a->sd[4 * l + k]);
                r->w[8 * l + 4 + k] = us16(b->sd[4 * l + k]);
            }
        break;
    case 0x37: for (k = 0; k < n64; k++) r->q[k] = a->sq[k] > b->sq[k] ? ~0ull : 0; break;
    case 0x38: for (k = 0; k < n8; k++) r->sb[k] = a->sb[k] < b->sb[k] ? a->sb[k] : b->sb[k]; break;
    case 0x39: for (k = 0; k < n32; k++) r->sd[k] = a->sd[k] < b->sd[k] ? a->sd[k] : b->sd[k]; break;
    case 0x3A: for (k = 0; k < n16; k++) r->w[k] = a->w[k] < b->w[k] ? a->w[k] : b->w[k]; break;
    case 0x3B: for (k = 0; k < n32; k++) r->d[k] = a->d[k] < b->d[k] ? a->d[k] : b->d[k]; break;
    case 0x3C: for (k = 0; k < n8; k++) r->sb[k] = a->sb[k] > b->sb[k] ? a->sb[k] : b->sb[k]; break;
    case 0x3D: for (k = 0; k < n32; k++) r->sd[k] = a->sd[k] > b->sd[k] ? a->sd[k] : b->sd[k]; break;
    case 0x3E: for (k = 0; k < n16; k++) r->w[k] = a->w[k] > b->w[k] ? a->w[k] : b->w[k]; break;
    case 0x3F: for (k = 0; k < n32; k++) r->d[k] = a->d[k] > b->d[k] ? a->d[k] : b->d[k]; break;
    case 0x40: for (k = 0; k < n32; k++) r->d[k] = a->d[k] * b->d[k]; break;
    default: return 0;
    }
    return 1;
}

/* Execute; 1 = done (caller sets RIP to addr + len), 0 = leave it to Python. */
int vex_exec(uc_engine *uc, const Dec *d, uint64_t addr) {
    V a, b, r;
    int w = d->L ? 32 : 16, op = d->op, pp = d->pp, k;
    int mem = d->mod != 3;
    memset(&r, 0, sizeof r);

    if (d->map == 1) {
        switch (op) {
        case 0x58: case 0x59: case 0x5C: case 0x5D: case 0x5E: case 0x5F: case 0x51: case 0xC2: {
            int scalar = pp >= 2, dbl = pp & 1;
            int msize = scalar ? (dbl ? 8 : 4) : w;
            if (scalar) w = 16;
            vread(uc, d->vvvv, &a);
            if (!rmread(uc, d, addr, &b, msize)) return 0;
            r = a;
            int n = scalar ? 1 : (dbl ? w / 8 : w / 4);
            for (k = 0; k < n; k++) {
                if (op == 0x51) {
                    if (dbl) r.g[k] = sqrt(b.g[k]); else r.f[k] = sqrtf(b.f[k]);
                } else if (op == 0xC2) {
                    if (dbl) r.q[k] = fcmp(a.g[k], b.g[k], d->imm) ? ~0ull : 0;
                    else r.d[k] = fcmp(a.f[k], b.f[k], d->imm) ? ~0u : 0;
                } else {
                    if (dbl) r.g[k] = fop64(op, a.g[k], b.g[k]);
                    else r.f[k] = fop32(op, a.f[k], b.f[k]);
                }
            }
            vwrite(uc, d->reg, &r, w);
            return 1;
        }
        case 0x54: case 0x55: case 0x56: case 0x57:
            vread(uc, d->vvvv, &a);
            if (!rmread(uc, d, addr, &b, w)) return 0;
            for (k = 0; k < w / 8; k++)
                r.q[k] = op == 0x54 ? a.q[k] & b.q[k] : op == 0x55 ? ~a.q[k] & b.q[k]
                       : op == 0x56 ? a.q[k] | b.q[k] : a.q[k] ^ b.q[k];
            vwrite(uc, d->reg, &r, w);
            return 1;
        case 0x14: case 0x15:
            vread(uc, d->vvvv, &a);
            if (!rmread(uc, d, addr, &b, w)) return 0;
            unpack(&r, &a, &b, pp ? 8 : 4, op == 0x15, w);
            vwrite(uc, d->reg, &r, w);
            return 1;
        case 0xC6:
            vread(uc, d->vvvv, &a);
            if (!rmread(uc, d, addr, &b, w)) return 0;
            for (int l = 0; l < w / 16; l++) {
                if (pp == 0) {
                    const uint32_t *pa = a.d + 4 * l, *pb = b.d + 4 * l;
                    r.d[4 * l + 0] = pa[d->imm & 3];
                    r.d[4 * l + 1] = pa[(d->imm >> 2) & 3];
                    r.d[4 * l + 2] = pb[(d->imm >> 4) & 3];
                    r.d[4 * l + 3] = pb[(d->imm >> 6) & 3];
                } else {
                    int s = d->imm >> (2 * l);
                    r.q[2 * l] = a.q[2 * l + (s & 1)];
                    r.q[2 * l + 1] = b.q[2 * l + ((s >> 1) & 1)];
                }
            }
            vwrite(uc, d->reg, &r, w);
            return 1;
        case 0x2A: {
            uint64_t v;
            vread(uc, d->vvvv, &a);
            if (!rmint(uc, d, addr, &v, d->W ? 8 : 4)) return 0;
            int64_t s = d->W ? (int64_t)v : (int64_t)(int32_t)v;
            r = a;
            if (pp == 2) r.f[0] = (float)s; else r.g[0] = (double)s;
            vwrite(uc, d->reg, &r, 16);
            return 1;
        }
        case 0x5A:
            vread(uc, d->vvvv, &a);
            if (!rmread(uc, d, addr, &b, pp == 2 ? 4 : 8)) return 0;
            r = a;
            if (pp == 2) r.g[0] = (double)b.f[0]; else r.f[0] = (float)b.g[0];
            vwrite(uc, d->reg, &r, 16);
            return 1;
        case 0x10: case 0x11:
            if (pp >= 2) {                     /* vmovss/vmovsd xmm, xmm, xmm */
                int dst = op == 0x10 ? d->reg : d->rm, src = op == 0x10 ? d->rm : d->reg;
                vread(uc, d->vvvv, &a);
                vread(uc, src, &b);
                r = a;
                if (pp == 2) r.d[0] = b.d[0]; else r.q[0] = b.q[0];
                vwrite(uc, dst, &r, 16);
                return 1;
            }
            /* fallthrough: vmovups/vmovupd ymm */
        case 0x28: case 0x29: case 0x6F: case 0x7F:
            if (op == 0x10 || op == 0x28 || op == 0x6F) {
                if (!rmread(uc, d, addr, &r, w)) return 0;
                vwrite(uc, d->reg, &r, w);
            } else {
                vread(uc, d->reg, &r);
                if (mem) {
                    if (uc_mem_write(uc, ea(uc, d, addr), &r, w) != UC_ERR_OK) return 0;
                } else {
                    vwrite(uc, d->rm, &r, w);
                }
            }
            return 1;
        case 0x12: case 0x16:
            vread(uc, d->vvvv, &a);
            if (!rmread(uc, d, addr, &b, mem ? 8 : 16)) return 0;
            if (op == 0x12) { r.q[0] = mem ? b.q[0] : b.q[1]; r.q[1] = a.q[1]; }
            else { r.q[0] = a.q[0]; r.q[1] = b.q[0]; }
            vwrite(uc, d->reg, &r, 16);
            return 1;
        case 0x77: {
            V z;
            for (k = 0; k < 16; k++) {
                if (d->L) memset(&z, 0, sizeof z);
                else { vread(uc, k, &z); memset(z.b + 16, 0, 16); }
                uc_reg_write(uc, UC_X86_REG_YMM0 + k, &z);
            }
            return 1;
        }
        case 0x71: case 0x72: case 0x73: {
            int f = d->regf, c = d->imm;
            vread(uc, d->rm, &a);
            if (op == 0x71) {
                for (k = 0; k < w / 2; k++)
                    r.w[k] = f == 2 ? (c >= 16 ? 0 : (uint16_t)(a.w[k] >> c))
                           : f == 6 ? (c >= 16 ? 0 : (uint16_t)(a.w[k] << c))
                           : (uint16_t)(a.sw[k] >> (c > 15 ? 15 : c));
            } else if (op == 0x72) {
                for (k = 0; k < w / 4; k++)
                    r.d[k] = f == 2 ? (c >= 32 ? 0 : a.d[k] >> c)
                           : f == 6 ? (c >= 32 ? 0 : a.d[k] << c)
                           : (uint32_t)(a.sd[k] >> (c > 31 ? 31 : c));
            } else if (f == 2 || f == 6) {
                for (k = 0; k < w / 8; k++)
                    r.q[k] = c >= 64 ? 0 : f == 2 ? a.q[k] >> c : a.q[k] << c;
            } else {
                int n = c > 16 ? 16 : c;
                for (int l = 0; l < w / 16; l++) {
                    uint8_t *pr = r.b + 16 * l, *pa = a.b + 16 * l;
                    if (f == 3) memcpy(pr, pa + n, 16 - n);      /* psrldq */
                    else memcpy(pr + n, pa, 16 - n);             /* pslldq */
                }
            }
            vwrite(uc, d->vvvv, &r, w);
            return 1;
        }
        case 0xC4: {
            uint64_t v;
            vread(uc, d->vvvv, &a);
            if (!rmint(uc, d, addr, &v, 2)) return 0;
            r = a;
            r.w[d->imm & 7] = (uint16_t)v;
            vwrite(uc, d->reg, &r, 16);
            return 1;
        }
        }
        if (pp == 1 && is_int_binop(op)) {
            vread(uc, d->vvvv, &a);
            if (!rmread(uc, d, addr, &b, w)) return 0;
            if (!exec_int(op, &r, &a, &b, w)) return 0;
            vwrite(uc, d->reg, &r, w);
            return 1;
        }
        return 0;
    }

    if (d->map == 2) {
        if (op == 0x18 || op == 0x19 || op == 0x1A) {          /* broadcasts */
            if (!rmread(uc, d, addr, &b, op == 0x18 ? 4 : op == 0x19 ? 8 : 16)) return 0;
            for (k = 0; k < w / 4; k++)
                r.d[k] = op == 0x18 ? b.d[0] : op == 0x19 ? b.d[k & 1] : b.d[k & 3];
            vwrite(uc, d->reg, &r, w);
            return 1;
        }
        vread(uc, d->vvvv, &a);
        if (!rmread(uc, d, addr, &b, w)) return 0;
        if (!exec_map2(op, &r, &a, &b, w)) return 0;
        vwrite(uc, d->reg, &r, w);
        return 1;
    }

    /* map 3 */
    switch (op) {
    case 0x0A: case 0x0B:
        vread(uc, d->vvvv, &a);
        if (!rmread(uc, d, addr, &b, op == 0x0A ? 4 : 8)) return 0;
        r = a;
        if (op == 0x0A) r.f[0] = (float)rnd(b.f[0], d->imm);
        else r.g[0] = rnd(b.g[0], d->imm);
        vwrite(uc, d->reg, &r, 16);
        return 1;
    case 0x0C: case 0x0D: case 0x0E: case 0x0F:
        vread(uc, d->vvvv, &a);
        if (!rmread(uc, d, addr, &b, w)) return 0;
        if (op == 0x0C)
            for (k = 0; k < w / 4; k++) r.d[k] = (d->imm >> k) & 1 ? b.d[k] : a.d[k];
        else if (op == 0x0D)
            for (k = 0; k < w / 8; k++) r.q[k] = (d->imm >> k) & 1 ? b.q[k] : a.q[k];
        else if (op == 0x0E)
            for (k = 0; k < w / 2; k++) r.w[k] = (d->imm >> (k & 7)) & 1 ? b.w[k] : a.w[k];
        else
            for (int l = 0; l < w / 16; l++) {
                uint8_t cat[64] = {0};
                memcpy(cat, b.b + 16 * l, 16);
                memcpy(cat + 16, a.b + 16 * l, 16);
                if (d->imm < 48) memcpy(r.b + 16 * l, cat + d->imm, 16);
            }
        vwrite(uc, d->reg, &r, w);
        return 1;
    case 0x4A: case 0x4B: case 0x4C: {
        V m;
        vread(uc, d->vvvv, &a);
        if (!rmread(uc, d, addr, &b, w)) return 0;
        vread(uc, (d->imm >> 4) & 15, &m);
        if (op == 0x4A) for (k = 0; k < w / 4; k++) r.d[k] = m.sd[k] < 0 ? b.d[k] : a.d[k];
        else if (op == 0x4B) for (k = 0; k < w / 8; k++) r.q[k] = m.sq[k] < 0 ? b.q[k] : a.q[k];
        else for (k = 0; k < w; k++) r.b[k] = (m.b[k] & 0x80) ? b.b[k] : a.b[k];
        vwrite(uc, d->reg, &r, w);
        return 1;
    }
    case 0x21: {
        vread(uc, d->vvvv, &a);
        if (!rmread(uc, d, addr, &b, 4)) return 0;
        r = a;
        r.d[(d->imm >> 4) & 3] = mem ? b.d[0] : b.d[(d->imm >> 6) & 3];
        for (k = 0; k < 4; k++) if ((d->imm >> k) & 1) r.d[k] = 0;
        vwrite(uc, d->reg, &r, 16);
        return 1;
    }
    case 0x20: case 0x22: {
        uint64_t v;
        int size = op == 0x20 ? 1 : d->W ? 8 : 4;
        vread(uc, d->vvvv, &a);
        if (!rmint(uc, d, addr, &v, size)) return 0;
        r = a;
        if (op == 0x20) r.b[d->imm & 15] = (uint8_t)v;
        else if (d->W) r.q[d->imm & 1] = v;
        else r.d[d->imm & 3] = (uint32_t)v;
        vwrite(uc, d->reg, &r, 16);
        return 1;
    }
    case 0x18:                                               /* vinsertf128 */
        vread(uc, d->vvvv, &a);
        if (!rmread(uc, d, addr, &b, 16)) return 0;
        r = a;
        memcpy(r.b + 16 * (d->imm & 1), b.b, 16);
        vwrite(uc, d->reg, &r, 32);
        return 1;
    case 0x19:                                               /* vextractf128 */
        vread(uc, d->reg, &a);
        memcpy(r.b, a.b + 16 * (d->imm & 1), 16);
        if (mem) return uc_mem_write(uc, ea(uc, d, addr), &r, 16) == UC_ERR_OK;
        vwrite(uc, d->rm, &r, 16);
        return 1;
    case 0x06: {                                             /* vperm2f128 */
        vread(uc, d->vvvv, &a);
        if (!rmread(uc, d, addr, &b, 32)) return 0;
        const uint8_t *lanes[4] = {a.b, a.b + 16, b.b, b.b + 16};
        if (!(d->imm & 0x08)) memcpy(r.b, lanes[d->imm & 3], 16);
        if (!(d->imm & 0x80)) memcpy(r.b + 16, lanes[(d->imm >> 4) & 3], 16);
        vwrite(uc, d->reg, &r, 32);
        return 1;
    }
    }
    return 0;
}
