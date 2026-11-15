"""AMD GCN gen2 ("Sea Islands" / GFX7) instruction decoder.

The PS4 GPU ("Liverpool") is a GFX7 part, so every shader in the firmware is
GFX7 machine code. This module turns raw dwords into `Insn` objects and can
print them as assembly. Execution lives in `wave.py`.

Encodings handled: SOP2 SOPK SOP1 SOPC SOPP SMRD VOP2 VOP1 VOPC VOP3a/b
VINTRP DS MUBUF MTBUF MIMG EXP FLAT.
"""
import struct


def _table(pairs):
    return dict(pairs)


SOP2 = _table(enumerate(
    "s_add_u32 s_sub_u32 s_add_i32 s_sub_i32 s_addc_u32 s_subb_u32 s_min_i32 "
    "s_min_u32 s_max_i32 s_max_u32 s_cselect_b32 s_cselect_b64 - - s_and_b32 "
    "s_and_b64 s_or_b32 s_or_b64 s_xor_b32 s_xor_b64 s_andn2_b32 s_andn2_b64 "
    "s_orn2_b32 s_orn2_b64 s_nand_b32 s_nand_b64 s_nor_b32 s_nor_b64 s_xnor_b32 "
    "s_xnor_b64 s_lshl_b32 s_lshl_b64 s_lshr_b32 s_lshr_b64 s_ashr_i32 s_ashr_i64 "
    "s_bfm_b32 s_bfm_b64 s_mul_i32 s_bfe_u32 s_bfe_i32 s_bfe_u64 s_bfe_i64 "
    "s_cbranch_g_fork s_absdiff_i32".split()))

SOPK = {0: "s_movk_i32", 2: "s_cmovk_i32", 3: "s_cmpk_eq_i32", 4: "s_cmpk_lg_i32",
        5: "s_cmpk_gt_i32", 6: "s_cmpk_ge_i32", 7: "s_cmpk_lt_i32", 8: "s_cmpk_le_i32",
        9: "s_cmpk_eq_u32", 10: "s_cmpk_lg_u32", 11: "s_cmpk_gt_u32", 12: "s_cmpk_ge_u32",
        13: "s_cmpk_lt_u32", 14: "s_cmpk_le_u32", 15: "s_addk_i32", 16: "s_mulk_i32",
        17: "s_cbranch_i_fork", 18: "s_getreg_b32", 19: "s_setreg_b32",
        21: "s_setreg_imm32_b32"}

SOP1 = {3: "s_mov_b32", 4: "s_mov_b64", 5: "s_cmov_b32", 6: "s_cmov_b64",
        7: "s_not_b32", 8: "s_not_b64", 9: "s_wqm_b32", 10: "s_wqm_b64",
        11: "s_brev_b32", 12: "s_brev_b64", 13: "s_bcnt0_i32_b32", 14: "s_bcnt0_i32_b64",
        15: "s_bcnt1_i32_b32", 16: "s_bcnt1_i32_b64", 17: "s_ff0_i32_b32",
        18: "s_ff0_i32_b64", 19: "s_ff1_i32_b32", 20: "s_ff1_i32_b64",
        21: "s_flbit_i32_b32", 22: "s_flbit_i32_b64", 23: "s_flbit_i32",
        24: "s_flbit_i32_i64", 25: "s_sext_i32_i8", 26: "s_sext_i32_i16",
        27: "s_bitset0_b32", 28: "s_bitset0_b64", 29: "s_bitset1_b32",
        30: "s_bitset1_b64", 31: "s_getpc_b64", 32: "s_setpc_b64", 33: "s_swappc_b64",
        34: "s_rfe_b64", 36: "s_and_saveexec_b64", 37: "s_or_saveexec_b64",
        38: "s_xor_saveexec_b64", 39: "s_andn2_saveexec_b64", 40: "s_orn2_saveexec_b64",
        41: "s_nand_saveexec_b64", 42: "s_nor_saveexec_b64", 43: "s_xnor_saveexec_b64",
        44: "s_quadmask_b32", 45: "s_quadmask_b64", 46: "s_movrels_b32",
        47: "s_movrels_b64", 48: "s_movreld_b32", 49: "s_movreld_b64",
        50: "s_cbranch_join", 52: "s_abs_i32", 53: "s_mov_fed_b32"}

SOPC = _table(enumerate(
    "s_cmp_eq_i32 s_cmp_lg_i32 s_cmp_gt_i32 s_cmp_ge_i32 s_cmp_lt_i32 s_cmp_le_i32 "
    "s_cmp_eq_u32 s_cmp_lg_u32 s_cmp_gt_u32 s_cmp_ge_u32 s_cmp_lt_u32 s_cmp_le_u32 "
    "s_bitcmp0_b32 s_bitcmp1_b32 s_bitcmp0_b64 s_bitcmp1_b64 s_setvskip".split()))

SOPP = {0: "s_nop", 1: "s_endpgm", 2: "s_branch", 4: "s_cbranch_scc0",
        5: "s_cbranch_scc1", 6: "s_cbranch_vccz", 7: "s_cbranch_vccnz",
        8: "s_cbranch_execz", 9: "s_cbranch_execnz", 10: "s_barrier",
        11: "s_setkill", 12: "s_waitcnt", 13: "s_sethalt", 14: "s_sleep",
        15: "s_setprio", 16: "s_sendmsg", 17: "s_sendmsghalt", 18: "s_trap",
        19: "s_icache_inv", 20: "s_incperflevel", 21: "s_decperflevel",
        22: "s_ttracedata", 23: "s_cbranch_cdbgsys", 24: "s_cbranch_cdbguser",
        25: "s_cbranch_cdbgsys_or_user", 26: "s_cbranch_cdbgsys_and_user"}

SMRD = {0: "s_load_dword", 1: "s_load_dwordx2", 2: "s_load_dwordx4",
        3: "s_load_dwordx8", 4: "s_load_dwordx16", 8: "s_buffer_load_dword",
        9: "s_buffer_load_dwordx2", 10: "s_buffer_load_dwordx4",
        11: "s_buffer_load_dwordx8", 12: "s_buffer_load_dwordx16",
        29: "s_dcache_inv_vol", 30: "s_memtime", 31: "s_dcache_inv"}

VOP2 = _table(enumerate(
    "v_cndmask_b32 v_readlane_b32 v_writelane_b32 v_add_f32 v_sub_f32 v_subrev_f32 "
    "v_mac_legacy_f32 v_mul_legacy_f32 v_mul_f32 v_mul_i32_i24 v_mul_hi_i32_i24 "
    "v_mul_u32_u24 v_mul_hi_u32_u24 v_min_legacy_f32 v_max_legacy_f32 v_min_f32 "
    "v_max_f32 v_min_i32 v_max_i32 v_min_u32 v_max_u32 v_lshr_b32 v_lshrrev_b32 "
    "v_ashr_i32 v_ashrrev_i32 v_lshl_b32 v_lshlrev_b32 v_and_b32 v_or_b32 v_xor_b32 "
    "v_bfm_b32 v_mac_f32 v_madmk_f32 v_madak_f32 v_bcnt_u32_b32 v_mbcnt_lo_u32_b32 "
    "v_mbcnt_hi_u32_b32 v_add_i32 v_sub_i32 v_subrev_i32 v_addc_u32 v_subb_u32 "
    "v_subbrev_u32 v_ldexp_f32 v_cvt_pkaccum_u8_f32 v_cvt_pknorm_i16_f32 "
    "v_cvt_pknorm_u16_f32 v_cvt_pkrtz_f16_f32 v_cvt_pk_u16_u32 v_cvt_pk_i16_i32".split()))

VOP1 = {0: "v_nop", 1: "v_mov_b32", 2: "v_readfirstlane_b32", 3: "v_cvt_i32_f64",
        4: "v_cvt_f64_i32", 5: "v_cvt_f32_i32", 6: "v_cvt_f32_u32", 7: "v_cvt_u32_f32",
        8: "v_cvt_i32_f32", 9: "v_mov_fed_b32", 10: "v_cvt_f16_f32", 11: "v_cvt_f32_f16",
        12: "v_cvt_rpi_i32_f32", 13: "v_cvt_flr_i32_f32", 14: "v_cvt_off_f32_i4",
        15: "v_cvt_f32_f64", 16: "v_cvt_f64_f32", 17: "v_cvt_f32_ubyte0",
        18: "v_cvt_f32_ubyte1", 19: "v_cvt_f32_ubyte2", 20: "v_cvt_f32_ubyte3",
        21: "v_cvt_u32_f64", 22: "v_cvt_f64_u32", 23: "v_trunc_f64", 24: "v_ceil_f64",
        25: "v_rndne_f64", 26: "v_floor_f64", 32: "v_fract_f32", 33: "v_trunc_f32",
        34: "v_ceil_f32", 35: "v_rndne_f32", 36: "v_floor_f32", 37: "v_exp_f32",
        38: "v_log_clamp_f32", 39: "v_log_f32", 40: "v_rcp_clamp_f32",
        41: "v_rcp_legacy_f32", 42: "v_rcp_f32", 43: "v_rcp_iflag_f32",
        44: "v_rsq_clamp_f32", 45: "v_rsq_legacy_f32", 46: "v_rsq_f32", 47: "v_rcp_f64",
        48: "v_rcp_clamp_f64", 49: "v_rsq_f64", 50: "v_rsq_clamp_f64", 51: "v_sqrt_f32",
        52: "v_sqrt_f64", 53: "v_sin_f32", 54: "v_cos_f32", 55: "v_not_b32",
        56: "v_bfrev_b32", 57: "v_ffbh_u32", 58: "v_ffbl_b32", 59: "v_ffbh_i32",
        60: "v_frexp_exp_i32_f64", 61: "v_frexp_mant_f64", 62: "v_fract_f64",
        63: "v_frexp_exp_i32_f32", 64: "v_frexp_mant_f32", 65: "v_clrexcp",
        66: "v_movreld_b32", 67: "v_movrels_b32", 68: "v_movrelsd_b32",
        69: "v_log_legacy_f32", 70: "v_exp_legacy_f32"}

VOP3_ONLY = _table((320 + i, n) for i, n in enumerate(
    "v_mad_legacy_f32 v_mad_f32 v_mad_i32_i24 v_mad_u32_u24 v_cubeid_f32 "
    "v_cubesc_f32 v_cubetc_f32 v_cubema_f32 v_bfe_u32 v_bfe_i32 v_bfi_b32 "
    "v_fma_f32 v_fma_f64 v_lerp_u8 v_alignbit_b32 v_alignbyte_b32 v_mullit_f32 "
    "v_min3_f32 v_min3_i32 v_min3_u32 v_max3_f32 v_max3_i32 v_max3_u32 v_med3_f32 "
    "v_med3_i32 v_med3_u32 v_sad_u8 v_sad_hi_u8 v_sad_u16 v_sad_u32 v_cvt_pk_u8_f32 "
    "v_div_fixup_f32 v_div_fixup_f64 v_lshl_b64 v_lshr_b64 v_ashr_i64 v_add_f64 "
    "v_mul_f64 v_min_f64 v_max_f64 v_ldexp_f64 v_mul_lo_u32 v_mul_hi_u32 "
    "v_mul_lo_i32 v_mul_hi_i32 v_div_scale_f32 v_div_scale_f64 v_div_fmas_f32 "
    "v_div_fmas_f64 v_msad_u8 v_qsad_pk_u16_u8 v_mqsad_pk_u16_u8 v_trig_preop_f64 "
    "v_mqsad_u32_u8 v_mad_u64_u32 v_mad_i64_i32".split()))

# VOPC: compare ops. 16 float predicates, 8 integer predicates.
_FCMP = "f lt eq le gt lg ge o u nge nlg ngt nle neq nlt tru".split()
_ICMP = "f lt eq le gt ne ge t".split()


def _vopc_table():
    t = {}
    for base, kind in ((0x00, "cmp_%s_f32"), (0x10, "cmpx_%s_f32"),
                       (0x20, "cmp_%s_f64"), (0x30, "cmpx_%s_f64"),
                       (0x40, "cmps_%s_f32"), (0x50, "cmpsx_%s_f32"),
                       (0x60, "cmps_%s_f64"), (0x70, "cmpsx_%s_f64")):
        for i, p in enumerate(_FCMP):
            t[base + i] = "v_" + kind % p
    for base, kind in ((0x80, "cmp_%s_i32"), (0x90, "cmpx_%s_i32"),
                       (0xA0, "cmp_%s_i64"), (0xB0, "cmpx_%s_i64"),
                       (0xC0, "cmp_%s_u32"), (0xD0, "cmpx_%s_u32"),
                       (0xE0, "cmp_%s_u64"), (0xF0, "cmpx_%s_u64")):
        for i, p in enumerate(_ICMP):
            t[base + i] = "v_" + kind % p
    t[0x88] = "v_cmp_class_f32"; t[0x98] = "v_cmpx_class_f32"
    t[0xA8] = "v_cmp_class_f64"; t[0xB8] = "v_cmpx_class_f64"
    return t


VOPC = _vopc_table()


def vop3_name(op):
    if op < 256:
        return VOPC.get(op)
    if op < 320:
        return VOP2.get(op - 256)
    if op < 384:
        return VOP3_ONLY.get(op)
    return VOP1.get(op - 384)


# VOP3b ops: these write a scalar carry/flag (sdst) as well as vdst.
VOP3B = {"v_add_i32", "v_sub_i32", "v_subrev_i32", "v_addc_u32", "v_subb_u32",
         "v_subbrev_u32", "v_div_scale_f32", "v_div_scale_f64"}

VINTRP = {0: "v_interp_p1_f32", 1: "v_interp_p2_f32", 2: "v_interp_mov_f32"}

DS = {0: "ds_add_u32", 1: "ds_sub_u32", 2: "ds_rsub_u32", 3: "ds_inc_u32",
      4: "ds_dec_u32", 5: "ds_min_i32", 6: "ds_max_i32", 7: "ds_min_u32",
      8: "ds_max_u32", 9: "ds_and_b32", 10: "ds_or_b32", 11: "ds_xor_b32",
      12: "ds_mskor_b32", 13: "ds_write_b32", 14: "ds_write2_b32",
      15: "ds_write2st64_b32", 16: "ds_cmpst_b32", 17: "ds_cmpst_f32",
      18: "ds_min_f32", 19: "ds_max_f32", 20: "ds_nop", 25: "ds_gws_sema_release_all",
      26: "ds_gws_init", 27: "ds_gws_sema_v", 28: "ds_gws_sema_br", 29: "ds_gws_sema_p",
      30: "ds_write_b8", 31: "ds_write_b16", 32: "ds_add_rtn_u32", 33: "ds_sub_rtn_u32",
      34: "ds_rsub_rtn_u32", 35: "ds_inc_rtn_u32", 36: "ds_dec_rtn_u32",
      37: "ds_min_rtn_i32", 38: "ds_max_rtn_i32", 39: "ds_min_rtn_u32",
      40: "ds_max_rtn_u32", 41: "ds_and_rtn_b32", 42: "ds_or_rtn_b32",
      43: "ds_xor_rtn_b32", 44: "ds_mskor_rtn_b32", 45: "ds_wrxchg_rtn_b32",
      46: "ds_wrxchg2_rtn_b32", 47: "ds_wrxchg2st64_rtn_b32", 48: "ds_cmpst_rtn_b32",
      49: "ds_cmpst_rtn_f32", 50: "ds_min_rtn_f32", 51: "ds_max_rtn_f32",
      52: "ds_wrap_rtn_b32", 53: "ds_swizzle_b32", 54: "ds_read_b32",
      55: "ds_read2_b32", 56: "ds_read2st64_b32", 57: "ds_read_i8", 58: "ds_read_u8",
      59: "ds_read_i16", 60: "ds_read_u16", 61: "ds_consume", 62: "ds_append",
      63: "ds_ordered_count", 64: "ds_add_u64", 77: "ds_write_b64",
      78: "ds_write2_b64", 79: "ds_write2st64_b64", 96: "ds_add_rtn_u64",
      118: "ds_read_b64", 119: "ds_read2_b64", 120: "ds_read2st64_b64",
      222: "ds_write_b96", 223: "ds_write_b128", 254: "ds_read_b96", 255: "ds_read_b128"}

MUBUF = {0: "buffer_load_format_x", 1: "buffer_load_format_xy",
         2: "buffer_load_format_xyz", 3: "buffer_load_format_xyzw",
         4: "buffer_store_format_x", 5: "buffer_store_format_xy",
         6: "buffer_store_format_xyz", 7: "buffer_store_format_xyzw",
         8: "buffer_load_ubyte", 9: "buffer_load_sbyte", 10: "buffer_load_ushort",
         11: "buffer_load_sshort", 12: "buffer_load_dword", 13: "buffer_load_dwordx2",
         14: "buffer_load_dwordx4", 15: "buffer_load_dwordx3", 24: "buffer_store_byte",
         26: "buffer_store_short", 28: "buffer_store_dword", 29: "buffer_store_dwordx2",
         30: "buffer_store_dwordx4", 31: "buffer_store_dwordx3",
         48: "buffer_atomic_swap", 49: "buffer_atomic_cmpswap", 50: "buffer_atomic_add",
         51: "buffer_atomic_sub", 53: "buffer_atomic_smin", 54: "buffer_atomic_umin",
         55: "buffer_atomic_smax", 56: "buffer_atomic_umax", 57: "buffer_atomic_and",
         58: "buffer_atomic_or", 59: "buffer_atomic_xor", 60: "buffer_atomic_inc",
         61: "buffer_atomic_dec", 112: "buffer_wbinvl1_vol", 113: "buffer_wbinvl1"}

MTBUF = {0: "tbuffer_load_format_x", 1: "tbuffer_load_format_xy",
         2: "tbuffer_load_format_xyz", 3: "tbuffer_load_format_xyzw",
         4: "tbuffer_store_format_x", 5: "tbuffer_store_format_xy",
         6: "tbuffer_store_format_xyz", 7: "tbuffer_store_format_xyzw"}

_SAMPLE = ("", "_cl", "_d", "_d_cl", "_l", "_b", "_b_cl", "_lz")
MIMG = {0: "image_load", 1: "image_load_mip", 2: "image_load_pck",
        3: "image_load_pck_sgn", 4: "image_load_mip_pck", 5: "image_load_mip_pck_sgn",
        8: "image_store", 9: "image_store_mip", 10: "image_store_pck",
        11: "image_store_mip_pck", 14: "image_get_resinfo", 15: "image_atomic_swap",
        16: "image_atomic_cmpswap", 17: "image_atomic_add", 18: "image_atomic_sub",
        20: "image_atomic_smin", 21: "image_atomic_umin", 22: "image_atomic_smax",
        23: "image_atomic_umax", 24: "image_atomic_and", 25: "image_atomic_or",
        26: "image_atomic_xor", 27: "image_atomic_inc", 28: "image_atomic_dec",
        96: "image_get_lod"}
for _i, _s in enumerate(_SAMPLE):
    MIMG[32 + _i] = "image_sample" + _s
    MIMG[40 + _i] = "image_sample_c" + _s
    MIMG[48 + _i] = "image_sample" + _s + "_o"
    MIMG[56 + _i] = "image_sample_c" + _s + "_o"
    MIMG[64 + _i] = "image_gather4" + _s
    MIMG[72 + _i] = "image_gather4_c" + _s
    MIMG[80 + _i] = "image_gather4" + _s + "_o"
    MIMG[88 + _i] = "image_gather4_c" + _s + "_o"
for _i, _s in enumerate(("image_sample_cd", "image_sample_cd_cl", "image_sample_c_cd",
                         "image_sample_c_cd_cl", "image_sample_cd_o", "image_sample_cd_cl_o",
                         "image_sample_c_cd_o", "image_sample_c_cd_cl_o")):
    MIMG[104 + _i] = _s

FLAT = {8: "flat_load_ubyte", 9: "flat_load_sbyte", 10: "flat_load_ushort",
        11: "flat_load_sshort", 12: "flat_load_dword", 13: "flat_load_dwordx2",
        14: "flat_load_dwordx4", 15: "flat_load_dwordx3", 24: "flat_store_byte",
        26: "flat_store_short", 28: "flat_store_dword", 29: "flat_store_dwordx2",
        30: "flat_store_dwordx4", 31: "flat_store_dwordx3", 48: "flat_atomic_swap",
        49: "flat_atomic_cmpswap", 50: "flat_atomic_add", 51: "flat_atomic_sub"}

EXP_TARGETS = {**{i: "mrt%d" % i for i in range(8)}, 8: "mrtz", 9: "null",
               **{12 + i: "pos%d" % i for i in range(4)},
               **{32 + i: "param%d" % i for i in range(32)}}

# Scalar operand codes (shared by 7/8-bit SOP fields and 9-bit VOP src fields).
SRC_LITERAL = 255
INLINE_FLOATS = {240: 0.5, 241: -0.5, 242: 1.0, 243: -1.0, 244: 2.0, 245: -2.0,
                 246: 4.0, 247: -4.0}
_SPECIAL = {104: "flat_scratch_lo", 105: "flat_scratch_hi", 106: "vcc_lo",
            107: "vcc_hi", 108: "tba_lo", 109: "tba_hi", 110: "tma_lo", 111: "tma_hi",
            124: "m0", 126: "exec_lo", 127: "exec_hi", 251: "vccz", 252: "execz",
            253: "scc", 254: "lds_direct"}
_PAIR = {106: "vcc", 126: "exec", 104: "flat_scratch", 108: "tba", 110: "tma"}


def inline_const(code):
    """Return the 32-bit pattern of an inline constant, or None."""
    if code == 128:
        return 0
    if 129 <= code <= 192:
        return code - 128
    if 193 <= code <= 208:
        return (-(code - 192)) & 0xFFFFFFFF
    if code in INLINE_FLOATS:
        return struct.unpack("<I", struct.pack("<f", INLINE_FLOATS[code]))[0]
    return None


def operand_str(code, nregs=1, literal=None):
    if code >= 256:
        r = code - 256
        return "v%d" % r if nregs == 1 else "v[%d:%d]" % (r, r + nregs - 1)
    if code < 104:
        return "s%d" % code if nregs == 1 else "s[%d:%d]" % (code, code + nregs - 1)
    if 112 <= code <= 123:
        t = code - 112
        return "ttmp%d" % t if nregs == 1 else "ttmp[%d:%d]" % (t, t + nregs - 1)
    if nregs == 2 and code in _PAIR:
        return _PAIR[code]
    if code in _SPECIAL:
        return _SPECIAL[code]
    if code == SRC_LITERAL:
        return "0x%x" % (literal or 0)
    if code == 128:
        return "0"
    if 129 <= code <= 208:
        return str(code - 128 if code <= 192 else -(code - 192))
    if code in INLINE_FLOATS:
        return repr(INLINE_FLOATS[code])
    return "src%d" % code


class Insn:
    """One decoded instruction. `f` holds the raw encoding fields."""
    __slots__ = ("pc", "enc", "op", "name", "size", "f", "lit")

    def __init__(self, pc, enc, op, name, size, f, lit=None):
        self.pc, self.enc, self.op, self.name = pc, enc, op, name
        self.size, self.f, self.lit = size, f, lit

    def __repr__(self):
        return "<%s @%#x %s>" % (self.enc, self.pc, self.text())

    # -------------------------------------------------------- disassembly
    def text(self):
        f, n, L = self.f, self.name or "%s_op%d" % (self.enc.lower(), self.op), self.lit
        w = 2 if n.endswith("64") and not n.startswith("s_cmp") else 1
        e = self.enc
        try:
            if e == "SOP2":
                w0 = 2 if n.endswith("_b64") or n.endswith("_i64") or n.endswith("_u64") else 1
                w1 = 1 if n in ("s_lshl_b64", "s_lshr_b64", "s_ashr_i64", "s_bfm_b64") else w0
                if n.startswith("s_bfe_") and n.endswith("64"):
                    w1 = 1
                if n == "s_bfm_b64":
                    w0 = 1
                return "%s %s, %s, %s" % (n, operand_str(f["sdst"], 2 if n.endswith("64") else 1),
                                          operand_str(f["ssrc0"], w0, L), operand_str(f["ssrc1"], w1, L))
            if e == "SOPK":
                return "%s %s, 0x%x" % (n, operand_str(f["sdst"]), f["simm16"])
            if e == "SOP1":
                if n in ("s_getpc_b64",):
                    return "%s %s" % (n, operand_str(f["sdst"], 2))
                if n in ("s_setpc_b64", "s_rfe_b64"):
                    return "%s %s" % (n, operand_str(f["ssrc0"], 2))
                dw = 1 if ("bcnt" in n or "ff" in n or "flbit" in n) else w
                return "%s %s, %s" % (n, operand_str(f["sdst"], dw), operand_str(f["ssrc0"], w, L))
            if e == "SOPC":
                w = 2 if n.endswith("64") else 1
                return "%s %s, %s" % (n, operand_str(f["ssrc0"], w, L), operand_str(f["ssrc1"], 1, L))
            if e == "SOPP":
                s = f["simm16"]
                if n == "s_waitcnt":
                    return "s_waitcnt vmcnt(%d) expcnt(%d) lgkmcnt(%d)" % (
                        s & 0xF, (s >> 4) & 7, (s >> 8) & 0x1F)
                if "branch" in n:
                    off = s - 0x10000 if s & 0x8000 else s
                    return "%s 0x%x" % (n, self.pc + 4 + off * 4)
                if n in ("s_endpgm", "s_barrier", "s_icache_inv"):
                    return n
                return "%s 0x%x" % (n, s)
            if e == "SMRD":
                cnt = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16}[self.op & 7] if self.op not in (29, 30, 31) else 0
                if self.op in (29, 31):
                    return n
                if self.op == 30:
                    return "%s %s" % (n, operand_str(f["sdst"], 2))
                base = operand_str(f["sbase"], 4 if self.op >= 8 else 2)
                off = "0x%x" % f["offset"] if f["imm"] else operand_str(f["offset"], 1, L)
                return "%s %s, %s, %s" % (n, operand_str(f["sdst"], cnt), base, off)
            if e in ("VOP1", "VOP2", "VOPC", "VOP3"):
                return self._valu_text(n)
            if e == "VINTRP":
                ch = "xyzw"[f["attrchan"]]
                src = "p%d" % (10, 20, 0)[f["vsrc"] % 3] if self.op == 2 else "v%d" % f["vsrc"]
                return "%s v%d, %s, attr%d.%s" % (n, f["vdst"], src, f["attr"], ch)
            if e == "DS":
                return "%s vdst=v%d addr=v%d d0=v%d d1=v%d off0=%d off1=%d%s" % (
                    n, f["vdst"], f["addr"], f["data0"], f["data1"], f["offset0"],
                    f["offset1"], " gds" if f["gds"] else "")
            if e in ("MUBUF", "MTBUF"):
                extra = ""
                if e == "MTBUF":
                    extra = " format:[%d,%d]" % (f["dfmt"], f["nfmt"])
                mods = "".join(" " + k for k in ("offen", "idxen", "glc", "addr64", "lds")
                               if f.get(k))
                return "%s v%d, v%d, s[%d:%d], %s offset:%d%s%s" % (
                    n, f["vdata"], f["vaddr"], f["srsrc"] * 4, f["srsrc"] * 4 + 3,
                    operand_str(f["soffset"]), f["offset"], mods, extra)
            if e == "MIMG":
                return "%s v%d, v%d, s[%d:%d], s[%d:%d] dmask:0x%x%s%s" % (
                    n, f["vdata"], f["vaddr"], f["srsrc"] * 4, f["srsrc"] * 4 + 7,
                    f["ssamp"] * 4, f["ssamp"] * 4 + 3, f["dmask"],
                    " unorm" if f["unorm"] else "", " da" if f["da"] else "")
            if e == "EXP":
                regs = ", ".join("v%d" % f["vsrc"][i] if f["en"] >> i & 1 else "off"
                                 for i in range(4))
                return "exp %s, %s%s%s%s" % (
                    EXP_TARGETS.get(f["tgt"], "tgt%d" % f["tgt"]), regs,
                    " compr" if f["compr"] else "", " done" if f["done"] else "",
                    " vm" if f["vm"] else "")
            if e == "FLAT":
                return "%s v%d, v[%d:%d], v%d" % (n, f["vdst"], f["addr"], f["addr"] + 1, f["data"])
        except Exception as ex:  # disassembly must never crash a scan
            return "%s <%s>" % (n, ex)
        return n

    def _valu_text(self, n):
        f, L = self.f, self.lit
        d64 = "_f64" in n or "_b64" in n or "_i64" in n or "_u64" in n
        w = 2 if d64 else 1

        def src(i):
            c = f["src%d" % i]
            s = operand_str(c, w if not n.startswith("v_cvt_f32_f64") or i else 2, L)
            if self.enc == "VOP3":
                if f["abs"] >> i & 1:
                    s = "|%s|" % s
                if f["neg"] >> i & 1:
                    s = "-" + s
            return s

        if self.enc == "VOPC" or (self.enc == "VOP3" and self.op < 256):
            dst = "vcc" if self.enc == "VOPC" else operand_str(f["vdst"], 2)
            return "%s %s, %s, %s" % (n, dst, src(0), src(1))
        nsrc = {"VOP1": 1, "VOP2": 2}.get(self.enc)
        if self.enc == "VOP3":
            nsrc = 1 if self.op >= 384 else (2 if self.op < 320 else 3)
            if n in ("v_cndmask_b32", "v_addc_u32", "v_subb_u32", "v_subbrev_u32"):
                nsrc = 3
        vd = f["vdst"]
        dst = ("v[%d:%d]" % (vd, vd + 1)) if d64 and "cvt_f32_f64" not in n and "cvt_i32_f64" not in n \
            and "cvt_u32_f64" not in n else "v%d" % vd
        if n in ("v_readlane_b32", "v_readfirstlane_b32"):
            dst = operand_str(vd)
        parts = [src(i) for i in range(nsrc)]
        if self.enc == "VOP2" and n in ("v_madmk_f32",):
            parts = [src(0), "0x%x" % L, src(1)]
        elif self.enc == "VOP2" and n in ("v_madak_f32",):
            parts = [src(0), src(1), "0x%x" % L]
        elif self.enc == "VOP2" and n in ("v_cndmask_b32", "v_addc_u32", "v_subb_u32",
                                          "v_subbrev_u32"):
            parts.append("vcc")
        if self.enc == "VOP2" and n in ("v_add_i32", "v_sub_i32", "v_subrev_i32",
                                        "v_addc_u32", "v_subb_u32", "v_subbrev_u32"):
            dst += ", vcc"
        if self.enc == "VOP3" and n in VOP3B:
            dst += ", " + operand_str(f["sdst"], 2)
        txt = "%s %s, %s" % (n, dst, ", ".join(parts))
        if self.enc == "VOP3":
            if f.get("clamp"):
                txt += " clamp"
            if f["omod"]:
                txt += (" mul:2", " mul:4", " div:2")[f["omod"] - 1]
        return txt


# ---------------------------------------------------------------- decoding

class DecodeError(Exception):
    pass


def _bits(v, lo, n):
    return (v >> lo) & ((1 << n) - 1)


def decode_one(code, pos, pc=None):
    """Decode the instruction at byte offset `pos` of `code` (bytes-like).
    `pc` is the address printed for it (defaults to pos)."""
    if pc is None:
        pc = pos
    if pos + 4 > len(code):
        raise DecodeError("truncated at %#x" % pos)
    d0 = struct.unpack_from("<I", code, pos)[0]

    def d1():
        if pos + 8 > len(code):
            raise DecodeError("truncated 64-bit insn at %#x" % pos)
        return struct.unpack_from("<I", code, pos + 4)[0]

    def lit(at=4):
        if pos + at + 4 > len(code):
            raise DecodeError("truncated literal at %#x" % pos)
        return struct.unpack_from("<I", code, pos + at)[0]

    top9 = d0 >> 23
    if d0 >> 31 == 0:  # VOP1 / VOPC / VOP2
        if (d0 >> 25) == 0x3F:
            op = _bits(d0, 9, 8)
            f = {"src0": _bits(d0, 0, 9), "vdst": _bits(d0, 17, 8)}
            size, L = 4, None
            if f["src0"] == SRC_LITERAL:
                L, size = lit(), 8
            return Insn(pc, "VOP1", op, VOP1.get(op), size, f, L)
        if (d0 >> 25) == 0x3E:
            op = _bits(d0, 17, 8)
            f = {"src0": _bits(d0, 0, 9), "src1": 256 + _bits(d0, 9, 8)}
            size, L = 4, None
            if f["src0"] == SRC_LITERAL:
                L, size = lit(), 8
            return Insn(pc, "VOPC", op, VOPC.get(op), size, f, L)
        op = _bits(d0, 25, 6)
        f = {"src0": _bits(d0, 0, 9), "src1": 256 + _bits(d0, 9, 8), "vdst": _bits(d0, 17, 8)}
        name = VOP2.get(op)
        size, L = 4, None
        if f["src0"] == SRC_LITERAL or name in ("v_madmk_f32", "v_madak_f32"):
            L, size = lit(), 8
        return Insn(pc, "VOP2", op, name, size, f, L)

    if top9 == 0x17D:
        op = _bits(d0, 8, 8)
        f = {"ssrc0": _bits(d0, 0, 8), "sdst": _bits(d0, 16, 7)}
        size, L = 4, None
        if f["ssrc0"] == SRC_LITERAL:
            L, size = lit(), 8
        return Insn(pc, "SOP1", op, SOP1.get(op), size, f, L)
    if top9 == 0x17E:
        op = _bits(d0, 16, 7)
        f = {"ssrc0": _bits(d0, 0, 8), "ssrc1": _bits(d0, 8, 8)}
        size, L = 4, None
        if SRC_LITERAL in (f["ssrc0"], f["ssrc1"]):
            L, size = lit(), 8
        return Insn(pc, "SOPC", op, SOPC.get(op), size, f, L)
    if top9 == 0x17F:
        op = _bits(d0, 16, 7)
        return Insn(pc, "SOPP", op, SOPP.get(op), 4, {"simm16": d0 & 0xFFFF})
    if d0 >> 28 == 0xB:
        op = _bits(d0, 23, 5)
        f = {"simm16": d0 & 0xFFFF, "sdst": _bits(d0, 16, 7)}
        size, L = 4, None
        if op == 21:
            L, size = lit(), 8
        return Insn(pc, "SOPK", op, SOPK.get(op), size, f, L)
    if d0 >> 30 == 0x2:
        op = _bits(d0, 23, 7)
        f = {"ssrc0": _bits(d0, 0, 8), "ssrc1": _bits(d0, 8, 8), "sdst": _bits(d0, 16, 7)}
        size, L = 4, None
        if SRC_LITERAL in (f["ssrc0"], f["ssrc1"]):
            L, size = lit(), 8
        return Insn(pc, "SOP2", op, SOP2.get(op), size, f, L)
    if d0 >> 27 == 0x18:
        op = _bits(d0, 22, 5)
        f = {"offset": d0 & 0xFF, "imm": _bits(d0, 8, 1), "sbase": _bits(d0, 9, 6) * 2,
             "sdst": _bits(d0, 15, 7)}
        size, L = 4, None
        if not f["imm"] and f["offset"] == SRC_LITERAL:
            L, size = lit(), 8
        return Insn(pc, "SMRD", op, SMRD.get(op), size, f, L)

    top6 = d0 >> 26
    if top6 == 0x34:  # VOP3
        x = d1()
        op = _bits(d0, 17, 9)
        name = vop3_name(op)
        f = {"vdst": d0 & 0xFF, "src0": _bits(x, 0, 9), "src1": _bits(x, 9, 9),
             "src2": _bits(x, 18, 9), "omod": _bits(x, 27, 2), "neg": _bits(x, 29, 3)}
        if name in VOP3B:
            f.update(sdst=_bits(d0, 8, 7), abs=0, clamp=0)
        else:
            f.update(abs=_bits(d0, 8, 3), clamp=_bits(d0, 11, 1))
        return Insn(pc, "VOP3", op, name, 8, f)
    if top6 == 0x32:
        op = _bits(d0, 16, 2)
        f = {"vsrc": d0 & 0xFF, "attrchan": _bits(d0, 8, 2), "attr": _bits(d0, 10, 6),
             "vdst": _bits(d0, 18, 8)}
        return Insn(pc, "VINTRP", op, VINTRP.get(op), 4, f)
    if top6 == 0x36:
        x = d1()
        op = _bits(d0, 18, 8)
        f = {"offset0": d0 & 0xFF, "offset1": _bits(d0, 8, 8), "gds": _bits(d0, 17, 1),
             "addr": x & 0xFF, "data0": _bits(x, 8, 8), "data1": _bits(x, 16, 8),
             "vdst": _bits(x, 24, 8)}
        return Insn(pc, "DS", op, DS.get(op), 8, f)
    if top6 == 0x37:
        x = d1()
        op = _bits(d0, 18, 7)
        f = {"glc": _bits(d0, 16, 1), "slc": _bits(d0, 17, 1), "addr": x & 0xFF,
             "data": _bits(x, 8, 8), "tfe": _bits(x, 23, 1), "vdst": _bits(x, 24, 8)}
        return Insn(pc, "FLAT", op, FLAT.get(op), 8, f)
    if top6 in (0x38, 0x3A):
        x = d1()
        f = {"offset": d0 & 0xFFF, "offen": _bits(d0, 12, 1), "idxen": _bits(d0, 13, 1),
             "glc": _bits(d0, 14, 1), "addr64": _bits(d0, 15, 1), "vaddr": x & 0xFF,
             "vdata": _bits(x, 8, 8), "srsrc": _bits(x, 16, 5), "slc": _bits(x, 22, 1),
             "tfe": _bits(x, 23, 1), "soffset": _bits(x, 24, 8)}
        if top6 == 0x38:
            op = _bits(d0, 18, 7)
            f["lds"] = _bits(d0, 16, 1)
            return Insn(pc, "MUBUF", op, MUBUF.get(op), 8, f)
        op = _bits(d0, 16, 3)
        f["dfmt"] = _bits(d0, 19, 4)
        f["nfmt"] = _bits(d0, 23, 3)
        return Insn(pc, "MTBUF", op, MTBUF.get(op), 8, f)
    if top6 == 0x3C:
        x = d1()
        op = _bits(d0, 18, 7)
        f = {"dmask": _bits(d0, 8, 4), "unorm": _bits(d0, 12, 1), "glc": _bits(d0, 13, 1),
             "da": _bits(d0, 14, 1), "r128": _bits(d0, 15, 1), "tfe": _bits(d0, 16, 1),
             "lwe": _bits(d0, 17, 1), "slc": _bits(d0, 25, 1), "vaddr": x & 0xFF,
             "vdata": _bits(x, 8, 8), "srsrc": _bits(x, 16, 5), "ssamp": _bits(x, 21, 5)}
        return Insn(pc, "MIMG", op, MIMG.get(op), 8, f)
    if top6 == 0x3E:
        x = d1()
        f = {"en": d0 & 0xF, "tgt": _bits(d0, 4, 6), "compr": _bits(d0, 10, 1),
             "done": _bits(d0, 11, 1), "vm": _bits(d0, 12, 1),
             "vsrc": [x & 0xFF, _bits(x, 8, 8), _bits(x, 16, 8), _bits(x, 24, 8)]}
        return Insn(pc, "EXP", 0, "exp", 8, f)
    raise DecodeError("unknown encoding %#010x at %#x" % (d0, pc))


def decode_program(code, start=0, base_pc=None, max_bytes=None):
    """Linear-sweep decode from `start` until s_endpgm (that is not jumped
    over) or `max_bytes`. Returns {offset: Insn} keyed by byte offset from
    `start`. Branch targets past an s_endpgm keep the sweep going."""
    out = {}
    pos = start
    end = len(code) if max_bytes is None else min(len(code), start + max_bytes)
    furthest_target = start
    base = start if base_pc is None else base_pc
    while pos < end:
        ins = decode_one(code, pos, pc=pos - start + (0 if base_pc is None else base_pc - 0))
        ins.pc = pos - start
        out[pos - start] = ins
        if ins.enc == "SOPP" and ins.name and "branch" in ins.name:
            s = ins.f["simm16"]
            off = s - 0x10000 if s & 0x8000 else s
            furthest_target = max(furthest_target, pos + 4 + off * 4)
        pos += ins.size
        if ins.name == "s_endpgm" and pos > furthest_target:
            break
        if ins.name == "s_setpc_b64" and pos > furthest_target:
            break  # fetch shader return; caller continues elsewhere
    return out


def disassemble(prog):
    lines = []
    for off in sorted(prog):
        ins = prog[off]
        lines.append("  %04x: %s" % (off, ins.text()))
    return "\n".join(lines)
