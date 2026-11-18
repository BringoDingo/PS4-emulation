"""Minimal PS4 param.sfo (PSF) reader: returns {key: value} with str / int values.

PSF layout: header {magic "\\0PSF", version, key_table_off, data_table_off, n_entries}, then
n_entries index records {key_off u16, fmt u16, len u32, max_len u32, data_off u32}; fmt 0x0004 =
utf8 (no NUL), 0x0204 = utf8 text (NUL terminated), 0x0404 = u32.
"""
import struct


def parse_sfo(data):
    if data[:4] != b"\x00PSF":
        raise ValueError("not a PSF file")
    _ver, key_off, data_off, n = struct.unpack_from("<IIII", data, 4)
    out = {}
    for i in range(n):
        k_off, fmt, ln, _mx, d_off = struct.unpack_from("<HHIII", data, 20 + 16 * i)
        k_end = data.index(b"\x00", key_off + k_off)
        key = data[key_off + k_off:k_end].decode("ascii", "replace")
        raw = data[data_off + d_off:data_off + d_off + ln]
        if fmt == 0x0404:
            out[key] = struct.unpack_from("<I", raw)[0]
        else:
            out[key] = raw.split(b"\x00")[0].decode("utf-8", "replace")
    return out


def read_sfo(path):
    with open(path, "rb") as fh:
        return parse_sfo(fh.read())
