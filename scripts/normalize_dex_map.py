#!/usr/bin/env python3
"""Rebuild or validate DEX map_list structure."""
import struct, sys
from pathlib import Path

def normalize_dex(data):
    """Ensure map_list is present and correct. Append if missing."""
    buf = bytearray(data)
    map_off = struct.unpack_from("<I", buf, 0x34)[0]
    if map_off > 0 and map_off < len(buf):
        return bytes(buf)  # Already has map_list

    # Build map_list from sections
    header_size = 0x70
    sections = [
        (0x0000, 1, 0x00),   # HEADER_ITEM
        (0x0001, struct.unpack_from("<I", buf, 0x38)[0], struct.unpack_from("<I", buf, 0x3C)[0]),  # STRING_ID
        (0x0002, struct.unpack_from("<I", buf, 0x40)[0], struct.unpack_from("<I", buf, 0x44)[0]),  # TYPE_ID
        (0x0003, struct.unpack_from("<I", buf, 0x48)[0], struct.unpack_from("<I", buf, 0x4C)[0]),  # PROTO_ID
        (0x0004, struct.unpack_from("<I", buf, 0x50)[0], struct.unpack_from("<I", buf, 0x54)[0]),  # FIELD_ID
        (0x0005, struct.unpack_from("<I", buf, 0x58)[0], struct.unpack_from("<I", buf, 0x5C)[0]),  # METHOD_ID
        (0x0006, struct.unpack_from("<I", buf, 0x60)[0], struct.unpack_from("<I", buf, 0x64)[0]),  # CLASS_DEF
        (0x1000, struct.unpack_from("<I", buf, 0x68)[0], struct.unpack_from("<I", buf, 0x6C)[0]),  # MAP_LIST
    ]

    map_list_size = 4 + 8 * len(sections)
    map_off = len(buf)
    buf.extend(b'\x00' * map_list_size)
    struct.pack_into("<I", buf, map_off, len(sections))
    for i, (t, count, off) in enumerate(sections):
        struct.pack_into("<HI", buf, map_off + 4 + i * 8, t, 0)  # unused field
        struct.pack_into("<HI", buf, map_off + 4 + i * 8 + 4, count, off)
        struct.pack_into("<HI", buf, map_off + 4 + i * 8, t, count)
        struct.pack_into("<I", buf, map_off + 4 + i * 8 + 4, off)

    struct.pack_into("<I", buf, 0x34, map_off)
    struct.pack_into("<I", buf, 0x20, len(buf))  # update file_size
    struct.pack_into("<I", buf, 0x68, len(buf))  # update data_size (approximation)
    return bytes(buf)

def main():
    import argparse
    p = argparse.ArgumentParser(description="Normalize DEX map_list")
    p.add_argument("input", help="Input DEX file or directory")
    p.add_argument("--output", "-o", help="Output directory")
    args = p.parse_args()

    inp = Path(args.input)
    if inp.is_file():
        data = normalize_dex(inp.read_bytes())
        out = Path(args.output) if args.output else inp.with_suffix(".normalized.dex")
        out.write_bytes(data)
        print(f"Normalized: {inp} -> {out} ({len(data)} bytes)")
    elif inp.is_dir():
        out_dir = Path(args.output) if args.output else inp.parent / "normalized"
        out_dir.mkdir(parents=True, exist_ok=True)
        for dex in sorted(inp.glob("*.dex")):
            data = normalize_dex(dex.read_bytes())
            (out_dir / dex.name).write_bytes(data)
            print(f"  {dex.name}: {len(data)} bytes")
    return 0

if __name__ == "__main__":
    sys.exit(main())
