#!/usr/bin/env python3
"""Repair DEX file headers: recompute SHA1 signature and Adler32 checksum."""
import hashlib, struct, sys, zlib
from pathlib import Path

def repair_dex(data):
    buf = bytearray(data)
    if len(buf) < 0x70: return bytes(buf)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)

def main():
    import argparse
    p = argparse.ArgumentParser(description="Repair DEX file headers")
    p.add_argument("input", help="Input DEX file or directory")
    p.add_argument("--output", "-o", help="Output file or directory")
    p.add_argument("--recursive", "-r", action="store_true")
    args = p.parse_args()

    inp = Path(args.input)
    if inp.is_file():
        data = inp.read_bytes()
        out_path = Path(args.output) if args.output else inp.with_suffix(".fixed.dex")
        out_path.write_bytes(repair_dex(data))
        print(f"Repaired: {inp} -> {out_path}")
    elif inp.is_dir():
        out_dir = Path(args.output) if args.output else inp.parent / "fixed"
        out_dir.mkdir(parents=True, exist_ok=True)
        dexes = sorted(inp.glob("*.dex"))
        for dex in dexes:
            data = dex.read_bytes()
            repaired = repair_dex(data)
            (out_dir / dex.name).write_bytes(repaired)
            print(f"  {dex.name}: size={len(repaired)}, checksum=0x{struct.unpack_from('<I', repaired, 8)[0]:08x}")
        print(f"Repaired {len(dexes)} DEX files -> {out_dir}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
