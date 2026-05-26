#!/usr/bin/env python3
"""DEX inventory: count classes, show package distribution."""
import struct, sys, os
from collections import Counter
from pathlib import Path

def read_strings(dex_data):
    ss = struct.unpack_from('<I', dex_data, 0x38)[0]; so = struct.unpack_from('<I', dex_data, 0x3C)[0]
    strings = []
    for i in range(min(ss, 10000)):
        try:
            off = struct.unpack_from('<I', dex_data, so + i * 4)[0]; end = dex_data.find(b'\x00', off)
            if end > off: strings.append(dex_data[off:end].decode('utf-8', errors='replace'))
        except: pass
    return strings

def main():
    import argparse
    p = argparse.ArgumentParser(description="DEX file content inventory")
    p.add_argument("dex_dir", help="Directory containing .dex files")
    args = p.parse_args()

    dex_dir = Path(args.dex_dir)
    total_c, total_s = 0, 0
    for df in sorted(dex_dir.glob("*.dex")):
        data = df.read_bytes()
        cd = struct.unpack_from('<I', data, 0x60)[0]; si = struct.unpack_from('<I', data, 0x38)[0]
        size_mb = len(data) / (1024*1024)
        print(f"{df.name}: {size_mb:.1f}MB, classes={cd}, strings={si}")
        total_c += cd; total_s += si

    print(f"\nTotal: {total_c} classes, {total_s} strings (across all DEX files)")

if __name__ == "__main__":
    main()
