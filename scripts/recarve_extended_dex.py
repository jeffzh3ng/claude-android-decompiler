#!/usr/bin/env python3
"""Re-carve DEX files from large segments with relaxed/continuous matching."""
import re, struct, sys, hashlib
from pathlib import Path

DEX_MAGIC = re.compile(rb"dex\n0[0-9]{2}\x00")

def carve(data, base_off=0):
    found = []
    for m in DEX_MAGIC.finditer(data):
        off = m.start()
        if off + 0x70 > len(data): continue
        h = data[off:off+0x70]
        fs = struct.unpack_from("<I", h, 0x20)[0]; hs = struct.unpack_from("<I", h, 0x24)[0]
        et = struct.unpack_from("<I", h, 0x28)[0]; mo = struct.unpack_from("<I", h, 0x34)[0]
        if hs != 0x70 or et != 0x12345678 or fs < 0x70 or fs > 500*1024*1024 or mo >= fs: continue
        end = off + fs; blob = data[off:end] if end <= len(data) else data[off:]
        found.append({"offset": base_off + off, "file_size": fs, "complete": end <= len(data),
                       "sha256": hashlib.sha256(blob).hexdigest(), "data": blob})
    return found

def main():
    import argparse
    p = argparse.ArgumentParser(description="Re-carve DEX from large memory dumps")
    p.add_argument("input", help="Input binary file or directory")
    p.add_argument("--output", "-o", default="extended")
    args = p.parse_args()

    inp, out = Path(args.input), Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    files = [inp] if inp.is_file() else sorted(inp.glob("*.bin"))
    seen, count = {}, 0
    for f in files:
        data = f.read_bytes()
        dexes = carve(data)
        if dexes: print(f"{f.name}: {len(dexes)} DEX")
        for dex in dexes:
            sha = dex["sha256"]
            if sha in seen: continue
            seen[sha] = True; count += 1
            dn = f"extended_{count:02d}_{dex['offset']:x}_{dex['file_size']}.dex"
            (out / dn).write_bytes(dex["data"])
            print(f"  + {dn} ({dex['file_size']} bytes)")

    print(f"\nTotal unique: {count}")
    return 0

if __name__ == "__main__": sys.exit(main())
