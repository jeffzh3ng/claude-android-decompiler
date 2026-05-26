#!/usr/bin/env python3
"""Dump readable Android process memory segments and carve DEX files."""
import argparse, hashlib, json, os, re, struct, subprocess, sys
from pathlib import Path

DEX_MAGIC = re.compile(rb"dex\n0[0-9]{2}\x00")


def reason_for(entry, package, max_segment):
    if "r" not in entry["perms"]: return ""
    path, size = entry["path"], entry["size"]
    if size <= 0: return ""
    if path.startswith(("/apex/","/system/","/vendor/","/product/","/system_ext/","/dev/__properties__/")): return ""
    if any(t in path for t in ("boot.","boot-","jit-cache","zygote-cache","dalvik-main space","thread local mark stack","indirect ref table","gralloc-buffer","fontMap","GFXStats")): return ""
    if "[anon:dalvik-DEX data]" in path: return "dalvik_dex_data"
    if f"/data/data/{package}/" in path and ".dex" in path: return "private_code_cache_dex"
    if "[anon:Mem_" in path: return "secneo_mem"
    if package in path and "/data/app/" in path and (".apk" in path or ".vdex" in path): return "app_mapped_file"
    if "libDexHelper" in path or "libdexjni" in path: return "secneo_native"
    if "[anon:scudo:secondary]" in path and size <= max_segment: return "scudo_secondary"
    if "[anon:dalvik-LinearAlloc]" in path and size <= 2*1024*1024: return "linear_alloc"
    if not path and "r" in entry["perms"] and size <= max_segment: return "anonymous_readable"
    return ""


def find_dexes(data):
    found = []
    for m in DEX_MAGIC.finditer(data):
        offset = m.start()
        if offset + 0x70 > len(data): continue
        h = data[offset:offset+0x70]
        fs = struct.unpack_from("<I", h, 0x20)[0]; hs = struct.unpack_from("<I", h, 0x24)[0]
        et = struct.unpack_from("<I", h, 0x28)[0]; mo = struct.unpack_from("<I", h, 0x34)[0]
        if hs != 0x70 or et != 0x12345678 or fs < 0x70 or fs > 512*1024*1024 or mo >= fs: continue
        end = offset + fs; blob = data[offset:end] if end <= len(data) else data[offset:]
        found.append({"offset": offset, "file_size": fs, "complete": end <= len(data), "sha256": hashlib.sha256(blob).hexdigest(), "data": blob})
    return found


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--adb", default=None)
    p.add_argument("--serial", default="emulator-5556")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--package", default="com.chinaservices.freight")
    p.add_argument("--maps")
    p.add_argument("--out", default=None)
    p.add_argument("--max-segment-mb", type=int, default=96)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--keep-all-segments", action="store_true")
    args = p.parse_args()

    adb = Path(args.adb) if args.adb else Path(__file__).resolve().parent.parent / "Sdk" / "platform-tools" / "adb.exe"
    out = Path(args.out) if args.out else Path(f"dumps/{args.package}")
    seg_dir = out / "memsegs"; dex_dir = out / "carved"
    seg_dir.mkdir(parents=True, exist_ok=True); dex_dir.mkdir(parents=True, exist_ok=True)

    def adb_cmd(cmd, check=True):
        full = [str(adb), "-s", args.serial] + cmd
        proc = subprocess.run([str(c) for c in full], capture_output=True, text=True, check=False)
        if check and proc.returncode != 0:
            raise RuntimeError(f"Failed: {cmd}\n{proc.stdout}\n{proc.stderr}")
        return proc

    if args.maps:
        maps_text = Path(args.maps).read_text(encoding="utf-8")
    else:
        maps_text = adb_cmd(["shell", f"cat /proc/{args.pid}/maps"]).stdout

    maps_path = out / f"pid_{args.pid}.maps"; maps_path.write_text(maps_text, encoding="utf-8")
    entries = []
    for line in maps_text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or "-" not in parts[0]: continue
        s, e = parts[0].split("-", 1)
        try:
            start, end = int(s,16), int(e,16)
            entries.append({"start": start, "end": end, "size": end-start, "perms": parts[1], "path": parts[5].strip() if len(parts) > 5 else ""})
        except: pass

    max_seg = args.max_segment_mb * 1024 * 1024
    selected = []
    for e in entries:
        r = reason_for(e, args.package, max_seg)
        if r:
            e["reason"] = r; selected.append(e)

    priority = {"private_code_cache_dex":0,"dalvik_dex_data":1,"secneo_mem":2,"app_mapped_file":3,"secneo_native":4,"anonymous_readable":5,"scudo_secondary":6,"linear_alloc":7}
    selected.sort(key=lambda e: (priority.get(e["reason"],99), e["size"]))
    if args.limit: selected = selected[:args.limit]

    seen, dex_count = {}, 0
    for idx, entry in enumerate(selected):
        remote = f"/data/local/tmp/cdx_{args.pid}_{idx}.bin"
        pages = (entry["size"] + 4095) // 4096; skip = entry["start"] // 4096
        adb_cmd(["shell", f"dd if=/proc/{args.pid}/mem of={remote} bs=4096 skip={skip} count={pages} 2>/dev/null"], check=False)
        local = seg_dir / f"{idx+1:03d}_{entry['start']:x}_{entry['reason']}_{Path(entry['path']).name or 'anon'}.bin"
        adb_cmd(["pull", remote, str(local)], check=False)
        adb_cmd(["shell", f"rm -f {remote}"], check=False)

        if local.exists():
            data = local.read_bytes()
            dexes = find_dexes(data)
            print(f"[{idx+1}/{len(selected)}] {entry['start']:x} {entry['size']//1024}KB -> {len(dexes)} DEX {entry['reason']}")
            if not dexes and not args.keep_all_segments: local.unlink()
            for dex in dexes:
                sha = dex["sha256"]
                if sha in seen: print(f"  dup: {sha[:12]}"); continue
                dex_count += 1
                dn = f"classes{dex_count:02d}_{entry['start'] + dex['offset']:x}_{dex['file_size']}.dex"
                (dex_dir / dn).write_bytes(dex["data"])
                seen[sha] = str(dex_dir / dn)
                print(f"  + {dn} ({dex['file_size']} bytes)")

    print(f"\nDone. DEX files: {dex_count}")
    return 0


if __name__ == "__main__":
    try: sys.exit(main())
    except KeyboardInterrupt: sys.exit(130)
    except Exception as e: print(f"fatal: {e}", file=sys.stderr); sys.exit(1)
