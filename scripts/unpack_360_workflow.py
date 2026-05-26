#!/usr/bin/env python3
"""Complete 360 Jiagu unpacking workflow."""
import os, subprocess, sys, time, json, hashlib, struct, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADB = str(ROOT / "Sdk" / "platform-tools" / "adb.exe")
DEX_MAGIC = re.compile(rb"dex\n0[0-9]{2}\x00")


def run(cmd, check=True):
    print("[run]", " ".join(str(c) for c in cmd), flush=True)
    proc = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise RuntimeError(f"Failed: {cmd}\n{proc.stdout}\n{proc.stderr}")
    return proc


def find_dexes(data, base_offset=0):
    found = []
    for m in DEX_MAGIC.finditer(data):
        offset = m.start()
        if offset + 0x70 > len(data): continue
        h = data[offset:offset + 0x70]
        fs = struct.unpack_from("<I", h, 0x20)[0]
        hs = struct.unpack_from("<I", h, 0x24)[0]
        et = struct.unpack_from("<I", h, 0x28)[0]
        mo = struct.unpack_from("<I", h, 0x34)[0]
        if hs != 0x70 or et != 0x12345678 or fs < 0x70 or fs > 500*1024*1024 or mo >= fs: continue
        end = offset + fs; blob = data[offset:end] if end <= len(data) else data[offset:]
        found.append({"offset": base_offset + offset, "file_size": fs, "complete": end <= len(data), "sha256": hashlib.sha256(blob).hexdigest(), "data": blob})
    return found


def repair_dex(data):
    import zlib; buf = bytearray(data)
    if len(buf) >= 0x70:
        buf[12:32] = hashlib.sha1(buf[32:]).digest()
        struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def main():
    import frida, argparse
    p = argparse.ArgumentParser()
    p.add_argument("--package", default="com.chinaservices.freight")
    p.add_argument("--serial", default="emulator-5556")
    p.add_argument("--wait", type=int, default=20)
    p.add_argument("--apk", default=str(ROOT / "app-uat-v2.3.7_237_jiagu_fengchi.apk"))
    p.add_argument("--out", default=None)
    args = p.parse_args()

    out = Path(args.out) if args.out else ROOT / "dumps" / args.package
    out.mkdir(parents=True, exist_ok=True)
    adb = lambda cmd, check=True: run([ADB, "-s", args.serial] + cmd, check=check)

    # Step 1: Spawn with bypass
    print("[*] Spawning app with Frida bypass...")
    device = frida.get_usb_device()
    pid = device.spawn([args.package])
    session = device.attach(pid)
    bypass = ROOT / "scripts" / "bypass_360_minimal.js"
    script = session.create_script(bypass.read_text(encoding="utf-8"))
    script.on("message", lambda msg, data: print(f"[frida] {msg}"))
    script.load()
    device.resume(pid)

    # Step 2: Wait
    for i in range(args.wait):
        time.sleep(1)
        r = subprocess.run([ADB, "-s", args.serial, "shell", f"pidof {args.package}"], capture_output=True, text=True)
        if i % 5 == 0: print(f"  [{i+1}s] alive={r.stdout.strip()}")
        if not r.stdout.strip(): print("[!] App died!"); session.detach(); return 1
    print(f"[*] App survived {args.wait}s, PID={pid}")

    # Step 3: Read maps
    maps_text = adb(["shell", f"cat /proc/{pid}/maps"]).stdout
    (out / f"pid_{pid}.maps").write_text(maps_text, encoding="utf-8")

    # Parse and select segments
    entries = []
    for line in maps_text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or "-" not in parts[0]: continue
        s, e = parts[0].split("-", 1)
        try:
            start, end = int(s, 16), int(e, 16)
            path = parts[5] if len(parts) > 5 else ""
            entries.append({"start": start, "end": end, "size": end - start, "perms": parts[1], "path": path.strip()})
        except: pass

    selected = []
    for e in entries:
        if "r" not in e["perms"]: continue
        p = e["path"]; sz = e["size"]
        if any(p.startswith(x) for x in ["/apex/","/system/","/vendor/","/product/","/system_ext/"]): continue
        reason = ""
        if "[anon:dalvik-DEX data]" in p: reason = "dalvik_dex"
        elif "[anon:Mem_" in p: reason = "secneo_mem"
        elif "[anon:scudo:secondary]" in p and sz <= 200*1024*1024: reason = "scudo"
        elif ".dex" in p or ".vdex" in p: reason = "dex_file"
        elif not p and sz <= 200*1024*1024: reason = "anon_r"
        if reason: e["reason"] = reason; selected.append(e)

    priority = {"secneo_mem": 0, "dalvik_dex": 1, "dex_file": 2, "scudo": 3, "anon_r": 4}
    selected.sort(key=lambda e: (priority.get(e["reason"], 99), -e["size"]))
    print(f"[*] Selected {len(selected)} of {len(entries)} segments")

    # Step 4: Dump and carve
    seg_dir = out / "memsegs"; carved_dir = out / "carved"; fixed_dir = out / "fixed"
    for d in [seg_dir, carved_dir, fixed_dir]: d.mkdir(parents=True, exist_ok=True)

    seen = {}; all_dexes = 0
    for idx, entry in enumerate(selected):
        remote = f"/data/local/tmp/cs_{pid}_{idx+1}.bin"
        pages = (entry["size"] + 4095) // 4096; skip = entry["start"] // 4096
        adb(["shell", f"dd if=/proc/{pid}/mem of={remote} bs=4096 skip={skip} count={pages} 2>/dev/null"], check=False)
        local = seg_dir / f"{idx+1:03d}_{entry['start']:x}_{entry['reason']}.bin"
        adb(["pull", remote, str(local)], check=False)
        adb(["shell", f"rm -f {remote}"], check=False)

        if local.exists():
            data = local.read_bytes()
            dexes = find_dexes(data, entry["start"])
            if dexes:
                print(f"  [{idx+1}/{len(selected)}] {entry['start']:x} {len(data)//1024}KB -> {len(dexes)} DEX")
                for dex in dexes:
                    sha = dex["sha256"]
                    if sha in seen: continue
                    seen[sha] = True; all_dexes += 1
                    dn = f"classes{all_dexes:02d}_{dex['offset']:x}_{dex['file_size']}.dex"
                    (carved_dir / dn).write_bytes(dex["data"])
                    repaired = repair_dex(dex["data"])
                    (fixed_dir / dn).write_bytes(repaired)
            elif local.stat().st_size < 50*1024*1024:
                local.unlink()

    session.detach()
    print(f"\n[*] Done! Carved: {all_dexes} DEX files")
    print(f"    carved/: {carved_dir}")
    print(f"    fixed/:  {fixed_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
