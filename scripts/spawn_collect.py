#!/usr/bin/env python3
"""Spawn app with Frida bypass, wait, then collect device-side code_cache/files."""
import argparse, pathlib, subprocess, sys, time, frida

def run(cmd):
    print("[cmd]", " ".join(cmd), flush=True)
    return subprocess.run(cmd, text=True, capture_output=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--package", default="com.chinaservices.freight")
    p.add_argument("--serial", default="emulator-5556")
    p.add_argument("--adb", default=None)
    p.add_argument("--script", default="scripts/bypass_root.js")
    p.add_argument("--output", default=None)
    p.add_argument("--wait", type=int, default=12)
    args = p.parse_args()

    root = pathlib.Path.cwd()
    adb = str((root / args.adb).resolve()) if args.adb else str(root / "Sdk" / "platform-tools" / "adb.exe")
    script_path = root / args.script
    out_dir = root / (args.output or f"dumps/{args.package}/device-files")
    out_dir.mkdir(parents=True, exist_ok=True)

    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([args.package])
    session = device.attach(pid)
    script = session.create_script(script_path.read_text(encoding="utf-8"))
    script.on("message", lambda msg, data: print("[frida]", msg, flush=True))
    script.load()
    device.resume(pid)
    print(f"[spawned] pid={pid}", flush=True)

    for sec in range(args.wait):
        time.sleep(1)
        alive = run([adb, "-s", args.serial, "shell", "pidof", args.package]).stdout.strip()
        print(f"[wait] {sec+1}/{args.wait} pidof={alive}", flush=True)
        if not alive: break

    remote = f"/data/local/tmp/codex-{args.package}-files"
    shell = (
        f"rm -rf {remote}; mkdir -p {remote}; "
        f"cp -a /data/user/0/{args.package}/code_cache {remote}/ 2>/dev/null || true; "
        f"cp -a /data/user/0/{args.package}/files {remote}/ 2>/dev/null || true; "
        f"find {remote} -type f -exec ls -l {{}} \\; 2>/dev/null"
    )
    result = run([adb, "-s", args.serial, "shell", shell])
    print(result.stdout)

    pull = run([adb, "-s", args.serial, "pull", remote, str(out_dir)])
    print(pull.stdout)
    try: session.detach()
    except: pass

if __name__ == "__main__": main()
