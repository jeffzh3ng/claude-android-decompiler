#!/usr/bin/env python3
"""Static extraction of API indicators from APK assets (no unpacking needed)."""
import zipfile, os, re, io, sys
from collections import Counter
from pathlib import Path

URL_RE = re.compile(rb'https?://[a-zA-Z0-9._\[\]]+(?::\d+)?/[^\s"\'<>]*')

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("apk", help="APK file path")
    p.add_argument("--out-dir")
    args = p.parse_args()

    apk = Path(args.apk); out = Path(args.out_dir) if args.out_dir else Path(f"dumps/{apk.stem}")
    out.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(apk) as z:
        # Config files
        conf = [n for n in z.namelist() if any(n.endswith(e) for e in ['.xml','.properties','.json','.conf','.cfg','.txt'])
                and not n.startswith('res/')]
        for cf in conf:
            try:
                data = z.read(cf)
                if len(data) > 100000: continue
                print(f"\n--- {cf} ({len(data)} bytes) ---")
                print(data.decode('utf-8', errors='replace')[:2000])
            except: pass

        # Embedded ZIP (assets/ae/res.zip)
        if 'assets/ae/res.zip' in z.namelist():
            with zipfile.ZipFile(io.BytesIO(z.read('assets/ae/res.zip'))) as rz:
                js_files = [n for n in rz.namelist() if n.endswith('.js')]
                print(f"\nJS in res.zip: {len(js_files)}")
                domains = Counter()
                for jf in js_files:
                    try:
                        for m in URL_RE.finditer(rz.read(jf)):
                            u = m.group().decode('utf-8', errors='replace')
                            d = re.search(r'https?://([a-zA-Z0-9._\-]+)', u)
                            if d: domains[d.group(1)] += 1
                    except: pass
                for d, c in domains.most_common(20):
                    print(f"  {d}: {c}")

        # URLs in native libs
        for lib in [n for n in z.namelist() if n.endswith('.so')][:10]:
            try:
                for m in URL_RE.finditer(z.read(lib)):
                    print(f"  [{lib}] {m.group().decode('utf-8', errors='replace')}")
            except: pass

    print("\nDone.")

if __name__ == "__main__": main()
