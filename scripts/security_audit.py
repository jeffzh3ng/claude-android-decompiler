#!/usr/bin/env python3
"""
Comprehensive security audit for unpacked Android DEX files.
Checks: hardcoded secrets, network config, crypto, WebView, logging, etc.
"""
import struct, os, re, zipfile, sys, csv
from pathlib import Path
from collections import Counter

def read_dex_strings(dex_data):
    strings = []; ss = struct.unpack_from('<I', dex_data, 0x38)[0]; so = struct.unpack_from('<I', dex_data, 0x3C)[0]
    for i in range(ss):
        try:
            off = struct.unpack_from('<I', dex_data, so + i * 4)[0]; end = dex_data.find(b'\x00', off)
            s = dex_data[off:end].decode('utf-8', errors='replace')
            if s: strings.append(s)
        except: pass
    return strings

def main():
    import argparse
    p = argparse.ArgumentParser(description="Security audit for unpacked DEX files")
    p.add_argument("--dex-dir", default="dumps/com.chinaservices.freight/fixed")
    p.add_argument("--apk")
    p.add_argument("--out", default="security_audit.csv")
    args = p.parse_args()

    dex_dir = Path(args.dex_dir); findings = []
    def add(sev, cat, finding, evidence=""):
        findings.append((sev, cat, finding, evidence[:300])); print(f"[{sev}] [{cat}] {finding}")

    all_s = []
    for df in sorted(dex_dir.glob("*.dex")):
        if df.name.startswith("classes01_"): continue
        all_s.extend(read_dex_strings(df.read_bytes()))

    # Hardcoded secrets
    for s in all_s:
        for m in re.finditer(r'(?i)(?:api[_-]?key|apikey|appkey|app_key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,64})["\']?', s):
            add("CRITICAL", "API Key", f"Hardcoded: {s[:200]}")
        for m in re.finditer(r'(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,64})["\']?', s):
            add("CRITICAL", "Secret Key", f"Hardcoded: {s[:200]}")
        if re.match(r'^wx[0-9a-f]{14,20}$', s):
            add("CRITICAL", "WeChat AppID", f"Hardcoded WeChat AppID: {s}")

    # Cleartext HTTP
    for s in all_s:
        for m in re.finditer(r'http://[a-zA-Z0-9]', s):
            if not any(skip in s[m.start():m.start()+80] for skip in ['schemas.android.com','slf4j','bouncycastle','xml','localhost','gcc.gnu','ns.adobe','winimage']):
                add("HIGH", "Cleartext HTTP", f"HTTP endpoint: {s[m.start():m.start()+120]}")
                break

    # SSL bypass
    if any('AllowAllHostnameVerifier' in s for s in all_s) or any('trustAllCerts' in s for s in all_s):
        add("HIGH", "SSL Bypass", "Trust-all SSL implementation detected (AllowAllHostnameVerifier or trustAllCerts)")

    # Weak crypto
    if any('MD5' in s for s in all_s) or any(s.strip() == 'md5' for s in all_s):
        add("HIGH", "Weak Crypto", "MD5 hash usage detected")
    if any('ECB' in s for s in all_s):
        add("HIGH", "Weak Crypto", "ECB block cipher mode detected")

    # WebView
    for s in all_s:
        if 'addJavascriptInterface' in s:
            add("MEDIUM", "WebView", "JS interface exposed: addJavascriptInterface")
            break
    if any('X5WebJSInterface' in s for s in all_s):
        add("MEDIUM", "WebView", f"X5WebJSInterface found — check for exposed native methods")

    # allowBackup
    if args.apk:
        with zipfile.ZipFile(args.apk) as z:
            manifest = z.read('AndroidManifest.xml').decode('latin-1', errors='replace')
            if 'android:allowBackup="true"' in manifest or 'android:allowBackup' not in manifest:
                add("MEDIUM", "Manifest", "allowBackup=true — data extractable via adb backup")

    # OkHttp version
    for s in all_s:
        m = re.search(r'okhttp/([0-9.]+)', s)
        if m:
            add("MEDIUM", "SDK Version", f"OkHttp {m.group(1)}")
            break

    # CollectLog
    if any('CollectLog' in s or 'UploadLog' in s for s in all_s):
        add("LOW", "Logging", "Log upload mechanism detected — check for PII in logs")

    # Write CSV
    with open(args.out, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f); w.writerow(['Severity','Category','Finding','Evidence'])
        for sev, cat, finding, evidence in sorted(findings): w.writerow([sev, cat, finding, evidence])

    counts = Counter(s[0] for s in findings)
    print(f"\nSummary: CRITICAL={counts.get('CRITICAL',0)} HIGH={counts.get('HIGH',0)} MEDIUM={counts.get('MEDIUM',0)} LOW={counts.get('LOW',0)}")
    print(f"Output: {args.out}")

if __name__ == "__main__": main()
