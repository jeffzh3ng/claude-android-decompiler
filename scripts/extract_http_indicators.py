#!/usr/bin/env python3
"""Extract HTTP indicators: URLs, domains, IPs, paths from unpacked APK artifacts."""
import argparse, csv, json, re, struct, zipfile
from collections import defaultdict
from pathlib import Path

URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>\\\]\)]+")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|cn|net|org|io|cc|top|xyz)(?::\d{1,5})?(?:/[^\s\"'<>\\\]\)]*)?")

THIRD_PARTY_HINTS = ("alipay","amap","autonavi","baidu","bugly","firebase","google","qq.com","tencent","weixin",
                     "wechat","github","slf4j","apache","bouncycastle","openssl","gcc","winimage","jiagu",
                     "aliyun","aliyuncs","alibaba","umeng","jiguang","getui","xpush","schemas.android")

TEXT_EXTS = {".js",".html",".htm",".json",".xml",".txt",".properties",".conf",".config",".css",".mf"}

def read_dex_strings(data):
    strings = []; ss = struct.unpack_from('<I', data, 0x38)[0]; so = struct.unpack_from('<I', data, 0x3C)[0]
    for i in range(ss):
        try:
            off = struct.unpack_from('<I', data, so + i * 4)[0]; end = data.find(b'\x00', off)
            if end > off: strings.append(data[off:end].decode('utf-8', errors='replace'))
        except: pass
    return strings

def is_third_party(url_or_domain):
    return any(h in url_or_domain.lower() for h in THIRD_PARTY_HINTS)

def main():
    p = argparse.ArgumentParser(description="Extract URL/domain/IP/path indicators from unpacked APK")
    p.add_argument("--dex-dir"); p.add_argument("--apk")
    p.add_argument("--out-json", default="http_indicators.json")
    p.add_argument("--out-csv", default="http_indicators.csv")
    args = p.parse_args()

    indicators = []

    # From DEX
    if args.dex_dir:
        for df in sorted(Path(args.dex_dir).glob("*.dex")):
            for s in read_dex_strings(df.read_bytes()):
                for m in URL_RE.finditer(s):
                    url = m.group(0)
                    if is_third_party(url): continue
                    indicators.append({"category":"url","kind":"http","host":"","value":url,"sources":df.name,"contexts":""})
                for m in DOMAIN_RE.finditer(s):
                    d = m.group(0)
                    if is_third_party(d): continue
                    indicators.append({"category":"domain","kind":"http","host":"","value":d,"sources":df.name,"contexts":""})

    # From APK assets
    if args.apk:
        with zipfile.ZipFile(args.apk) as z:
            for name in z.namelist():
                if any(name.endswith(ext) for ext in TEXT_EXTS):
                    try:
                        text = z.read(name).decode('utf-8', errors='replace')
                        for m in URL_RE.finditer(text):
                            url = m.group(0)
                            if not is_third_party(url):
                                indicators.append({"category":"url","kind":"asset","host":"","value":url,"sources":name,"contexts":""})
                    except: pass

    print(f"items: {len(indicators)}")
    with open(args.out_json, 'w', encoding='utf-8') as f: json.dump(indicators, f, ensure_ascii=False, indent=2)
    with open(args.out_csv, 'w', newline='', encoding='utf-8-sig') as f:
        if indicators:
            w = csv.DictWriter(f, fieldnames=list(indicators[0].keys())); w.writeheader(); w.writerows(indicators)
    print(f"json: {args.out_json}\ncsv: {args.out_csv}")

if __name__ == "__main__": main()
