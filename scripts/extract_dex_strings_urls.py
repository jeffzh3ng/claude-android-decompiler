#!/usr/bin/env python3
"""Extract all strings from DEX files and identify URLs, API endpoints, domains."""
import struct, os, re, csv, sys
from collections import Counter, defaultdict
from pathlib import Path

URL_PAT = re.compile(r'https?://[a-zA-Z0-9][a-zA-Z0-9._\-]*(?::\d+)?(?:/[^\s"\'<>\[\]{}|\\^~`]*)?')
DOMAIN_PAT = re.compile(r'(?:^|[^a-zA-Z0-9])([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.(?:com|cn|net|org|io|cc|me|xyz|top|info|biz|gov|edu)(?::\d+)?)', re.IGNORECASE)

THIRD_PARTY = {'amap.com','autonavi.com','alibaba-inc.com','aliyun.com','aliyuncs.com','alipay.com','weixin.qq.com','qq.com','tencent.com','bugly.qq.com','baidu.com','google.com','android.com','github.com','w3.org','apache.org','slf4j.org','openssl.org','gcc.gnu.org','winimage.com','schemas.android.com','play.google.com','firebase.google.com','googlesource.com','umeng.com','xpush.cn','getui.com','jiguang.cn','weibo.com','sina.com','appjiagu.com',}

BUSINESS_KW = ['/api/','/rest/','/v1/','/v2/','/v3/','/login','/auth','/token','/user','/order','/cargo','/truck','/driver','/freight','/shipping','/pay','/wallet','/sms','/verify','/upload','/download','/search','/list','/detail','/query','/submit','/save']

def read_strings(dex_data):
    ss = struct.unpack_from('<I', dex_data, 0x38)[0]; so = struct.unpack_from('<I', dex_data, 0x3C)[0]
    strings = []
    for i in range(ss):
        try:
            off = struct.unpack_from('<I', dex_data, so + i * 4)[0]; end = dex_data.find(b'\x00', off)
            if end > off:
                s = dex_data[off:end].decode('utf-8', errors='replace')
                if s: strings.append(s)
        except: pass
    return strings

def is_third_party(domain):
    d = domain.lower().rstrip('.')
    return d in THIRD_PARTY or any(d.endswith('.'+t) for t in ['amap.com','autonavi.com','aliyun.com','aliyuncs.com','alibaba-inc.com','qq.com','baidu.com','weixin.qq.com','umeng.com','jiguang.cn','getui.com'])

def is_business(path):
    return any(kw in path.lower() for kw in BUSINESS_KW)

def main():
    import argparse
    p = argparse.ArgumentParser(description="Extract URLs/API endpoints from DEX files")
    p.add_argument("--dex-dir", default="dumps/com.chinaservices.freight/fixed")
    p.add_argument("--out-urls", default="all_urls.csv")
    p.add_argument("--out-api", default="api_endpoints.csv")
    args = p.parse_args()

    dex_dir, all_urls, api_endpoints = Path(args.dex_dir), [], defaultdict(set)
    for df in sorted(dex_dir.glob("*.dex")):
        if "classes01_" in df.name: continue  # skip shell DEX
        strings = read_strings(df.read_bytes())
        print(f"{df.name}: {len(strings)} strings")
        for s in strings:
            for m in URL_PAT.finditer(s):
                url = m.group(0); all_urls.append({"value": url, "source": df.name})
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url); domain = parsed.netloc.split(':')[0]; path = parsed.path or '/'
                    if domain and not is_third_party(domain) and is_business(path):
                        api_endpoints[domain].add(path)
                except: pass

    with open(args.out_urls, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=['value','source']); w.writeheader(); w.writerows(all_urls)
    with open(args.out_api, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f); w.writerow(['domain','path','full_url'])
        for domain in sorted(api_endpoints):
            for path in sorted(api_endpoints[domain]):
                w.writerow([domain, path, f"https://{domain}{path}"])

    print(f"\nURLs: {len(all_urls)}, API endpoints: {sum(len(v) for v in api_endpoints.values())}")
    for domain in sorted(api_endpoints):
        for path in sorted(api_endpoints[domain])[:5]:
            print(f"  https://{domain}{path}")

if __name__ == "__main__": main()
