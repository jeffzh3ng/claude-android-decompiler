#!/usr/bin/env python3
"""Filter HTTP indicators to focus on business-relevant (non-third-party) entries."""
import csv, json, sys
from pathlib import Path

THIRD_PARTY_KW = ("amap","autonavi","alibaba","aliyun","alipay","baidu","bugly","firebase","google",
                  "qq.com","tencent","weixin","wechat","github","slf4j","apache","bouncycastle",
                  "openssl","gcc","winimage","jiagu","umeng","jiguang","getui","xpush",
                  "schemas.android","android.com","gradle","maven","w3.org","xml.org",
                  "sourceforge","googlesource","example.com")

BUSINESS_KW = ("api","rest","login","auth","token","order","cargo","freight","driver","truck",
               "upload","download","file","image","verify","sms","pay","wallet","location",
               "dispatch","shipping","warehouse","invoice","bill","contract")

def is_third_party(value):
    return any(k in value.lower() for k in THIRD_PARTY_KW)

def is_business(value):
    return any(k in value.lower() for k in BUSINESS_KW)

def main():
    import argparse
    p = argparse.ArgumentParser(description="Filter HTTP indicators for business relevance")
    p.add_argument("--input", "-i", default="http_indicators.csv")
    p.add_argument("--output", "-o", default="business_http_indicators.csv")
    args = p.parse_args()

    inp, out = Path(args.input), Path(args.output)
    with open(inp, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        all_rows = list(reader)

    business = [r for r in all_rows if not is_third_party(r.get('value','')) and is_business(r.get('value',''))]
    other = [r for r in all_rows if r not in business]

    with open(out, 'w', newline='', encoding='utf-8-sig') as f:
        if business:
            w = csv.DictWriter(f, fieldnames=list(business[0].keys())); w.writeheader(); w.writerows(business)

    print(f"All: {len(all_rows)}, Business: {len(business)}, Third-party/Other: {len(other)}")
    print(f"Output: {out}")

if __name__ == "__main__": main()
