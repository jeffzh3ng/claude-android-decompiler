#!/usr/bin/env python3
"""
Android APK 加固壳识别工具 v2.0
基于 ApkCheckPack 特征数据库 (51 厂商 / 170+ 规则)
用法: python identify_shell.py <apk> [-v] [--list-vendors]
"""
import zipfile, struct, re, os, sys, argparse
from pathlib import Path
from collections import defaultdict

SHELL_DB = {
    "360加固 (三六零天御)": {"sonames": ["libjiagu.so","libjiagu_a64.so","libjiagu_art.so","libjiagu_ls.so","libjiagu_x64.so","libjiagu_x86.so","libjiagu_sdk_*.so","libjgdtc.so","libjgdtc_a64.so","libjgdtc_art.so","libjgdtc_x64.so","libjgdtc_x86.so","libprotectClass.so","libSafeManageService.so"],"sopaths":["assets/libjiagu.so"],"others":["assets/.appkey","appjiagu.com"],"classes":["StubApp"]},
    "腾讯御安全": {"sonames":["libtosprotection.armeabi.so","libtosprotection.armeabi-v7a.so","libtosprotection.x86.so","libBugly-yaq.so","libshellx-super.2019.so","libzBugly-yaq.so"],"sopaths":["assets/libtosprotection.armeabi.so","assets/libtosprotection.armeabi-v7a.so","assets/libtosprotection.x86.so"],"others":["assets/tosversion","000000011111.dex","o0ooo000oo0o.dat","tosprotection"],"classes":[]},
    "腾讯乐固 (VMP)": {"sonames":["libxgVipSecurity.so"],"sopaths":["lib/arm64-v8a/libxgVipSecurity.so","lib/armeabi-v7a/libxgVipSecurity.so"],"others":[],"classes":[]},
    "腾讯乐固 (旧版)": {"sonames":["liblegudb.so","libshel1x.so","libshell.so","libshella.so","libshellx.so","libtup.so"],"sopaths":["lib/armeabi/libshella-xxxx.so","lib/armeabi/libshellx-xxxx.so"],"others":["lib/armeabi/mix.dex","lib/armeabi/mixz.dex","tencent_stub"],"classes":[]},
    "腾讯云加固": {"sonames":["libshell-super.2019.so","libshellx-super.2021.so"],"sopaths":["assets/libshellx-super.2021.so","lib/armeabi/libshell-super.2019.so"],"others":["tencent_sub"],"classes":[]},
    "梆梆安全 (免费版)": {"sonames":["libSecShell_art.so","libSecShell.so","libSecShel1.so","libsecexe.so","libsecmain.so"],"sopaths":["lib/armeabi/libSecShell-x86.so","lib/armeabi/libSecShell.so"],"others":["assets/secData0.jar"],"classes":[]},
    "梆梆安全 (企业版)": {"sonames":["libDexHelper-x86.so","libDexHelper.so"],"sopaths":[],"others":[],"classes":[]},
    "梆梆安全 (定制版)": {"sonames":["DexHelper.so"],"sopaths":["lib/armeabi/DexHelper.so"],"others":["assets/classes.jar"],"classes":[]},
    "爱加密": {"sonames":["libexecmain.so","libexec.so"],"sopaths":["assets/ijm_lib/armeabi/libexec.so","assets/ijm_lib/X86/libexec.so","lib/armeabi/libexecmain.so"],"others":["assets/af.bin","assets/signed.bin","ijiami.dat"],"classes":["com.ijiami"]},
    "爱加密 (3代)": {"sonames":["libexecv3.so"],"sopaths":[],"others":["assets/ijiami3.ajm"],"classes":[]},
    "爱加密 (5代)": {"sonames":["libijmDataEncryption.so"],"sopaths":["assets/libijmDataEncryption.so"],"others":["assets/IJMDal.Data"],"classes":[]},
    "网易易盾": {"sonames":["libnesec.so"],"sopaths":[],"others":[],"classes":[]},
    "百度加固": {"sonames":["libbaiduprotect.so","libbaiduprotect_art.so","libbaiduprotect_x86.so"],"sopaths":["lib/armeabi/libbaiduprotect.so"],"others":["assets/baiduprotect.jar"],"classes":[]},
    "阿里聚安全": {"sonames":["libsgmain.so","libsgsecuritybody.so","libmobisec.so","libzuma.so","libpreverify1.so"],"sopaths":["assets/libzuma.so","assets/libpreverify1.so","assets/libzumadata.so"],"others":["aliprotect.dat"],"classes":["com.alibaba.wireless.security"]},
    "娜迦加固": {"sonames":["libchaosvmp.so","libddog.so","libfdog.so","libhdog.so","libedog.so","libxloader.so"],"sopaths":["lib/armeabi/libxloader.so"],"others":["assets/maindata/fake_classes.dex"],"classes":[]},
    "几维安全": {"sonames":["libkdp.so","libkwscmm.so","libkadp.so","libkiwi_dumper.so","libkiwicrash.so","libKwProtectSDK.so","libkwdataenc.so"],"sopaths":["lib/armeabi/kdpdata.so","lib/armeabi/libkdp.so"],"others":["assets/dex.dat"],"classes":[]},
    "通付盾": {"sonames":["libNSaferOnly.so","libegis.so","libgeiri.so","libgeiri-x86.so"],"sopaths":[],"others":[],"classes":[]},
    "蛮犀加固": {"sonames":["libdSafeShell.so","libmxacc.so"],"sopaths":["assets/mxsafe/arm64-v8a/libdSafeShell.so","assets/mxsafe/x86_64/libdSafeShell.so"],"others":["assets/mxsafe.config","assets/mxsafe.data"],"classes":[]},
    "Google Play 签名": {"sonames":["libpairipcore.so"],"sopaths":["lib/arm64-v8a/libpairipcore.so","lib/armeabi-v7a/libpairipcore.so"],"others":[],"classes":[]},
    "中国移动加固": {"sonames":["libcmvmp.so","libmogosec_dex.so","libmogosec_sodecrypt.so","libmogosecurity.so"],"sopaths":["lib/armeabi/libcmvmp.so"],"others":["assets/mogosec_classes","assets/mogosec_data","assets/mogosec_dexinfo"],"classes":[]},
    "腾讯Bugly (SDK非加固)": {"sonames":["libBugly.so"],"sopaths":["lib/arm64-v8a/libBugly.so"],"others":[],"classes":[],"_not_packer":True},
}


def analyze_apk(apk_path, verbose=False):
    apk_path = Path(apk_path)
    if not apk_path.exists():
        print(f"[!] APK not found: {apk_path}"); return None
    results = defaultdict(lambda: {"score": 0, "matches": []})
    with zipfile.ZipFile(apk_path) as z:
        all_files = z.namelist()
        lib_files = [n for n in all_files if n.endswith('.so') or n.startswith('lib/')]
        dex_classes = set()
        if 'classes.dex' in z.namelist():
            try:
                dex_data = z.read('classes.dex')
                string_ids_off = struct.unpack_from('<I', dex_data, 0x3C)[0]
                string_ids_size = struct.unpack_from('<I', dex_data, 0x38)[0]
                for i in range(min(string_ids_size, 5000)):
                    try:
                        off = struct.unpack_from('<I', dex_data, string_ids_off + i * 4)[0]
                        end = dex_data.find(b'\x00', off)
                        if end > off:
                            s = dex_data[off:end].decode('utf-8', errors='replace')
                            if len(s) > 5: dex_classes.add(s)
                    except: pass
            except: pass
        for vendor, rules in SHELL_DB.items():
            score, matches = 0, []
            matched_sonames = set()
            for soname in rules.get("sonames", []):
                for lib in lib_files:
                    lb = os.path.basename(lib); matched = False
                    if '*' in soname:
                        p = soname.replace('*','.*').replace('.','\\.')
                        if re.search(p, lb): matched = True
                    elif lb == soname: matched = True
                    if matched and lb not in matched_sonames:
                        matched_sonames.add(lb); matches.append(f"SO: {lib}"); score += 5
            for sopath in rules.get("sopaths", []):
                for lib in lib_files:
                    if '*' in sopath:
                        if re.search(sopath.replace('*','.*'), lib):
                            matches.append(f"Path: {lib}"); score += 8
                    elif sopath in lib:
                        matches.append(f"Path: {lib}"); score += 8
            for other in rules.get("others", []):
                for f in all_files:
                    if other.lower() in f.lower():
                        matches.append(f"Asset: {f}"); score += 3
            for cls in rules.get("classes", []):
                for dc in dex_classes:
                    if cls.lower() in dc.lower():
                        matches.append(f"Class: {dc[:80]}"); score += 4
            if score > 0: results[vendor] = {"score": score, "matches": matches}
        dex_stats = {}
        if 'classes.dex' in z.namelist():
            try:
                d = z.read('classes.dex')
                dex_stats["class_defs"] = struct.unpack_from('<I', d, 0x60)[0]
                dex_stats["string_ids"] = struct.unpack_from('<I', d, 0x38)[0]
                dex_stats["file_size"] = struct.unpack_from('<I', d, 0x20)[0]
            except: pass
    is_packed = dex_stats and dex_stats.get("class_defs", 999) < 50 and dex_stats.get("string_ids", 999) < 1000
    for vendor in list(results.keys()):
        rules = SHELL_DB.get(vendor, {})
        if is_packed and not rules.get("_not_packer"):
            results[vendor]["score"] += 8; results[vendor]["matches"].append("DEX: packed shell")
        if rules.get("_not_packer"):
            results[vendor]["score"] -= 15; results[vendor]["matches"].append("NOTE: SDK, not packer")
    return {"results": dict(results), "dex_stats": dex_stats, "lib_count": len(lib_files), "dex_count": len([n for n in all_files if n.endswith('.dex')])}


def print_report(analysis, verbose=False):
    results = analysis["results"]; ds = analysis["dex_stats"]
    print("\n" + "=" * 65 + "\n  Android APK 加固壳识别报告\n" + "=" * 65)
    if ds:
        print(f"\n  [DEX] classes.dex: {ds['file_size']:,} bytes, {ds['class_defs']} classes, {ds['string_ids']} strings")
        if ds['class_defs'] < 50 and ds['string_ids'] < 1000: print("  >>> 强烈加固信号: 壳 DEX")
    sr = sorted(results.items(), key=lambda x: -x[1]["score"])
    if not sr: print("\n  [结果] 未识别到已知加固特征")
    else:
        print(f"\n  [识别结果] {len(sr)} 个匹配:\n")
        for vendor, info in sr:
            bar = "#" * min(info["score"], 40)
            print(f"  {vendor}\n    置信度: [{bar}] ({info['score']})")
            if verbose:
                for m in info["matches"][:10]: print(f"      - {m}")
            print()
    if sr:
        top = sr[0]; ts = top[1]["score"]
        ss = sr[1][1]["score"] if len(sr) > 1 else 0
        if ts >= 10 and ts > ss * 1.5: print(f"  [结论] 高度疑似: {top[0]}")
        elif ts >= 5: print(f"  [结论] 可能为: {top[0]}")
        else: print(f"  [结论] 特征不明显")
    print(f"\n  [参考] SO: {analysis['lib_count']}, DEX: {analysis['dex_count']}\n" + "=" * 65)


def main():
    p = argparse.ArgumentParser(description="Android APK 加固壳识别工具 v2.0")
    p.add_argument("apk", nargs="?")
    p.add_argument("-v","--verbose", action="store_true")
    p.add_argument("--list-vendors", action="store_true")
    args = p.parse_args()
    if args.list_vendors:
        print(f"支持 {len(SHELL_DB)} 个加固厂商:"); [print(f"  - {v}") for v in sorted(SHELL_DB)]; return 0
    if args.apk:
        a = analyze_apk(args.apk, args.verbose)
        if a: print_report(a, args.verbose); return 0
    p.print_help(); return 0

if __name__ == "__main__": sys.exit(main())
