#!/usr/bin/env python3
"""
Generate a self-contained HTML report from APK unpacking results.
Usage: python scripts/generate_report.py --output-dir output/<package>
"""
import argparse
import csv
import os
import re
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Third-party domain classification (aligned with filter_business_http.py)
# ---------------------------------------------------------------------------
THIRD_PARTY_KW = (
    "amap", "autonavi", "alibaba", "aliyun", "alipay", "baidu", "bugly",
    "firebase", "google", "qq.com", "tencent", "weixin", "wechat", "github",
    "slf4j", "apache", "bouncycastle", "openssl", "gcc", "winimage", "jiagu",
    "umeng", "jiguang", "getui", "xpush", "schemas.android", "android.com",
    "gradle", "maven", "w3.org", "xml.org", "sourceforge", "googlesource",
    "example.com", "appjiagu", "adobe.com",
)

def is_third_party(value):
    return any(k in value.lower() for k in THIRD_PARTY_KW)

# ---------------------------------------------------------------------------
# DEX header parsing
# ---------------------------------------------------------------------------
def read_dex_header(dex_path):
    data = dex_path.read_bytes()
    class_defs = struct.unpack_from("<I", data, 0x60)[0]
    string_ids = struct.unpack_from("<I", data, 0x38)[0]
    file_size = dex_path.stat().st_size
    return class_defs, string_ids, file_size

def read_dex_strings(dex_path):
    data = dex_path.read_bytes()
    ss = struct.unpack_from("<I", data, 0x38)[0]
    so = struct.unpack_from("<I", data, 0x3C)[0]
    strings = []
    for i in range(ss):
        try:
            off = struct.unpack_from("<I", data, so + i * 4)[0]
            end = data.find(b"\x00", off)
            if end > off:
                s = data[off:end].decode("utf-8", errors="replace")
                if s: strings.append(s)
        except Exception:
            pass
    return strings

# ---------------------------------------------------------------------------
# Maps file parsing
# ---------------------------------------------------------------------------
def parse_maps(maps_path):
    if not maps_path.exists():
        return {"found": False}

    lines = maps_path.read_text(encoding="utf-8").strip().splitlines()
    info = {
        "found": True, "total_segments": len(lines),
        "jiagu_detected": False, "jiagu_paths": [],
        "anon_mem_segments": [], "dalvik_heap_size": 0,
        "total_anon_size": 0, "anon_mem_regions": [],
    }

    for line in lines:
        parts = line.split()
        if len(parts) < 5: continue
        addr_range, perms = parts[0], parts[1]
        pathname = " ".join(parts[5:]) if len(parts) > 5 else ""
        try:
            s, e = addr_range.split("-", 1)
            start, end = int(s, 16), int(e, 16)
            size = end - start
        except ValueError:
            continue

        if "jiagu" in pathname.lower():
            info["jiagu_detected"] = True
            info["jiagu_paths"].append(pathname)
        if "[anon:Mem_" in pathname:
            info["anon_mem_segments"].append({"start": s, "end": e, "size": size, "path": pathname})
        if pathname == "" or pathname.startswith("[anon"):
            info["total_anon_size"] += size
        if "dalvik-main space" in pathname:
            info["dalvik_heap_size"] += size

    return info

# ---------------------------------------------------------------------------
# CSV reading
# ---------------------------------------------------------------------------
def read_csv_safe(path):
    if not path.exists(): return []
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []

# ---------------------------------------------------------------------------
# Tech stack detection
# ---------------------------------------------------------------------------
TECH_PATTERNS = [
    (r"okhttp/(\d+\.\d+\.\d+)", "OkHttp", "网络库"),
    (r"retrofit2[/.]Retrofit", "Retrofit 2", "网络库"),
    (r"com\.alibaba\.fastjson", "Fastjson (Alibaba)", "JSON解析"),
    (r"com\.google\.gson\.", "Gson", "JSON解析"),
    (r"com\.bumptech\.glide\.", "Glide", "图片加载"),
    (r"io\.reactivex\.", "RxJava", "响应式编程"),
    (r"kotlinx\.coroutines\.", "Kotlin Coroutines", "协程"),
    (r"org\.springframework\.", "Spring Framework", "框架"),
    (r"com\.tencent\.bugly\.", "Tencent Bugly", "崩溃上报"),
    (r"com\.tencent\.smtt\.", "TBS (腾讯浏览服务)", "WebView"),
    (r"com\.tencent\.mm\.sdk\.", "微信 SDK", "第三方SDK"),
    (r"com\.heytap\.", "OPPO SDK", "厂商SDK"),
    (r"androidx\.", "AndroidX", "支持库"),
    (r"com\.google\.android\.gms\.", "Google Play Services", "第三方SDK"),
    (r"com\.google\.firebase\.", "Firebase", "第三方SDK"),
    (r"com\.baidu\.", "Baidu SDK", "第三方SDK"),
    (r"com\.amap\.api\.", "高德地图 SDK", "地图SDK"),
    (r"com\.google\.zxing\.", "ZXing", "条码扫描"),
    (r"com\.squareup\.okhttp3\.", "OkHttp 3", "网络库"),
    (r"com\.squareup\.retrofit2\.", "Retrofit 2", "网络库"),
    (r"com\.squareup\.picasso\.", "Picasso", "图片加载"),
    (r"com\.facebook\.", "Facebook SDK", "第三方SDK"),
    (r"okio\.", "Okio", "I/O库"),
]

def detect_tech_stack(all_strings):
    combined = "\n".join(all_strings)
    normalized = combined.replace("/", ".")
    found = {}
    for pattern, name, category in TECH_PATTERNS:
        for m in re.finditer(pattern, normalized, re.IGNORECASE):
            ver = m.group(1) if m.groups() else ""
            key = (name, category)
            if key not in found: found[key] = set()
            if ver: found[key].add(ver)
    result = []
    for (name, category), versions in sorted(found.items()):
        ver_str = ", ".join(sorted(versions)) if versions else "detected"
        result.append({"name": name, "version": ver_str, "category": category})
    return result

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
def fmt_size(bytes_val):
    for unit in ("B", "KB", "MB", "GB"):
        if bytes_val < 1024: return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} TB"

SEV_COLORS = {"CRITICAL": ("#dc3545", "#fff"), "HIGH": ("#fd7e14", "#fff"),
              "MEDIUM": ("#ffc107", "#212529"), "LOW": ("#17a2b8", "#fff")}

def severity_badge(severity):
    bg, fg = SEV_COLORS.get(severity, ("#6c757d", "#fff"))
    return f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:bold;background:{bg};color:{fg}">{severity}</span>'

# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
CSS = """\
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei","Helvetica Neue",Arial,sans-serif;background:#f0f2f5;color:#2c3e50;line-height:1.6}
.header{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);color:#fff;padding:40px 30px}
.header h1{font-size:1.8em;margin-bottom:5px}
.header .subtitle{color:#8892b0;font-size:.95em}
.summary-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:15px;padding:20px 30px;background:#fff;border-bottom:1px solid #e0e0e0}
.summary-card{text-align:center;padding:15px 10px;border-radius:8px;background:#f8f9fa;border:1px solid #e9ecef}
.summary-card .value{font-size:1.6em;font-weight:bold;color:#0f3460}
.summary-card .label{font-size:.8em;color:#6c757d;margin-top:4px}
.container{max-width:1200px;margin:0 auto;padding:20px}
.section{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:24px;overflow:hidden}
.section-header{background:#0f3460;color:#fff;padding:14px 20px;font-size:1.15em;font-weight:600}
.section-body{padding:20px}
table{width:100%;border-collapse:collapse;font-size:.9em}
thead th{background:#f1f3f5;color:#495057;font-weight:600;text-align:left;padding:10px 12px;border-bottom:2px solid #dee2e6;white-space:nowrap}
tbody td{padding:8px 12px;border-bottom:1px solid #e9ecef;vertical-align:top;word-break:break-all}
tbody tr:hover{background:#f8f9fa}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
.info-item{padding:10px;background:#f8f9fa;border-radius:6px}
.info-item .ilabel{font-size:.8em;color:#6c757d}
.info-item .ivalue{font-size:.95em;color:#2c3e50;word-break:break-all}
.badge-shell{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;background:#dc3545;color:#fff}
.badge-real{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;background:#28a745;color:#fff}
.footer{text-align:center;padding:20px;color:#6c757d;font-size:.85em}
.empty-hint{color:#6c757d;font-style:italic;padding:10px 0}
.api-subsection{margin:15px 0}
.api-subsection h3{color:#0f3460;margin-bottom:10px;border-bottom:2px solid #e9ecef;padding-bottom:6px}
@media(max-width:768px){
.header{padding:25px 15px}
.summary-cards{grid-template-columns:repeat(2,1fr);padding:15px}
.section-body{padding:10px}
table{font-size:.8em}
thead th,tbody td{padding:6px 8px}
}
@media print{
body{background:#fff}
.header{background:#1a1a2e!important;-webkit-print-color-adjust:exact}
.section{box-shadow:none;border:1px solid #ddd;break-inside:avoid}
}
"""

def render_html(package_name, summary, dex_inventory, shell_info, maps_info,
                api_endpoints, security_findings, tech_stack, all_urls_lookup):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Summary cards
    sc = summary.get("severity_counts", {})
    cards = (
        f'<div class="summary-card"><div class="value">{summary.get("dex_count",0)}</div><div class="label">DEX 文件</div></div>'
        f'<div class="summary-card"><div class="value">{summary.get("total_classes",0):,}</div><div class="label">总类数</div></div>'
        f'<div class="summary-card"><div class="value">{summary.get("total_strings",0):,}</div><div class="label">总字符串</div></div>'
        f'<div class="summary-card"><div class="value">{summary.get("api_endpoint_count",0)}</div><div class="label">API 端点</div></div>'
        f'<div class="summary-card"><div class="value">{sc.get("CRITICAL",0)}</div><div class="label" style="color:#dc3545">严重</div></div>'
        f'<div class="summary-card"><div class="value">{sc.get("HIGH",0)}</div><div class="label" style="color:#fd7e14">高危</div></div>'
        f'<div class="summary-card"><div class="value">{sc.get("MEDIUM",0)}</div><div class="label" style="color:#ffc107">中危</div></div>'
        f'<div class="summary-card"><div class="value">{sc.get("LOW",0)}</div><div class="label" style="color:#17a2b8">低危</div></div>'
    )

    # Shell info
    shell = '<div class="info-grid">'
    shell += f'<div class="info-item"><div class="ilabel">加固状态</div><div class="ivalue">{"360 加固 (Jiagu) — 已脱壳" if shell_info.get("is_packed") else "未检测到已知加固壳"}</div></div>'
    shell += f'<div class="info-item"><div class="ilabel">Jiagu SO 检测</div><div class="ivalue">{"是 ✓" if maps_info.get("jiagu_detected") else "否"}</div></div>'
    shell += f'<div class="info-item"><div class="ilabel">壳 DEX</div><div class="ivalue">{shell_info.get("shell_dex_name","N/A")} <span style="color:#dc3545">({shell_info.get("shell_classes",0)} 类 / {shell_info.get("shell_strings",0)} 字符串)</span></div></div>'
    shell += f'<div class="info-item"><div class="ilabel">SecNeo 内存段</div><div class="ivalue">{len(maps_info.get("anon_mem_segments",[]))} 个 Mem_* 段</div></div>'
    shell += f'<div class="info-item"><div class="ilabel">内存映射段总数</div><div class="ivalue">{maps_info.get("total_segments",0)}</div></div>'
    shell += f'<div class="info-item"><div class="ilabel">匿名内存总计</div><div class="ivalue">{fmt_size(maps_info.get("total_anon_size",0))}</div></div>'
    if maps_info.get("jiagu_paths"):
        shell += '<div class="info-item"><div class="ilabel">Jiagu 内存路径</div><div class="ivalue" style="font-family:monospace;font-size:.8em">' + "<br>".join(maps_info["jiagu_paths"]) + "</div></div>"
    shell += "</div>"

    # DEX inventory table
    dex_table = """<table style="margin-top:20px">
<thead><tr><th>文件名</th><th>大小</th><th>类数量</th><th>字符串数量</th><th>状态</th></tr></thead><tbody>"""
    for d in dex_inventory:
        status = '<span class="badge-shell">壳 DEX</span>' if d["is_shell"] else '<span class="badge-real">真实 DEX</span>'
        dex_table += f'<tr><td style="font-family:monospace;font-size:.85em">{d["name"]}</td><td>{d["size_str"]}</td><td>{d["class_defs"]:,}</td><td>{d["string_ids"]:,}</td><td>{status}</td></tr>'
    total_sz = sum(d["file_size"] for d in dex_inventory)
    total_cls = sum(d["class_defs"] for d in dex_inventory)
    total_str = sum(d["string_ids"] for d in dex_inventory)
    real_count = sum(1 for d in dex_inventory if not d["is_shell"])
    shell_count = sum(1 for d in dex_inventory if d["is_shell"])
    dex_table += f'<tr style="font-weight:bold;background:#f1f3f5"><td>合计</td><td>{fmt_size(total_sz)}</td><td>{total_cls:,}</td><td>{total_str:,}</td><td>{real_count} 真实 + {shell_count} 壳</td></tr>'
    dex_table += "</tbody></table>"

    # API endpoints
    business_eps, third_eps = [], []
    for ep in api_endpoints:
        if is_third_party(ep.get("domain", "")):
            third_eps.append(ep)
        else:
            business_eps.append(ep)

    def render_api_table(eps):
        if not eps: return '<div class="empty-hint">无数据</div>'
        t = '<table><thead><tr><th>域名</th><th>路径</th><th>完整 URL</th><th>来源 DEX</th></tr></thead><tbody>'
        for ep in eps:
            full = ep.get("full_url", "")
            src = all_urls_lookup.get(full, "")
            if not src:
                alt = full.replace("https://", "http://")
                src = all_urls_lookup.get(alt, "")
            if isinstance(src, set): src = ", ".join(sorted(src))
            t += f'<tr><td>{ep.get("domain","")}</td><td style="font-family:monospace;font-size:.85em">{ep.get("path","")}</td><td style="font-family:monospace;font-size:.8em"><a href="{full}" target="_blank">{full}</a></td><td style="font-size:.8em">{src or "-"}</td></tr>'
        t += "</tbody></table>"
        return t

    api_html = ""
    if business_eps:
        api_html += f'<div class="api-subsection"><h3>业务 API 端点 ({len(business_eps)})</h3>{render_api_table(business_eps)}</div>'
    if third_eps:
        api_html += f'<div class="api-subsection"><h3>第三方 SDK 端点 ({len(third_eps)})</h3>{render_api_table(third_eps)}</div>'
    if not api_html:
        api_html = '<div class="empty-hint">未找到 API 端点数据</div>'

    # Security findings
    sec = ""
    if security_findings:
        sev_counter = Counter(f.get("Severity", "").strip() for f in security_findings if f.get("Severity", "").strip())
        sec += '<div style="display:flex;gap:20px;margin-bottom:15px;flex-wrap:wrap">'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counter.get(s, 0) > 0:
                sec += f'<div>{severity_badge(s)} <strong>{sev_counter[s]}</strong></div>'
        sec += "</div>"
        sec += '<table><thead><tr><th style="width:85px">严重度</th><th style="width:110px">分类</th><th>发现</th><th>证据</th></tr></thead><tbody>'
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for f in sorted(security_findings, key=lambda x: rank.get(x.get("Severity", ""), 99)):
            sec += f'<tr><td>{severity_badge(f.get("Severity",""))}</td><td>{f.get("Category","")}</td><td>{f.get("Finding","")}</td><td style="font-family:monospace;font-size:.8em;max-width:400px">{f.get("Evidence","") or "-"}</td></tr>'
        sec += "</tbody></table>"
    else:
        sec = '<div class="empty-hint">无安全发现 — 未找到 security_audit.csv</div>'

    # Tech stack
    tech = ""
    if tech_stack:
        tech = '<table><thead><tr><th>组件/库</th><th>版本</th><th>类别</th></tr></thead><tbody>'
        for t in tech_stack:
            tech += f'<tr><td><strong>{t["name"]}</strong></td><td style="font-family:monospace">{t["version"]}</td><td>{t["category"]}</td></tr>'
        tech += "</tbody></table>"
    else:
        tech = '<div class="empty-hint">未检测到已知技术栈组件</div>'

    # Assemble
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{package_name} - APK 分析报告</title>
<style>{CSS}</style>
</head>
<body>
<div class="header">
<h1>{package_name}</h1>
<div class="subtitle">APK 脱壳分析报告 | 生成时间: {ts}</div>
</div>
<div class="summary-cards">{cards}</div>
<div class="container">

<div class="section">
<div class="section-header">加固与壳信息</div>
<div class="section-body">{shell}{dex_table}</div>
</div>

<div class="section">
<div class="section-header">API 端点分析</div>
<div class="section-body">{api_html}</div>
</div>

<div class="section">
<div class="section-header">安全审计发现</div>
<div class="section-body">{sec}</div>
</div>

<div class="section">
<div class="section-header">技术栈与依赖</div>
<div class="section-body">{tech}</div>
</div>

<div class="footer">由 generate_report.py 自动生成 | {package_name} | {ts}</div>
</div>
</body>
</html>"""
    return html

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="生成 APK 脱壳分析 HTML 报告")
    p.add_argument("--output-dir", required=True, help="输出目录，如 output/com.cns.fengxing")
    p.add_argument("--apk", default=None, help="原始 APK 路径 (可选)")
    args = p.parse_args()

    out = Path(args.output_dir)
    if not out.is_dir():
        print(f"[!] 目录不存在: {out}", file=sys.stderr)
        sys.exit(1)

    pkg = out.name
    fixed = out / "fixed"
    print(f"[*] 包名: {pkg}")

    # Phase 1: DEX inventory
    dex_inv = []
    shell = {"is_packed": False, "shell_dex_name": "", "shell_classes": 0, "shell_strings": 0}
    if fixed.is_dir():
        for df in sorted(fixed.glob("*.dex")):
            cds, sis, fsz = read_dex_header(df)
            is_s = "classes01_" in df.name and cds < 50
            dex_inv.append({"name": df.name, "file_size": fsz, "size_str": fmt_size(fsz),
                           "class_defs": cds, "string_ids": sis, "is_shell": is_s})
            if is_s:
                shell.update(is_packed=True, shell_dex_name=df.name, shell_classes=cds, shell_strings=sis)

    # Phase 2: Maps
    maps_files = sorted(out.glob("pid_*.maps"))
    maps_info = parse_maps(maps_files[0]) if maps_files else {"found": False}

    # Phase 3: CSVs
    api_eps = read_csv_safe(out / "api_endpoints.csv")
    sec_findings = read_csv_safe(out / "security_audit.csv")
    all_urls = read_csv_safe(out / "all_urls.csv")

    print(f"[*] DEX: {len(dex_inv)} | API端点: {len(api_eps)} | 安全发现: {len(sec_findings)} | URL映射: {len(all_urls)}")

    # Phase 4: Cross-reference URLs → DEX source
    url_src = defaultdict(set)
    for row in all_urls:
        u = row.get("value", "").strip()
        s = row.get("source", "").strip()
        if u and s: url_src[u].add(s)

    # Phase 5: Tech stack
    tech = []
    if fixed.is_dir():
        all_strs = []
        for df in sorted(fixed.glob("*.dex")):
            if "classes01_" in df.name: continue
            try:
                all_strs.extend(read_dex_strings(df))
            except Exception:
                pass
        tech = detect_tech_stack(all_strs)
        print(f"[*] 技术栈: {len(tech)} 个组件")

    # Phase 6: Summary
    sev_counts = Counter(f.get("Severity", "").strip() for f in sec_findings if f.get("Severity", "").strip())
    summary = {
        "dex_count": len(dex_inv),
        "total_classes": sum(d["class_defs"] for d in dex_inv),
        "total_strings": sum(d["string_ids"] for d in dex_inv),
        "api_endpoint_count": len(api_eps),
        "security_finding_count": len(sec_findings),
        "severity_counts": dict(sev_counts),
    }

    # Phase 7: Render & write
    html = render_html(pkg, summary, dex_inv, shell, maps_info, api_eps, sec_findings, tech, url_src)
    rpt = out / "report.html"
    rpt.write_text(html, encoding="utf-8")
    print(f"\n[*] 报告已生成: {rpt} ({fmt_size(len(html.encode('utf-8')))})")

if __name__ == "__main__":
    main()
