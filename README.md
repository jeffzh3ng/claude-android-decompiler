# Claude Android Decompiler

Android APK 脱壳与逆向分析工具链，基于 Frida + 内存 dump 实现。

## 快速开始

```bash
# 1. 识别加固
python scripts/identify_shell.py apk/target.apk -v

# 2. 一键脱壳 (360 加固)
python scripts/unpack_360_workflow.py --package com.example.app --apk apk/target.apk

# 3. 提取接口 + 安全审计
python scripts/extract_dex_strings_urls.py --dex-dir output/<pkg>/fixed
python scripts/security_audit.py --dex-dir output/<pkg>/fixed --apk apk/target.apk --out output/<pkg>/security_audit.csv

# 4. 生成报告
python scripts/generate_report.py --output-dir output/<pkg>
# -> output/<pkg>/report.html
```

## 环境要求

- **模拟器**: x86_64 Android 12 (SDK 32)，需开启 root
- **Python**: 3.14 + `frida==17.9.10 frida-tools==14.8.2`
- **JDK**: 17+ (`C:\Program Files\Java\jdk-25`)
- **ADB**: `tools/bin/adb.exe`

## 工作流

```
APK → 加固识别 → Frida 绕过 + 内存 dump → DEX carving/repair → 接口提取 + 安全审计 → HTML 报告
```

## 目录结构

```
├── apk/              ← 待脱壳 APK
├── output/<pkg>/     ← 脱壳产物 + report.html
├── scripts/          ← 16 个分析脚本
├── tools/
│   ├── bin/          ← adb, aapt, apksigner, d8, frida-cli
│   ├── frida/        ← frida-server (4 架构)
│   └── jadx/         ← jadx 反编译器
└── temp/             ← 临时文件
```

## 核心脚本

| 脚本 | 功能 |
|------|------|
| `identify_shell.py` | 加固识别 (51 厂商, 170+ 规则) |
| `unpack_360_workflow.py` | 360 加固一键脱壳 |
| `dump_mem_dex.py` | 通用内存 dump + carving |
| `repair_dex_headers.py` | 修复 DEX SHA1/Adler32 |
| `normalize_dex_map.py` | 重建 DEX map_list |
| `extract_dex_strings_urls.py` | 提取 API 端点 |
| `extract_http_indicators.py` | 提取 HTTP 指标 |
| `security_audit.py` | 安全审计 (密钥/SSL/WebView) |
| `generate_report.py` | 生成 HTML 聚合报告 |

## 支持加固

360加固、腾讯御安全/乐固/云加固、梆梆安全、爱加密、网易易盾、百度加固、阿里聚安全、娜迦加固 等 51 种。

## 安全审计覆盖

硬编码密钥 · 明文 HTTP · SSL 信任绕过 · 弱加密 (MD5/ECB) · WebView JS 接口 · allowBackup · SDK 版本

## License

工具脚本仅供安全研究和授权测试使用。
