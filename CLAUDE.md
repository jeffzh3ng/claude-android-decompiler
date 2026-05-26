# CLAUDE.md — Android APK 脱壳与逆向操作手册

## 环境约定

- **工具目录**: `tools\bin\` (所有 CLI 工具统一入口)
- **ADB**: `tools\bin\adb.exe`
- **模拟器**: x86_64, Android 12 (SDK 32), 默认 serial `emulator-5556`
- **Python**: 3.14, pip 清华源 `https://pypi.tuna.tsinghua.edu.cn/simple`
- **JDK**: `C:\Program Files\Java\jdk-25`
- **Shell**: PowerShell (Windows), 复杂 Python 脚本写入文件再执行避免转义问题
- **adb root 可用**: `adb root` 后 uid=0
- **工作目录严禁污染**: 所有产出物必须输出到 `output/<package>/`，不允许多余内容

## 禁止事项

> **以下行为严格禁止，除非用户明确要求:**

1. **禁止自主安装或创建模拟器** — 不要执行 `sdkmanager install emulator`、`avdmanager create` 等操作。模拟器由用户预先配置
2. **禁止在项目根目录生成临时文件** — Python 脚本、测试文件、dump 中间产物等一律放到 `temp/` 或 `output/` 下
3. **禁止自行下载大文件 (>50MB)** — 需要新工具时，告知用户: 工具名称、下载来源 URL、用途，由用户决定是否安装
4. **禁止在根目录散落文件** — APK 文件放 `apk/`、脱壳产物放 `output/`、临时文件放 `temp/`

## 注意事项

### 模拟器连接

- 连接不成功时先重试 2-3 次 (`adb devices` / `adb kill-server` / `adb start-server`)
- 基础重试无法恢复时，检查模拟器进程是否运行
- 仍无法连接时：**询问用户模拟器是否已开启**，不要自行启动或创建

### 工具安装

- 需要新工具时，告知用户: **工具名称、下载途径 (URL)、用途说明**
- 等待用户确认后再下载安装
- 工具安装到 `tools/` 下对应子目录

### 文件输出规范

- APK 文件 → `apk/` 目录
- 脱壳产物 → `output/<package_name>/` 目录
- 临时文件 → `temp/` 目录
- 项目结构不能被打乱，完成后清理 `temp/`

## 工具与目录结构

```
D:\PROGRAMS\ANDROID/
├── apk/                         ← 待脱壳的 APK 文件放这里
├── output/                      ← 所有脱壳产物的输出根目录
│   └── <package_name>/          ← 每个 APP 一个子目录
│       ├── pid_XXXX.maps        ← 进程内存映射
│       ├── memsegs/             ← dd dump 的原始内存段
│       ├── carved/              ← carving 出的 DEX
│       ├── fixed/               ← repair 后的 DEX
│       ├── normalized/          ← normalize 后的 DEX
│       ├── http_indicators.csv  ← HTTP 接口指标
│       └── api_endpoints.csv    ← 业务 API 端点
├── temp/                        ← 临时文件 (脚本中间产物、测试数据)
├── tools/
│   ├── bin/                     ← 所有 CLI 可执行文件
│   │   ├── adb.exe, fastboot.exe + AdbWinApi.dll, AdbWinUsbApi.dll
│   │   ├── aapt.exe, aapt2.exe
│   │   ├── apksigner.bat, d8.bat, zipalign.exe
│   │   ├── frida.bat, frida-ps.bat, frida-trace.bat, frida-kill.bat,
│   │   │   frida-discover.bat, frida-ls-devices.bat
│   │   └── lib/  (d8/aapt2 依赖)
│   ├── frida/                   ← Frida 服务端 (多架构, 228MB)
│   │   ├── frida-server-17.9.10-android-x86_64  (模拟器/真机)
│   │   ├── frida-server-17.9.10-android-x86     (旧模拟器)
│   │   ├── frida-server-17.9.10-android-arm64   (真机)
│   │   └── frida-server-17.9.10-android-arm     (旧真机 arm/v7)
│   └── jadx/                    ← jadx 反编译器 v1.5.5
│       └── bin/{jadx.bat, jadx-gui.bat}
├── scripts/                     ← 脱壳/分析脚本 (15个)
└── CLAUDE.md                    ← 本手册
```

### 必装工具

```bash
pip install frida frida-tools        # 版本需与 frida-server 一致 (17.9.10)
# JDK 17+: C:\Program Files\Java\jdk-25
```

### 工具路径速查

| 工具 | 路径 | 用途 |
|------|------|------|
| adb | `tools\bin\adb.exe` | Android 设备通信 |
| aapt | `tools\bin\aapt.exe` | APK 信息查看 |
| apksigner | `tools\bin\apksigner.bat` | APK 签名 |
| zipalign | `tools\bin\zipalign.exe` | APK 对齐优化 |
| d8 | `tools\bin\d8.bat` | Java class → DEX |
| jadx | `tools\jadx\bin\jadx.bat` | DEX/APK 反编译 |
| jadx-gui | `tools\jadx\bin\jadx-gui.bat` | jadx 图形界面 |
| frida | `tools\bin\frida.bat` | Frida CLI |
| frida-ps | `tools\bin\frida-ps.bat` | 进程列表 |
| frida-trace | `tools\bin\frida-trace.bat` | 动态追踪 |

### frida-server 部署 (按架构选择)

```bash
# 模拟器 x86_64 (默认)
adb push tools\frida\frida-server-17.9.10-android-x86_64 /data/local/tmp/frida-server
# 真机 arm64
adb push tools\frida\frida-server-17.9.10-android-arm64 /data/local/tmp/frida-server
# 旧模拟器 x86
adb push tools\frida\frida-server-17.9.10-android-x86 /data/local/tmp/frida-server
# 旧真机 arm
adb push tools\frida\frida-server-17.9.10-android-arm /data/local/tmp/frida-server

# 通用启动
adb root
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server -D &
# 验证: python -c "import frida; print(frida.get_device_manager().enumerate_devices())"
```

### Frida CLI 常用命令

```bash
tools\bin\frida-ps.bat -U          # 列出 USB 设备进程
tools\bin\frida-ps.bat -Uai        # 列出已安装 APP
tools\bin\frida.bat -U -f com.example.app -l scripts\bypass_root.js --no-pause
tools\bin\frida-trace.bat -U -j "com.example.*" com.example.app
tools\bin\frida-kill.bat -U 1234   # 终止远程进程
```

### jadx 使用

```bash
tools\jadx\bin\jadx.bat -d output_dir classes.dex    # 反编译 DEX
tools\jadx\bin\jadx.bat -d output_dir target.apk     # 反编译 APK
tools\jadx\bin\jadx-gui.bat target.apk               # 图形界面
```

## 工具获取与安装说明

### 目录总览

```
tools/
├── bin/     — Android SDK 工具 + Frida CLI 包装器 (从 Sdk\ 复制而来 + 自建)
├── frida/   — Frida 服务端 4 架构 (.xz 下载后用 Python lzma 解压)
└── jadx/    — jadx GitHub Release .zip 下载解压
```

### tools/bin/ — Android SDK 工具

来源: Android SDK platform-tools / build-tools 35.0.0。必要时可通过 `sdkmanager` 重装。

| 文件 | 来源 | 版本 |
|------|------|------|
| `adb.exe` + 2 DLL | Android SDK platform-tools | 35.0.0 |
| `fastboot.exe` | Android SDK platform-tools | 35.0.0 |
| `aapt.exe`, `aapt2.exe` | Android SDK build-tools | 35.0.0 |
| `zipalign.exe` | Android SDK build-tools | 35.0.0 |
| `apksigner.bat` | Android SDK build-tools | 35.0.0 |
| `d8.bat` (调用 lib/d8.jar) | Android SDK build-tools | 35.0.0 |
| `lib/` | Android SDK build-tools lib\ | d8/aapt2 依赖 |

常用命令:
```bash
# APK 信息
tools\bin\aapt.exe dump badging target.apk

# APK 签名
tools\bin\apksigner.bat sign --ks debug.keystore target.apk

# APK 对齐
tools\bin\zipalign.exe -v 4 in.apk out.apk

# DEX 编译
tools\bin\d8.bat --min-api 24 --output out_dir/ classes/*.class
```

### tools/bin/ — Frida CLI 包装器

来源: 自建 `.bat` 包装器，指向 Python Scripts 目录下的 `frida*.exe`。

| 文件 | 实际指向 | 版本 |
|------|---------|------|
| `frida.bat` | `C:\Users\DP\AppData\Local\Python\pythoncore-3.14-64\Scripts\frida.exe` | 17.9.10 |
| `frida-ps.bat` | 同上 `frida-ps.exe` | 17.9.10 |
| `frida-trace.bat` | 同上 `frida-trace.exe` | 17.9.10 |
| `frida-discover.bat` | 同上 `frida-discover.exe` | 17.9.10 |
| `frida-kill.bat` | 同上 `frida-kill.exe` | 17.9.10 |
| `frida-ls-devices.bat` | 同上 `frida-ls-devices.exe` | 17.9.10 |

安装: `pip install frida==17.9.10 frida-tools==14.8.2`

更新版本时:
```bash
pip install frida==<new_version> frida-tools --upgrade
# 重新下载对应版本的 frida-server 放到 tools\frida\
```

### tools/frida/ — Frida 服务端

来源: [GitHub Releases](https://github.com/frida/frida/releases) 下载 `.xz` 后用 Python lzma 解压。

| 文件 | 适用环境 | 大小 | 下载链接 |
|------|---------|------|---------|
| `frida-server-17.9.10-android-x86_64` | 模拟器/真机 x86_64 | 106 MB | `frida-server-17.9.10-android-x86_64.xz` |
| `frida-server-17.9.10-android-x86` | 旧模拟器 x86 | 51 MB | `frida-server-17.9.10-android-x86.xz` |
| `frida-server-17.9.10-android-arm64` | 真机 arm64-v8a | 51 MB | `frida-server-17.9.10-android-arm64.xz` |
| `frida-server-17.9.10-android-arm` | 旧真机 armeabi-v7a | 21 MB | `frida-server-17.9.10-android-arm.xz` |

部署前先确认设备架构:
```bash
tools\bin\adb.exe shell getprop ro.product.cpu.abi    # 输出如 x86_64 / arm64-v8a
tools\bin\adb.exe root
tools\bin\adb.exe push tools\frida\frida-server-17.9.10-android-<arch> /data/local/tmp/frida-server
tools\bin\adb.exe shell chmod 755 /data/local/tmp/frida-server
tools\bin\adb.exe shell /data/local/tmp/frida-server -D &
```

**版本一致性检查**:
```bash
python -c "import frida; print('Python:', frida.__version__)"
# frida-server 版本: tools\bin\adb.exe shell /data/local/tmp/frida-server --version
# 两者必须一致!
```

### tools/jadx/ — 反编译器

来源: [GitHub Releases](https://github.com/skylot/jadx/releases) 下载 `jadx-<version>.zip` 解压。

当前版本: **v1.5.5**

```bash
# 常用参数
tools\jadx\bin\jadx.bat -d <output> --show-bad-code --deobf <input>
tools\jadx\bin\jadx.bat -d src/ --no-res app.apk    # 跳过资源只反编译代码
tools\jadx\bin\jadx.bat -d src/ classes*.dex         # 反编译多个 DEX
```

## APK 加固识别

> **使用专用脚本**: `python scripts/identify_shell.py <apk> [-v]` — 基于 ApkCheckPack 数据库 (51 厂商, 170+ 规则)
>
> 或手动按照以下三步判断:

### Step 1: 快速判断 — DEX 规模

```python
import zipfile, struct
with zipfile.ZipFile("target.apk") as z:
    with z.open("classes.dex") as f:
        data = f.read(0x70)
    cd = struct.unpack_from("<I", data, 0x60)[0]   # class_defs_size
    si = struct.unpack_from("<I", data, 0x38)[0]   # string_ids_size
    print(f"class_defs={cd}, string_ids={si}")
    # cd < 50 且 si < 1000  → 壳 DEX (加固)
    # cd > 1000              → 可能是真实 DEX 或未加固
```

### Step 2: SO 库特征匹配

检查 APK 内 `lib/` 和 `assets/` 下的 .so 文件:

```python
libs = [n for n in z.namelist() if n.endswith('.so')]
```

### Step 3: 完整加固厂商特征速查表 (51 厂商)

| 加固厂商 | SO 特征文件 | 路径/Assets 特征 | 包名/类名特征 |
|---------|------------|-----------------|-------------|
| **360加固 (三六零天御)** | `libjiagu.so`, `libjiagu_a64.so`, `libjiagu_art.so`, `libjiagu_x64.so`, `libjiagu_x86.so`, `libjiagu_ls.so`, `libjgdtc.so`, `libjgdtc_*.so`, `libprotectClass.so`, `libSafeManageService.so` | `assets/libjiagu.so`, `assets/.appkey` | `com.stub.StubApp`, `com.qihoo.*` |
| **腾讯御安全** | `libtosprotection.armeabi.so`, `libtosprotection.armeabi-v7a.so`, `libtosprotection.x86.so`, `libBugly-yaq.so`, `libshellx-super.2019.so` | `assets/libtosprotection.*.so`, `assets/tosversion`, `o0ooo000oo0o.dat` | `com.tencent.legu.*` |
| **腾讯乐固 (VMP)** | `libxgVipSecurity.so` | `lib/arm64-v8a/libxgVipSecurity.so` | — |
| **腾讯乐固 (旧版)** | `libshell.so`, `libshella.so`, `libshellx.so`, `libtup.so`, `liblegudb.so` | `lib/armeabi/mix.dex`, `lib/armeabi/mixz.dex`, `tencent_stub` | — |
| **腾讯云加固** | `libshell-super.2019.so`, `libshellx-super.2021.so` | `assets/libshellx-super.2021.so`, `tencent_sub` | — |
| **腾讯手游加固** | `libtprt.so` | — | — |
| **梆梆安全 (免费版)** | `libsecexe.so`, `libsecmain.so`, `libSecShell.so`, `libSecShel1.so`, `libSecShell_art.so` | `lib/armeabi/libSecShell.so`, `assets/secData0.jar` | — |
| **梆梆安全 (企业版)** | `libDexHelper.so`, `libDexHelper-x86.so` | — | — |
| **梆梆安全 (定制版)** | `DexHelper.so` | `lib/armeabi/DexHelper.so`, `assets/classes.jar` | — |
| **爱加密** | `libexec.so`, `libexecmain.so` | `assets/ijm_lib/armeabi/libexec.so`, `assets/af.bin`, `assets/signed.bin`, `ijiami.dat` | `com.ijiami.*` |
| **爱加密 (3代)** | `libexecv3.so` | `assets/ijiami3.ajm` | — |
| **爱加密 (5代)** | `libijmDataEncryption.so` | `assets/libijmDataEncryption.so`, `assets/IJMDal.Data` | — |
| **爱加密 (企业版)** | — | `assets/ijiami.ajm` | — |
| **网易易盾** | `libnesec.so` | — | `com.netease.nis.*` |
| **百度加固** | `libbaiduprotect.so`, `libbaiduprotect_art.so`, `libbaiduprotect_x86.so` | `lib/armeabi/libbaiduprotect.so`, `assets/baiduprotect.jar` | — |
| **阿里聚安全** | `libsgmain.so`, `libsgsecuritybody.so`, `libmobisec.so`, `libzuma.so` | `assets/libzuma.so`, `assets/libpreverify1.so`, `aliprotect.dat` | `com.alibaba.wireless.security.*` |
| **阿里云加固** | `libdemolish.so`, `libdemolishdata.so`, `libfakejni.so`, `libmobisec.so`, `libsgmain.so`, `libsgsecuritybody.so`, `libzumadata.so` | `assets/armeabi/libfakejni.so`, `assets/libpreverify1.so`, `assets/libzuma.so`, `aliprotect.dat` | — |
| **娜迦加固** | `libchaosvmp.so`, `libddog.so`, `libfdog.so`, `libhdog.so`, `libedog.so` | — | — |
| **娜迦加固 (VMP)** | `libvdog.so`, `libvdog-x86.so` | — | — |
| **娜迦加固 (2022新版)** | `libxloader.so` | `lib/armeabi/libxloader.so`, `assets/maindata/fake_classes.dex` | — |
| **顶像科技** | `libx3g.so`, `libjni.so` | `lib/armeabi/libx3g.so` | — |
| **通付盾** | `libNSaferOnly.so`, `libegis.so`, `libgeiri.so`, `libgeiri-x86.so` | — | — |
| **几维安全 (Kiwi)** | `libkdp.so`, `libkwscmm.so`, `libkadp.so`, `libkiwi_dumper.so`, `libkiwicrash.so`, `libKwProtectSDK.so`, `libkwdataenc.so` | `lib/armeabi/kdpdata.so`, `assets/dex.dat` | — |
| **海云安** | `libitsec.so` | `lib/armeabi/libitsec.so`, `assets/itse` | — |
| **蛮犀加固** | `libdSafeShell.so`, `libmxacc.so` | `assets/mxsafe/`, `assets/mxsafe.config`, `assets/mxsafe.data` | — |
| **中国移动加固** | `libcmvmp.so`, `libmogosec_dex.so`, `libmogosec_sodecrypt.so`, `libmogosecurity.so` | `assets/mogosec_classes`, `assets/mogosec_data` | — |
| **瑞星加固** | `librsprotect.so` | — | — |
| **盛大加固 (网秦)** | `libapssec.so`, `libnqshield.so` | — | — |
| **UU安全** | `libuusafe.so`, `libuusafe.jar.so`, `libuusafeempty.so` | `assets/libuusafe.so` | — |
| **珊瑚灵御** | `libreincp.so`, `libreincp_x86.so` | `assets/libreincp.so` | — |
| **CFCA (金融认证)** | `libbasec.so`, `libbasec_x86.so`, `libsecenh.so`, `libsecenh_a64.so`, `libsecenh_x86.so` | `my_classes.jar` | — |
| **深盾 Virbox** | `libvirbox32.so`, `libvirbox64.so` | — | — |
| **G-Presto (BishopSoft)** | `libATG_D.so`, `libATG_H.so`, `libATG_L.so` | `assets/ATG_E.sec`, `assets/ATG_E_x64.sec` | `Presto_Init` |
| **APKProtect** | `libAPKProtect.so` | — | — |
| **DexProtect** | — | `assets/classes.dex.dat`, `dp.arm-v7.so.dat` | — |
| **LIAPP** | — | `assets/LIAPP.ini`, `assets/pkgInfo.txt` | — |
| **AppGuard.us** | `libloader.so` | — | `AppGuard_*` |
| **OPPO应用加固** | `OPPOProtect.so`, `OPPOProtect2019.so` | — | — |
| **OPPO安全检测** | `libomesStdSco.so` | `jni/*/libomesStdSco.so` | — |
| **Google Play 签名** | `libpairipcore.so` | `lib/*/libpairipcore.so` | — |
| **apktoolplus** | `libapktoolplus_jiagu.so` | `assets/jiagu_data.bin`, `assets/sign.bin` | — |
| **启明星辰** | `libvenSec.so`, `libvenustech.so` | — | — |

### 常见加固的附加特征

| 加固厂商 | ZIP Comment | DEX 类名特征 | 特殊 URL / 域名 |
|---------|------------|-------------|----------------|
| 360加固 | 加密签名数据 (10-12KB) | `Lcom/stub/StubApp;` | `c.appjiagu.com` (崩溃上报) |
| 腾讯御安全 | — | `com.secneo.apkwrapper.*` | — |
| 爱加密 | — | `com.ijiami.*` | — |
| 梆梆安全 | — | `com.secneo.*` (与腾讯御安全同源) | — |
| 网易易盾 | — | `com.netease.nis.*` | `appjiagu.com` 实为 360 域名,非网易 |
| 娜迦加固 | — | `com.nagain.*` | — |

### 混淆要点

- `libDexHelper.so` 同时出现在 **梆梆安全(企业版)** 和 **梆梆安全(定制版)**，不是腾讯的特征
- `libexec.so` 同时出现在 **爱加密** 和 **腾讯乐固(旧版)**，需结合其他特征判断
- `libjiagu.so` 是 360 的特征，**不是** 爱加密或网易的特征
- `appjiagu.com` 域名 ICP 备案归属 **上海奇虎科技有限公司(360)**，与网易易盾无关
- `libBugly.so` 是腾讯 Bugly 崩溃上报 SDK，**不是加固壳**，仅代表集成了 Bugly
- `assets/libjiagu.so` (在 assets/ 目录下) 是 360 加固的强烈特征 (sopath 匹配)

## 脱壳方案: /proc/pid/mem 内存 dump + 离线 carving

### 核心原则

> **Frida 只负责: (1) 让 APP 活着 (2) 绕过反检测。真正的 DEX 提取靠 `dd if=/proc/pid/mem` 通过 ADB shell 完成，不要在 Frida JS 里做文件 I/O。**

Frida JS 环境有 NativeFunction 符号查找失败、File API 权限不足等问题。内存 dump 走 ADB shell `dd` 命令，Python 端离线 carving。

### 流程概览

```
Frida spawn + bypass_root.js (保持进程存活)
    ↓
读 /proc/{pid}/maps → 识别 DEX 相关内存段
    ↓
dd if=/proc/{pid}/mem → 逐段 dump 到 /data/local/tmp/
    ↓
adb pull → Python 正则匹配 dex\n0xx → carving DEX
    ↓
repair headers → normalize map_list → build APK
```

### Step 1: 绕过检测 (bypass_root.js)

必须处理 4 类检测:

1. **Native 层 Frida 检测**: hook `strstr`/`strcmp`/`open`/`readlink`，遮蔽含 "frida"/"gum-js"/"linjector" 的字符串
2. **Java 层 Root 检测**: hook `File.exists()`/`canExecute()`，对含 "su"/"magisk"/"busybox" 的路径返回 false
3. **调试检测**: hook `Debug.isDebuggerConnected()` → false
4. **模拟器检测**: hook `SystemProperties.get()`，遮蔽 `ro.debuggable`(→"0")、`ro.secure`(→"1")、qemu 属性(→"")

脚本模板见 `scripts/bypass_root.js`。

### Step 2: 选择内存段

`/proc/{pid}/maps` 中按优先级 dump:

| 优先级 | maps 标记 | 含义 |
|--------|----------|------|
| 0 | `[anon:Mem_0x...]` | SecNeo 解密后的 DEX 专用内存 (出现则说明 APP 完整运行过) |
| 1 | `[anon:dalvik-DEX data]` | ART 的 DEX 数据映射 |
| 2 | `[anon:scudo:secondary]` ≤96MB | 分配器释放内存，常含残留 DEX |
| 3 | `/code_cache/*.dex (deleted)` | 已被删除的内存映射 |
| 4 | `/oat/.../base.vdex` | ART 编译产物 |
| 5 | 匿名可读段 ≤96MB | 通用兜底 |

`dump_mem_dex.py` 中的 `reason_for()` 函数实现了上述逻辑，参数 `--max-segment-mb 96`。

### Step 3: dd 内存 dump

```bash
# 对每个选中的内存段:
pages=$(( (size + 4095) / 4096 ))
skip=$(( start / 4096 ))
dd if=/proc/{pid}/mem of=/data/local/tmp/seg_N.bin bs=4096 skip=$skip count=$pages 2>/dev/null
```

Python 端通过 subprocess 调用 ADB shell 完成。需要 root (`adb root`) 才能读 `/proc/{pid}/mem`。

**关键: 进程死亡后 `/proc/{pid}/mem` 不可读，必须快速 dump。优先 dump 最大的段。**

### Step 4: Python 端 carving

```python
DEX_MAGIC = re.compile(rb"dex\n0[0-9]{2}\x00")

for match in DEX_MAGIC.finditer(data):
    offset = match.start()
    header = data[offset:offset + 0x70]
    file_size = struct.unpack_from("<I", header, 0x20)[0]
    header_size = struct.unpack_from("<I", header, 0x24)[0]
    endian_tag = struct.unpack_from("<I", header, 0x28)[0]
    # 校验: header_size==0x70, endian_tag==0x12345678,
    #       file_size>=0x70, file_size<=100MB
    blob = data[offset:offset + file_size]
```

### Step 5: 修复 DEX header

从内存 dump 的 DEX 文件，SHA1 签名和 Adler32 校验和需要重算:

```python
buf = bytearray(data)
buf[12:32] = hashlib.sha1(buf[32:]).digest()
struct.pack_into("<I", buf, 8, zlib.adler32(buf[12:]) & 0xFFFFFFFF)
```

脚本: `scripts/repair_dex_headers.py`

### Step 6: 重建 map_list

内存 dump 的 DEX 可能缺少或损坏 map_list。需要:
1. 遍历 DEX 所有 section，收集偏移
2. 重建 map_list 条目 (type, count, offset)
3. 追加到 DEX 末尾，更新 header 中的 `map_off`/`file_size`/`data_size`

脚本: `scripts/normalize_dex_map.py`

### Step 7: 构建可运行 APK

用 stub 类替换壳代码:

```bash
# 1. 编译 stub (替换 com.secneo.apkwrapper.AW/AP/CP)
javac -source 8 -target 8 -bootclasspath android.jar stubs/secneo/*.java
d8 --min-api 24 --output stub-dex/ *.class

# 2. 组装: classes.dex=stub, classes2.dex~N=真实DEX
# 3. zipalign + apksigner sign
```

脚本: `scripts/build_runnable_unpacked_apk.py`

stub AW.java 核心: 在 `attachBaseContext()` 中用 `DexClassLoader` 加载 payload DEX，反射替换 `LoadedApk.mClassLoader`。

## 部署与安装注意事项

1. **ABI 与 lib 完整性**: 安装前检查 APK 中哪些 ABI 有完整的 .so 文件。
   ```bash
   # 如果 APK 只有 arm64/armeabi 的 lib，但某些 .so 只存在特定目录，用:
   adb install --abi arm64-v8a target.apk
   ```
   否则系统可能选择 armeabi-v7a 导致某些 .so 缺失。

2. **`debuggable=true` 的 APK** 可直接 attach，不需要 `adb root`。但 `adb root` 能解决更多权限问题。

3. **frida-server 版本必须与 `pip show frida` 版本完全一致**。

## 模拟器兼容性

**x86_64 模拟器 + ARM64-only APP**:
- 依赖 houdini (ARM→x86 翻译层) 运行 native 代码
- 不同 Android 版本/厂商的 houdini 兼容性不同
- 可能遇到 SIGSEGV at 0x0 (NULL 函数指针调用)
- **如果能运行 ≥10 秒** → 可以用本方案脱壳
- **如果立即崩溃** → 需 ARM64 模拟器镜像或真机

模拟器 vs 真机:
| 因素 | 模拟器 | 真机 |
|------|--------|------|
| root | `adb root` 一键 | Magisk/KernelSU |
| ARM64 兼容 | 看 houdini 版本 | 原生 |
| 获取难度 | 本地创建 | 需实体设备 |

## 从脱壳产物提取接口

脱壳前能提取的信息非常有限 (约 5%):

| 可提取来源 | 不需要脱壳 | 内容量 |
|-----------|----------|--------|
| `res/xml/http.xml` (网络安全配置) | ✅ | 少数域名 |
| `assets/*.properties` | ✅ | 少数配置 |
| `assets/dist/**/*.js` (WebView) | ✅ | 部分 URL |
| `AndroidManifest.xml` | ✅ | intent-filter 信息 |
| DEX 字符串 (壳) | ✅ | 仅 300 个壳字符串 |
| DEX 字符串 (真实代码) | ❌ 必须脱壳 | ~300,000 个字符串, ~29,000 类 |

脱壳后提取使用:
```bash
python scripts/extract_http_indicators.py --dex-dir <fixed/> --apk <原始APK>
python scripts/filter_business_http.py
```
输出: `http_indicators.csv` (全部), `business_http_indicators.csv` (业务相关)

## 脚本清单

| 脚本 | 功能 |
|------|------|
| `scripts/identify_shell.py` | **加固壳识别** (44厂商/170+规则) → `python scripts/identify_shell.py <apk> -v` |
| `scripts/bypass_root.js` | Frida 绕过 root/Frida/调试/模拟器 检测 (通用) |
| `scripts/bypass_360_minimal.js` | Frida 360 加固专用绕过脚本 |
| `scripts/dump_mem_dex.py` | 读取 /proc/pid/maps → dd dump → carving |
| `scripts/unpack_360_workflow.py` | **一键脱壳工作流** (spawn + bypass + dump + repair) |
| `scripts/repair_dex_headers.py` | 修复 DEX SHA1 签名和 Adler32 校验和 |
| `scripts/normalize_dex_map.py` | 重建 DEX map_list 结构 |
| `scripts/dex_inventory.py` | DEX 内容统计 (类数/字符串数) |
| `scripts/recarve_extended_dex.py` | 从大段中重新 carving (连续多 DEX) |
| `scripts/extract_http_indicators.py` | 从 DEX + APK 提取 URL/域名/IP/路径 |
| `scripts/extract_dex_strings_urls.py` | 直接从 DEX 字符串表提取 API 端点 |
| `scripts/filter_business_http.py` | 过滤业务相关 HTTP 指标 |
| `scripts/security_audit.py` | **安全审计** (硬编码凭证/SSL/加密/WebView/日志) |
| `scripts/generate_report.py` | **生成 HTML 报告** (聚合所有产物为可视化报告) |
| `scripts/spawn_collect.py` | Spawn APP + 收集设备端 code_cache/files |
| `scripts/static_extract_assets.py` | 静态提取 APK assets 中的 URL/域名 |

## 常见问题

**Q: Frida spawn 报 `InvocationTargetException`**
→ frida-server 权限不足。`adb root` → killall frida-server → 重启。

**Q: Frida `unable to access process with pid X`**
→ 同上，非 root 运行的 frida-server 无法 attach。

**Q: APP 启动后立即 SIGSEGV at 0x0**
→ houdini 翻译 ARM64 代码时调用 NULL 函数指针。检查 tombstone: `adb shell ls /data/tombstones/`。无法修复，换 ARM64 环境。

**Q: maps 中没有 `[anon:Mem_` 段**
→ APP 没有运行到 SecNeo 解密阶段。需要 APP 存活 ≥10 秒，或换设备。

**Q: dd 出来的段 carving 不到 DEX**
→ 段可能不包含完整 DEX。优先 dump `scudo:secondary` 大段 (50MB+)，其次检查 oat/vdex 区域。

**Q: ADB 路径在 Git Bash 中被 MSYS2 转换为 Windows 路径**
→ 所有 ADB 命令通过 Python `subprocess.run([adb, ...])` 调用，不要直接在 bash 中调用 adb。

**Q: `dd` 读 `/proc/pid/mem` 返回 Permission denied**
→ 需要 root。`adb root` 重试。

## 产出物目录结构

> **所有脱壳产物必须输出到 `output/<package_name>/`，不允许在项目根目录或其他位置散落文件。**

```
output/<package_name>/
├── pid_XXXX.maps              # 进程内存映射
├── memsegs/                   # dd dump 的原始内存段 (.bin)
├── carved/                    # carving 出的 DEX (可能有 header 问题)
├── fixed/                     # repair 后的 DEX
├── normalized/                # normalize 后的 DEX (如需要)
├── extended/                  # recarve 的扩展 DEX (如需要)
├── all_urls.csv               # 所有 URL 及来源 DEX 映射
├── http_indicators.csv        # 全部 HTTP 接口指标
├── api_endpoints.csv          # 业务 API 端点汇总
├── security_audit.csv         # 安全审计结果
├── report.html                # **聚合 HTML 报告** (脱壳完成后必须生成)
└── SECURITY_AUDIT.md          # 安全审计报告 (由 report.html 替代)
```

**工作流完成后必须确保**:
- 根目录只有 `CLAUDE.md`，没有散落的 `.json` / `.csv` / `.dex` / `.bin` / `.maps` / `.apk`
- `temp/` 中的中间产物在工作完成后清理
- `apk/` 中只保留源 APK，不保留脱壳产物

## 生成聚合报告

> **脱壳 + 接口提取 + 安全审计全部完成后，必须执行此步骤生成最终 HTML 报告。**

```bash
python scripts/generate_report.py --output-dir output/<package_name>
# 产出: output/<package_name>/report.html
```

### 报告要求

`generate_report.py` 从 output 目录的所有 CSV 和 DEX 文件中聚合数据，生成自包含的单文件 HTML 报告（内联 CSS，无外部依赖）。

**报告必须包含以下 6 个 Section：**

1. **头部摘要卡片** — 包名、生成时间、DEX 数 / 总类数 / 总字符串数 / API 端点数 / 安全发现（按 CRITICAL/HIGH/MEDIUM/LOW 分色）
2. **加固与壳信息** — 壳类型检测、Jiagu SO 状态、SecNeo 内存段统计、DEX 清单表（文件名/大小/类数/字符串数/壳或真实标记）
3. **API 端点分析** — 分业务/第三方两个子表，每行含：域名、路径、完整 URL、**来源 DEX 文件名**（通过 all_urls.csv 反查）
4. **安全审计发现** — 严重度彩色 badge（CRITICAL=红 / HIGH=橙 / MEDIUM=黄 / LOW=青）、分类、发现描述、证据
5. **技术栈与依赖** — 从 DEX 字符串中检测 SDK/库（OkHttp/Retrofit/Fastjson/Spring/TBS 等 30 种模式）
6. **页脚** — 生成工具名 + 时间戳

### 设计约束

- 中文标签为主
- 严重度颜色固定: CRITICAL=#dc3545, HIGH=#fd7e14, MEDIUM=#ffc107, LOW=#17a2b8
- 响应式布局，支持打印
- 各数据源文件缺失时优雅降级（显示 "无数据"），不得崩溃
- 壳检测规则: `classes01_*` 且 class_defs < 50 → 壳 DEX
- 第三方判断复用 `filter_business_http.py` 的关键词列表
- DEX 字符串中的 `/` 分隔符需归一化为 `.` 后再匹配 SDK 模式
