/**
 * General root/Frida/debug/emulator bypass script for Frida.
 * Masks frida strings, root paths, debug detection, emulator properties.
 */
(function () {
    const fakePath = "/system/nonexistent";
    const rootPathTokens = ["/su", "/.su", "/magisk", "/busybox", "/superuser", "/supersu",
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
        "/system/bin/failsafe/su", "/system/bin/.ext/su"];
    const fridaTokens = ["frida", "gum-js-loop", "gadget", "re.frida", "linjector"];

    function lower(value) { return (value || "").toString().toLowerCase(); }
    function containsAny(value, tokens) {
        const text = lower(value);
        for (let i = 0; i < tokens.length; i++) { if (text.indexOf(tokens[i]) !== -1) return true; }
        return false;
    }
    function shouldHidePath(path) { return containsAny(path, rootPathTokens) || containsAny(path, fridaTokens); }

    function readCString(ptrValue) {
        try { if (ptrValue.isNull()) return ""; return ptrValue.readCString(); } catch (_) { return ""; }
    }

    function installPathHook(name, index, failRet) {
        const target = Module.findExportByName(null, name); if (!target) return;
        Interceptor.attach(target, {
            onEnter(args) {
                const path = readCString(args[index]);
                if (shouldHidePath(path)) { this.hidden = true; args[index] = Memory.allocUtf8String(fakePath); }
            },
            onLeave(retval) { if (this.hidden && failRet !== null) retval.replace(failRet); }
        });
    }

    function installNativeHooks() {
        [["access",0,-1],["faccessat",1,-1],["stat",0,-1],["stat64",0,-1],["lstat",0,-1],["lstat64",0,-1],
         ["fopen",0,ptr(0)],["opendir",0,ptr(0)],["readlink",0,-1],["execve",0,-1],["system",0,-1],
         ["open",0,-1],["open64",0,-1],["openat",1,-1]].forEach(function(item) {
            try { installPathHook(item[0], item[1], item[2]); } catch (_) {}
        });
    }

    function installJavaHooks() {
        if (typeof Java === "undefined" || !Java.available) return false;
        Java.perform(function () {
            try {
                const File = Java.use("java.io.File");
                ["exists","isFile","canExecute"].forEach(function(method) {
                    const original = File[method].overload();
                    original.implementation = function () {
                        let path = ""; try { path = this.getAbsolutePath().toString(); } catch (_) {}
                        if (shouldHidePath(path)) return false;
                        return original.call(this);
                    };
                });
            } catch (_) {}
            try {
                const Debug = Java.use("android.os.Debug");
                Debug.isDebuggerConnected.implementation = function () { return false; };
            } catch (_) {}
            try {
                const SystemProperties = Java.use("android.os.SystemProperties");
                const get1 = SystemProperties.get.overload("java.lang.String");
                const get2 = SystemProperties.get.overload("java.lang.String","java.lang.String");
                get1.implementation = function (key) {
                    const k = key.toString();
                    if (k === "ro.debuggable") return "0"; if (k === "ro.secure") return "1";
                    if (k === "service.adb.root") return "0"; if (k.indexOf("qemu") !== -1) return "";
                    return get1.call(this, key);
                };
                get2.implementation = function (key, def) {
                    const k = key.toString();
                    if (k === "ro.debuggable") return "0"; if (k === "ro.secure") return "1";
                    if (k.indexOf("qemu") !== -1) return def;
                    return get2.call(this, key, def);
                };
            } catch (_) {}
            try {
                const Runtime = Java.use("java.lang.Runtime");
                Runtime.exec.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        const args = [].slice.call(arguments);
                        const joined = args.map(function (a) { return a ? a.toString() : ""; }).join(" ");
                        if (shouldHidePath(joined) || joined.indexOf("getprop") !== -1 || joined.indexOf("mount") !== -1) {
                            if (typeof args[0] === "string") args[0] = "true";
                        }
                        return overload.apply(this, args);
                    };
                });
            } catch (_) {}
        });
        return true;
    }

    installNativeHooks();
    const javaTimer = setInterval(function () { if (installJavaHooks()) clearInterval(javaTimer); }, 10);
})();
