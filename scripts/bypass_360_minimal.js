/**
 * Minimal 360 Jiagu bypass script for Frida.
 * Masks frida strings/libs, blocks anti-debug, hides root/emulator.
 */
(function () {
    "use strict";
    var fridaTokens = ["frida", "gum-js", "linjector", "gadget", "frida-agent", "gmain", "gdbus"];
    var rootTokens = ["/su", "/magisk", "/busybox", "/superuser", "/supersu"];

    function lower(v) { return (v || "").toString().toLowerCase(); }
    function containsAny(text, tokens) { var t = lower(text); for (var i = 0; i < tokens.length; i++) { if (t.indexOf(tokens[i]) !== -1) return true; } return false; }
    function readCString(ptr) { try { return ptr.isNull() ? "" : (ptr.readCString() || ""); } catch (_) { return ""; } }

    function hook_strstr() {
        var fn = Module.findExportByName(null, "strstr"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) { if (containsAny(readCString(args[1]), fridaTokens)) this.hide = true; },
            onLeave: function (retval) { if (this.hide) retval.replace(ptr(0)); }
        });
    }
    function hook_strcmp() {
        var fn = Module.findExportByName(null, "strcmp"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) { if (containsAny(readCString(args[0]), fridaTokens) || containsAny(readCString(args[1]), fridaTokens)) this.hide = true; },
            onLeave: function (retval) { if (this.hide) retval.replace(ptr(1)); }
        });
    }
    function hook_open() {
        var fn = Module.findExportByName(null, "open"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) {
                var p = readCString(args[0]);
                if (containsAny(p, fridaTokens) || containsAny(p, rootTokens) || (p.indexOf("/proc/") !== -1 && p.indexOf("maps") !== -1)) this.hide = true;
            },
            onLeave: function (retval) { if (this.hide) retval.replace(ptr(-1)); }
        });
    }
    function hook_readlink() {
        var fn = Module.findExportByName(null, "readlink"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) { if (containsAny(readCString(args[0]), fridaTokens)) this.hide = true; },
            onLeave: function (retval) { if (this.hide) retval.replace(ptr(-1)); }
        });
    }
    function hook_access() {
        var fn = Module.findExportByName(null, "access"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) { if (containsAny(readCString(args[0]), fridaTokens) || containsAny(readCString(args[0]), rootTokens)) this.hide = true; },
            onLeave: function (retval) { if (this.hide) retval.replace(ptr(-1)); }
        });
    }
    function hook_stat() {
        var fn = Module.findExportByName(null, "stat"); if (!fn) fn = Module.findExportByName(null, "__xstat"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) { if (containsAny(readCString(args[0]), fridaTokens) || containsAny(readCString(args[0]), rootTokens)) this.hide = true; },
            onLeave: function (retval) { if (this.hide) retval.replace(ptr(-1)); }
        });
    }
    function hook_ptrace() {
        var fn = Module.findExportByName(null, "ptrace"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) { if (args[0].toInt32() === 0) this.block = true; },
            onLeave: function (retval) { if (this.block) retval.replace(ptr(0)); }
        });
    }
    function hook_connect() {
        var fn = Module.findExportByName(null, "connect"); if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function (args) {
                try { var sa = args[1]; if (!sa || sa.isNull()) return;
                    if (sa.readU16() === 2) { var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        if (port >= 27042 && port <= 27050) this.block = true; }
                } catch (_) {}
            },
            onLeave: function (retval) { if (this.block) retval.replace(ptr(-1)); }
        });
    }

    try { hook_strstr(); } catch (_) {}; try { hook_strcmp(); } catch (_) {};
    try { hook_open(); } catch (_) {}; try { hook_readlink(); } catch (_) {};
    try { hook_access(); } catch (_) {}; try { hook_stat(); } catch (_) {};
    try { hook_ptrace(); } catch (_) {}; try { hook_connect(); } catch (_) {};
    console.log("[bypass] Native hooks installed");

    function installJavaHooks() {
        if (typeof Java === "undefined" || !Java.available) return false;
        Java.perform(function () {
            try { var Debug = Java.use("android.os.Debug"); Debug.isDebuggerConnected.implementation = function () { return false; }; } catch (_) {}
            try {
                var SysProp = Java.use("android.os.SystemProperties");
                var get1 = SysProp.get.overload("java.lang.String");
                get1.implementation = function (key) {
                    var k = key.toString();
                    if (k === "ro.debuggable") return "0"; if (k === "ro.secure") return "1";
                    if (k === "service.adb.root") return "0"; if (k.indexOf("qemu") !== -1) return "";
                    if (k.indexOf("goldfish") !== -1) return ""; return get1.call(this, key);
                };
            } catch (_) {}
            try {
                var File = Java.use("java.io.File"); var exists = File.exists.overload();
                exists.implementation = function () {
                    try { var p = this.getAbsolutePath().toString().toLowerCase();
                        if (containsAny(p, fridaTokens) || containsAny(p, rootTokens)) return false; } catch (_) {}
                    return exists.call(this);
                };
            } catch (_) {}
            console.log("[bypass] Java hooks installed");
        }); return true;
    }
    var timer = setInterval(function () { if (installJavaHooks()) clearInterval(timer); }, 50);
    console.log("[bypass] 360 Jiagu bypass ready");
})();
