# Android-JniPtracePatcher — JNI + ptrace 内存补丁工具

> 攻防演练用（仅自有产物）。目标：`libprot.so` 的 `nativeIsDebugged`（TracerPid 反调试）
> 与 `nativeDetectHook`（Frida/Xposed 检测）等 JNI 导出函数。
> 绕过方式：把函数头 patch 成 `mov x0,#0; ret`（arm64）→ 检测函数永远返回 0（"未调试"）。

## 组成

| 文件 | 说明 |
|------|------|
| `elfparse/elfparse.h/.c` | ELF64 .symtab/.dynsym 符号解析器（纯 C，宿主编译可测） |
| `elfdump.c` | 命令行符号查看（宿主编译，测试用） |
| `gen_test_elf.py` | 生成测试 ELF（无 NDK 环境的验证样本） |
| `patcher_jni.c` | JNI 补丁模块（模式 A 同进程 / 模式 B ptrace） |
| `ptrace_patcher_cli.c` | 命令行 ptrace 补丁器（真机 root 用） |

## 宿主编译验证（Windows）

```powershell
# 1. 生成测试 ELF
python gen_test_elf.py test_lib.so
# 2. 编译 elfdump
cl /I elfparse elfparse\elfparse.c elfdump.c /link /SUBSYSTEM:CONSOLE /OUT:elfdump.exe
# 3. 验证符号解析 (JNI 导出在 .dynsym)
elfdump.exe test_lib.so Java_com_prot_demo_Prot_nativeIsDebugged
```

## 真机部署（Android, 需 NDK + root）

```bash
# 1. NDK 编译 (CMake): patcher_jni.c + elfparse.c -> libpatcher.so
#    JNI 类: com.prot.demo.Patcher { nativePatchSelf, nativePatchRemote }
# 2. 同进程模式 (免 root):
#    System.loadLibrary("patcher");
#    new Patcher().nativePatchSelf("/data/app/.../lib/arm64/libprot.so",
#                                  "Java_com_prot_demo_Prot_nativeIsDebugged");
# 3. ptrace 模式 (root, 命令行):
#    adb root
#    ./ptrace_patcher_cli <pid> /data/app/.../lib/arm64/libprot.so \
#        Java_com_prot_demo_Prot_nativeIsDebugged 0
```

## 实证结果（宿主编译验证）

- ELF 符号解析器：**6/6 符号命中**（.symtab + .dynsym），JNI 导出定位正确；
- 待真机：同进程 patch / ptrace 附加（需 NDK/真机环境，见 EXTENSION_PLAN T1）。

## 与 Windows 侧对照（已实证）

| 项 | Windows (WinPE-SymPatcher) | Android (本工具) |
|----|---------------------------|-------------------|
| 符号解析 | MAP 文件 + PE 导出表 + COFF | ELF .symtab/.dynsym |
| 定位目标 | prot_antidebug_detected 等 | nativeIsDebugged 等 |
| 写入方式 | OpenProcess + WriteProcessMemory | process_vm_writev / ptrace |
| 实证结果 | **patch 判定函数 → 盾失效**（clean） | 宿主编译就绪，真机待测 |
