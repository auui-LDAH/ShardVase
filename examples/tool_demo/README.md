# 接入示例 — 把你的工具接入保护套件 (tool_demo)

一个"文件加密小工具"演示如何用本套件保护**你自己的工具**。构建产物:
`build\tool_demo.exe` + `build\tool_vm.blob`(exe 内无 VM 逻辑,断源)。

## 它展示了什么

| 保护层 | 机制 | 在示例里的位置 |
|--------|------|----------------|
| 校验逻辑进 VM | `check.vasm` 被加密汇编,静态不可读 | `examples/tool_demo/check.vasm` |
| 断源 | VM 镜像打包为 `vm.blob`,启动时装载 | `build_example.ps1` 步骤 2-3 |
| 授权门 | RSA license + 机器绑定 + 试用期(expires) | `main.c` `verify_license_file()` |
| 防篡改 | .text/.rdata/.pdata CRC + 看门狗 | `main.c` 步骤 2 |
| 反调试 | 完整 antidebug 扫描 | `main.c` 步骤 1 |
| 吊销 | revoke.blob 黑名单 | `main.c` 步骤 8 |

## 如何接入你自己的工具(三步)

### 1. 把你的"关键校验逻辑"写成 .vasm

模仿 `check.vasm`:定义宿主内存布局(serial/result/中间值),
用指令表(docs/CONTRACT.md §4.2)写校验算法。
示例:FNV-1a(serial) → xorshift → 与期望值比对。

```asm
; 你的工具: 注册码校验
; 读 host.serial, 算 hash, 与 EXPECT 比对 -> host.result
```

### 2. 在工具源码里调用保护库

```c
#include "protect/vm.h"          /* prot_vm_run */
#include "protect/license.h"     /* RSA 验签 */
#include "protect/integrity.h"   /* 防篡改 */
#include "protect/antidebug.h"   /* 反调试 */
#include "protect/revoke.h"      /* 吊销 */
#include "protect/blob.h"        /* vm.blob 装载 */

/* 启动流程 (见 main.c 完整实现):
 * 1. prot_antidebug_scan -> detected? 退出
 * 2. prot_integrity_check_self -> 失败? 退出; 启动看门狗
 * 3. prot_vm_blob_load("vm.blob") -> 装载 VM 镜像
 * 4. 组装宿主内存 (serial + machine_id)
 * 5. (可选) license 验签: prot_license_build_message + prot_license_verify
 * 6. prot_vm_run(&img, &mem, sizeof(mem)) -> 校验在 VM 内执行
 * 7. mem.result 非 0 才允许使用业务功能
 */
```

### 3. 构建管线 (照抄 build_example.ps1)

```
genserial (算期望值) -> keygen (RSA 公钥) -> assemble (加密 .vasm)
-> pack (vm.blob) -> cl (工具源码 + src/*.c 链接) -> hashpatch (CRC 烧录)
-> 冒烟
```

## 运行示例

```powershell
powershell -ExecutionPolicy Bypass -File examples\tool_demo\build_example.ps1

# 授权通过: 加密/解密文件
build\tool_demo.exe --serial DEMO-2026-ABCDEFGH --vm-blob build\tool_vm.blob --encrypt somefile
# 错误序列号: 拒绝
build\tool_demo.exe --serial WRONG-123 --vm-blob build\tool_vm.blob --encrypt somefile
# 带 RSA license (可选门): 先签 license
python tools\vmenc.py sign --key build\keys\license_priv.json --json demo\vm_build.json --out build\license.txt
build\tool_demo.exe --serial DEMO-2026-ABCDEFGH --license-file build\license.txt --vm-blob build\tool_vm.blob --encrypt somefile
```

## 生产注意

- **每工具独立** serial/json/种子(vm_build.json 与 build/seeds.json 按工具归档,
  见 docs/OPS.md §4 客户台账)
- 保护重点是**授权校验 + 1-2 个核心功能开关**;整个工具搬进 VM 成本高、
  性能损失大,不建议
- GUI/插件体系:授权逻辑抽成独立 native DLL(本示例为单 exe 简化形态),
  各插件调用同一授权实例
- 更多接入细节:docs/RELEASE.md(构建/签名/可复现)、docs/OPS.md(签发/吊销/密钥)
