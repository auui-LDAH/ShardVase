# prot_sdk — 保护接入 SDK (P0)

第三方开发者把整套保护接入自己的 Windows x64 C 程序。
（demo/ 仍为参考实现与回归锚；prot_sdk 是与业务解耦的接入层。）

## 组成

```
prot_sdk/
  skeleton/               骨架模板 (向导复制到工程)
    app_main.c            保护壳入口 (装配反调试/完整性/watchdog/VM/授权门)
    prot_shell.h          壳 <-> 业务接口 (prot_business_ctx / prot_business_main)
    business_stub.c       业务模板 (用户的起点)
    license_*.vasm        授权 VM 链 (hash/mix/verify/gate, 复制进工程)
    strings.txt           文案 (BANNER 等, strgen 生成 strings.c)
    version.rc            版本资源模板
    build_skeleton.ps1    构建流水线 (读 build-skeleton.json)
  wizard/
    prot_wizard.py        接入向导 (tkinter GUI; generate_project/build_project 可无头调用)
  QUICKSTART.md           3 步接入文档
```

## 保护链（骨架 = 与 demo 同源，不改 core）
- N1 自解密引擎（VM 函数原位加密 + 活动窗口密文化）
- 反调试多因子 + 反 DBI/hook + 虚拟机检测（Lite 模式隐藏咨询提示）
- 完整性自检 .text/.rdata/.pdata + watchdog 周期复查（含 N3 冗余+dbiguard 复查）
- VM blob 装载（签名强制 v1）+ revoke 黑名单 + 可选在线查询
- 授权门：机器绑定 RSA-3072 + tier/expires + VM#1-4 判定链
- 业务接入：授权门通过 → `prot_business_main(ctx)`

## 密钥与授权模型
| 模式 | 用途 | 说明 |
|------|------|------|
| `new` | 开发/演示 | 构建自动 keygen + 自签 license + 全 smoke |
| `pub` | 正式 | demo 内嵌签发方公钥；license 与 vm.blob 均由签发方私钥产出 |

发布流程：客户 `.req` → 签发台/服务器签发 `license.txt` + 补签 `vm.blob`
→ 客户离线运行。

## 验收记录（2026-08-28，真机）
- 全新工程 `my_tool`：向导生成 → 构建（new 模式 smoke PASS：
  license:1 + business 执行）→ pub 模式 + 服务器补签/签发 →
  真机运行 `license: 1` + 业务执行 ✓
- 防御回归：serial/tier/空签篡改全拒，与 demo 基线行为一致
- 快速回归 A 类语义等价 demo；深层攻防矩阵见 docs/ATTACK_DRILL.md + 5/6 轮

## 已知边界（诚实，与 THREATMODEL 一致）
- 安装目录防写是硬前提（L3 公钥替换）；EXPIRES 本地时钟（L4 回拨）
- 业务函数体本身的 VM 保护需按 vasm 文档扩展（当前 VM 链保护授权判定）
- 序列号模板为单一常量；"每客户专属序列号"需按 EXTENSION 路线设计