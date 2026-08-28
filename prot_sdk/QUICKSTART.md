# QUICKSTART — 3 步接入保护（面向开发者）

> prot_sdk 让任意 Windows x64 C 程序接入全套保护（VM 混淆/反调试/完整性/
> RSA-3072 机器绑定授权）。全程约 5 分钟，无需理解内部实现。

## 准备
- Windows x64 + VS2022（C++ 工作负载）+ Python 3.8+
- 本仓库（`tools/`、`src/`、`include/` 会被复用）

## 第 1 步：生成工程

```powershell
python prot_sdk\wizard\prot_wizard.py
```
- **选择工程目录**（新建空目录）
- 填产品名 / exe 名 / 序列号模板（默认 `DEMO-2026-ABCDEFGH`）
- 密钥模式二选一：
  - `新密钥（开发/演示）` —— 构建自动生成密钥并自签，可立即跑通
  - `引用正式公钥` —— 选签发方的 `pub-blob.c`，授权由签发体系下发（仅你）
- 点【生成工程】

## 第 2 步：写业务

编辑工程里自动生成的 `business_<app>.c`，在 `prot_business_main(ctx)` 中
写你的业务逻辑：

```c
int prot_business_main(const prot_business_ctx* ctx) {
    /* ctx->serial / ctx->machine_id / ctx->license_tier(0/1/2) /
       ctx->license_expires 可用 */
    if (ctx->license_tier >= 2) { /* 高级版功能 */ }
    return 0; /* 业务正常结束 */
}
```
注意：**别改 app_main.c**（保护壳）；业务冷启动函数可用 `strings.txt`
显示文本（BANNER 可改）。

## 第 3 步：构建 + 运行

```powershell
powershell -File <工程>\build_skeleton.ps1 -Project <工程>
```
- `new` 模式：自动 smoke，看到 `business:` 输出 = 全链路通过
- `pub` 模式：产物 `vm.blob` **未签名**，下发前由签发方补签：
  ```bash
  # 服务器（签发方）
  python3 tools/vmenc.py pack --sign sdk_service/keys/prot-priv.json \
      --out vm.blob vm_hash_blob.bin vm_mix_blob.bin vm_verify_blob.bin vm_gate_blob.bin
  ```
- 交付物：`build\<app>.exe` + 补签后的 `vm.blob`（+ 可选 `revoke.blob`）
- 授权：客户运行 `req_gen.py` 生成 `.req` → 签发方发回 `license.txt` →
  客户 `--license-file license.txt` 启动（或产品集成默认路径）
  序列号在启动时输入（首行）

## 常见问题
- **WDAC/企业签名拦截**（WinError 4551）：本机若启用了 WDAC 企业签名
  策略，全新 exe 会被拦（与保护无关）；用真机/无策略环境验收，或配置
  `build\keys\codesign.pfx` 走自动签名。
- **退出码**：0 业务正常 / 1 授权无效 / 0xDB 调试环境 / 0xBAD 被篡改。
- **Lite 模式**：内部工具场景隐藏"疑似 hook/虚拟机"咨询提示
  （向导勾选，保护强度不变）。
- 已知边界（诚实）：EXPIRES 依赖本地时钟（可回拨）；安装目录须防写
  （否则攻击者能换公钥自授权）；blob 与 license 只能由签发方私钥产生。