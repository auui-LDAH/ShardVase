# 从零到受保护 exe —— 15 分钟上手（含实测计时）

> 面向**第一次接触本项目**的开发者。全部数字为 2026-09-20 在本机实测，
> 不是估计值。机器部分总耗时约 **17 秒**；其余时间是你在读文档和写代码。

---

## 时间预算（先看这个）

| 环节 | 谁来做 | 实测/预估 |
|------|--------|-----------|
| 读本文 + 选拼装图 | 你 | ~2 分钟 |
| 生成工程 | 机器 | **0.03 秒** |
| 写业务逻辑 | 你 | ~10 分钟（取决于复杂度） |
| 构建 + 自检 | 机器 | **16 秒** |
| 验证运行 | 机器 | **0.6 秒** |
| **合计** | | **机器 <17 秒，其余是人工** |

> **为什么强调这个**：实测确认瓶颈**不在构建**（只有 16 秒）。
> 所以如果你觉得慢，问题通常出在"不确定该写什么/选哪个拼装图"——
> 本教程就是为了消除这部分。

---

## 前置条件（一次性）

| 需要 | 验证命令 | 若缺失 |
|------|----------|--------|
| Python 3.8+ | `python --version` | 装 Python |
| VS2022 C++ 生成工具 | 见下 | 装 VS2022 BuildTools，勾选「使用 C++ 的桌面开发」 |

```powershell
# 验证 VS2022 是否就绪（任一路径存在即可）
Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

构建脚本会自动探测 vcvars；探测不到会给出明确提示与处理办法。

---

## 第 1 步：生成工程（机器 0.03 秒）

```powershell
python prot_sdk\wizard\prot_wizard.py
```

在向导里填 4 项：

| 字段 | 填什么 |
|------|--------|
| 工程目录 | 一个**新建空目录** |
| 产品名 / exe 名 | 你的程序名，如 `myapp` |
| 序列号模板 | 保持默认 `DEMO-2026-ABCDEFGH` 即可（本地开发用） |
| 拼装图 | 首次建议 **`standard`**（见下） |

### 拼装图怎么选（唯一需要动脑的地方）

| 拼装图 | 编译模块 | 什么时候选 |
|--------|----------|------------|
| `minimal` | 8（只有授权链） | 你已有别的保护手段；或对启动开销极敏感 |
| **`standard`** | 11（+反调试/完整性/自加密） | **默认选这个**，覆盖绝大多数场景 |
| `hardened` | 13（+DBI/VM 检测/函数间接化） | 软件价值高，能接受更高误报率 |
| `full` | 13（含已知冲突） | 仅供演示组合校验，**别用它做发布** |

> 未选中的模块**既不编译也不链接**（不是空桩）—— 产物更小、攻击面更少。
> 想确认某个组合是否自洽：`python tools\modcheck.py --compose standard`

点【生成工程】。

---

## 第 2 步：写业务（人工，约 10 分钟）

工程目录里会有一个 `business_<app>.c`，**只改这个文件**：

```c
#include <stdio.h>
#include "prot_shell.h"

int prot_business_main(const prot_business_ctx* ctx)
{
    /* 可用的授权信息 */
    printf("my-app: tier=%u expires=%u\n",
           ctx->license_tier, ctx->license_expires);

    /* 按授权等级开功能 */
    if (ctx->license_tier >= 1) {
        printf("pro feature unlocked\n");
    }
    return 0;   /* 0 = 业务正常结束 */
}
```

`ctx` 里有什么：

| 字段 | 含义 |
|------|------|
| `ctx->serial` | 用户输入的序列号（字符串） |
| `ctx->machine_id` | 本机机器标识 |
| `ctx->license_tier` | 授权等级：0 试用 / 1 正式 / 2 增值 |
| `ctx->license_expires` | 到期 Unix 时间，0 = 永久 |

> ⚠️ **不要改 `app_main.c`** —— 那是保护壳，升级时会覆盖你的改动。
> 所有业务逻辑都写在 `business_<app>.c` 里。

---

## 第 3 步：构建（机器 16 秒）

```powershell
powershell -File <工程>\build_skeleton.ps1 -Project <工程>
```

正常输出结尾：

```
build_skeleton: composition 'standard' — 13 源文件
build_skeleton: smoke output: ... license: 1 ... | my-app: tier=1 ...
build_skeleton: smoke PASS (license gate passed)
build_skeleton: DONE -> <工程>\build
```

产物：`<工程>\build\myapp.exe`（实测 231384 字节）+ `vm.blob`。

### 实测结果（本教程跑通的完整链路）

```
1. 生成工程 (机器)   : 0.03 秒
2. 写业务 (人工)     : 取决于你（本例 15 行）
3. 构建 + smoke (机器): 16.14 秒   rc=0
4. 验证运行 (机器)   : 0.64 秒    exit=0
     输出: my-app: tier=1 expires=0
           pro feature unlocked
```

---

## 第 4 步：交付（`pub` 模式才需要）

上面用的是 `new` 模式（本地密钥 + 自签），**只适合开发**。对外交付要走签发体系：

1. 向导里选「引用正式公钥」并指向签发方的 `pub-blob.c`
2. 构建产物的 `vm.blob` **未签名**，须由签发方补签（见 `QUICKSTART.md`）
3. 客户拿到 `exe + vm.blob` 后，用 `req_gen.py` 生成 `.req` 申请授权
4. 签发方回发 `license.txt`

---

## 出错了怎么办

构建脚本会给出**可操作提示**，而不只是报错。常见三类：

### 1. 编译/链接失败

```
build_skeleton FAILED: cl (编译/链接)
可能原因与处理:
  1. 若报 "无法解析的外部符号 prot_xxx": 拼装图与调用不匹配。
     运行 `python tools\modcheck.py --compose <你的拼装图>` 查看组合自洽性。
  2. 若报 "无法打开包括文件": 业务代码缺 #include, 或仓库路径变化。
  3. 若报 C2220 (警告被视为错误): 你的业务代码有警告; /W4 /WX 下警告即错误。
```

### 2. `hashpatch SKIPPED`

```
build_skeleton: hashpatch SKIPPED (组合不含 integrity, 无 .protcrc 段)
```

**这是正常的**，不是错误。`minimal` 组合没有完整性校验模块，自然没有 CRC 要烧录。

### 3. `selfcrypt_proto: skipped N target(s)`

**这也是正常的**。所选拼装图不含某些被加密的模块（如 `integrity`/`antidebug`），
它们的函数不在 `.map` 里，所以跳过加密。`full` 组合会用 `--require-all` 严格校验。

### 其它

| 现象 | 原因与处理 |
|------|-----------|
| `license: 0` | license 与机器不匹配。换机后属正常：删掉 `<工程>\vm_build.json` 和 `gen\` 后重建 |
| `VM 镜像装载失败` | `vm.blob` 缺失/损坏，检查 `<工程>\build\vm.blob` |
| WinError 4551 被拦 | 本机启用了 WDAC 企业签名策略（与保护无关）；换无策略环境，或配置 `codesign.pfx` |
| 进程不退出 | 看门狗/反调试误判；试 `-Composition minimal` 隔离定位 |

---

## 退出码约定

| 码 | 含义 |
|----|------|
| `0` | 业务正常结束 |
| `1` | 授权无效（序列号错 / 签名不匹配 / 异机） |
| `0xDB` (219) | 检测到调试环境 |
| `0xBAD` (2989) | 完整性校验失败（被篡改） |
| `0xB10B` | VM blob 缺失/损坏 |
| `0xB1E4` | 授权已被吊销 |

---

## 已知边界（诚实说明）

| 边界 | 说明 |
|------|------|
| 到期依赖本地时钟 | 可回拨绕过；商业版需在线时间锚点 |
| 安装目录须防写 | 否则攻击者能替换公钥自授权（部署时用 ACL 只读） |
| 用户态限制 | 无法防内核级攻击 |
| 撤销非实时 | 依赖黑名单分发 |

完整列表见 `publish/06-诚实边界.md`。

---

© ShardVase · 接入教程 · 2026-09-20
