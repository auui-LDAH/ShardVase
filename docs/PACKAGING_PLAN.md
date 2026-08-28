# 接入向导（P0）计划 — 第三方开发者低门槛集成保护 (PACKAGING_PLAN)

> 版本：2026-08-28 v2 · 状态：**✅ 已实施（真机端到端验收通过）** ·
> v1 规划；实施记录见第 8 节。
> 定位：商业化 P0
> （市场分析结论：主攻"中小工具软件 + 企业内部工具"，综合覆盖率
> 85-90%；最大门槛是接入向导/文档而非保护能力本身）。
> 关联：`docs/THREATMODEL.md`、`sdk_service/`（授权签发体系）、
> `src/`（保护核心）、`demo/`（当前唯一接入样例）。

---

## 1. 背景与目标

### 1.1 现状：保护能力成熟，接入方式只有一个"demo 式样"
完整的保护链（VM/自加密/反调试/完整性/授权绑定）全部围绕 `demo/main.c`
这块"业务壳"存在：想保护自己的程序，目前只能照 demo 抄一份——业务耦合、
复制门槛高、无向导。签发侧已有 GUI（issue_console），**接入侧缺同样体验**。

### 1.2 目标
1. 把保护层从 demo 业务中**剥离成可移植 SDK 骨架**（保护层与业务层解耦）；
2. 提供**向导**（GUI，沿用 tkinter 风格）：输入业务代码 → 一键产出
   受保护 exe（含授权验签 + 公钥嵌入 + smoke 自检）；
3. 产出面向开发者的 **QUICKSTART（3 步接入）** 文档；
4. 以"全新空工程"做端到端验收：5 分钟内出受保护 exe。

---

## 2. 方案设计

### 2.1 分层（保护 SDK = 后果持久结构）

```
prot_sdk/                     # 新增: 可移植保护 SDK（由向导生成/复用）
  core/                       # 现有 src/*.c + include/protect/*.h（通用，不改）
  skeleton/                   # 模板工程（核心新增）
    app_main_template.c       # 业务壳骨架: 授权门 + 受保护业务入口桩
    protect_init.c            # 装配: 反调试/完整性/watchdog 启动序列
    placeholder_vm.c          # 业务 VM 区块占位（后续由向导替换）
    build.ps1（向导生成版）   # 由向导填充密钥/路径后落盘
  wizard/                     # 接入向导（tkinter)
    prot_wizard.py            # 主程序（沿用 issue_console 风格）
```

关键原则：**只动"壳"不动"核"** —— core 与现有 release gate 共用同一套
源码，保护强度零回归；向导只生成壳与装配代码。

### 2.2 向导流程（GUI 步骤）
| 步 | 输入 | 动作 |
|----|------|------|
| 1 选工程 | 业务源码目录 / 或"仅生成骨架" | 生成骨架工程（含业务入口桩）|
| 2 选密钥 | 公钥 blob（从服务器 pub-blob.c）或临时 keygen | 嵌入公钥文件 |
| 3 配置 | serial 方案（固定/每客户）/ 试用参数 | 写 vm_build.json/配置 |
| 4 构建 | 调 build 流水线 | 产出受保护 exe + vm.blob + smoke |
| 5 交付清单 | — | 输出打包清单（exe/vm.blob/license 说明）|

### 2.3 序列号与授权方案（对齐现有机制）
- license 机制、machine 绑定、tier/expires：全复用现有（零改动）；
- 序列号初始化：向导生成 `vm_build.json`（serial 模板）+ 文档说明
  "正式发售时按客户用 genserial 生成专属期望"（如实记录：当前 demo 与
  骨架均用固定 serial 教学形态，每客户专属 serial 需按 EXTENSION 路径做）。

### 2.4 决策点
| 编号 | 决策 | 选项 | 推荐 |
|------|------|------|------|
| D1 | 业务接入形态 | ① 骨架模板（业务函数从桩开始写，宿主编译该函数受保护）② 现有函数原地标注受保护（需源码变换工具，工作量大） | **① 骨架模板**（诚实：VM 保护需要指导编译，全自动变换不现实）|
| D2 | 向导语言 | tkinter 中文 GUI / 纯脚本 | **tkinter GUI**（与签发台一致）|
| D3 | 向导产出物 | 新工程目录 / 覆盖 demo | **新工程目录**（demo 保持为参考/回归锚）|
| D4 | 骨架保护范围 | 全特性（VM+N3+watchdog）简配（仅授权+反调试） | **全特性默认，提供 -Lite 开关**（简配用于内部工具场景）|
| D5 | 验收标准强度 | 仅 smoke / smoke+攻防回归 | **smoke + 本机关键攻防快速回归（A 类 5 项）** |

---

## 3. 实施步骤

| 步骤 | 内容 | 工作量 |
|------|------|--------|
| 1 | 骨架工程：从 demo 剥离业务 → `prot_sdk/skeleton`（保留全部保护装配）| 1 天 |
| 2 | 向导 `prot_wizard.py`（步骤 1-5 + 生成 build 脚本）| 1 天 |
| 3 | QUICKSTART.md + README 更新（目标群体视角的 3 步接入）| 0.5 天 |
| 4 | 端到端验收：全新空工程 → 向导 → 受保护 exe → 授权闭环 | 0.5 天 |
| 5 | 防御回归：骨架产物跑 A1-A5 快速回归 + release gate | 0.5 天 |
| **合计** | | **3.5 天** |

## 4. 验收标准
1. 全新空工程（含两个业务函数的 C 文件）经向导 ≤5 分钟产出受保护 exe；
2. 该 exe 通过授权闭环（服务器签发 → 允许运行；无 license/错机/过期 → 拒）；
3. 保护链 smoke 自检 PASS（反调试/完整性/blob/授权）；
4. 快速攻防回归 A 类 5 项（注入/伪造/替换/机器绑定/时序）不弱于 demo 基线；
5. QUICKSTART 文档 3 步可复现。

## 5. 风险与回退
| 风险 | 缓解 |
|------|------|
| 骨架剥离引入回归 | 步骤 5 强制回归；core 不做任何修改 |
| 全自动变换不现实（D1）| 已按骨架模板定位，诚实记录边界 |
| 向导代码膨胀 | 复用 issue_console 组件；单一文件内聚 |

**回退**：P0 全新增目录（prot_sdk/ + 文档），删除即回退；不动 core/src。

## 6. 实施记录与待办（v2）

### 6.1 实施记录（2026-08-28）

- 骨架：`prot_sdk/skeleton`（app_main.c 从 demo 剥离业务，保留全保护链；
  prot_shell.h 定义业务回调；business_stub.c 模板；授权 vasm 复制进工程）
- 向导：`prot_sdk/wizard/prot_wizard.py`（GUI；generate/build 可无头调用）
- 构建：`build_skeleton.ps1`（参数化流水线；new 模式自签+全 smoke；
  pub 模式产出"待签发 vm.blob"，发布前由签发方补签）
- 排障记录：PS5.1 param 默认值不能用函数调用；ps1 中文需 UTF-8 BOM；
  `-DNAME="x"` 经 cmd 丢失引号 → 字符串化宏 APP_EXE_NAME_STR 解决；
  selfcrypt_proto.py 增 `--mask-out`（向后兼容）；blob 必须与 license
  同私钥签名（D1a 强制 v1，骨架明确 pub 模式补签流程）
- 端到端验收（真机 my_tool）：
  - new 模式：构建 → smoke PASS（license:1 + business 执行）
  - pub 模式：服务器补签 vm.blob + 签发 license → 真机 `license: 1` + 业务执行
  - 防御快速回归：serial/tier/空签篡改全拒（与 demo 基线行为一致）
  - 向导 GUI 冒烟 OK

### 6.2 待办
- [x] 拍板 D1-D5
- [x] 步骤 1-2：骨架 + 向导（`prot_sdk/`）
- [x] 步骤 3：QUICKSTART.md + prot_sdk/README.md
- [x] 步骤 4-5：真机端到端验收 + 防御快速回归
  （深层攻防矩阵沿用 ATTACK_DRILL 各轮；业务函数体 VM 化与
  每客户专属序列号列为后续扩展）