# 高级能力路线图 (ADVANCED)

> 版本：2026-08-20 v1 · 定位：补齐与成熟产品(VMProtect/Themida 类)的三大差距——
> **自动虚拟化 / 反虚拟机·反沙箱 / 自动混淆**。用户已确认接受开发量，按里程碑
> 慢慢推进。本文件是这三项的实施计划（技术路线、里程碑、验收、风险）。
> 关联：`docs/BUSINESS.md`（总纲）· `docs/CONTRACT.md`（VM 指令集/契约）·
> `docs/tool_demo/README.md`（现有手动虚拟化接入方式）。

## 1. 背景与目标

| 短板 | 现状 | 目标 |
|------|------|------|
| 虚拟化是手动的 | 校验逻辑需手写 `.vasm` 汇编（门槛高、易错） | 写**类 C 代码**自动编译成 VM 字节码（`vmc` 编译器） |
| 无反 VM/反沙箱 | 攻击者可在 VM 里分析 | 新增 VM/沙箱检测层（咨询项策略） |
| 无自动混淆 | VM 字节码结构固定 | 编译期**控制流平坦化** + 栈布局随机化 |

**定位说明**：不追求 LLVM 级"拖入 exe 自动虚拟化任意函数"（数月工程且稳定性风险高）；
我们的路线是**"类 C 迷你编译器 + 平坦化"**，覆盖用户真实场景（授权校验/功能开关），
且与现有 VM 引擎、加密、断源、每构建随机化完全兼容。

## 2. 里程碑总览

| 里程碑 | 内容 | 工作量 | 依赖 |
|--------|------|--------|------|
| **M1 反 VM/反沙箱** | CPUID/厂商串/I/O 端口/进程四类检测，咨询项接入 demo selftest | 1-2 天 | 无 |
| **M2 vmc 类 C 编译器** | 类 C 语法 → VM 字节码；单测与 tool_demo 示例改造 | 5-7 天 | 无 |
| **M3 自动混淆** | vmc 输出层控制流平坦化 + 栈布局随机化 | 3-5 天 | M2 |

> 顺序：M1 最快见效先行；M2 是核心价值；M3 叠加在 M2 输出层。
> 每里程碑独立可验收、可回退。

## 3. M1 — 反 VM/反沙箱检测（1-2 天）

### 3.1 检测项（全部咨询项，只报告不触发策略）
| 项 | 机制 | 实现 | 状态 |
|----|------|------|------|
| cpu_hypervisor | CPUID.1:ECX bit31（hypervisor present） | MSVC `__cpuid` | ✅ |
| hv_vendor | CPUID.0x40000000 厂商串：Microsoft Hv / KVMKVMKVM / VMwareVMware / VBoxVBoxVBox / XenVMMXenVMM / prl hyperv | `__cpuid`，映射枚举 | ✅ |
| ~~vmware_io / vbox_io~~ | ~~I/O 端口 0x5658/0x5659 回显~~ | **已移除**：真机实测 `IN` + VEH 在异常分发层触发死循环（Rip 修正后仍挂起），风险不可控 | ❌ 移除 |
| vm_processes | vmtoolsd.exe / vmwaretray.exe / VBoxService.exe / VBoxClient.exe / qemu-ga.exe / xenservices.exe / prl_tools.exe | `CreateToolhelp32Snapshot` 遍历进程名 | ✅ |

### 3.2 接入
- 新文件 `src/vmdetect.c` + `include/protect/vmdetect.h`（report 结构 + scan + suspicious）。
- demo `--selftest` 输出追加 5 个字段；`prot_vmdetect_suspicious` 结果作为**咨询项**
  打印一行（"疑似虚拟机环境"），不退出、不伪造（与 antidebug 咨询项同策略）。
- 构建：build.ps1/tool_demo 链接 vmdetect.c。

### 3.3 验收
- 本机（物理机）selftest 5 项全 0；
- 任一 VM 环境（真机上的 Hyper-V/VMware 客户机）至少 1 项非 0；
- e2e T7/selftest-clean 断言字段全 0（本机）不回归。

## 4. M2 — vmc 类 C 迷你编译器（5-7 天）

### 4.1 目标
`tools/vmc.py`：把"类 C 的校验函数"编译成现有 VM 字节码（`vmenc.py` 的指令集），
替代手写 `.vasm`。tool_demo 的 `check.vasm` 用 vmc 源码重写作为示例。

### 4.2 支持语法（受限 C 子集）
```
// 单函数; 参数/局部变量为 uint64
uint64 check(uint64 h, uint64 serial) {
    uint64 i = 0;
    uint64 sum = 0;
    while (i < 20) {
        sum = sum + serial_byte(i);   // 调用宿主内存读取(内置函数)
        i = i + 1;
    }
    if (sum == 0x1234) { return 1; }
    return 0;
}
```
- 类型：`uint64`/`uint32`（内部统一 64 位栈机语义，32 位截断由编译器插入掩码）
- 语句：`uint64 v = expr;` / `v = expr;` / `if (cond) {...} else {...}` /
  `while (cond) {...}` / `return expr;` / `{}` 块
- 表达式：字面量（dec/0x/0b）、变量、二元 `+ - * / % ^ & | << >>`、比较 `== != < <= > >=`、
  逻辑 `&& || !`、括号
- **内置函数**（与宿主内存/VM 契约交互）：
  `mem8(addr)`/`mem32(addr)`/`mem64(addr)`（读宿主内存）、`load(addr)`=mem64、
  可扩展（如 `fnv1a_byte()` 等预置密码学原语）
- 注释 `//` 与 `/* */`

### 4.3 编译流程
```
vmc.py check.vmc check.json check.vasm
  -> 词法/语法分析 (递归下降, 无第三方依赖)
  -> 语义检查 (未定义变量/类型/常量折叠)
  -> 代码生成: 栈机指令 (与 vmenc.py INSTRUCTIONS 完全对齐)
  -> 输出 .vasm (文本) 供 vmenc.py assemble 加密打包
```
- **控制流**：if/while → 标签 + jz/jnz/jmp（M3 再平坦化）；
  短路 `&& ||` → 临时标签。
- **栈机约定**：与现有指令集一致（push/load/store/算术/比较/跳转）。
- **确定性**：同一输入 → 同一 .vasm（可复现构建兼容）。

### 4.4 测试
- `tests/vmc_cases/*.vmc` + 期望值表（Python 单测：`vmc.py --self-test` 逐例验证
  编译输出与参考结果）。
- 端到端：tool_demo 改用 vmc 源码 → 构建 → E1-E7 全绿。
- 边界：除零、移位 ≥64、栈深、未定义变量、类型错误 → 编译期报错。

### 4.5 验收
- 支持语法全覆盖的单测 PASS；
- tool_demo 用 vmc 重写后 E1-E7 不回归；
- 编译产物可被现有管线（assemble→pack→运行）完整消费。

## 5. M3 — 自动混淆：控制流平坦化 + 栈随机化（3-5 天）

### 5.1 控制流平坦化（CFG flattening）
- 在 vmc 输出层（.vasm 生成时）把函数控制流改造为：
  ```
  entry: 初始化 dispatch 变量 state=0
  loop:  push state; jmp dispatcher
  dispatcher: 查表/比较 -> 各基本块
  基本块: 执行原逻辑, 末尾重写 state 并跳回 loop
  ```
- 基本块划分：按 if/while 的跳转边界切块；state 用哈希/异或混淆（非 0/1/2 明文）。
- 注意与现有 VM 窗口/回跳兼容（现有引擎支持回跳重绕密钥流 ✓）。

### 5.2 栈布局随机化
- 编译期随机化变量到栈槽位的映射（seed 参数，每构建不同）；
- 与"每构建随机化"哲学一致，同 vmc 源码不同 seed → 不同字节码。

### 5.3 验收
- M2 全部测试在平坦化开启/关闭下均通过；
- 开启平坦化的字节码与关闭的**结构完全不同**（构建指纹断言）；
- tool_demo E1-E7 不回归。

## 6. 风险与边界（诚实面）

| 项 | 说明 | 缓解 |
|----|------|------|
| 反 VM 误报 | 合法用户跑在 VM 里 | 咨询项策略（默认只报告）；可配置从严 |
| vmc 是受限子集 | 不支持任意 C（指针/结构体/递归等） | 覆盖校验类逻辑足够；LLVM 级列为远期（不承诺） |
| 平坦化性能 | dispatch 循环开销 | 保护函数规模小（校验逻辑），可接受 |
| 平坦化可读性 | 状态机模式可被脚本识别 | 与现有引擎随机化/加密叠加，整体成本仍高 |
| 兼容性 | 新字节码模式需 VM 引擎回归 | 每里程碑全量 verify |

## 7. 工作量与节奏

| 里程碑 | 估计 | 备注 |
|--------|------|------|
| M1 反 VM | 1-2 天 | 独立交付 |
| M2 vmc | 5-7 天 | 核心价值 |
| M3 平坦化+栈随机 | 3-5 天 | 依赖 M2 |
| 回归/文档 | 1-2 天 | 随里程碑 |

> 总计约 2 周（断续推进则按月计）。每里程碑完成即提交 + 更新本文档状态。

## 8. 状态跟踪

| 里程碑 | 状态 | 完成日期 |
|--------|------|---------|
| M1 反 VM/反沙箱 | ✅ 完成（CPUID/厂商串/进程；I/O 端口因真机异常死循环移除） | 2026-08-20 |
| M2 vmc 编译器 | ✅ 完成（类 C 子集→VM 字节码；单测 9 项全绿；tool_demo 改用 check.vmc） | 2026-08-20 |
| M3 控制流平坦化 | 未开始 | — |
