# 模块宿主钩子协议（Host Hook Protocol）— 设计

> **目标**：破掉 BLUEPRINT §3.4.3 **边界①** ——
> "加模块须改宿主源码（`demo/main.c` + `app_main.c` 各加 `#ifdef`），
> 不能动态插拔"。
>
> **状态**：设计 + 最小验证（**未全量实施**，见 §6 风险）
> **日期**：2026-09-23
> **关联**：`docs/MODULE_PROTOCOL_SPEC.md`、`docs/BLUEPRINT.md` §3.4.3 / §10

---

## 1. 实测起点（先看清问题）

**两处宿主各 11 个 `#ifdef PROT_MOD_*` 调用点**：

| 宿主 | 行数 | `#ifdef` 数 |
|------|------|------------|
| `demo/main.c` | 1006 | 11 |
| `prot_sdk/skeleton/app_main.c` | 1030 | 11 |

**逐块分类实测**（`demo/main.c`）：

| 类别 | 数量 | 例子 |
|------|------|------|
| **H1 纯调用** | **4** | `prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000);` |
| **H2 含宿主决策** | **7** | `if (prot_dbiguard_suspicious(&drep)) return PROT_ERR_INTEGRITY;` |
| H3 结构性 | 0 | —— |

### 1.1 关键洞察：**H2 不是障碍，而是揭示了正确的分离**

我最初把 H2（含宿主决策）看作"无法声明化"的障碍。但仔细想：

> **`if (suspicious) exit(1)` 是【产品的策略】，不是【模块的能力】。**

模块应该声明：**我检测什么、我在哪个时机被调用、我报告什么**。
宿主应该决定：**检测到之后怎么办**（退出/警告/继续）。

**这两件事本就不该混在一起** —— 混在一起才是当前设计的问题：
每个模块的 `#ifdef` 块里都**重复**写了一遍宿主的策略逻辑。

---

## 2. 设计：钩子点 + 策略表

### 2.1 两侧职责分离

```
┌─────────────────────────────────────────────────────────┐
│  模块（声明侧）                                          │
│  · host_hooks: 我在哪些【钩子点】被调用                   │
│  · 报告结构: 我检测到什么（report / suspicious）          │
└──────────────────────┬──────────────────────────────────┘
                       │ 编排器生成分发代码
                       ▼
┌─────────────────────────────────────────────────────────┐
│  宿主（策略侧）                                          │
│  · 固定钩子点（只写一次 prot_host_run(HOOK_X)）           │
│  · policy 表: 每个钩点检测到异常时怎么办                  │
└─────────────────────────────────────────────────────────┘
```

### 2.2 钩子点定义（`host_hooks` 的值域）

| 钩子点 | 时机 | 现有对应调用点 |
|--------|------|--------------|
| `pre_license` | 许可证校验**之前** | `dbiguard_scan`（L161）|
| `post_license` | 校验通过**之后** | `antidebug_scan`（L511）|
| `pre_business` | 进入业务逻辑前 | `integrity_check_self`（L592）|
| `post_business` | 业务逻辑返回后 | —— |
| `watchdog` | 周期回调 | `integrity_start_watchdog`（L602）|
| `selftest` | `--selftest` 诊断路径 | `print_selftest`（L304）|
| `vm_result` | VM 执行结果后 | `antidebug_fake_active`（L979）|

### 2.3 模块侧声明（`modules.json` 新增字段）

```json
"antidebug": {
  "host_hooks": [
    { "hook": "post_license", "call": "prot_antidebug_scan",
      "report_type": "prot_antidebug_report",
      "predicate": "prot_antidebug_detected",
      "on_trigger": "exit",        // 建议（宿主可覆盖）
      "selftest": "PROT_STR_SELFTEST_PEB" },
    { "hook": "vm_result", "call": "prot_antidebug_fake_active",
      "on_trigger": "xor_vm_result" }
  ]
}
```

**字段语义**：

| 键 | 含义 |
|----|------|
| `hook` | 钩子点名（值域见 §2.2）|
| `call` | 要调用的模块函数 |
| `report_type` | 报告结构体类型（用于生成局部变量）|
| `predicate` | 判定函数（返回"是否异常"）|
| `on_trigger` | **建议**的响应（宿主可覆盖）|
| `selftest` | 自检字符串 ID（可选）|

### 2.4 宿主侧：固定钩子 + 策略表

**宿主只写一次**（不再随模块增减而改）：
```c
/* 钩子分发点 —— 由 tools/hostgen.py 生成，模块增减不改此处 */
prot_hook_result r;
r = prot_host_run_hook(PROT_HOOK_PRE_LICENSE);
if (r.triggered && PROT_POLICY_ACTION(r.action) == PROT_ACT_EXIT) {
    return r.status;
}
```

**策略表**（`policy.json`，**用户可配置，不改 C**）：
```json
{
  "pre_license":  { "on_trigger": "exit" },
  "post_license": { "on_trigger": "exit", "warn": true },
  "watchdog":     { "interval_ms": 5000 }
}
```

---

## 3. 收益与代价

### 3.1 收益

| 项 | 改动前 | 改动后 |
|----|--------|--------|
| **加模块** | 改 2 处宿主源码（各加 `#ifdef`）| **只改 `modules.json`** |
| **改策略** | 改 C 源码 + 重新编译 | 改 `policy.json` |
| **策略重复** | 每个模块块重复一遍宿主逻辑 | 集中在策略表 |
| **第三方模块** | 必须提供宿主 patch | 声明 `host_hooks` 即可 |

### 3.2 代价与风险（**必须如实记录**）

| 风险 | 说明 | 缓解 |
|------|------|------|
| **改动核心构建路径** | `demo/main.c` 是 1000 行、被 e2e/attacks/protchain 全面覆盖 | **分阶段**：先加机制，后迁移模块 |
| **页关系 P2 风险** | 排版变化可能破坏 selfcrypt 加密段与页关系 | 每阶段跑门禁 + `repro_check` |
| **间接层开销** | 钩子分发引入间接调用 | 与现有 `indirect` 一致，可接受 |
| **selfcrypt 交互** | `sc_ext_enter/leave` 包裹逻辑需保留 | 在生成的分发代码中保留 |
| **新增攻击面** | 分发函数本身可被 patch | 与其它模块同级（本就都可 patch）|

---

## 4. 最小验证（本轮做的）

**不做**全量重构（风险高）。**先做**：
1. 定义钩子点值域（§2.2）
2. 加 `host_hooks` 契约字段 + 校验规则（R19）
3. **对现有 4 个可声明模块**（antidebug/dbiguard/integrity/vmdetect）
   写 `host_hooks` 声明 —— **只声明，不改宿主**
4. 写 `hostgen.py` **原型**：从声明生成分发代码（**对照现有手写代码**）
5. **验证生成的代码与手写代码语义等价**（不替换，只比对）

> **为什么不全量实施**：宿主是**核心构建路径**，全量替换需逐模块迁移 +
> 每步门禁验证。本轮先证明"声明 -> 生成"的**语义等价**，
> 为后续替换建立**可验证的中间态**。

---

## 5. 验收判据（后续实施用）

| # | 判据 | 验证方法 |
|---|------|---------|
| V1 | 生成的钩子分发代码与手写**语义等价** | 生成后编译 + e2e 全绿 |
| V2 | **加模块不改宿主** | 新增一个测试模块，只改 `modules.json`，构建通过 |
| V3 | **改策略不改 C** | 改 `policy.json`，行为随之变化 |
| V4 | 门禁全绿 + `repro_check` 通过 | 标准门禁 |
| V5 | 排版不变（页关系保持）| `protchain P1-P6` |

---

## 6. 诚实边界

| 边界 | 说明 |
|------|------|
| **本轮未全量实施** | 只做设计 + 契约 + 生成原型，**宿主未替换** |
| **H2 决策未完全消除** | 部分决策（如 `mem.result ^= 1`）是**产品语义**，仍需宿主 |
| **新增攻击面** | 分发函数集中了所有模块调用 —— 但**patch 它等价于 patch 任一模块**（成本相同）|
| **不解决"运行期 ABI"** | 仍是**编译期**组合（`#ifdef` -> 生成代码），未引入动态加载 |

---

*2026-09-23 · 设计 + 最小验证；全量实施待后续（见 §5 验收判据）*
