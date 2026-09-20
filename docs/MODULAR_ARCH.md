# 模块化架构设计（Modular Architecture）

> 版本：2026-09-20 v1 · 状态：**设计提案，待评审**（未动代码）
> 目标：把当前单体保护套件演进为**攻防双侧、可组合、开源**的反逆向框架。
> 关联：`docs/CONTRACT.md`（现有契约）、`docs/COST_ASYMMETRY.md`（战略层）、
> `docs/THREATMODEL.md`（威胁模型）、`docs/DEFENSE_DEEPEN_PLAN.md`（S1-S5 技术债）。

---

## 0. 结论先行

**好消息**：这个项目离模块化框架比预期近得多。实测依赖图（排除模块对自身头文件的
自引用）显示：

```
15 个 src/*.c 模块中
  · 10 个零跨模块依赖  (只 include 自身头 + protdef.h)
      crc32 / dbiguard / hostid / indirect / license /
      selfcrypt / strcrypt / syscall / vm / vmdetect
  ·  5 个有真实跨模块依赖，合计仅 6 条边:
      antidebug -> syscall
      blob      -> license
      revoke    -> license
      vm_rekey  -> vm
      integrity -> antidebug, selfcrypt      ← 唯一的"聚合者"
  · protdef.h 是所有头的共同基础（纯类型，无实现）
```

**这已经是一份教科书级的低耦合依赖图**——10/15 零依赖、6 条边、无环。
框架化的工作是**显式化这层隐含契约**，而不是重构它。

而且**三个检测器已共享同一采集/判定模式**（这本身就是模块化的天然接缝）：

```c
prot_status prot_X_scan(prot_X_report* out);           /* 采集 —— 三者都有 */
uint32_t     prot_X_suspicious(const prot_X_report*);  /* 判定 —— 三者都有 */
prot_status  prot_X_apply_policy(prot_policy);         /* 响应 —— 仅 antidebug 有 */
```

| 模块 | scan | 判定函数 | apply_policy |
|------|------|----------|--------------|
| `antidebug` | ✅ | `prot_antidebug_detected` | ✅ |
| `dbiguard` | ✅ | `prot_dbiguard_suspicious` | ❌ |
| `vmdetect` | ✅ | `prot_vmdetect_suspicious` | ❌ |

> `dbiguard` / `vmdetect` 是**咨询项**（只报告不阻断，因误杀成本高）。
> 这个差异恰好说明为什么需要 `phases` 位掩码字段——
> 它们只参与 `SCAN`/`DECIDE`，不参与 `ENFORCE`。

**缺口**：框架化需要三样现在没有的东西——

| # | 缺口 | 说明 |
|---|------|------|
| 1 | **统一模块契约** | 现在每个模块 API 形状各异，没有「模块」这个抽象 |
| 2 | **组合校验** | 没有机制阻止用户拼出**互相破坏**的组合 |
| 3 | **攻防对称** | 攻击侧工具（`tools/attacker/`）与防御侧不在同一抽象层，无法声明"本模块对抗哪类攻击" |

---

## 1. 设计原则（从项目实证中提炼，非空想）

这四条不是我发明的，是**这个项目已经用血换来的教训**：

### P1. 语义等价必须可验证，不能靠「看起来一样」

`.text` CRC 那件事：任何新增编译单元都会改变布局 → 改动即 TAMPERED
（`docs/DEFENSE_DEEPEN_PLAN.md` 技术债 ②）。而我尝试"骨架一致的整文件重建"
也证明了：**ASCII 骨架逐字符相同 ≠ 语义等价**（`e2e T1` 失败）。

→ **框架必须内建「组合后的语义等价验证」**，而不是信任拼装。

### P2. 页粒度与布局是硬约束，不是实现细节

S1 的 `revoke` 加密被**永久排除**，原因是它与 `main` 同页，
`VirtualProtect` 切 RW 会禁执行 `main`（自伤）。

→ **模块必须显式声明资源占用**（页对齐、段归属），否则组合必然踩雷。

### P3. 门禁绕过路径会掩盖真实缺陷

`build.ps1` 的 smoke 测试**必然失败**却被掩盖了整整一个月，
因为所有自动门禁都带 `-SkipSmoke`。

→ **框架的每个模块必须能被独立验证**，且**禁止**"整体门禁跳过它"。

### P4. 诚实边界是资产，不是弱点

`publish/06-诚实边界.md` 列了 6 条已知边界；`ATTACK_DRILL7` 诚实记录
"3 字节 patch 使盾失效"。

→ **模块契约里必须有 `known_limits` 字段**，且**框架强制要求公开**。

---

## 2. 三层结构

```
┌─────────────────────────────────────────────────────────┐
│  L3  组合层 (Composition)                                │
│      拼装图 / 组合校验 / 冲突检测 / 成本核算              │
├─────────────────────────────────────────────────────────┤
│  L2  模块层 (Modules)                                    │
│      统一契约 + 生命周期 + 能力声明 + 依赖声明            │
├─────────────────────────────────────────────────────────┤
│  L1  原语层 (Primitives)                                 │
│      已有资产: vm / crc32 / syscall / strcrypt ...        │
│      （几乎不动，它们是稳定地基）                          │
└─────────────────────────────────────────────────────────┘
```

**关键设计决策：L1 保持不动。** 现有 15 个模块的依赖图已经很干净，
推翻重写是负收益。框架的价值在 L2/L3。

---

## 3. L2 模块契约

### 3.1 统一签名

从现有三个检测器的共同模式**泛化**（而非新发明）：

```c
/* include/protect/module.h — 新增，框架核心 */

typedef enum prot_capability {
    PROT_CAP_DETECT      = 1u << 0,  /* 检测环境/篡改 */
    PROT_CAP_PREVENT     = 1u << 1,  /* 阻止（终止/降级） */
    PROT_CAP_CONCEAL     = 1u << 2,  /* 隐藏（加密/混淆） */
    PROT_CAP_VERIFY      = 1u << 3,  /* 校验（完整性/授权） */
    PROT_CAP_RESPOND     = 1u << 4,  /* 响应（轮换/重算） */
} prot_capability;

typedef enum prot_phase {
    PROT_PHASE_INIT      = 0,  /* 启动期: 解密/装载 */
    PROT_PHASE_SCAN      = 1,  /* 检测期: 采集 */
    PROT_PHASE_DECIDE    = 2,  /* 判定期: 聚合 */
    PROT_PHASE_ENFORCE   = 3,  /* 执行期: 策略 */
    PROT_PHASE_WATCH     = 4,  /* 驻留期: 周期复查 */
} prot_phase;

typedef struct prot_module_desc {
    const char*      name;           /* 唯一标识, 如 "antidebug" */
    uint32_t         abi_version;    /* 契约版本 */
    uint32_t         caps;           /* prot_capability 位掩码 */
    uint32_t         phases;         /* 参与的 prot_phase 位掩码 */
    /* 依赖声明: 本模块需要哪些能力先就绪 */
    uint32_t         requires_caps;
    /* 资源声明 (P2): 防止组合踩布局雷 */
    uint32_t         wants_page_align;   /* 需要独占页 (selfcrypt 类) */
    uint32_t         touches_text;       /* 会改 .text (selfcrypt/hashpatch) */
    uint32_t         needs_writable_dir; /* 需要可写目录 (部署约束) */
    /* 诚实边界 (P4): 强制声明 */
    const char* const* known_limits;     /* NULL 结尾字符串数组 */
    /* 生命周期钩子 */
    prot_status (*init)(void);
    prot_status (*scan)(void* report_out);
    uint32_t    (*decide)(const void* report);
    prot_status (*enforce)(prot_policy pol);
    prot_status (*fini)(void);
} prot_module_desc;
```

### 3.2 为什么这样设计

| 字段 | 解决什么 | 来自哪个教训 |
|------|----------|--------------|
| `caps` / `requires_caps` | 组合时能静态检查依赖满足 | 当前无依赖检查，靠人记 |
| `wants_page_align` | 防止 selfcrypt 类模块与宿主同页自伤 | **P2**：S1 revoke 被永久排除 |
| `touches_text` | 提示"本模块会改 .text"，与 integrity 冲突 | **P2**：`.text` CRC 原子性缺陷 |
| `known_limits` | 强制公开边界 | **P4**：诚实边界是资产 |
| `phases` 位掩码 | 允许一个模块只参与部分阶段 | 现有 `dbiguard` 只报告不阻断 |

### 3.3 现有模块的映射（零重写）

| 现有模块 | name | caps | 备注 |
|----------|------|------|------|
| `antidebug.c` | `antidebug` | DETECT \| PREVENT | 已有 scan/detected/apply_policy，形状最标准 |
| `dbiguard.c` | `dbiguard` | DETECT | 咨询项，只参与 SCAN/DECIDE |
| `vmdetect.c` | `vmdetect` | DETECT | 同上 |
| `integrity.c` | `integrity` | VERIFY \| RESPOND | **唯一跨模块依赖者**，需改造为消费其他模块的 report |
| `selfcrypt.c` | `selfcrypt` | CONCEAL | `wants_page_align=1`, `touches_text=1` |
| `vm.c` + `vm_rekey.c` | `vm` | CONCEAL \| VERIFY | `phases` 含 INIT（装载）与 WATCH（rekey） |
| `license.c` / `revoke.c` | `license` | VERIFY | 授权链 |
| `hostid.c` | `hostid` | VERIFY | 机器绑定 |
| `strcrypt.c` | `strcrypt` | CONCEAL | 字符串表 |
| `blob.c` | `blob` | VERIFY | 外部装载 + 验签 |
| `syscall.c` | `syscall` | CONCEAL | 反 hook 基础设施（被 antidebug 用） |
| `indirect.c` | `indirect` | CONCEAL | 函数级间接化 |
| `crc32.c` | （原语） | — | 不注册为模块，是公共设施 |

> **改造量**：每个模块加一个 `const prot_module_desc g_mod_X = {...}` 描述符
> + 让现有函数签名适配（多数是包装）。**不重写实现逻辑。**

---

## 4. L3 组合层

### 4.1 组合校验器（解决 P2 + P3）

```c
/* tools/modcheck.py — 静态校验，构建期跑 */
def validate_composition(mods):
    """返回 (ok, warnings, errors)"""
    errors = []
    # 1. 依赖满足 (requires_caps ⊆ 已选模块的 caps 并集)
    # 2. 页对齐冲突 (两个 wants_page_align 模块落在同一页)
    # 3. .text 改写冲突 (selfcrypt touches_text + integrity 校验 .text)
    #    → 必须走 selfcrypt_mask 豁免，否则必然 TAMPERED
    # 4. 阶段顺序 (INIT 必须先于 SCAN 等)
    # 5. known_limits 非空 (P4 强制)
    return errors
```

**必须构建期运行**，而不是文档里写"请注意"——因为 P2 的教训就是
"两个各自正确的机制放在一起就崩"，靠人记不住。

### 4.2 参考拼装图（解决"用户不会拼"）

```
compositions/
  minimal/        最小可用: license + hostid + strcrypt
  standard/       推荐: + antidebug + integrity + selfcrypt(vm组)
  hardened/       强化: + dbiguard + vmdetect + indirect + blob
  full/           全部（含已知冲突项，附说明为何不推荐某些组合）
```

每个拼装图 = 一个 `composition.json` + 由 `modcheck.py` 校验 + 一键构建脚本。

### 4.3 攻防对称（这是本框架区别于他人的地方）

当前 `tools/attacker/` 与防御侧不在同一抽象层。**重新组织为对称结构**：

```
framework/
  defense/        防御模块 (原 src/)
  offense/        攻击模块 (原 tools/attacker/)
  drills/         对抗矩阵: 每项声明「攻击 X ↔ 防御模块 Y」的实测结果
```

`drills/` 的每项是一个结构化记录（而非散落的 md）：

```json
{
  "attack": "patch_function_head",
  "target_module": "antidebug",
  "method": "3-byte overwrite (31 C0 C3)",
  "result": "BREACHED",
  "evidence": "ATTACK_DRILL7 §3.2 步骤 4",
  "countermeasure": null,
  "known_limit": true
}
```

**价值**：
- 每个防御模块自动获得"被哪些攻击打过、结果如何"
- 新增模块必须提交对应的 drill 记录才能合入（**用纪律保证诚实**）
- 对外可生成实时对抗矩阵（比散文更有说服力）

---

## 5. 分阶段实施（每阶段保持全绿）

> 纪律：每阶段结束必须 `build.ps1` 裸跑 DONE + `release_check` 11/11。
> 这是 P3 的直接应用——不许有任何模块走"跳过验证"的路径。

### 阶段 0：前置清理（**必须先做**）

| 项 | 理由 |
|----|------|
| 关闭 `SCDBG`（加编译开关） | Release 产物泄漏每个加密函数的 RVA/密钥/CRC —— 框架的"可公开"前提 |
| 补 `ATTACK_DRILL8`（验证关闭后仍可攻防） | 证明改动未削弱能力 |

### 阶段 1：模块契约落地（不改变行为）

- 新增 `include/protect/module.h`
- 为每个现有模块加 `prot_module_desc` 描述符
- 新增 `tools/modcheck.py`（仅校验，不阻断）
- **验收**：`modcheck` 能列出全部 13 个模块及其 caps/依赖/边界；
  `build.ps1` + `release_check` 仍全绿（**行为零变化**）

### 阶段 2：组合校验 + 参考拼装图

- `modcheck` 接入构建，冲突即失败
- 建立 `compositions/` 四个参考图
- **验收**：故意构造一个冲突组合（selfcrypt + integrity 未豁免）→
  `modcheck` 报错；四个参考图全部可构建 + 通过 e2e

### 阶段 3：攻防对称重组

- 建立 `drills/` 结构化记录
- 把已有 7 轮演练 + 3 组矩阵**回填**为 drill 记录
- **验收**：对抗矩阵可自动生成；每条记录的 evidence 可追溯到原始文档

### 阶段 4（可选）：成本模型

基于 `drills/` 数据产出 `tools/cost_model.py`（见 `COST_ASYMMETRY.md` 路线 A）。

---

## 6. 风险与对策

| 风险 | 对策 |
|------|------|
| 模块化放大组合脆弱性 | **P2** 对策：资源声明 + 构建期校验（阶段 2） |
| 重构破坏既有能力 | 阶段 1 明确"行为零变化"；每阶段全量回归 |
| 契约太复杂没人用 | 描述符有**默认值宏**（`PROT_MODULE_MINIMAL`），简单模块 3 行注册 |
| 对外承诺超出实际 | `known_limits` 强制字段 + drill 记录准入 |

---

## 7. 与既有文档的关系

| 文档 | 关系 |
|------|------|
| `CONTRACT.md` | 现有实现契约（"怎么做"）——框架层**引用**它，不取代 |
| `THREATMODEL.md` | 威胁模型与成本矩阵——`drills/` 的结构化来源 |
| `COST_ASYMMETRY.md` | 战略层（为什么做这个框架） |
| `DEFENSE_DEEPEN_PLAN.md` | S1-S5 技术债——P1/P2 原则的来源 |
| `publish/06-诚实边界.md` | 对外边界——`known_limits` 的公开面 |

---

## 8. 待评审决策点

| # | 决策 | 选项 | 影响 |
|---|------|------|------|
| M1 | 是否动 L1 原语层 | 不动（建议）/ 一并重构 | 决定工作量与风险 |
| M2 | 契约用 C 结构体 vs 纯元数据文件 | C 头（建议，可静态检查）/ JSON | 决定能否编译期校验 |
| M3 | 目录重组 `defense/`+`offense/` vs 保持 `src/`+`tools/attacker/` | 重组（对称性好）/ 保持（无迁移成本） | 影响对外观感与引用 |
| M4 | drill 记录是否作为合入硬门槛 | 是（用纪律保证诚实）/ 否 | 影响长期维护负担 |
| M5 | 阶段顺序 | 0→1→2→3（建议）/ 直接 3（先做对抗矩阵） | 见 §5 |

---

© ShardVase · 模块化架构设计（提案） · 2026-09-20
