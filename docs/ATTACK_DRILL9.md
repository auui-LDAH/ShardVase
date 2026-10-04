# 第九轮 — **判定点 patch + CRC 重算 vs 判定点快照守卫**（ATTACK_DRILL9）

> 版本：2026-10-02 v1 · **2026-10-04 v2（§5 已收口）** · 状态：**✅ 已实施（实测）** ·
> 关联：`docs/DECISION_REDUNDANCY_PLAN.md`（§11.5 记"仍未做"）、
> `docs/ATTACK_DRILL7.md`（步骤 4 的手法 + 后续建议第 4 条）、
> `docs/ATTACK_DRILL8.md`（定位失效，故本轮用**同一发布**）、
> `docs/COST_ASYMMETRY.md`（§4 杠杆表）、`docs/ATTACK_MATRIX.md`

---

## 1. 缘起：`DECISION_REDUNDANCY §11.5` 的**"仍未做"**

`docs/DECISION_REDUNDANCY_PLAN.md:503-518` 把守卫（判定点序言快照）的诚实边界写得很清楚：

```
掩码区外目标由**段 CRC 先终止**（L175-178）、掩码区内目标由 **selfcrypt 先拦截**（L163）
=> 守卫在出厂策略下**不是第一发现者**。
它的价值在于"**段 CRC 被中和（重算）后仍有第二道**"。
```

而同一节 `:516` 明确记下缺口：

```
仍未做：在 **EXIT 策略下**的端到端演示（需要构造"CRC 已被重算"的二进制）
        -> 留给 R3.2-d/DRILL9。
```

**本轮就是补这个缺口。** 判据不是"守卫代码存在"（那是 R3.2-b 的静态事实），
而是：**把段 CRC 真的中和掉之后，守卫是否仍然是第二道。**

---

## 2. 复核发现：`0xBAD` 有**四个**出口，必须逐个排除

读 `src/integrity.c` 看门狗循环（`watchdog_thread`，`:144-223`），
出厂 `PROT_POLICY_EXIT` 下能产生 `PROT_EXIT_TAMPERED`（`0xBAD` = 2989）的有四处：

| 位置 | 校验 | 失败动作 |
|------|------|----------|
| `:163` | `prot_selfcrypt_enter(GROUP_EXT)` | EXIT -> `prot_plat_terminate(0xBAD)`（**唯一带 `continue` 的分支**）|
| `:175` | `check_self`（段 CRC）| EXIT -> `prot_plat_terminate(0xBAD)` |
| `:192` | `check_iat`（运行期 IAT 改写复查）| EXIT -> `prot_plat_terminate(0xBAD)` |
| `:211` | `check_guards`（**判定点序言快照**，R3.2-b）| EXIT -> `prot_plat_terminate(0xBAD)` |

> **只测"patch 后进程死了"是无效测量** —— 死的可能是前两道。
> 必须构造对照，把前两道逐一排除，剩下的才是守卫的功劳。
> （这正是 `ATTACK_MATRIX.md` 已记名的教训：**无对照 = 无效测量**。）

---

## 3. 实证（**8 个用例，单轮实测**）

### 3.1 用例设计与归因逻辑

探针 `build/_drill9_probe.py`（`build/` 被 `.gitignore:2` 忽略，故输出内嵌于 §3.2）。
手法完全沿用 DRILL7 步骤 4 的 `31 C0 C3`（`xor eax,eax; ret`），
只把"要不要重算 CRC"和"patch 哪个目标"参数化：

| 用例 | patch 目标 | 重算 CRC | 策略 | 用途 |
|------|-----------|---------|------|------|
| `A_baseline` | —— | 否 | EXIT | 基线：未被终止 |
| `B_guard_no_recalc` | 守卫 `prot_antidebug_detected` | **否** | EXIT | 复现 DRILL7 步骤 4 的前置：段 CRC 先抓 |
| `D_ctrl_recalc` | **非守卫** `prot_antidebug_apply_policy` | **是** | EXIT | **对照组**：证明"重算确实生效" |
| `C_guard_recalc` | 守卫 `prot_antidebug_detected` | **是** | EXIT | **决定性用例** |
| `E_guard_recalc_continue` | 守卫 | 是 | **CONTINUE** | 观测 `g_guard_hits` 计数器佐证 |
| `F_checker_recalc` | **检查器自身** `prot_integrity_check_guards` | 是 | EXIT | 诚实边界（见 §5）|
| `G_checker_no_recalc` | 检查器自身 | **否** | EXIT | 诚实边界（见 §5）|
| `H_full_chain` | 检查器自身 **+** 守卫 | 是 | EXIT | 端到端链条闭合（见 §5）|

**为什么选 `prot_antidebug_apply_policy` 当对照**：非守卫（不在快照表内）、
在 selfcrypt 掩码区外、且**启动后不再被调用** —— patch 它惰性、不影响任何行为。

**前置守卫（防止假结论）**：探针在跑用例前断言
① 目标必须**不在** selfcrypt 掩码区（区内目标在 `:163-173` 被 `continue` 整轮跳过，无判别力）；
② **守卫目标必须落在 `.text`**（否则段 CRC 覆盖不到它，"重算"这件事本身无意义）。

**CRC 复算口径**：探针读**内存镜像**（非文件），按 `min(virtual_size, size_raw)` 取
`.text` 的 `crc_len = 139024`，把 IAT 单区间 + `.reloc` 槽位 + 8 条 selfcrypt 段整段掩码清零后
`zlib.crc32`。用例 `A0` 断言该复算值**等于**进程内 `g_prot_baked_crc` 的烧录值 —— 这是全部结论的地基。

### 3.2 实测输出原文（**决定性**）

```
[drill9] .text rva=0x2000 crc_len=139024 mask_regions=8
[drill9]   prot_antidebug_detected        rva=0x6f20   guard                in_mask=False sec=.text
[drill9]   prot_antidebug_apply_policy    rva=0x6e60   control(non-guard)   in_mask=False sec=.text
[drill9]   prot_integrity_check_guards    rva=0x14d0   checker(boundary)    in_mask=False sec=.3y7lsz8
[drill9] A_baseline                        exit=1      wrote=None  fidelity=True  hits=0
[drill9] B_guard_no_recalc                 exit=2989   wrote=True  fidelity=True  hits=0
[drill9] D_ctrl_recalc                     exit=1      wrote=True  fidelity=True  hits=0
[drill9] C_guard_recalc                    exit=2989   wrote=True  fidelity=True  hits=0
[drill9] E_guard_recalc_continue           exit=1      wrote=True  fidelity=True  hits=4
[drill9] F_checker_recalc                  exit=1      wrote=True  fidelity=True  hits=0
[drill9] G_checker_no_recalc               exit=1      wrote=True  fidelity=True  hits=0
[drill9] H_full_chain                      exit=1      wrote=True  fidelity=True  hits=0

  [ok] A0 CRC 复算口径与内存烧录值一致  (before=2087216295 computed=2087216295)
  [ok] A 基线不被终止(exit 1)  (exit=1)
  [ok] B patch 守卫(不重算)-> 段 CRC 先终止(0xBAD)  (exit=2989)
  [ok] D patch 非守卫 + 重算 -> CRC 通过, 正常结束(exit 1)  (exit=1 crc_after_write=884772529)
  [ok] C patch 守卫 + 重算 -> 仍被终止(0xBAD)  (exit=2989 crc_after_write=3467459129)
  [ok] E 佐证: 策略 CONTINUE 下 g_guard_hits > 0  (hits=4)
  [obs] patch prot_integrity_check_guards 函数头 + 重算 CRC -> exit=1  (不参与 PASS/FAIL; 诚实边界)
  [obs] patch prot_integrity_check_guards 函数头, 完全不重算 CRC -> exit=1  (不参与 PASS/FAIL; 诚实边界)
  [obs] patch prot_integrity_check_guards(抵消第二道) + patch prot_antidebug_detected(DRILL7 步骤 4) + 重算 CRC -> exit=1  (不参与 PASS/FAIL; 诚实边界)
[drill9] PASS
```

**逐用例关键字段**（`build/drill9/probe.json`）：

| 用例 | exit | 写入 | `crc_after_write` | 其他 |
|------|------|------|-------------------|------|
| `A_baseline` | 1 | —— | —— | —— |
| `B_guard_no_recalc` | **2989** | ✅ | —— | 反汇编 `31 c0 c3` |
| `D_ctrl_recalc` | **1** | ✅ | **884772529** | `crc_unchanged_by_patch=False` |
| `C_guard_recalc` | **2989** | ✅ | **3467459129** | `crc_unchanged_by_patch=False` |
| `E_guard_recalc_continue` | 1 | ✅ | 3467459129 | **`g_guard_hits=4`**（峰值轮询）|
| `F_checker_recalc` | 1 | ✅ | **2087216295（= `crc_before`）** | **`crc_unchanged_by_patch=True`** |
| `G_checker_no_recalc` | 1 | ✅ | —— | —— |
| `H_full_chain` | 1 | ✅✅ | 未变 | 双目标均写入成功 |

### 3.3 证据文件

```
build/_drill9_probe.py                （探针源码；build/ 被 .gitignore:2 忽略）
build/_drill9_run5.txt                （上表 stdout 原文，本次实测）
build/drill9/probe.json               （4428 B：4 目标符号 / 节归属 / 8 用例全字段 / 6 判定 / 3 观测）
build/drill9/{A,D,E}_*.out.txt        （713 B；B/C 为 0 B —— 见 §4.1 ⑤）
```

---

## 4. 结论（**三档判定**）

| 项 | 判定 |
|----|------|
| `DECISION_REDUNDANCY §11.5:516`"EXIT 策略下的端到端演示" | **已完成**（用例 C：段 CRC 已被重算，进程仍 `0xBAD`）|
| 守卫是否**只是第一道的副本** | **不是** —— 段 CRC 通过后守卫**独立**终止了进程 |
| `COST_ASYMMETRY §4` 杠杆表 | **新增一行**（见 §4.2）|
| 守卫的**上界** | ⚠️ **有** —— 见 §5（本轮新发现的真漏洞）|

**归因链为何闭合**（四条例外全部排除）：

```
① 排除 selfcrypt（:163）—— 探针只 patch 掩码区外目标，未触碰 8 条加密段
② 排除段 CRC（:175）—— 由对照用例 D 直接实证"重算生效"
   （D 也是 patch + 重算，却走到 exit 1；若重算没生效，D 也会死）
③ 排除 IAT（:192）—— 探针未改 IAT；且 D 同样未改 IAT 却 exit 1
   => IAT 校验在两种情况下都通过
④ A5 反附加复查（:226）只产 0xDB(219)，全部用例均未出现 219
=> **C 的 0xBAD 只能由 :211 check_guards 解释。**
```

**独立佐证（用例 E）**：把策略改成 `PROT_POLICY_CONTINUE`（**纯观测手段，不影响 A/B/C/D**）
后直接读到 `g_guard_hits = 4`。窗口 20 s ÷ 看门狗周期 5 s ≈ 4，与周期吻合 ——
**从计数器层面独立确认了 C 的归因**（不是"进程碰巧死了"）。

### 4.1 诚实边界（**不可过度声称**）

```
① 测试工具自己用了 OpenProcess/WriteProcessMemory —— 该行为本身会被产品反调试看到。
   本 drill 测的是"**内存改写能否被守卫抓住**"，不是"攻击者能否不被发现"。
② 只有用例 E 把运行期策略改为 CONTINUE；**A/B/C/D/F/G/H 全部保持出厂 EXIT**
   => C 是真正意义上"EXIT 策略下的端到端演示"，满足 :516 的要求。
   （对比: tools/guard_selftest.py 是靠**改策略模拟**段 CRC 被中和；
     本轮的新增量正是把它**显式化为真的重算**。）
③ build/demo.exe 是 **NotSigned** => 本 drill **不覆盖 Authenticode 签名这道线**。
④ 仅 Windows。
⑤ 守卫快照在 start_watchdog 内对**内存当前字节**建立 => **离线（文件级）patch 无效**，
   故必须运行期实施。这澄清了守卫的威胁模型 = "**进程起来之后的运行期内存改写**"。
⑥ 用例 B/C 的 stdout 为 0 字节：TerminateProcess 立即杀进程、用户态缓冲未 flush。
   **不削弱结论** —— 判据是退出码；A/D/E 的 713 B stdout 证明同一条启动路径确实会打印。
```

### 4.2 `COST_ASYMMETRY §4` 回填

在杠杆表新增一行（并同步更新该文件头部 `最后核实`）：

```
| 10 | **patch 判定点 + 重算段 CRC** | **判定点序言快照（check_guards）** | **高（第二道独立成立）** |
  依据: ✅ DRILL9（2026-10-02）: EXIT 策略下重算 .text CRC 并写回
  （2087216295 -> 3467459129，用例 D 反证重算生效）-> 仍被 0xBAD 终止；
  CONTINUE 下 g_guard_hits=4 独立佐证
```

---

## 5. ✅ 已收口（2026-10-04）：**守卫检查器自身不在段 CRC 覆盖内**

> 本节是本轮相对 `tools/guard_selftest.py` 的**真正新增量**：
> 它把"第二道守卫有上界"从**推测**变成**实测**。
>
> **2026-10-04 更新**：本节描述的缺口已按 §5.3 的**建议 ②** 修复并实测收口 ——
> `.protxec` 已成为**第 4 个段 CRC 目标**，用例 F/G/H 由 `exit=1`（攻击成功）
> 翻转为 `exit=2989`（被段 CRC 拦截）。§5.1–§5.3 保留**发现时（2026-10-02）**的
> 原文与观测，收口证据见 §5.4。

### 5.1 发现（**2026-10-02 收口前观测**）

`prot_integrity_check_guards` 的 rva = **`0x14d0`**，落在 **`.protxec`** 节
（PE 名 `.3y7lsz8`，va `0x1000`–`0x1c00`），**不是 `.text`**。
（rva/节名**每构建随机**，上值是当次构建的实测值。）

而段 CRC 只覆盖 `prot_plat_crc_target_name()` 给出的三个节
（`src/platform/prot_platform_win.c:678-683`）：**`.text` / `.rdata` / `.pdata`**。

```
=> 检查器自身的代码从来不在段 CRC 的覆盖范围内。
=> 攻击者 patch prot_integrity_check_guards 函数头（31 C0 C3）
   -> 立即 return PROT_OK（PROT_OK = 0, include/protect/protdef.h:27）
   -> 整个 check_guards 环节恒真，且**无需任何 CRC 重算**。
```

**双重实证**：

| 用例 | 观测 | 说明 |
|------|------|------|
| `F_checker_recalc` | `crc_unchanged_by_patch = True`（重算值 = 原值 `2087216295`）| 重算前后 CRC **完全没变** -> 该 patch 根本不进 `.text` |
| `G_checker_no_recalc` | **完全不重算 CRC，仍 exit 1** | 重算对这个目标**本就多余** |
| `H_full_chain` | 检查器 + 守卫双 patch -> **exit 1（盾失效）** | **完整攻击链闭合** |

### 5.2 覆盖缺口此前**已被记录**，但后果从未被评估

`docs/OPEN_SOURCE_COMPENSATION.md:87` 原文已把 `.protxec` 列在"未覆盖"清单里
（该清单 2026-10-04 已更新为 `.data` `.protcrc` `.protcry` `.protpad` `.fptable`
`.rsrc` `.reloc` —— `.protxec` 已移出）：

```
- **未覆盖**：`.protxec` `.data` `.protcrc` `.protcry` `.protpad` `.fptable` `.rsrc` `.reloc`
```

但**从未把它与守卫联系起来**。`.protxec` 的设计意图是**分页隔离**（防 selfcrypt 自伤，
见 `docs/DEFENSE_DEEPEN_PLAN.md:107`/`:142`、`docs/部署档案-ShardVase.md:55`）——
它是为**功能正确性**而设的，**其安全后果是副作用，未被评估**。

> **教训（与 DRILL8 §2 同一模式）**：
> **能力/缺口落地了，但它的安全含义没被推导**。

### 5.3 修复方向（**2026-10-02 提出，2026-10-04 按 ② 实施**）

```
① 把 prot_integrity_check_guards（或整个守卫快照实现）移入 .text -> 落入 CRC 覆盖
   （代价: 需确认不会触发 selfcrypt 同页自伤 —— 这正是 .protxec 当初存在的原因）
② 或把 .protxec 加入 prot_plat_crc_target_name() 第四节
   （需 g_prot_baked_crc[3] 数组扩容 + MAGICS 同步；注意 .protxec 含解密器本身，
     自引用问题须先解决 —— 参考 src/integrity.c:52-53 已因自引用把烧录表排除在 CRC 外）
③ 或对检查器自身再加一层独立校验（自引用问题需另设计）
```

**最终选择 ②，理由（否决 ① 的实证代价）**：

- 本仓库有硬约束「**只增函数、不重排**」（R3.2-c 刚把副本间距抖动做成不变量，
  `docs/DECISION_REDUNDANCY_PLAN.md:184` 的 `.text` 布局漂移风险项）——
  ① 会把已稳定的 `.text` 布局整体挪动，**成本真实且立即**。
- ② 是**零搬移**改动，且覆盖面**更大**：`.protxec` 里除了 `prot_integrity_check_guards`，
  还有 `check_iat` / `register_guard` / `start_watchdog` 等同样不被覆盖的代码。
- 自引用问题在 ② 下**并未新增**：`prot_crc32_step` 自身本就在 `.text` 内，
  既有实现已接受该残余（`.protcrc` 烧录表自身不被覆盖是**刻意**的，见
  `src/integrity.c` 的烧录表注释）。
- Linux 侧**刻意保持 3 个目标**：`include/protect/prot_compiler.h:273-276` 里
  `PROT_CODE_SEG()` 在非 MSVC 下为空 ⇒ ELF 侧检查器本就落在 `.text`、
  已被下标 0 覆盖 ⇒ 不对称是**显式设计**，不是漏配。

### 5.4 ✅ 收口实测（2026-10-04）

改动落点（4 处契约必须同步，全部已改并被新门禁第 36 项守护）：

| 文件 | 改动 |
|------|------|
| `tools/hashpatch.py` | `MAGICS` 加 `b'PROTCRCX'`；`TARGET_NAMES` 加 `.protxec`；**新增 `TARGET_LOGICAL = (None, None, None, 'protxec')`** 与 `resolve_target_names()` |
| `src/integrity.c` | `g_prot_baked_crc[4]`（加 `{ PROT_MAGIC_XEC_BYTES, 0, 0 }`）；两处 `j < 4u` 循环 |
| `include/protect/prot_sections.h` | 新增 `PROT_MAGIC_XEC` / `PROT_MAGIC_XEC_BYTES` |
| `tools/gen_sections.py` | magics 4 元组 + 头文件写入顺序 |
| `src/platform/prot_platform_win.c` | `prot_plat_crc_target_name()` 第 4 节 = `PROT_SEC_XEC` |

> **`TARGET_LOGICAL` 是本次的关键坑**：阶段 1 起 `.protxec` 的**节名每构建随机**
> （`gen_sections.py` 写 `#undef PROT_SEC_XEC` + `#define PROT_SEC_XEC ".xxxxxxxx"`）。
> 若 `hashpatch.py` 只用常量名 `.protxec` 去找节，生成路径下 `next(...)` **永远返回 None**
> -> 走 `print('hashpatch: %s section absent — skip')` 分支 -> **静默不校验**
> （CRC 字段恒为 0、不报错、构建成功、门禁全绿）。这比不修更危险。
> ⇒ 新增 `tools/check_crc_targets.py`（门禁第 **36** 项）专门守护这条不变量。

**用例翻转（同一探针 `build/_drill9_probe.py`，`--verbose`，`rc=0`）**：

| 用例 | 收口前（2026-10-02） | **收口后实测** |
|------|----------------------|----------------|
| `F_checker_recalc`（patch 检查器头 + 重算 CRC） | `exit=1`（攻击成功） | **`exit=2989`（`0xBAD`，被段 CRC 拦）** |
| `G_checker_no_recalc`（patch 检查器头，完全不重算） | `exit=1`（攻击成功） | **`exit=2989`** |
| `H_full_chain`（检查器 + 守卫双 patch + 重算 CRC） | `exit=1`（**盾失效**） | **`exit=2989`** |

同轮其余判据仍全 `[ok]`：`A 基线 exit=1`；`B exit=2989`；`D exit=1 crc_after_write=2948866091`
（证明重算本身确实能通过 CRC）；`C exit=2989`；`E hits=3`。
符号归属实测：`prot_integrity_check_guards rva=0x10f0 sec=.8kqb0fb`（= `PROT_SEC_XEC` 的随机名，
**已进入 CRC 覆盖**，`in_mask=False`）。

构建实测（3 连建 × `hashpatch` 第 4 行，节名每次不同）：

```
#1 protxec -> .fpmhwjo   hashpatch: patched .fpmhwjo crc=0xa6347550 at offset 214584 (magic at 214576)
                         hashpatch: .fpmhwjo raw [141312, +2573) -> crc32 0xa6347550
#2 protxec -> .b7ogh7p   hashpatch: patched .b7ogh7p crc=0xf51f5c76 at offset 215608 (magic at 215600)
#3 protxec -> .lf7t0q3   hashpatch: patched .lf7t0q3 crc=0x5ba64a79 at offset 235576 (magic at 235568)
```

> `merge_baseline` 在 #2 报 `protcrc vsize 0x30 -> 0x40`（首建）与
> `.text 0x22420 -> 0x22450` / `.rdata 0xE544 -> 0xE5EC`（#2）——
> 烧录表由 3×16 涨到 4×16 字节，基线**只增不减**（`tools/gen_padding.py:211`）故自动提升，
> 属预期节尺寸变化。烧录表自身仍住 `.protcrc` 且**不被任何段 CRC 覆盖**（避免自引用），该设计未变。

### 5.5 ⚠️ 收口后的**残余边界**（不可过度声称）

```
=> F/G/H 被拦住 != "第二道不可移除"。
=> 攻击者若**同时中和段 CRC**（使 .protxec 的校验失效，例如 patch 掉
   比对逻辑或直接改烧录表），仍可关掉检查器。
=> prot_crc32_step 自身在被校验段内（自引用边界），与 .text 同理，
   属既有残余，非本次新增。
=> 本条把攻击成本从"patch 一个函数头"提高到"必须同时中和第 4 个段的 CRC"
   —— 是**成本提高**，不是**不可破**。
```

---

*2026-10-02 · DRILL9: 判定点 patch + CRC 重算 vs 快照守卫 —— EXIT 策略下重算 CRC 仍被 0xBAD 终止（`g_guard_hits=4` 佐证）；杠杆表新增一行；**附带发现 `.protxec` 盲区：检查器自身不在 CRC 覆盖内，可被直接 patch**（用例 F/G/H）*

*2026-10-04 · DRILL9 §5 **收口**: `.protxec` 成为第 4 个段 CRC 目标（否决"搬进 .text"因布局漂移代价），F/G/H 由 `exit=1` 翻转为 `exit=2989`；新增门禁第 36 项 `tools/check_crc_targets.py` 守护四处契约一致性（曾因 `.protxec` 节名随机而静默 skip）；残余边界：须同时中和第 4 段 CRC 仍可关闭检查器*
