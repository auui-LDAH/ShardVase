# 项目汇报与迁移交接 (HANDOVER)

> 生成日期：2026-08-21（v7：阶段 II 收尾 + 已知环境限制）· 基线提交：`44621db` 之后
> **最新增量：2026-09-20 迁移后状态见 §2.6（基线提交 `add234a`）**
> 本文档对当前开发状态的唯一快照性说明。与本项目相关的正式规范/历史/路线图
> 见 `docs/BUSINESS.md`（总纲）/ `docs/RELEASE.md` / `docs/OPS.md` /
> `docs/COMPAT.md` / `docs/PHASE2.md` / `docs/PHASE3.md` / `docs/ADVANCED.md` /
> `docs/ADVANCED2.md` / `docs/CONTRACT.md` / `docs/PLAN.md` / `docs/ROADMAP.md` /
> `docs/THREATMODEL.md` / `docs/PRODUCTION.md` / `docs/N1_PLAN.md`（N1 一期计划）/
> `docs/N1_PHASE2_PLAN.md`（N1 二期增强计划）/ `docs/BLOB_SIGN_PLAN.md`（blob 签名+网络下发计划）/
> `docs/CI_PLAN.md`（CI 增强计划）/ `docs/ATTACK_PLAN.md`（攻击模拟扩展计划）/
> `docs/VERIFY_PLAN.md`（verify 门禁增强计划）/ `docs/ATTACK_DRILL.md`（批量攻防演练计划）/
> `docs/ATTACK_DRILL2.md`（第二轮攻防演练计划）/ `docs/ATTACK_DRILL3.md`（第三轮攻防演练计划）/
> `docs/ATTACK_DRILL4.md`（第四轮攻防演练计划）/ `docs/ATTACK_DRILL5.md`（D5/E5 补充）/
> `docs/EXTENSION_PLAN.md`（Android SO 保护 A + 跨平台许可服务化 C 延申计划）/
> `docs/INFRA_PLAN.md`（基础设施完善计划）/ `docs/WIN_ENHANCE.md`（Windows 侧增强计划）。
> **交接任何事项前务必先读本文档 + CONTRACT。**
> **最后核实**: 2026-10-06 · 方法: tools/docclaim_check.py（8/8 PASS）+ tools/doccheck.py（0 错误；自计数随文档增长，见 §2.36.7）+ replica_check **五条判据**（含 6 组单点变异 + 全打掉对照 + 位置抖动）+ crc_targets **13 条判据**（含 8 负向变异）+ gate_log 自检 6 项（含 4 负向）+ e2e T1-T30 + android_compile_check T1-T13 + selfcrypt_residency_check **4 条判据**（含 4 负向变异）+ 门禁 **39** 项（默认 36）· 提交 `6c52733`（阶段总结 28287ea + 陈旧复选框整理 9e013ff/ed398ac/ed669fe + e2e T29 补齐 80db8ba + e2e T30 补齐 efb81b7 + D2c 收口见 §2.35）


## 1. 项目是什么

Windows x64 原生 C 反逆向保护套件 + 演示程序（仓库根目录名「反逆向研究」）。
演示程序 `build\demo.exe` 集成了：

| 保护层 | 机制 | 文件 |
|--------|------|------|
| VM 代码保护 | 核心校验逻辑以自定义字节码编写，构建期加密 + opcode 置换 + 槽位随机化 + 等价实现多样性；解密窗不入堆 | `src/vm.c`、`src/crc32.c`、`tools/vmenc.py`、4 个 `demo/*.vasm` |
| 反调试 | PEB / NtQueryInformationProcess / 硬件断点 / 计时 / int3 蜜罐 / 内核调试器探测 | `src/antidebug.c` |
| 完整性 | `.text` CRC32 构建期烧录 + 后台看门狗 | `src/integrity.c`、`tools/hashpatch.py` |
| 字符串加密 | 运行期一次性解密 | `src/strcrypt.c`、`tools/strgen.py`、`demo/strings.txt` |
| 机器绑定 | hostid 多因子折叠 → machine_id，绑定序列号期望值 | `src/hostid.c` |
| **RSA 授权（A1，2026-08-10 落地）** | 离线签发 RSA-2048/PKCS#1v1.5/SHA-256；宿主验签 + **VM#4 门控**（`result &= license_ok`） | `src/license.c`、`include/protect/license.h`、`tools/vmenc.py keygen/sign`、`demo/license_gate.vasm` |
| **分级授权（Phase 4，2026-08-14 落地）** | `--tier 0|1|2`（试用/正式/增值）参与签名载荷 `serial‖mid‖PRODUCT‖tier`；license.txt `TIER=` 行，篡改即验签失败 | `tools/vmenc.py sign --tier`、`src/license.c`、`demo/main.c` |
| **引擎语义变异（A2，2026-08-14 落地）** | 操作数字节序 LE/BE-SWAP + 折叠公式 4 选 1（`key[1]` 流派生 `sem`，两侧同位置复算） | `src/vm.c`（`vm_wfetch32/64`、`vm_fold`、`vm_build_keymaps`）、`tools/vmenc.py make_opcode_keymaps` |
| **完整性扩三节（A3，2026-08-14 落地）** | `.protcrc` 专用段烧录 `.text/.rdata/.pdata` 3 组 CRC；IAT/重定位字段两侧同掩码归零 | `src/integrity.c`、`tools/hashpatch.py` |
| **反附加定时器（A5，2026-08-14 落地）** | 看门狗周期重跑 `prot_antidebug_scan` + 间隔 ±40% 抖动 | `src/integrity.c`（watchdog_thread） |
| **direct syscall（A6，2026-08-14 落地）** | 运行时提取 SSN + 内存生成 12B 直调 stub，关键信息类绕 ntdll hook；失败回退 API 路径 | `src/syscall.c`、`include/protect/syscall.h`、`src/antidebug.c`、`tests/syscall_probe.c` |
| **VM 外部装载（DBI launcher，2026-08-14 落地）** | VM 密文打包 `build\vm.blob`（`vmenc.py pack`），launcher 启动装载校验；exe 无 VM 逻辑 | `src/blob.c`、`include/protect/blob.h`、`tools/vmenc.py pack/--bin-out`、`demo/main.c --vm-blob` |
| **授权吊销（I1，2026-08-15 落地）** | 离线黑名单 revoke.blob（版本化+CRC），strict/warn 策略，退出码 0xB1E4 | `src/revoke.c`、`include/protect/revoke.h`、`tools/vmenc.py revoke`、`demo/main.c` |
| **发行加固+可复现（I2/I3，2026-08-15 落地）** | version.h/--version/版本资源/自签签名；种子注入 + /Brepro（无签名产物字节一致） | `include/protect/version.h`、`demo/version.rc`、`build.ps1 -Config/-SeedsFile/-RecordSeeds`、`verify.ps1 -Reproducible` |
| **函数级间接化（N4，2026-08-22 落地）** | 4 个关键宿主函数（VM 执行/验签/吊销/机器标识）经槽位随机化指针表间接调用；静态零直接 call，调用点 `call resolve + call rax`；种子可复现 | `src/indirect.c`、`include/protect/indirect.h`、`tools/indirect.py`、`demo/gen/indirect_table.c`（生成）、`demo/main.c`（PROT_INDIRECT_CALL 宏）、`build.ps1` 步骤 4c |
| **服务器端兜底（N5，2026-08-22 落地）** | `/v1/check` 下发会话级期望值 expect1/expect2（服务端复算）；VM#3 期望值改读 demo_mem +112/+120（在线=会话值，离线=构建期默认）；破解者 patch "期望值比较" 只对当次会话有效 | `tools/mock_server.py`（N5 扩展）、`demo/license_verify.vasm`（改读内存）、`demo/main.c`（解析+填充）、`build.ps1` 步骤 2.2（生成 expect_default.c）、e2e T25/T26 |
| **运行时自变形（N1，2026-08-22 落地，二期完成）** | VM 引擎 4 函数（prot_vm_run/keymaps/wb/var）构建期 .text 原位 XOR 加密；运行期解密执行（D2a 默认 / `-D2b` 调用级解密 enter/leave）；解密态 CRC 校验（篡改→0xBAD）；.text CRC 对加密段掩码（D1b）零误报；方案 C（搬移+跳板）证伪 | `src/selfcrypt.c`、`include/protect/selfcrypt.h`、`tools/selfcrypt_proto.py`、`demo/main.c`（.protcry 容器+vm_run_wrapped）、`hashpatch.py --mask`、`integrity.c build_selfcrypt_mask`、`build.ps1` 步骤 6 + `-D2b` 开关；计划 `docs/N1_PLAN.md` / `docs/N1_PHASE2_PLAN.md` |
| **blob 签名绑定+网络下发（BLOB_SIGN，2026-08-22 落地）** | vm.blob/revoke.blob 升级 v1 签名格式（RSA-2048 PKCS#1 v1.5 SHA-256，复用 A1 私钥）；自建/替换/回滚 blob 全拒（D1a 强制 v1）；`--blob-url` 在线下发 `/v1/blob` + 离线回退（验签兜底防中间人） | `tools/vmenc.py`（pack/revoke --sign）、`src/blob.c`/`src/revoke.c`（验签）、`demo/main.c`（--blob-url）、`tools/mock_server.py`（/v1/blob）、e2e T27/T28；计划 `docs/BLOB_SIGN_PLAN.md` |

核心论断（废 `demo\license_vm.vasm` 的旧单一 VM，2026-08-09 拆为 4 个小 VM）：
**攻击者即使还原全部 VM 也造不出合法授权 key**（私钥离线），这是 THREATMODEL §4 的"离线不可破"锚点。

## 2. 当前验收状态（2026-08-14 实测基线）

一键构建 `powershell -ExecutionPolicy Bypass -File build.ps1` → **DONE**，零 warning。
`tests\e2e.py` 与 `tests\attacks.py` 在 A2/A3/A4/A5 之后实测：

```
T1 normal-ok      PASS  T2 normal-bad   PASS  T3 debug-detect SKIP(需真机)
T4 tamper-detect  PASS  T5 vm-unit-ops  PASS  T6 multi-run-stable PASS (8/8)
T7 selftest-clean PASS  T8 license-forge PASS
T9 tamper-rdata   PASS  T10 tamper-pdata PASS   (A3: .rdata/.pdata 篡改也 0xBAD)
T11 watchdog-stable PASS                              (A5: 14s 驻留周期复查零误报)
T12 tier-forge    PASS                                  (Phase 4: 改 TIER 行被拒)
T13 blob-missing  PASS  T14 blob-tamper PASS   (DBI launcher: blob 缺失/篡改 0xB10B)
T15 revoke-hit    PASS  T16 revoke-clean  PASS          (I1: 黑名单命中 0xB1E4)
T17 revoke-absent PASS  T18 revoke-corrupt PASS T19 revoke-warn PASS
A1 machine-bind   PASS  A2 vm-ciphertext PASS  A3 build-fingerprint PASS
A4 selftest-clean PASS  A5 license-forge PASS  A6 license-other-machine PASS
A7 tier-forge     PASS                                  (Phase 4 attacks 面)
syscall_probe     PASS                                  (A6: 直调 == API 路径)
```
Release 构建: 签名验证通过 (signtool verify /pa); 可复现验证通过
(verify.ps1 -Reproducible: 无签名产物字节一致)。

`verify.ps1 -Minimal`（单轮全链回归）此前亦 **PASS**；`verify.ps1`（3 轮随机重建）
是发版 gate（B3 待真机后启用）。A2 落地后连续 8 轮随机重建 e2e 全绿
（BE/LE 操作数序与 4 种折叠公式均被实际覆盖）。

被测行为要点（黑盒断言，勿破坏）：
- 正确序列号 + 有效 `--license-file build\license.txt` → 输出 `license: 1 (tier=1)` 与
  `校验通过`，退出码 0；无 license 参数时 license_ok=1（旧行为兼容）。
- 错误序列号 / 改 1 位签名 / 改 TIER 行 / 异机 license → `license: 0`，退出码 1。
- 篡改 `.text`/`.rdata`/`.pdata` → 0xBAD；调试附加 → 0xDB；看门狗 5s（±40% 抖动）
  周期复查完整性 + 反调试。

## 2.5 当前验收状态（2026-08-30 增量）

### 构建与回归
- `build.ps1` 一键 DONE；`tools\release_check.ps1` **11/11 PASS**（含可复现、
  e2e T1-T28、attacks A1-A12、vm_unit/vmc/example/protchain）。
- **标准稳定性回归器 `tools\mask_stability_test.ps1`**（真机）：删旧 mask +
  完整管线构建 + UTF-8 判定，3 连建门槛；S1-S5 每次改动后均 3/3 PASS。

### 本轮能力增量（S1-S5/S2/A2/签发）
- **S1 selfcrypt 扩容**：meta 24B 组化 + EXT 组包裹；**落地 2 枚**
  （blob_load + license_verify 加密）；pdata 边界防御（防写坏邻节）；
  `.protxec` 独立可执行节（解密器/crc32/完整性辅助分页）。
  antidebug/integrity/revoke 三枚 = 页粒度 VP 禁执行自伤技术债（下轮
  PAGE_ALIGN 专项）。
- **S2 运行时密钥多样性**：`prot_vm_rekey` 装载后内存差分流重编码——
  每次运行密钥域不同（实证 A/B 两次不同），blob 文件/签名不变。
- **S3 平坦化试点**：`prot_antidebug_detected` switch-dispatch 状态机
  （语义等价，7 关键项含 ppid）。
- **S4 字符串收敛**：HWID 格式 / revoke 提示 / 在线 URL 模板入 strcrypt
  表（exe 扫描已无这些明文）。
- **S5 反调试 +2 维**：父进程调试器黑名单（关键项）+ 墙钟-tick 漂移
  （咨询项）；真机 selftest 0 误报。
- **A2**：`// @vmcalc` 业务函数自动 VM 化（c2vasm 翻译器 + 桩 + blob 同链）
  已落地（golden 6/6 + flow test 11/11 + 真机 hashcalc 验收）。
- **签发体系**：Ubuntu Server（离线签发机，主机名已脱敏）离线签发 + GUI 签发台（本机
  桌面快捷方式）+ 台账哈希链/重放拦截/字段卫生（D-D1/D-D2/D-D4）。
- **ShardVase 公开面**：GitHub 仓库（auui-LDAH/ShardVase-*）+ 演示包
  v1.0（hashcalc + 评估授权）+ 文档（能力/边界/攻防记录）。
- **攻防矩阵**：drill6（签发链路）、sdk1（骨架产物 14 项）、sdk2
  （vmcalc 面 M11/M12）、sdk3（回归全绿含 M4 换机）。

### 待办（详见各计划文档）
- S1 三枚 PAGE_ALIGN 专项；S3 扩展；AV/兼容矩阵（VM 暂停中，用户手动接管）；
  VirusTotal 手动上传；文章发布；HANDOVER 随版本持续更新。

## 2.6 迁移后状态（2026-09-20 增量）

> 完整报告见 **`docs/迁移核验-2026-09-20.md`**（含核验方法、纠错留档、放弃方案评估）。
> 本节只摘录下一位开发者**接手即需知道**的内容。

### 环境（新机）

| 项 | 值 |
|----|----|
| 主机 | `<开发机>` / 用户 `<用户名>` / Win11 26200 x64 |
| 仓库路径 | `D:\specifically for development and work\Reverse Engineering`（含空格） |
| 工具链 | `D:\environment\VS2022BuildTools`（MSVC 14.44）+ `D:\environment\PYTHON`（3.13.13）——**均不在 PATH**，`build.ps1` 自动探测可命中 |
| 生产私钥 | ✅ 已随迁移带入 `build\keys\license_priv.json`（RSA-3072）——沿用同一把密钥 |
| machine_id | `12981648366597980211`（`demo\vm_build.json` 一致） |

### 已修复（提交 `24335c4` / `dc4d15b`）

| # | 缺陷 | 要点 |
|---|------|------|
| 1 | **selfcrypt meta 步长 20B → 24B** | S1(`855b9a9`) 改了格式但解析侧未同步，**3 文件 8 处**：`protchain_check.py`(P1/P2 FAIL)、`attacks.py`、`attack_drill.py`（后者 5 处为**静默假绿**——错位 rva 恰不命中目标 → 报 PASS）。修法：建单一入口 `protchain_check.selfcrypt_meta()`，其余复用 |
| 2 | **SDK 骨架缺 3 项字符串** | `prot_sdk/skeleton/strings.txt` 11→14 项；`strgen.py:108` 严格 `raise` → 向导生成的新工程**构建即失败**。同步修 `strgen.FALLBACK_ORDER`（9→14） |
| 3 | **`build.ps1` 冒烟自检必然失败** | 两个独立成因：(a) `EAP=Stop` 下 stderr 重定向(`2>&1`/`2>$null` 均然)被包装成终止性异常；(b) PS 管道向原生 stdin 写 BOM。改用 `cmd /c`。**此前未暴露因所有门禁都带 `-SkipSmoke`** |
| 4 | **编码损坏（有损，不可逆）** | `855b9a9` 引入：UTF-8 字节被 CP936 有损解码（产生 U+E21B 等私用区）。已修**全部字符串字面量**（全库 62 个 `.c/.h` 扫描 = 0）+ BOM + 首行注释；**224 行纯注释乱码保留**（零功能影响） |

### 接手须知（踩坑纪律）

1. **不要试图「重建」乱码文件的注释**。已证伪：用干净祖先做骨架对齐重建后
   **能编译**，但 `e2e T1` 失败（`exit=1` 而 `license_ok=1`）——乱码吞换行，
   还原时丢 `*/` 终止符，注释边界与 `demo_mem` 相关宏行序被改变。
   **ASCII 骨架一致 ≠ 语义等价。**
2. **检测工具的准确性本身要验证**。初版乱码扫描用正则剥注释，无法处理
   「字符串内出现 `/*`」，漏检了 `app_main.c:740`；换带字符串状态机的剥离器才扫净。
   同理：仅查 `U+FFFD` **不足以**判定双重编码（产出的是合法字符，含 PUA）。
3. **`.ps1` 必须保留 UTF-8 BOM**（PS 5.1 无 BOM 时按 GBK 解析，破坏中文字符串，
   见 `72b75eb`）。**编辑工具会静默去掉 BOM**——改完 `.ps1` 后务必复查首 3 字节
   `EF BB BF`。
4. **`build.ps1` 冒烟测试现在裸跑可用**（无需 `-SkipSmoke`）。跨机绑定构建
   （运行机 ≠ 构建机）仍应显式带 `-SkipSmoke`。
5. `release_check` 的「11/11」= 10 个 `Check` + `codesign.pfx` 存在时签名块 `pass++`。

### 验收基线（迁移后实测，五提交后）

```
build.ps1（裸跑，无 -SkipSmoke）  DONE (exit 0)
release_check.ps1                 11/11 PASS
e2e                               27 PASS / 0 FAIL / 1 SKIP (T3 需交互式桌面)
attacks                           A1-A12 全 PASS
protchain                         6/6 PASS
vmc / c2vasm golden / vm_unit / syscall_probe / example   全 PASS
全库乱码字符串字面量               0
```

### 迁移后待办（承接 §4.3，未变）

`release_check` 全量实跑（现已可裸跑）／Android **NDK 交叉编译 ✅ 2026-10-06** + T1 真机攻防矩阵／
GitHub 真实 push 后 CI 实跑替换 `ci_sim`／Defender 引擎修复（DISM）／
W2 长驻留实跑／T3 真机（需**交互式桌面**，SSH 与计划任务均被 session 0 拒绝）。

## 2.7 模块化框架进度（2026-09-20 起）

> 总纲见 **`docs/BLUEPRINT.md`**（目标/路线图/验收）
> 架构细节见 **`docs/MODULAR_ARCH.md`**
> 本节只记"做到哪了、下次从哪继续"。

### 已完成阶段

| 阶段 | 内容 | 提交 |
|------|------|------|
| 0 | SCDBG 调试日志改为 opt-in（Release 不再泄漏 RVA/密钥/CRC） | `ab873f4` |
| 1 | 模块注册表 `modules.json` + 校验器 `tools/modcheck.py` + 四档 `compositions/`，接入门禁 | `5a1c4bc` |
| 2-构建层 | `tools/compose.py`（拼装图→源文件/宏/头文件）+ 宿主下限链接器实测 | `a5c6e54` |
| 2-宿主批1 | `vmdetect`/`dbiguard` 条件编译（实证：13→11 模块，产物省 3584B） | `72f0de6` |

### 门禁基线

`release_check` 现为 **12 项**（新增「模块契约 (modcheck)」），全绿。

### ⬜ 下次继续：阶段 2 宿主批2

**起点文件**：`demo/main.c`（批1 已插入 3 处 `#ifdef`，模式可复用）

**待处理模块**：`antidebug` / `integrity` / `indirect` / `revoke`

**三类已知难点**（详见 `BLUEPRINT.md` §5 阶段 2）：

1. `rep` 变量跨函数共享（`main()` 声明 → `print_selftest()` 使用）
2. `selftest` 在全部相关段排除后会变 unused → `/WX` 报错
3. ⚠️ **`selfcrypt_proto.py` 的 `EXT_TARGETS` 硬编码** `prot_integrity_check_self`
   与 `prot_antidebug_scan`；组合排除这两个模块会导致 `.map` 中找不到符号 →
   构建失败。**这是"组合"与"自加密"的真实耦合点**，批2 的核心工作。

**纪律提醒**（本期血泪）：
- 改 `.ps1` 后必须复查 UTF-8 BOM（`EF BB BF`）—— 编辑工具会静默剥离，
  导致 PS 5.1 按 GBK 解析、中文损坏 + 语法假错
- 验证组合开关必须**重新生成 `prot_modconfig.h`**，叠加命令行 `-D` 无效
  （头文件已定义的宏，命令行只能增加不能删除）
- 改 `.text` 相关代码后跑 3 连建稳定性门槛（布局敏感是已知雷区）

## 2.8 平台隔离与验证加固（2026-09-29 增量）

> 本轮**完整记录**见 **`docs/阶段总结-2026-09-29.md`**（含技术沉淀与交接要点）
> 逐项细节见 **`docs/PLATFORM_ISOLATION_PLAN.md`** §34.6、§35–§40
> 审计快照见 **`docs/STAGE_AUDIT.md`**

### 本轮完成（10 提交）

| 步 | 内容 | 提交 |
|----|------|------|
| 清理 | flat 目录清理（38 文件）+ 2 处隐藏依赖修复 | `d633afa` `fdb2f7e` |
| D2 | **并发状态锁**（门禁↔ci 互斥，自检 6 项/3 负向） | `8eca3bc` |
| D3 | **判据盲区固化**（padding⊆json、flat 无残留；自检 6→8） | `4b4a31c` |
| D1 | **Linux 检查器健康**（mutate 6 健康/0 盲 + 镜像 7 项进 ci） | `98b47e5` |
| D4 | **攻防矩阵复核**（BREACHED 6→4；PARTIAL 3→BLOCKED；**V2 修复**） | `d6a6219` `b5f3891` |
| 审计 | 阶段审计 + 计划章节标题回填 | `f5d9395` |

### 门禁基线（本轮后）

```
release_check: **25 项**（新增「验证互斥锁自检」）· 全绿
ci_linux:      **20 项**（运行时 12 + 镜像 7 + 变异 1）· PASS
```

### ⬜ 下次继续：候选方向（**均非阻塞**）

1. `S5` 台账**外部锚点**（跨机校验，使"整文件删除"从不可检变可检）
2. `L4` 单调时钟（需权衡**误报风险**：正常对时/NTP 校正会被拒）
3. 攻防面扩大（新攻击链组合）

### 纪律提醒（**本轮新增**）

- **验证必须串行**：门禁与 ci 共享可变状态（`demo/gen/`、`build/`、
  `demo/vm_build.json`）-> 已用锁强制；拿不到锁会**明确报错**而非排队
- **改动后立即 `ParseFile` / `py_compile`**：本轮 4 个语法级问题都是一步抓到的
- **判据用唯一结构形态**：宽松子串匹配已造成 **4 次假阳性**
- **复用他模块函数时连同隐式上下文一起设**（`_CURRENT_EXE` 事故）
- **攻防矩阵是动态证据**：防御落地后**必须回填**（否则持续低估自身能力）

## 3. 迁移到其他电脑 — 交接清单

### 3.1 需要带走 / 确认的东西（**必须**）

| 项 | 说明 | 是否入库 |
|----|------|----------|
| 整个 git 仓库（含 `docs/`、`src/`、`tools/`、`tests/`、`demo/*.vasm`、`build.ps1`、`verify.ps1`） | 迁移核心；CI yaml 也含 | ✅ 全部已提交（`git status` 干净） |
| Python ≥ 3.8（标准库即可，无三方依赖） | `vmenc.py`/`strgen.py`/`hashpatch.py`/`tests/*.py` 均只用 stdlib | 环境项 |
| VS2022（BuildTools 或 Community，勾选"C++ 生成工具/桌面开发"） | 编译需要；`build.ps1` 现支持 **vcvars 自动探测**（vswhere + 常见路径），也可 `-VcVars <path>` 显式给 | 环境项 |
| 私钥备份 `build\keys\license_priv.json`（**可选但建议**） | 若想沿用同一把生产私钥签发 license，需手动复制；**不复制时新机 build.ps1 会重新生成一把新私钥**（不影响演示，但历史 license.txt 全部失效） | ❌ gitignore（绝不入库） |

### 3.2 新机器首次构建步骤（已验证步骤）

```powershell
# 1. 装 Python（PATH 里有 python）+ VS2022 C++ 工作负载
# 2. cd <仓库>
git status                 # 确认干净
powershell -ExecutionPolicy Bypass -File build.ps1
#   vcvars 自动探测; 如需指定:  -VcVars 'C:\...\vcvars64.bat'
#   python 自动探测 (跳过 WindowsApps 存根, 含 D:\environment\PYTHON); 如需指定: -Python <path>
powershell -ExecutionPolicy Bypass -File verify.ps1 -Minimal
python tests\e2e.py
python tests\attacks.py
```

应得到与 §2 相同的全绿结果（除 T3 SKIP）。**注意**：新机 machine_id 不同，
`demo\vm_build.json` 会被 `genserial --machine-id auto` 自动重写（这是设计行为，
启动演示前无需手工改）；`build\license.txt` 也会对新 machine_id 重新签发。

### 3.3 跨机应当知道的行为差异

- **机器绑定是"本机"语义**：换机后旧 `license.txt` 一定失效（这是 A1 的目标，
  不是 bug）。要复用同一把私钥 → 拷 `build\keys\license_priv.json` 过去。

#### 迁移决策: 私钥带不带？（换机前定，一锤定音）

| 场景 | 做法 | 后果 |
|------|------|------|
| 纯演示 / 继续开发 | **不带**。新机 build.ps1 自动生成新私钥并重新签发 | 新旧 license 互不通用（本机语义，本来就应如此）；私钥永不外泄 |
| 生产遗留授权 / 正式发版 | **带**（安全通道复制 `build\keys\license_priv.json` 到同相对路径） | 同一把私钥继续签发，历史已下发 license 若绑定同一 machine_id 可继续用 |

> 无论带不带：**私钥永远只存在于 `build\keys\`（gitignore），禁止提交/进 CI 产物。
> 私钥外泄 = 防伪造全盘失效（THREATMODEL §4 的锚点崩塌）。**

- `manifest.json` 每构建重写（跑 git 引用、镜像种子指纹、exe SHA256）。
- T3 在新机（真机）可尝试：`python tests\e2e.py` 应把 SKIP 转 PASS/FAIL
  （真实 attach 依赖环境）。
- CI `ci.yml` 只在推到 GitHub 远程后生效（B2 待办）。

## 4. 重要知识 — 交接给下一位开发者

### 4.1 契约/事实来源（务必先读）
- `docs/CONTRACT.md` — 唯一事实来源：算法（滚动密钥流/CRC/FNV/xorshift/GOLDEN）、
  VM 指令表 0x00-0x2A、demo_mem 布局（+88 license_ok，总 96B）、退出码、
  构建管线、A1 验签细节。
- 任何"两侧不一致"的改动（vmenc.py ↔ vm.c ↔ license.h ↔ CONTRACT）必须同步，
  否则 T1/vm_unit 直接失败。

### 4.2 A1 RSA 的两个 Windows 硬坑（已在代码与 CONTRACT 固化）
1. `BCRYPT_RSAPUBLIC_BLOB` 必须是 **16B 头 + 8B 零填充 + exponent + modulus**
   的 283B 布局；无 8B 填充 → `BCryptImportKeyPair` 返回 `0x80090005`。
2. `BCryptVerifySignature` 必须传 **`BCRYPT_PKCS1_PADDING_INFO{ BCRYPT_SHA256_ALGORITHM }`**
   而非 NULL；NULL → `0xc000000d`。
3. `PROT_LICENSE_PRODUCT` = `PROT-DEMO-2026`（14 字符），与 `vmenc.py
   LICENSE_PRODUCT` 必须逐字节一致；消息 = serial ‖ LE64(machine_id) ‖ PRODUCT。

### 4.2b 运维踩坑记录（2026-08-21；2026-08-26 服务化）
0. **24h 驻留已服务化（2026-08-26）**：真机 `prot_resguard` 服务（NSSM 包装
   `residency_guard.py`）——SERVICE_AUTO_START 开机自启 + AppExit 崩溃自动重启
   + 守护循环保 3 个 demo 实例（被杀自动拉起，实测 RESILIENT）。服务用
   LocalSystem 运行，`run_guard.cmd` 需用 python 绝对路径（用户 AppData）；
   停止/启动：`nssm stop/start prot_resguard`（nssm 在
   `C:\Users\<用户>\nssm\nssm-2.24\win64\`）。
1. **SSH `echo | demo` 不可靠**：SSH 会话中 `echo xxx | exe` 的 stdin 传递异常，
   会导致 demo 读到不干净的 serial → 误判 license: 0。**验证必须用
   Python subprocess**（e2e.py 的方式），否则会误报"验签失败"。
2. **真机 hostid 随构建因子变化**：D5 硬件因子（MachineGuid/磁盘序列号）使
   hostid 与早期构建不同；跨机构建必须用目标机的 `--machine-id`（从运行期
   hostid 获取）。**构建机与运行机必须用同一 mid，否则 license/EXPECT 全拒。**
3. **T3/调试附加需交互会话**：SSH、计划任务（含 SYSTEM）下 `DebugActiveProcess`
   均返回 0x5 —— Windows 会话隔离，非权限问题，无法提权绕过（见 §4.5）。

### 4.3 未完成事项（下一位的待办）
| 优先级 | 项 | 状态 |
|--------|----|------|
| 阶段 II 剩余 | T3 真机调试（**2026-08-24 真机复验仍 SKIP**：SSH 会话限制，DebugActiveProcess rc=1——需**交互桌面会话**）；硬件绑定双机 **PASS**（本机产物在真机拒绝） | T3 待桌面会话；双机已验 |
| CI | **CI 增强已完成（2026-08-22）**：protchain_check.py P1-P6 静态断言 + vmc/example 覆盖 + reproducible job（同种子比对）—— 见 docs/CI_PLAN.md；首次远程 CI 运行结果待回填 compat-matrix.csv | 远程运行待验证 |
| 阶段 III | 服务端（可选）—— 详细计划见 **docs/PHASE3.md**；决策点 D2 已定离线优先（M3.1 已完成） | 未开工（按 D2 不启动 M3.2/M3.3） |
| N1 真机复核 | **✅ 完成（2026-08-24）**：D2b 高频 SMC 真机无杀软拦截，e2e T1/T6/T11 全过 —— 见 docs/N1_PHASE2_PLAN.md §8 | 完成 |
| 攻击模拟扩展 | **A8-A12 已实现（2026-08-22）**；**2026-08-24 真机 A1-A12 全 PASS**（含 A8/A9/A12 进程类）—— 见 docs/ATTACK_PLAN.md | 完成 |
| 批量攻防演练 | **batch red-team 已实施（2026-08-25）**：6 类 23 项，真机 15 BLOCKED/0 BREACHED/8 PARTIAL/0 SKIP；内存类疑难项已修复（psapi）全有结论 —— 见 docs/ATTACK_DRILL.md | 第一轮完成 |
| 第二轮攻防演练 | **完整 13 项 4 BLOCKED/9 PARTIAL/0 SKIP（2026-08-25 真机）**：E2-2 N2 EXIT 策略生效（0xDB，新增 --dbiguard-policy）；D3-2 D2b 间隙重加密确认；**G2 边界已补洞**（IAT 运行期快照校验，改写 1.9s 识破 0xBAD）；G4/G6 伪造/畸形 blob 拒绝 —— 见 docs/ATTACK_DRILL2.md | 完成 |
| 第三轮攻防演练 | **9 项 7 BLOCKED/0 BREACHED/2 PARTIAL/0 SKIP（2026-08-25 真机）**：组合链 C1-C5 全拦（G2/D1a/签名/复查）；暂停+改 IAT 不可绕过（快照提前设计）；驻留注入被周期检测（0xDB）；零误杀 —— 见 docs/ATTACK_DRILL3.md | 完成 |
| 攻防累计 | 三轮 45 项全结论（第一轮 23 + 第二轮 13 + 第三轮 9），**显式破防 0 项**，已知边界 3 类（D2a 明文 dump/离线可 patch/内存 patch 非文件 CRC） | 完成 |
| 第四轮攻防演练 | **10 项 6 BLOCKED/0 BREACHED/4 PARTIAL/0 SKIP（2026-08-25 真机）**：verify 语义还原成功（设计已知）但单镜像不足以通过；Procdump 16.9MB 明文在场（D2a 边界）；精确挂线程崩溃防绕过；DR 不可用户态清；重放被 N5 拒 —— 见 docs/ATTACK_DRILL4.md | 完成 |
| 攻防累计 | **四轮 55 项全结论（23+13+9+10），显式破防 0 项**；已知边界 4 类（D2a 明文 dump/离线可 patch/内存 patch 非文件 CRC（G2 已补）/单镜像可还原（多 VM+N5 阻断））；还原工具 vm_reduce.py + 取证转储 procdump_like.py 已建 | 完成 |
| D5/E5 补充 | **DLL 劫持（D5）BREACHED（环境下：同目录 winhttp.dll 影响运行——结论=安装目录 ACL 只读）**；VEH 覆盖（E5）PARTIAL（需注入前提，G1 已覆盖）—— 见 docs/ATTACK_DRILL5.md | 完成；**部署约束：安装目录 ACL 只读** |
| 平台延申 | **Android 原生 SO（A）+ 跨平台许可服务化（C）—— 完备计划见 docs/EXTENSION_PLAN.md**（C1/A1/A2/A3 源码就绪；**NDK r28c 交叉编译已通过，2026-10-06**，含修复 5 处缺陷） | 源码就绪 + NDK 交叉编译通过，真机待测 |
| 基础设施完善 | **I1-I6 全部完成（2026-08-26）**：ci_sim 本地 CI 模拟 / repro_check 统一 / release_check gate / build.ps1 --help+校验 / clean_build / changelog —— 见 docs/INFRA_PLAN.md | 完成 |
| **剩余待办（迁移）** | ① release_check 全量实跑 **✅ 已完成（2026-10-02 复跑：默认 30 项全 PASS，含 `-With*` 共 33 项）** ② Android T1 真机攻防矩阵（**NDK 环境已具备**，仅缺真机/root）③ GitHub 真实 push 后 CI 实跑替换 ci_sim ④ EXTENSION A 的 NDK 实编 **✅ 2026-10-06 已完成**（含 5 处缺陷修复）⑤ Windows 侧 W2 长驻留实跑验证 + Release D2b 真机确认 | 见对应文档 |
| Windows 侧增强 | **W1-W4 已实施（2026-08-26）**：Release 默认 D2b（-NoD2b 回退）+ watchdog 周期回调（N3 冗余 + dbiguard 周期，FAKE 翻转 sum 修复）+ ACL 部署要求 + Release 错误收敛 —— 见 docs/WIN_ENHANCE.md | 完成（长驻留实跑验证待） |
| 清理 | `demo\license_vm.vasm` 为历史遗留（已被 4 小 VM 取代），保留作参考 | — |
| verify 增强 | **verify.ps1 已同步 protchain 保护链断言（2026-08-22）**：本地门禁=CI 门禁；附带修复 example 适配 BLOB_SIGN（容器移 selfcrypt.c + pack/revoke --sign）—— 见 docs/VERIFY_PLAN.md | 完成 |

### 4.4 阶段 II 实测记录（2026-08-21；2026-08-24 真机复验全能力）
- 真机（独立测试机，主机名/内网地址已脱敏，Win11 家庭版 24H2 26200，2026-08-24 复验）：
  **verify -Minimal 全绿**（build/e2e/vm_unit/syscall_probe/attacks/vmc/example/protchain）；
  e2e T1-T28 除 T3 全 PASS（T10 tamper-pdata 真机 PASS，本机 WDAC SKIP 补齐）；
  attacks **A1-A12 全 PASS**（含本机 WDAC 无法跑的 A8/A9/A12——伪造 blob/revoke 拒绝、N5 边界）；
  N1 **D2b 真机复核 PASS**（高频 SMC 无杀软拦截，e2e T1/T6/T11 全过）；
  双机绑定 PASS（本机构建 exe+blob+license 在真机 exit=1 拒绝）；
  24h 驻留 **PASS（2026-08-27 确认：batch-1 满 1440 分钟零误杀，batch-2 已自动续跑）**；
  **T3 仍 SKIP**（SSH 会话限制，DebugActiveProcess rc=1）。
  真机新装 VS2022 BuildTools（原无编译器）；**无 git** → build.ps1/verify.ps1 已加 git 容错。
- 真机（oiahcoiah，Win11 24H2 26200，2026-08-21）：e2e T1-T24 除 T3 全 PASS；attacks A1-A7；vm_unit；syscall_probe；
  24h 驻留通过（3 进程存活 >24h 零误杀）；**无 WDAC**；篡改检测（T4/T9/T10）真实运行。
- 攻击模拟（个人破解者视角）：字符串搜索（中文消息全加密）、静态结构（断源生效）、
  授权伪造/篡改/试用期绕过——**全部拒绝**；发现的静态串暴露已加固（`38d8a21`）。
- **SSH/计划任务下 T3 不可行**：`DebugActiveProcess` 在 session 0 被拒（0x5），
  普通用户与 SYSTEM 均如此——Windows 安全模型，非权限问题。

### 4.5 已知环境限制（非代码缺陷，勿当 bug 排查）
| 限制 | 说明 | 解锁条件 |
|------|------|---------|
| T3 真机调试 | 需**交互式桌面会话**（有人登录/RDP）；SSH、计划任务（含 SYSTEM）均被 session 0 拒绝 | 真机桌面或 RDP 登录后跑 `python tests\e2e.py` |
| 硬件绑定双机 | 换机拒绝已在单机验证（异机 mid 产物被拒），但"双机实跑"需第二台物理机/VM | 第二台机器（PHASE2 P2-5 用例已备） |
| 本机 WDAC | 托管 VM 启用 Application Control，新构建 exe 偶发被信誉拦截（4551）；verify 已做 SKIP 容错 | 无 WDAC 环境（真机无此问题） |

### 4.6 常用命令速查
```powershell
powershell -ExecutionPolicy Bypass -File build.ps1            # 构建 + 单测 + manifest
powershell -ExecutionPolicy Bypass -File verify.ps1 -Minimal  # 单轮冒烟 (build+e2e+vm_unit+attacks+vmc+example)
powershell -ExecutionPolicy Bypass -File verify.ps1           # 3 轮随机重建回归 (发版用)
python tests\e2e.py && python tests\attacks.py                # 直接跑两套测试
python tests\vmc_tests.py                                     # vmc 编译器单测 (M2/M3)
python examples\tool_demo\test_example.py                     # 接入示例 E1-E7 (保护 SDK 验收)
python tools\vmenc.py genserial --json demo\vm_build.json --print  # 看 machine_id/expect
python tools\vmenc.py sign --key build\keys\license_priv.json --json demo\vm_build.json --out build\license.txt
"DEMO-2026-ABCDEFGH" | .\build\demo.exe --license-file .\build\license.txt  # 手动演示
```

## 5. 关键文件索引

| 路径 | 作用 |
|------|------|
| `include/protect/*.h` | 契约头（protdef/vm/antidebug/integrity/strcrypt/hostid/license/revoke/vmdetect/dbiguard/blob/version），勿改 |
| `src/*.c` | 实现（vm/crc32/antidebug/integrity/strcrypt/hostid/license/revoke/vmdetect/dbiguard/blob/syscall） |
| `tools/vmenc.py` | 汇编器+加密器+genserial+hostid+RSA keygen/sign/issue/revoke/pack |
| `tools/indirect.py` | N4 函数级间接化生成器（槽位随机化指针表，种子可复现） |
| `tools/vmc.py` | 类 C 编译器 -> VM 字节码（M2），--seed 栈随机化 + --flatten 控制流平坦化（M3） |
| `tools/strgen.py` / `tools/hashpatch.py` / `tools/mock_server.py` / `tools/osinfo.py` | 字符串加密 / CRC 烧录 / 在线验证 mock / 系统信息 |
| `demo/*.vasm` | 4 个 VM 源（hash/mix/verify/gate）+ `examples/tool_demo/check.vmc`（类 C 接入示例） |
| `demo/vm_build.json` | 序列号/机器标识/期望值（每构建重算，换机会变） |
| `tests/` | e2e.py(T1-24) / attacks.py(A1-7) / vmc_tests.py / vm_unit.c+brk / syscall_probe.c / vmdetect_probe.c |
| `examples/tool_demo/` | 保护 SDK 接入示例（build_example.ps1 + test_example.py E1-E7） |
| `docs/` | CONTRACT/PLAN/ROADMAP/THREATMODEL/PRODUCTION/BUSINESS/RELEASE/OPS/COMPAT/PHASE2/PHASE3/ADVANCED/ADVANCED2/HANDOVER |
| `docs/` | CONTRACT / PLAN / ROADMAP / THREATMODEL / PRODUCTION / **BUSINESS（总纲）+ RELEASE + OPS + COMPAT（商业化文档体系，2026-08-14）** / HANDOVER(本文件) |
| `build/`（gitignore） | 产物 + manifest.json + keys\（私钥） |

### 2.9 增量（2026-09-29 晚 – 2026-09-30）：REFINE_PLAN 全阶段 + R3.2 反向结论

**本阶段完成**：R1（决策留痕）· R2.1/R2.2/R2.3（可用性）· R3.1（对抗实证）·
R3.3（PARTIAL 复核）；**R3.2（判定点冗余）出计划并实施前两组，
当日先得出反向结论、随后由实测更正为"守卫有效"**（见下方接手须知第 1 条）。

**门禁 32 项**（新增 26–32）：
```
26 docclaim        文档断言一致性（断言值从文档解析，含"最后核实"元数据要求）
27 deploy_harden   部署加固自检（ACL 加固 -> L3/D5 攻击必须被阻断）
28 perf_baseline   性能基准自检
29 guard_selftest  判定点快照校验自检  <- **已 PASS（判据 = g_guard_hits；见下更正）**
30 prot_dbg        调试控制台自检（**第 1 步** doctor/sym/mask/exit；纯只读）
31 gate_log        门禁日志自检（本轮输出落盘 `build/logs/`；见下第 4 条）
32 prot_dbg live   调试控制台活体自检（第 2/4 步；OpenProcess/WriteProcessMemory）
```

#### ⚠️ 接手须知（**最重要**）

1. ✅ **更正（2026-09-30 晚）：门禁第 29 项现在 PASS，守卫机制已被证明有效。**
   当日早些时候记录的"`g_guard_hits` 恒为 0 ⇒ 守卫从未命中"**是测量假象**，
   根因有三层（`docs/DECISION_REDUNDANCY_PLAN.md` **§11**）：
   ```
   · map 正则形态假设错 -> 只解析出 948/2989 个符号
   · 用链接偏好基址 0x140000000 读进程 -> ASLR 已生效(真实 0x7FF6860A0000)
   · 采样间隔 120ms，而 hits 的自增与 terminate 在**同一 tick 内** -> 必然错过
   真实根因(src/integrity.c:163-173): selfcrypt_enter 失败 -> `continue;` **整轮跳过**
     -> 掩码区内目标(license_verify/check_self)被 patch 的是**密文**
     -> selfcrypt 自己的 per-region CRC 先失败 -> 守卫(L211)根本没跑
   ```
   把运行期 `g_wd_policy` 置 CONTINUE（模拟"段 CRC 已被中和"）后实测：
   `prot_antidebug_detected`/`prot_dbiguard_suspicious`/`prot_vmdetect_suspicious`
   三个掩码区外目标的 `g_guard_hits` 稳定增长（3/4/3），tamper 每 tick +2，
   与预测**定量吻合**。`guard_selftest` 重写后 **PASS（正向 0 / 负向 3）**。
   > **仍不要**为了让门禁变绿而删项 —— 但这次红线是**测量**：
   > 任何"读不到 / 恒为 0"的结论，**必须先用一个已知非零的靶子证明读取链路是通的**。

2. **R3.2-a 的发现仍然有效**（静态可复现）：
   `prot_integrity_check_self` 与 `prot_license_verify` **落在 selfcrypt 掩码区内**
   -> 段 CRC 先清零该区 -> **改它们不影响 CRC**。
   其中 `check_self` 是"**校验器不在自己覆盖范围内**"的自我指涉缺口。

3. **新待办：调试控制台** —— `docs/DEBUG_CONSOLE_PLAN.md`
   （用户 2026-09-30 提出；本轮手工做的 map 符号解析 / ASLR 换算 / 掩码归属 /
   运行期变量只读观测，**正是它的 `sym`+`mask`+`watch` 子命令**，
   而本轮踩的 3 个测量坑应收进它的 `doctor`）。
   > **进度（2026-09-30）**：**第 1 步已交付** —— `tools/prot_dbg.py`
   > （`doctor`/`sym`/`mask`/`exit`，**纯只读**）+ 门禁第 30 项。
   > 判据就是上面第 ② 条的固化: `doctor` 做**正向对照**（map 符号必须落进
   > 产物节区间），且**空 map / 格式不识别 / 解析出 0 符号分别报错、都不许 PASS**。
   > 价值已当场兑现: R3.2 会话里花 3 个失败探针才拿到的 8 个掩码区 + 5 个区内
   > `prot_*` 符号，现在 `mask` **一条命令**给出且**逐字吻合**。
   > 第 2 步（`patch`/`read`/`watch`）、第 4 步（反调试提示）**已于 2026-10-01 交付**
   > （提交 `5e7340b` + 门禁第 32 项，见下方 **§2.10**）；
   > 第 3 步（诊断构建）**降级为可选**（§5 已更新依据）。

4. **门禁现在会落日志**（2026-09-30）—— `tools/gate_log.ps1`
   ```
   为什么: 实测事故 —— 一次门禁报「1/29 未通过」，但调用方只截了 `-Last 6` 行,
           失败项名与详情**永久丢失** -> 此后连跑 5 轮**无法复现、无法定位**。
           （与 R2.3 记名的「诊断信息不可丢失」同型）
   现状:   门禁/ci_linux 每轮输出落盘 `build/logs/<name>_<时间戳>.log`
           （`build/` 已 gitignore），开头与结尾各打印一次路径。
   机制:   `Start-Transcript`（实测: Write-Host 裸调用 / `& { … } | Out-Null` 内 /
           `Check` 内部详情行 / `[ok]`/`[X]` 行 / `Write-Output` **全部落盘**）。
   ⚠️ 诚实边界: 日志记的是**门禁自己的控制台输出**。被 `Check` 里 `| Out-Null`
           吞掉的**子进程 stdout 不在其中** —— 现在至少能知道**哪一项**失败，
           详情仍需单独重跑该项。
   ⚠️ 已实测的两条坑: ① 自检要 start/stop 转录，而转录是**会话级**的 ——
           同一会话里跑会把**门禁这一轮**的日志掐断（同 verify_lock 自检删掉门禁
           锁那类事故）=> 检测到外层转录时**换子进程**跑自检（门禁输出里会打印
           `[gate_log] 检测到外层转录 -> …`）；② 子进程的 `Write-Host`
           **不进父进程转录**（所以子进程跑的自检横幅不在日志里，属预期）。
   ```

#### 本阶段最值钱的八条教训

```
① **判据必须打在被测对象的检测域内**（我犯了两次）
   R3.2-b 用"退出码 == 2989"判"守卫生效" -> 那是 **.text CRC** 的功劳
   （看门狗顺序: check_self L175 **先于** check_guards L211）
   改用守卫自己的计数后 -> 5/5 全为 0 -> 上轮结论被推翻。

② **"读不到" ≠ "不存在"**（同一小时内我连犯三次 —— 最贵的一条）
   map 正则形态假设错 / 用偏好基址读 ASLR 后的进程 / 采样间隔大于事件间隔
   => 任何"读不到 / 恒为 0"的结论，**必须先用一个已知非零的靶子证明链路是通的**。
   => 更要命的是: 由此得出的**假反向结论**看起来"诚实"，
      比假阳性更难被发现（它会伪装成项目最推崇的"诚实失败"）。

③ **诊断信息不可丢失**（R2.3）
   smoke 只重定向 stdout -> 日志 0 字节 -> 原因不可见。
   修好同时读 stderr 后，**立刻**暴露出真正的根因（参数被空格拆词）。

④ **把纪律"写进注释"不等于"写进了代码"**（2026-09-30，`tools/prot_dbg.py`）
   我在文件头把"读不到 != 不存在"写成头号纪律，代码里却把三个分支写成
   `if self.map_lines > 0: ...` —— 于是**空 map 会静默 PASS**（0 个符号还报通过）。
   抓住它的是自检 **T7（负向）**，不是我的复查。
   => 纪律必须落成**可执行的负向判据**；写下来的纪律仍然会漏。
   => 且**自检要先写"必须失败"的用例**：只写正向用例时，这个洞会一路进仓库。

⑤ **判据失败时留下的证据，比判据本身更值钱**（2026-09-30，`tools/gate_log.ps1`）
   门禁不落日志 -> 一次 1/29 失败因输出被截断而**永久丢失现场** ->
   此后连跑 5 轮都**无法复现**（不知是哪一项、什么形态）。
   => 任何"跑一次要几分钟、失败不常见"的门禁，**默认必须落盘**：
      否则一个偶发失败永远不会变成可修的问题，只会变成传说。
   => 且新机制自己要有**正向对照**（"开启后写的行必须落盘"）——
      否则"日志里没有"分不清是**没写**还是**没记**。

⑥ ⭐ **为防形式主义而写的检查器，自己会被形式主义骗过**（2026-09-30，`docclaim`）
   `verified-metadata` 探针的**全部意义**就是"要求方法、不许只写日期"，
   但它**没校验提交字段** —— 于是 3 份关键文档长期写着 `提交 \`pending\``
   而门禁全绿。占位符比日期**更隐蔽**：日期至少会显得"旧"，
   `pending` 看起来像"正在做"。
   => 判据要覆盖它自己声称防的那个东西（否则防了个寂寞）。
   => **先证明"修复前的形态会 FAIL"**（`%TEMP%\prove_t6.py` 复现缺陷并字节级恢复）
      —— 否则新自检只是自说自话。

⑦ **改 `.ps1` 必须"先解析、再提交"**（2026-09-30，同一天内踩第 2 次）
   `edit` 工具**会剥掉 UTF-8 BOM**（早已记名）-> PowerShell 5.1 按 GBK 读 ->
   全文件中文变乱码 -> 解析器在 `'[ok]'` 上报
   `Array index expression is missing or not valid` -> **门禁一步都跑不起来**。
   我这次**改完没做解析检查就提交**了 —— 于是"整条防线失效"被提交进仓库。
   => 改完 `.ps1`：`Parser::ParseFile` + 校验前三字节是 `239,187,191`，**然后**才提交。
   => 记名的坑仍然会踩：**纪律要变成提交前的一条命令**，而不是记忆里的一条注释。

   ⑧ 的同伴（2026-10-01，同一天内踩第 3 次 —— BOM 会从**任何**写文件的出口进来）:
     用 `Set-Content -Encoding UTF8 build\commitmsg.tmp` 写提交消息 ->
     **PowerShell 5.1 的 `-Encoding UTF8` 会加 BOM** -> 提交标题带不可见 BOM
     （`git log` 显示成 `﻿fix(gate)!: …`，肉眼几乎看不见，但会污染历史）。
   => 修法: 用 Python **读 `rb`、剥掉 `b'\xef\xbb\xbf'`、`open(...,'wb')` 无 BOM 写回**，
      再 `git commit --amend -F`；并用 `git log -1 --format=%s` 断言
      `s[:3] != b'\xef\xbb\xbf'` 来验。
   => 结论: 本项目里**"写文件"的每一个出口都要查 BOM**（`edit` 剥掉、
      `Set-Content` 加上 —— 两个方向都会出事），不限 `.ps1`。

⑧ ⭐ **门禁自己静默跳过了 10 项，还照打 `PASS`**（2026-10-01，`tools/release_check.ps1`）
   不带任何开关跑，报 `PASS: 19 项检查全通过` —— 而脚本里明明有 **32 个** `Check`。
   根因（二分 14 个历史 ref 定位）: 提交 `abc5edc`（2026-09-27）把一段**纯注释块**
   插进了 `if ($WithMigration) { … }` 的 body，**吃掉了它的 `} else {`** ——
   于是第 23~32 项**全部被罩进那个 if**，只有显式传 `-WithMigration` 才跑。
   实测对照（同一脚本、同一台机器）:
     · 不带开关                        -> `[ok]` 19 行 -> `PASS: 19 项`
     · `-WithSkeleton -WithMutation -WithMigration` -> `[ok]` 30 行 -> `PASS: 31 项`
   => **纯注释块插进 if 体，语法解析器发现不了**（`Parser::ParseFile` 报 0 error）。
   => 两个"数门禁项数"的检查器（含本节第 ⑥ 条那个 `docclaim`）都只数 `Check` 的
      **出现次数**（32 个全对），**没有一个断言它们在顶层**；更糟的是这两项
      **自己就落在被嵌套的区间里**，复发时根本不会运行 —— 守卫必须放在**上游**。
   => 修法: `tools/doccheck.py`（门禁第 13 项，默认必跑）新增结构断言 ——
      逐字符词法扫描（去字符串/去行注释后数括号），任何 `if ($With*)` 的 body 里
      出现 **>1 个** `Check` 即 FAIL。**判据不靠清单**（清单会过时）:
      `$With*` 的意义就是只控制它自己那一个可选项，多出来的必是事故。
   => ⚠️ 这条守卫的**第一版自己就是假的**: 它用"去字符串后的文本"匹配 `Check '`，
      而 `Check 'X' {` 去掉引号后变成 `Check {` -> **一个都数不到 -> 恒返回"无错误"**。
      注入 bug 复现时它照样打印 `[ok] … 32 项均为顶层语句`。
      **是负向测试（人为回退修复、确认守卫会 FAIL）把它抓出来的** ——
      教训: **一个从未被负向测试证明过会 FAIL 的守卫，等于没有守卫**，
      它只是把"没有防线"包装成了"防线全绿"。
```

#### 本阶段新增/修改的工具
```
新增: tools/docclaim_check.py · tools/deploy_harden.ps1 · tools/perf_baseline.py
      tools/guard_selftest.py（**当日重写**: 判据改 g_guard_hits · 目标自动选掩码区外
      · 新增 VirtualProtectEx + 写入读回验证）
      tools/prot_dbg.py（**调试控制台第 1 步**: doctor/sym/mask/exit，纯只读；
      **第 2/4 步 2026-10-01 已交付**: read/patch/watch + 反调试提示，见 §2.10）
      tools/gate_log.ps1（**门禁落日志**: start/-Stop/-Selftest；自检 6 项含 4 负向；
      检测到外层转录时自检自动换子进程；T1 用**有界等待**替代立即断言，见 §2.22）
修改: tools/release_check.ps1（26–32 项 + **结构修复**: 补回 `abc5edc` 吃掉的
      `} else {`，见教训 ⑧）
      tools/doccheck.py（**新增门禁结构断言**: 每个 `Check` 必须在顶层）
      tools/ci_linux.ps1（同步落日志）
      tools/mutate_check.py（--platform linux）
      prot_sdk/skeleton/build_skeleton.ps1（**4 处路径引用/诊断修复**）
      src/integrity.c · include/protect/integrity.h · modules.json
```

### 2.10 增量（2026-10-01）：调试控制台第 2/4 步 + **门禁"静默跳过 10 项"事故**

**本轮完成**：`docs/DEBUG_CONSOLE_PLAN.md` **第 2 步**（`read`/`patch`/`watch`）
与**第 4 步**（反调试干扰提示）交付（提交 `5e7340b`，门禁第 32 项）；
随后复查中发现并修复**门禁自身静默跳过 10 项**的结构事故（详见教训 ⑧）。

**① 调试控制台第 2/4 步**（`tools/prot_dbg.py`，第 1 步为纯只读）:
```
read  <符号> [--len N]                        读进程内存 + **与产物文件同址字节对照**
patch <符号> [--bytes "31 C0 C3"|--nop N|--restore]   写 + **读回验证** + 完整性边界提示
watch <符号> [--seconds S] [--patch <符号>…]   轮询被观测符号**自己的值**
活体通用: --pid P（附着已有进程）/ --no-keep-alive / --no-adwarn / --quiet
```
```
· ASLR 自动换算: Target.rt(link_va) = base + (link_va - PREF)；PREF = 0x140000000
· 验收① 一条命令替代 4 轮试错:
    watch g_guard_hits --seconds 6 --patch prot_antidebug_detected
    -> [3.01s] 00 00 00 00 -> 01 00 00 00 ; 「变化 1 次」（判据是符号自己的值）
· 验收② 写后必读回: 「写入前 / 期望 / 读回」三行 + `✓ 读回验证通过`
· 验收③ 错误分类（`DbError(kind,msg,hint)`，不静默退化成"读到 0"）:
    --pid 999999 -> process  (Win32 87)    --pid 4 -> permission (Win32 5)
    不存在的符号 -> symbol              非 Windows -> platform
· 第 4 步: `ANTIDEBUG_NOTICE` 在每个活体命令开头打印 —— 本工具用 OpenProcess /
    ReadProcessMemory，**这本身就是调试行为**，目标可能以 219
    (PROT_EXIT_DEBUG_DETECTED) 退出；**219 不能作为"守卫有效/失效"的判据**。
· 自检: `--selftest-live` 10 项全 PASS（含 4 负向），已入库门禁第 32 项。
```

**② ⚠️ 本轮最重要的发现: 门禁不带开关时会静默跳过 10 项仍报 PASS**
```
现象: `tools\release_check.ps1`（无开关）-> `PASS: 19 项`，而脚本里有 32 个 `Check`
根因: 提交 `abc5edc`（2026-09-27）把一段**纯注释块**插进了 `if ($WithMigration)`
      的 body，**吃掉了它的 `} else {`** -> 第 23~32 项全被罩进那个 if
      （二分 14 个历史 ref，该提交处 if body span 从 4 行跳到 32 行）
实测: 无开关 19 项 / 三开关全开 31 项（同一脚本、同一台机器）
修复: 补回 `} else {`；并在 `tools/doccheck.py`（门禁第 13 项，**默认必跑、
      且位于嵌套区间之前**）新增结构断言：任何 `if ($With*)` body 里 >1 个 `Check` 即 FAIL
教训: 见下方 ⑧ —— 尤其是**这条守卫的第一版自己就是假的**（被负向测试抓出）
```

#### 本轮新增纪律（延续 §2.9 的七条 -> 共八条）

上文 ⑧ 为 2026-10-01 新增；第 ⑦ 条（改 `.ps1` 必须先解析再提交）本轮**再次踩到**
（`edit` 又一次剥掉 `tools/release_check.ps1` 的 BOM，中途 AST 报 13 个 error），
再次验证它必须是一条**提交前的命令**而不是记忆里的注释。


### 2.11 增量（2026-10-02）：Q0/Q1/Q2 —— 216 行 mojibake 修复 + **判据换代** + 缺陷⑤定证

**本轮完成**（承 `docs/CONTINUATION_PLAN.md` 的 Q0–Q2）:
Q0 文档回填（`1c7604a`）/ Q1 源码 mojibake **216 行**修复 + 新增全库回归门禁第 33 项
（`4cf2cb6`）/ Q2 缺陷⑤ usage 字面宏名**定证并修复** + 判据 v5 补单字符盲区
（`efe4f3d`）。

**Q2 收尾实测**: 干净树上全量门禁 `PASS: 30 项检查全通过`
（`build/logs/release_check_20261002_022916.log`）；`tools/sdk_pack.py --force --zip`
重打包 101 文件 / 886.6 KB，产物 `app_main.c` 1106 行 **坏行 0**、`crc32.c` 86 行
**坏行 0**；`-WithMutation` / `-WithSkeleton` / `-WithMigration` 三项**未跑**
—— **未验证 != 通过**。

**① Q1: 旧判据是错的，漏检 73%**
```
旧判据 v1（gbk 比例法）: 遇 UDA/PUA 区字（U+E76C..U+E863）时 encode('gbk')
  抛 UnicodeEncodeError 被 except 吞掉 -> **整行静默放过**。
  权威 CP936 表 23940 条双字节里有 **81 条**落在该区。
实测（独立标注集）: v1 TP=57 R=0.2639（**漏掉 159 行**）; v2 单字法 FP=367 P=0.1365;
  v4 字节重建法 TP=216 FP=0 FN=0 P=1.0000 R=1.0000。
标注集来源: 正样本 = git 修复 diff 的 HEAD 侧行（**独立证据**），负样本 = 全库
  30548 条含非 ASCII 的 HEAD 侧行。**不使用任何判据** —— v1 时代那份 R=1.000
  是循环论证（正样本由该判据祖先圈出）。
```

**② 判据 v5（Q2 补）: 单字符盲区**
```
v4 盲区是**结构性**的: 原文 CJK 的 UTF-8 占 3 字节, CP936 每次只喂 2 字节,
  故还原的 CJK 必然成串 -> run>=2 对"原文是 CJK"完备。
  但原文若是**非 CJK 的 >127 字符**（`§` U+00A7, UTF-8 只 2 字节）,
  错解本身是 CJK（-> U+6402）, 还原后 run=0 -> 被放过。
实测: 全库 128 种非 CJK 字符里**恰好 16 种**如此 -> 盲区**有限可枚举**。
  但**纯编码规则无法区分**: 正确中文 `写` 与损坏的 `§` 在字节层面完全同构
  （全库 71 条硬验证候选里 **67 条其实是正确文本**）-> 必须引入语料统计。
_BLIND 表的判据（可审计、可重算）: freq_img == freq_cand and freq_orig >= 5,
  即"像字符的每一次出现都落在候选行上"（**从未观察过合法用法**）。
  16 对里只采纳 3 对（U+6402->U+00A7 / U+8133->U+00D7 / U+5364->U+00B1）。
  被拒典型: `实`->U+02B5（`实` 合法出现 3856 次）。
施加到全部候选行 -> 额外命中**恰好是那 4 处真损坏**, 假阳性 0。
⚠️ 诚实边界: 这是**按本仓库语料校准的白名单**, 换语料必须重算; 门禁每次运行
  都会重算频次并验证该表仍成立（校准失效即 FAIL）。
```

**③ Q2: 缺陷⑤ usage 显示字面宏名 —— 真存在，根因与 v1 猜测不同**
```
v1 猜测（已推翻）: "16 处 usage 用的 APP_EXE_NAME_STR 已经过宏展开, 未能复现"。
真根因: `#` 的操作数**不做宏展开**（C 标准）, 故一级字符串化得到的是
  **参数符号本身**:  #define APP_EXE_NAME_STR PROT_APP_STR_(APP_EXE_NAME)
  得到字面量 "APP_EXE_NAME"。修法 = 经典**两级间接**。
定证链（非静态推断）: ① cl 实测一级恒为参数名、二级带引号/带空格都正确展开
  ② tools/skeleton_check.py --keep 重建后扫 build/SkelCheck.exe: 8 条 usage
     全为 "usage: SkelCheck ...", literal macro name present? False
  ③ .map 里 usage?3?5APP_EXE_NAME 字面量确实曾入二进制。
旁证: demo/main.c 不受影响 —— 它的 13 处 usage 全是硬编码字面量 "demo.exe"。
```

**④ 自检从 7 项扩到 24 项，且**每项都经变异测试证明可以失败**
```
新增盲区层自检: 表空 / 表错 / 漏判 / 校准失效（合法用法出现、还原目标频次过低）/
  误改正常行（`实施` 回归守卫）。
6 项变异各自被对应检查捕获（build/_q2_selftest_falsify.py）, 无恒真装饰。
教训: 自检的**分母不能是魔法数字** —— 旧的"4 项"在豁免收缩后就不再属实;
  改为 check() 闭包 + nonlocal 计数, 且发现并修掉一个**同义反复**
  （旧第③项无论 scan() 怎么写都会通过）。
```

---

### 2.12 增量（2026-10-02）：Q3 —— `doccheck` 扫描盲区消除 + **7 类语境豁免** + 负向自检

**本轮完成**（承 `docs/CONTINUATION_PLAN.md` 的 Q3，提交 `2f48ab1`）:
把 `tools/doccheck.py` 从"只扫对外材料 16 文件"扩到 **24 文件**
（对外材料 16 + **自声明现时的内部文档 8**），新增 7 类语境豁免与
**21 项负向自检**，并连带修掉 4 条真缺陷。原计划 §5.2/§5.3 的设计
**被实测推翻**，本文档如实记录推翻依据。

**① 盲区规模远超原计划预估（3.4 倍）**
```
原计划 §5.2 称: 扩到 docs/**/*.md 后 "7 文件 / 17 处命中, 17/17 FAIL"。
实测（扩到顶层 docs/*.md 即得）: 97 文件, **58 条错误 + 1 警告**。
构成: 门禁项数漂移 16 / 死链 25 / 模糊表述 13 / 轮次 warning 1。
全库门禁项数断言实为 **219 处** = N/N 100 处 + **N 项 119 处**（旧正则看不见）。
```
**关键发现: 死链规则在旧范围内从未真正生效** —— 全库 25 条死链
**全在 `docs/`**，`publish/` 与 `docs/marketing/` **0 条**。该规则写了很久，
一次都没抓到过东西（旧范围太窄）。

**② 为什么不能"只加一行 glob"（两条路径都被证伪）**
```
单纯放宽容差不够: OK={33,30} + 代码块/序号/沿革三类豁免
  -> 仍有 PASS 8 / FAIL 123 / 豁免 88（21 文件有 FAIL）。
  因为绝大多数 docs/ 门禁项数是**当时的真实值**, 改成现值即**篡改历史**。
原计划的"按 `> **历史快照**` 标记豁免" -> 实测大量历史文档**从不带日期、
  也不自称快照**（docs/OSS_TAIL_PLAN.md、docs/PLATFORM_EXPANSION_PLAN.md、
  docs/BLUEPRINT.md:640）, 标记覆盖率不足。
原计划的"按文件名清单豁免" -> 违反 check_gate_structure 已确立的
  "判据不靠清单 —— 清单会过时"; 且 docs/BLUEPRINT.md / docs/HANDOVER.md /
  docs/WORKBENCH_ROADMAP.md **同时是历史快照与现役文档**, 整体豁免会掩盖真问题。
```

**③ 范围由文档**自声明**决定（关键设计）**
```
publish/*.md + docs/marketing/*.md  -> 恒为现时（对外材料, 读者是当下的人）
其余 docs/**/*.md -> **仅当头部块（首个 "## " 之前）含 `> **最后核实**`**
                    元数据时纳入。
依据: 该元数据是文档对"我自称现时"的**显式自声明**; 无声明者不纳入
  （新文档默认不被检查, 有意为之 —— 想被检查就先声明）。
实测"全量 docs"方案产出 31 条"真缺陷"跨 15 文件（12 个非元数据文件）,
  全是历史真值 —— 无自声明即无从区分"过期的现值"与"忠实的历史记录"。
```

**④ 7 类语境豁免（按判定顺序）与两个必须记住的坑**
```
代码块 -> 日期语境（标题栈任一祖先带日期）-> 自带日期（命中行含日期）
-> 沿革（→/->/⇒ 或 现为|曾|旧值?|已过期）
-> 序号（`第 N 项`, 窗口 -6 至 +2）
-> 转述他文（**必须带 `:NN` 行号** —— 该数字在描述**别的文件**的现值）
-> 计划验收（行内或**表格同列**含 验收|交付|目标|标准）

坑 1（标题栈）: 必须**先判 `if not inside:` 再解析 `#`**。
  否则文档里代码块内的 shell 注释（`# =====`、`# python 自动探测 …`）
  被当成 H1, **把带日期的父标题挤出标题栈** -> 历史行被误判成现时。
坑 2（必须比**分母**）: `门禁 21/22` 语义是"通过 21 / 共 22", 门禁项数
  只有分母。实测范围内 34 处 N/M 中 **16 处 N≠M**
  （docs/PLATFORM_ISOLATION_PLAN.md 多处以 "23/24（唯一失败=未提交）"记录当轮状态）
  —— 若比分子, 这些正确记录会被全部误报。
豁免**显式打印**（`豁免 79 处: 代码块 34 / 日期语境 29 / …`）:
  静默豁免 = 无人复查的后门; 豁免数突然变多说明判据正被削弱。
```

**⑤ 负向自检 `--selftest`（21 项，已接入门禁第 13 项）**
```
21 项 = 8 项负向注入（注入缺陷必须报错）+ 13 项合规豁免（合规写法不得误报）,
含**直接改真实文档 publish/01-关于ShardVase.md 的 `33/33` -> `32/32` 必须 FAIL**。
为什么必需: 本判据含 **7 类豁免**, 豁免越多越容易"宽到什么都不报";
  只验"仓库当前 PASS"是**无法发现判据失效**的 —— **一个恒返回空的检查器同样 PASS**。
实现要点: 判据逻辑抽成 `check_text(rel, t, gate, rounds, exc, exists=None)`,
  供自检走**完全同一条**代码路径（测的是生产实现, 不是另一个实现）;
  `exists` 可注入以伪造文件存在性; 真实文档用例走**真实的**存在性判断
  （否则它自身的链接全成死链）, 且断言错误数**恰好为 1**。
门禁接入: 失败时才打印自检明细, 成功时静默 —— 日志不被 21 行 [ok] 淹没。
自检**不落盘**（内存副本）—— 自检不得改动工作区。
```

**⑥ 连带修掉的真缺陷（4 条）**
```
docs/DEBUG_CONSOLE_PLAN.md:8      门禁 32 项 -> **33** 项
docs/HANDOVER.md:349 / :351       模糊表述 -> `**显式破防 0 项**`
  （合规口径来自 publish/07-攻防记录.md:35 与 docs/marketing/attack-record.md:34
    的 `> **我们不写"0 破防"** —— 那是模糊表述。`）
docs/HANDOVER.md:355              `当前 11/11 绿` -> ✅ 已完成（2026-10-02 复跑）
  该行标题链 `### 4.3 未完成事项（下一位的待办）` **不带日期** -> 属现时承诺, 必须更新
```

**⑦ 验证**
```
tools/doccheck.py            : 检查数字 401 处, 错误 0, 警告 0 -> PASS
  （豁免 79 处: 代码块 34 / 日期语境 29 / 自带日期 5 / 沿革 3 /
    转述他文 3 / 计划验收 3 / 规划交付物 2）
tools/doccheck.py --selftest : PASS 21 项（8 负向 + 13 合规）
tools/mojibake_check.py      : PASS（扫描 396 文件, 白名单外坏行 0, 豁免 3）
tools/comment_lint.py        : PASS（102 个 .c/.h, 0 警告）
门禁默认 30 项                : 仅 `git 工作区干净` 因未提交而红, 其余全过
```

**⑧ 诚实的覆盖边界**
```
本判据**只覆盖自声明现时的文档**。未自声明者（如 docs/LINUX_PORT_PLAN.md
  的状态行 `⬜ 待评审（未开始实施）` 已严重过期）**不会被门禁抓到**。
这是**有意的取舍**: 力争"不误报历史"必然牺牲"抓全全部过期现值"。
补充手段是人工复核（docs/CONTINUATION_PLAN.md §6 Q4 的逐条复核清单）。
```

### 2.13 增量（2026-10-02）：Q5 —— DRILL9 端到端实证 + ⚠️ **守卫检查器自身不在 CRC 覆盖内**（真漏洞）

**本轮完成**（承 `docs/CONTINUATION_PLAN.md` 的 Q5，提交 `acbdb94`）:
补上 `docs/DECISION_REDUNDANCY_PLAN.md:516` 记的"**仍未做**"—— 在**出厂
`PROT_POLICY_EXIT` 策略下**的端到端演示。`tools/guard_selftest.py` 是靠
**改策略模拟**段 CRC 被中和；本轮把它**显式化为真的重算**。
交付 `docs/ATTACK_DRILL9.md` + `docs/ATTACK_MATRIX.md` 复核节 +
`docs/COST_ASYMMETRY.md §4` 杠杆表第 10 行。

**① 缘起: `0xBAD` 有四个出口，只测"进程死了"是无效测量**
```
src/integrity.c 看门狗 (:144-223) 的 EXIT 分支:
  :163 prot_selfcrypt_enter  （唯一带 `continue` 的）
  :175 check_self  （段 CRC）
  :192 check_iat   （运行期 IAT 复查）
  :211 check_guards（判定点序言快照, R3.2-b）
=> 必须构造对照把前三道逐一排除, 剩下才是守卫的功劳。
   （这正是 ATTACK_MATRIX 已记名的教训: 无对照 = 无效测量。）
```

**② 8 用例设计（探针 `build/_drill9_probe.py`；`build/` 被 gitignore，输出内嵌文档）**
```
A_baseline              无 patch                             -> exit 1
B_guard_no_recalc       patch 守卫, 不重算                   -> exit 2989（段 CRC 先抓）
D_ctrl_recalc           patch 非守卫 + 重算                  -> exit 1  ← 对照
C_guard_recalc          patch 守卫 + 重算                    -> exit 2989 ← 决定性
E_guard_recalc_continue 同上但策略改 CONTINUE               -> hits=4  ← 独立佐证
F/G/H                   检查器自身 / 完整链（见 ⑤）           -> 见 ⑤
对照组选 prot_antidebug_apply_policy 的理由: 非守卫（不在快照表内）+
  掩码区外 + **启动后不再被调用** -> patch 它惰性、不影响任何行为。
两条前置守卫（防假结论）: ① 目标必须不在 selfcrypt 掩码区（区内目标在
  :163-173 被 continue 整轮跳过, 无判别力）② **守卫目标必须落在 .text**
  （否则段 CRC 覆盖不到它, "重算"这件事本身无意义）。
CRC 复算口径: 读**内存镜像**, .text 的 min(virtual_size, size_raw)=139024,
  IAT 单区间 + .reloc 槽位 + 8 条 selfcrypt 段整段掩码清零后 zlib.crc32;
  断言 A0: 该复算值 == 进程内 g_prot_baked_crc 烧录值（全部结论的地基）。
```

**③ 实测（`build/_drill9_run5.txt`，探针 exit 0）**
```
A0  CRC 复算 = 内存烧录值       before=2087216295 computed=2087216295
B   patch 守卫(不重算)          exit=2989  -> 段 CRC 先终止
D   patch 非守卫 + 重算         exit=1     crc_after_write=884772529
C   patch 守卫 + 重算           exit=2989  crc_after_write=3467459129
E   CONTINUE 下守卫生效         hits=4     （20s ÷ 5s 周期 ≈ 4, 与周期吻合）
=> C 的 0xBAD 只能由 :211 check_guards 解释（其余三处已逐条排除）。
```
归因链: ① 只 patch 掩码区外目标, 未触碰 8 条加密段 -> 排除 selfcrypt;
② 对照 D 也重算却 exit 1 -> **反证重算确实生效**, 排除段 CRC;
③ 未改 IAT, 且 D 同样未改却 exit 1 -> 排除 IAT;
④ A5 反附加(:226) 只产 0xDB(219), 全部用例均未出现 219。

**④ 回填**
```
COST_ASYMMETRY §4 新增第 10 行（patch 判定点 + 重算段 CRC -> 杠杆"高"）+
  更新头部 `最后核实`; ATTACK_MATRIX 追加 `## DRILL9（2026-10-02）` 节。
ATTACK_MATRIX 是**部分生成物**: `tools/drills.py matrix` 只生成到
  `## 显式 BREACHED` 表为止, D4/DRILL8/R3.3 等复核节**不在生成范围**,
  且生成器写 BOM、文件人工修正过未映射行（20/21/0）—— 
  **必须手工编辑, 绝不可 `--out docs/ATTACK_MATRIX.md` 覆盖**。
未加 `drills/*.json` 记录: DRILL7/DRILL8 均无入册 JSON（沿用先例）,
  且会级联改动多处公开计数（这些计数本就已不一致: 122/125/125）。
```

**⑤ ⚠️ 附带发现: 守卫检查器自身不在段 CRC 覆盖内（**真漏洞**）**
```
prot_integrity_check_guards 的 rva = 0x14d0, 落在 **.protxec** 节
  （PE 名 .3y7lsz8, va 0x1000-0x1c00）, **不是 .text**;
而段 CRC 只覆盖 prot_plat_crc_target_name() 的三个节
  （src/platform/prot_platform_win.c:678-683）: .text / .rdata / .pdata。
=> 检查器自身的代码**从来不在段 CRC 的覆盖范围内** ->
   patch 其函数头（31 C0 C3）-> 立即 return PROT_OK（protdef.h:27）-> 恒真,
   且**无需任何 CRC 重算**; 再按 DRILL7 步骤 4 patch 守卫 -> **盾失效**。
双重实证: F crc_unchanged_by_patch=True（重算值 = 原值 2087216295
   -> 该 patch 根本不进 .text）; G 零 CRC 操作仍 exit 1;
   H 检查器 + 守卫双 patch -> exit 1（完整攻击链闭合）。
该覆盖缺口**此前已被记录**: docs/OPEN_SOURCE_COMPENSATION.md:87 已列
   .protxec 在"未覆盖"清单里 —— 但**从未评估"守卫自身不在覆盖内"这一后果**。
   （.protxec 当初是为**分页隔离/防 selfcrypt 自伤**而设, 安全后果是副作用。）
=> 与 DRILL8 §2 **同一模式**: 能力/缺口落地了, 但它的**安全含义没被推导**。
```

**⑥ 诚实边界（**不过度声称**）**
```
① 测试工具自身用 OpenProcess/WriteProcessMemory -> 会被产品反调试看到;
   本 drill 测的是"内存改写能否被守卫抓住", 不是"攻击者能否不被发现"。
② 只有 E 改策略; **A/B/C/D/F/G/H 全部保持出厂 EXIT**
   -> C 是真正意义上"EXIT 策略下的端到端演示"。
③ build/demo.exe 是 NotSigned -> 不覆盖 Authenticode 签名这道线。
④ 仅 Windows。
⑤ 守卫快照在 start_watchdog 内对**内存当前字节**建立 -> 离线文件级 patch
   无效 -> 澄清威胁模型 = "进程起来之后的运行期内存改写"。
⑥ 用例 B/C 的 stdout 为 0 B（TerminateProcess 立即杀进程、缓冲未 flush）
   —— 判据是退出码, 不削弱结论（A/D/E 的 713 B 证明同一路径确实会打印）。
```

**⑦ 连带修掉: 轮次口径漂移（7 处）**
```
`actual_rounds()` = docs/ATTACK_DRILL*.md 的**文件个数**（本轮新增第 9 个
  -> 7 轮 已超 (rounds, rounds-1) 容差, doccheck 报 7 条 warning）。
  7 轮 -> 9 轮: publish/{01-关于ShardVase, 02-项目档案×2, 03-攻防实录-01-dump,
  06-诚实边界} + docs/marketing/{article-1-dump, boundaries}。
未在扫描范围内但同样过时（留给 Q4）: README.md:53、ShardVase-展示文档.md:86、
  docs/BLUEPRINT.md:21/:120/:641、docs/COST_ASYMMETRY.md:199、
  docs/阶段总结-2026-08-30.md:104、docs/部署档案-ShardVase.md:107/:165、
  docs/blog_project_overview.md:43/:71（多为 `8+ 轮` 形态, 语义已过时）。
```

**⑧ 验证**
```
tools/doccheck.py            : 检查 409 条, 错误 0, **警告 0** -> PASS
  （豁免 79: 代码块 36 / 日期语境 29 / 自带日期 5 / 沿革 3 / 转述他文 3 /
    计划验收 2 / 规划交付物 1）
tools/docclaim_check.py      : PASS (8/8)（含 verified-metadata 6 份齐备）
门禁默认 30 项                : 29/30 过, 唯一红项 = `git 工作区干净`（因未提交）
```

---

### 2.14 增量（2026-10-02）：Q4 —— 文档漂移清理 + 🔑 **量化出 doccheck 的覆盖缺口**（288 处无保护断言）

**① §6.2 的 13 处归档逐条复核 —— 全部确认有历史依据，一处未改**

写探针 `build/_q4_anc.py`（打印目标行原文 + 祖先标题栈及各级是否带日期）逐条实测:
```
docs/PLATFORM_ISOLATION_PLAN.md:146/:179  确证在围栏代码块 :141-147 / :174-180 内
docs/LINUX_PORT_PLAN.md:340               确证在 `## 4. 里程碑与门禁` 代码块 :339-345 内
docs/WORKBENCH_ROADMAP.md:17/:1808/:2264  文件结构: ## 0.-## 7.(:12-:294) = 计划期,
                                          ## 8. 起(:295+) 全部带日期(2026-09-23)
```
=> 判据原则再次成立: **"文件里有个陈旧的数字" != "文件在声称现值"**。

**② 已修的两处真过期项**

```
1. docs/LINUX_PORT_PLAN.md:7（该文件 2226 行）
   ⬜ 待评审（本文档为计划，未开始实施）
     -> ✅ 已完成（A–G 阶段全部落地，2026-09-25；§9 起为逐阶段实施记录）
   并加阅读提示块: §0–§8 是 2026-09-25 的**计划期文本，保持原样不改**
   （那些数字是当时的实况, 改动即篡改历史; 实际结果以 §9 起实施记录为准）。
   依据: §9–§23 的 ## 标题全部带 ✅ 与（2026-09-25）; :23 最终 | Windows 门禁 | ✅ 21/22 |
   ⚠️ 该文件**未自声明现时** -> 不在 doccheck 范围 -> 此过期**门禁永远抓不到**。
   （Q3 时已在 §6.2 附录里点出, Q4 才真正修掉。）

2. docs/WORKBENCH_ROADMAP.md:17（`## 0. 结论先行` 表, **不带日期**）
   ③跨构建差异率（实测仅 0.55%，目标 >30%）
   与本文件后文 20+ 处实测结论直接矛盾:
     :301   | V1 跨构建差异率 | >30% | **67.85%** | ✅ |
     :1729  | C1 | 跨构建差异率 | 67.85% | **86.45%~93.28%** | ⚠️ 数字不稳健 |
     :1772  | 跨构建差异率 | **约 86~94%**（>30% 目标**稳健达成**）|
     :1899  可控条件下（完整种子表）= **0.0000%**（完全可复现）;
            随机条件下 = **86~94%**
   -> **保留原句 + 追加 ⚠️ 推翻标注**（## 0. 是计划期结论, 需存沿革）。
```

**③ 轮次口径 / 门禁项数的对外一致性（Q5 只改了 7 处，留下跨文件分裂）**

权威判据（读 `tools/doccheck.py` 源码确认）:
```
actual_rounds()     @:568-571 = glob('docs/ATTACK_DRILL*.md') 的**文件个数** -> 9
actual_gate_count() @:400-428 = len(re.findall(r"(?m)^\s*Check\s+'", release_check.ps1)) -> 33
GATE_DEFAULT        @:148     = 30（3 项由 -WithSkeleton/-WithMutation/-WithMigration 控制）
```
改成现值的一览（13 处，跨 10 文件）:
```
README.md:53              7 轮正式演练 -> 9 轮正式演练
README.md:9               badge 14%2F14 -> 30%2F30
README.md:102             # 14 项门禁 -> # 30 项门禁（默认；共 33 项）
README.md:132-155         8 个并排项示意块 -> **全部 30 项默认项** + 3 项未跑项显式说明
ShardVase-展示文档.md:86   7 轮 -> 9 轮
ShardVase-展示文档.md:97-105 轮次表只到第 7 轮 -> 补第 8/9 轮（DRILL8/DRILL9）
ShardVase-展示文档.md:138/:163  14 项 -> 33 项（默认跑 30 项）
docs/BLUEPRINT.md:21/:120 7 轮 -> 9 轮
docs/BLUEPRINT.md:128     发布门禁（14 项）-> 发布门禁（33 项，默认 30）
docs/COST_ASYMMETRY.md:199 8 轮演练 -> 9 轮演练
CONTRIBUTING.md:67/:95    13 项 / 13/13 PASS -> 30 项（-With* 共 33）/ 30/30 PASS
.github/PULL_REQUEST_TEMPLATE.md:16  14/14 PASS -> 30/30 PASS（默认）
.github/workflows/ci.yml:52  release_check 覆盖 14 项 -> 覆盖 33 项 (默认 30)
```
**有意未改**: `docs/BLUEPRINT.md:640/:641/:667/:670`（历史漂移记录表 + `13 → 14 项`
沿革叙述）、`docs/MODULAR_ARCH.md:309`（阶段 3 待做项的历史描述）、
`docs/阶段总结-2026-08-30.md:104`（H1 带日期 ⇒ 历史快照）、
`docs/部署档案-ShardVase.md:107/:165` 与 `docs/blog_project_overview.md:43/:71`
（最后提交均 `c941c9c` ⇒ 博客发布稿存底, 非活文档）。

> **2026-10-06 更正**：上句原写的理由「~~无任何文件引用它们~~」**经实测不成立**
> —— `git grep` 在该判断作出的提交 `fc18ebb` 上**当时就有引用**，
> 且 `publish/README.md` 逐字写着「完整技术档案（内部版）：
> `docs/部署档案-ShardVase.md`（含更多内部细节，发布时按需删减）」。
> **结论不变，依据换了**：真正成立的是「**无任何机器消费者**」
> —— 限定可执行/配置类型搜索零命中，且两者都不在 doccheck 的扫描面内；
> 另有一层早已记对的口径：`publish/` 是 `docs/marketing/` 的发布快照，
> 「以 `publish/` 为准（新）；旧文件保留作历史」
> （`docs/项目文件分类-2026-08-30.md`）。
> 教训与 §2.28 / §2.32 同型：**记档里的「前提」也会过时，而且比结论更难被发现**
> —— 因为结论还能被下一次实跑证伪，依据则没人复算。
**"4 组矩阵"一律未动** —— `archive/` 有 13 份归档、`tests/attack_*` 只有 6 个文件,
矩阵"组"在**任何地方都没有权威定义**, 故只改有权威判据的**轮次**。

**④ 🔑 本轮量化出的覆盖缺口（比逐条漂移更重要）**

写探针 `build/_q4_census.py` 做**全库**普查（而非只扫 doccheck 的 TARGETS）:
```
基准: 门禁 33 项 (默认 30), 轮次 9 个
TARGETS 24 个文件 (doccheck 扫描范围)
非现值断言总数: 门禁 132 项 / 118 N/N / 38 轮
```
=> **全库有 288 处非现值断言, 而 doccheck 报 0 错误 —— 因为它只扫 24 个文件。**
**33 个文件完全不受门禁保护**（存疑处数降序, 前几名）:
```
docs/WORKBENCH_ROADMAP.md      43      docs/OSS_TAIL_PLAN.md          13
docs/LINUX_PORT_PLAN.md        25      docs/阶段总结-2026-09-30.md     12
docs/PORTABILITY_ASSESSMENT.md 10      docs/BLUEPRINT.md               9
...                                     README.md                       3
ShardVase-展示文档.md            3
```
**根因**（`tools/doccheck.py:36-57` 的注释**自己承认了**）:
`build_targets()` @`:72` 只纳入**头部块显式自声明 `最后核实`** 的 `docs/**/*.md`,
即**新文档默认不被检查**（注释原文: "无此声明不得纳入检查 … 是有意为之"）。
该设计避免了"历史文档标题从不带日期"导致的 31 条误报, 代价就是上表的量化结果。

**不可接受的子集**: `README.md` 与 `ShardVase-展示文档.md` 是**开源项目的门面**,
**既不在 doccheck 的 TARGETS、也不在 `docclaim_check` 的 KEY_DOCS**,
最后提交分别停在 `041753e`(2026-09-21) / `094e26e`(2026-09-25)
—— 它们携带的过期数字**对外可见且长期无人修**。
本轮已手工修正（见 ③）, 但**"靠人记得"不是机制**。
**建议（未实施, 留作独立排程）**: 把这两份门面纳入 `PUBLIC_MATERIAL`,
或在 PR 模板加"门面文档数字须与门禁实况一致"一条。

**⚠️ 反面教训**: 普查同时暴露大量**误报** ——
`docs/CONTRACT.md:313` `5 轮 × Sleep(20)`、`docs/COMPAT.md:21` `5 轮采样`、
`docs/DEFENSE_DEEPEN_PLAN.md:157` `连续 12 轮全 PASS`、
`docs/COST_ASYMMETRY.md:144` 的 `轮换`（被 `\d+\s*轮` 正则误吃）、
`docs/DEBUG_CONSOLE_PLAN.md:93` `第 1 / 2 / 4 步`。
=> **再次确认 §5.2 的结论: 扩范围不能只加一行 glob, 判据必须跟着扩。**
故本轮**只做手工修正, 不改任何检查器的扫描范围**。

**⑤ 验证（提交前实跑）**
```
tools/doccheck.py            : 检查 436 条, 错误 0, **警告 0** -> PASS
  （基准: 门禁 33 项, 轮次 9 个; 豁免 101: 日期语境 45 / 代码块 42 / 自带日期 5 /
    沿革 3 / 转述他文 3 / 计划验收 2 / 规划交付物 1）
tools/docclaim_check.py      : PASS (8/8)（gate-count: 一致 **33 项**, 2 份文档）
tools/drills.py lint         : 125 条攻击记录, 0 错误
tools/modcheck.py --all-compositions : PASS（全 8 模块均有演练记录）
tools/comment_lint.py        : PASS: 无注释词法陷阱（0 警告）
tools/mojibake_check.py      : PASS: 白名单外无 mojibake（豁免 3 行）
门禁默认 30 项                : **PASS: 30 项检查全通过**
  （log build/logs/release_check_20261002_073936.log）
```
⚠️ 过程中 `doccheck` 一度因我自己写的一个**不存在的相对路径**（把根目录的
`CONTRIBUTING.md` 误加成 `docs/` 前缀）报 1 条 error —— **写文档时引路径必须核对存在性**。

### 2.15 增量（2026-10-02）：Q6 —— CI 真实跑通 + T11 根因 + 缺陷 7/8（**三个"从没被执行过的步骤"**）

**① Q6 的结论先行**

CI 已在**真实 GitHub Actions** 上跑通 `build-and-verify` 与 `linux-portability`
两个 job（22/22 与 5/5 步全绿）。累计 **9 轮** run，每轮把失败前沿往前推一格:

```
1 36949863969  f6202d8  linux-portability : gcc 缺 -D_GNU_SOURCE
2 36957960288  5d601c5  vmc_tests : "vcvars not found"（三处各写各的探测器）
5 37010899200  f9285bf  门禁 : [skip] 被当成 [X]（三态缺失）
6 37038553576  38bc671  step17 变异测试 : 变异打偏 -> 假阳性"盲检查器"
7 37043872931  18d29da  step19 门禁 : 唯一失败项 = e2e T11
8 37055147715  e6917a2  ✅ **build-and-verify + linux-portability 全绿**
                        ❌ 但 reproducible 与 sdk-package **首次真正执行** -> 双失败
```

**② 🔑 本轮最重要的一条教训（三个"没跑过的步骤"）**

`reproducible` 与 `sdk-package` 两个 job 带 `needs: build-and-verify`，
而前 7 轮 `build-and-verify` 一直是红的 ⇒ 这两个 job **每一轮都是 `skipped`**，
里面的命令**从未在真实 CI 上执行过一次**。于是它们各自埋着一个**必然失败**:

```
缺陷 7 (reproducible, 第 5 步) : 产物路径少了一层目录
缺陷 8 (sdk-package,  第 6 步) : SDK 包缺 winproc.py / mapfile.py
两者互不相关, 但都会在"第一次真跑"时同时引爆。
```
=> **"跳过的步骤"与"没写的步骤"在证据上是等价的。**
CI 里任何 `needs:` 造成的连锁 skip，都必须**在依赖修好后确认它真的跑过一次**；
"绿了 7 轮"里可能一行都没执行。这与缺陷 5（`-SeedsFile` 从未生效）**同型**。

**③ T11 根因（唯一一个"只在 CI 崩、本机 62 次不崩"的缺陷）**

*现象*: `T11 watchdog-stable FAIL (exit=3221225477)` = `0xC0000005`，且**只在 CI 上**。

*根因*: `src/integrity.c` 的 A5 反附加周期复查原写在
`prot_selfcrypt_leave(PROT_SELFCRYPT_GROUP_EXT)` **之后**，而它通过
`g_ad_scan_fn` 间接调用的 `prot_antidebug_scan` **本身就是组 1 的 selfcrypt
加密目标**（`tools/selfcrypt_proto.py` 的 `EXT_TARGETS`）。`leave()` 用同一
密钥流 XOR 还原 ⇒ 内存**精确回到磁盘密文状态** ⇒ 那次调用执行的是**密文**。

*为什么本机长期不暴露（决定性的字节算术）*: 8 个 selfcrypt 条目的 `key0`
**完全相同**（`0x4E31504245474D21`，`selfcrypt_proto.py:339` 的硬编码 seed）
⇒ 密钥流与构建无关，`ks[0] = 0x8f` 恒定 ⇒
`磁盘首字节 = 明文首字节 ^ 0x8f`。
本机 MSVC **14.44.35207** 下该函数明文首字节是 `0x4C`（x64 帧序言）
⇒ 密文首字节 **`0xC3` = `ret`** ⇒ 调用**静默空转**（复查失效但不崩）。
CI 的 MSVC **14.51.36231** 序言字节不同 ⇒ 非 `ret` ⇒ 执行垃圾指令 ⇒ AV。
**这是编译器版本决定的"字节彩票"，与并发/布局随机化无关。**

*决定性复现（隔离手法 = 只改密钥、不改明文）*: 取 `key0=0x7b` 使
`ks[0]=0x83`，用新密钥流重新加密 ⇒ 磁盘首字节 `0x4c ^ 0x83 = 0xcf`
（`iretq`，用户态执行必 #GP），**明文与明文 CRC 完全不变**（启动路径不受影响）:

```
对照 (改前 demo.exe,     密文首字节 0xc3=ret)    rc=0        (0x00000000)
处理 (_t11_repro2.exe,   密文首字节 0xcf=iretq)  rc=3221225477 (0xC0000005)
修复后再施加同一危险密文                         rc=0        未崩 -> 修复生效
VERDICT fix_immunizes=True
```

*修法*: 把整个 A5 块**上移到 `leave(EXT)` 之前**。修复在二进制层确证 ——
反汇编里该 `call rax` 现落在配对 `enter`/`leave` **之间**。

*⚠️ 诚实边界*: 该约束**至今没有任何静态门禁覆盖**。
P5 只判"不得出现直接 `E8` 调用加密目标"，而这里是
`volatile` 函数指针调用（`call rax`），**字面判据天然看不见**；
"调用点是否落在解密窗口内"从来不在任何检查器的射程内。
**加一条"解析反汇编、断言每个加密目标调用点都在配对 enter/leave 之间"的静态检查
属于后续工作**（记为待办）。

**④ 缺陷 7：产物保留目录结构**

`actions/upload-artifact@v4` 取所有 path 的**最近公共祖先**作为根。
本 job 上传的 7 个路径横跨 `build\...` 与 `demo\...`，公共祖先是**工作区根**
⇒ 解压出来是 `build_artifacts\build\demo.exe`，**不是** `build_artifacts\demo.exe`:

```
Copy-Item: Cannot find path
  'D:\a\shardvase\shardvase\build_artifacts\seeds.json' because it does not exist.
```
修法 = 三条 `Copy-Item` 与两条 `Get-FileHash` 各补上一层 `build\` / `demo\`。

**为什么"修好路径能不能过"当时毫无证据**: 该 job 在第 5 步就死了，
**第 6 步 `Compare SHA-256` 从未执行过**。故写探针
`build/_def7_repro_sim.py`，用**该轮 CI 真实上传的产物**
（`gh run download 37055147715 -n build-artifacts`）+ 修正后的命令逐步复演:

```
步骤 3 跨编译器 (本机 14.44 vs runner 14.51): demo.exe MISMATCH, vm.blob identical
步骤 4 同机同种子重建 (真正判据):              demo.exe identical, vm.blob identical
[defect7] PASS: 修正路径后 reproducible job 的比对**会通过**
```
⇒ **重要预期**: `vm.blob` 跨编译器字节一致（由 Python 工具生成），
`demo.exe` 跨编译器不一致（C 编译产物）。这**不影响** CI ——
该 job 的两次构建都在**同一 runner** 上，跨编译器一致**从来不是**它的判据。

**⑤ 缺陷 8：SDK 包缺两个传递依赖**

`tools/sdk_pack.py` 的 `TOOLS_KEEP` 是**手写清单**，而手写清单必然漏。
实测静态依赖闭包 = **22** 个模块，清单只有 **20** 个:

```
winproc.py   <- vmcalc_build.py:46 `import winproc`
mapfile.py   <- selfcrypt_proto.py:47 的惰性 `import mapfile`
               （它在本仓库能 import 成功只因仓库根在 sys.path —— 一直是"靠环境侥幸可用"）
```
*决定性验证*: 把这两个文件手工塞进包内 → `verify_sdk_standalone.py` 由 rc=1 转 **rc=0**；
单独把 `mapfile.py` 改名 → 从包内 `import selfcrypt_proto` 立刻
`ModuleNotFoundError: No module named 'mapfile'`。

*修法（三条一起）*:
1. `TOOLS_KEEP` 补 `winproc.py` / `mapfile.py`；
2. 新增**闭包守卫** `_local_imports()` / `_tools_closure()` / `missing_closure_modules()`；
3. selftest 加**根因级**断言（原先只有"含 tools/vmenc.py"这种**点抽查**，
   点抽查不可能覆盖闭包 —— 缺陷 8 正是从两次点抽查之间漏过去的）。

*⚠️ 一个自己踩的坑*: 首版 `_local_imports` 用**正则**抓 import，结果把
`winproc.py` **文档字符串里**的示例 `from winproc import run` 当成了真导入，
输出里出现它"自己依赖自己"。**注释与文档里的示例代码不是依赖 ——
词法匹配分不清，`ast` 分得清。**改用 `ast` 后闭包精确。

*负向对照*（证明守卫不是装饰品）: 临时从 `TOOLS_KEEP` 抽掉成员再调
`missing_closure_modules()`，三个对照**全部报警**且互不误报:

```
抽掉 winproc.py -> ['winproc.py']（不误报 mapfile.py）
抽掉 mapfile.py -> ['mapfile.py']
抽掉两个        -> ['mapfile.py','winproc.py']
恢复后          -> 闭包完整
```

**⑥ 顺带修掉的一个"假绿"（`tools/repro_check.ps1`）**

原文 `if (-not $h1.ContainsKey($f)) { continue }` ——
**产物缺失 = 静默跳过 = 判 PASS**，即"什么都没建出来"也算可复现。
已改为缺失即 FAIL 并列出目录实际内容；同时新增 `-BaselineDir` 形态，
使本机判定与 CI 的"与既有产物比对"形态一致。
负向对照: 传一个空目录 → `FAIL (基线缺文件 ...)` + 目录内容清单，rc=1。

**⑦ 本机构建四件套（本轮全部实跑）**

```
tools/sdk_pack.py --selftest                : PASS（含新的"依赖闭包无缺口"）
tools/sdk_pack.py --force --zip             : rc=0（zip 372.0 KB）
tools/verify_sdk_standalone.py              : rc=0  构建 ✓ smoke ✓ DONE ✓ license:1 ✓
门禁（release_check.ps1 -SkipDirtyCheck）   : **PASS: 30 项检查全通过**（[skip] 0, [info] 3）
```

**⑧ 本轮新增的"本机应覆盖但原先没覆盖"的东西**

`tools/ci_sim.ps1` 是本地 CI 模拟器，此前它**只映射了 `build-and-verify` 与
`reproducible` 两个 job**，`sdk-package` 一个字都没有 ⇒
**缺陷 8 在本机根本没有暴露面**（`tools/release_check.ps1` 同样不含 SDK 打包）。
已补入 `job sdk-package` 的三步（`--selftest` / `--force --zip` /
`verify_sdk_standalone.py`），并加 `-SkipSdk` 开关。
=> **"CI 里有的 job，本机模拟器必须也有"**，否则本地全绿不能推出 CI 全绿。

**⑨ 第九跑实证（2026-10-02，本节写作后的补充）**

第九跑 `37061070912` / `90b98d4` **四个 job 全绿**：

| job | 步数 | 关键步 |
|---|---|---|
| `build-and-verify` | 22/22 | 含 step 19 `Full release gate` |
| `reproducible` | 6/6 | 含 step 6 `Compare SHA-256 with first build` |
| `sdk-package` | 7/7 | 含 step 6 `Verify SDK is standalone` |
| `linux-portability` | 5/5 | — |

唯一 `skipped`：`sdk-package` 的 `Publish GitHub Release`
（`ci.yml:283` `if: startsWith(github.ref, 'refs/tags/v')` —— **tag 门控，设计如此**）。
⇒ **Q6 验收达成**（判据 = 缺陷 7/8 修后 `reproducible` 与 `sdk-package`
至少各绿一次），缺陷 7 / 8 在真实 CI 上闭环。

**⑩ 本轮仍未验证的**

- 上述**静态门禁缺口**（加密目标调用点是否落在解密窗口内）**未实施**。
  > **已于 2026-10-03 补上**（见 §2.17）：建成 `tools/window_check.py` 并入库为门禁第 11 项。
- `tools/release_check.ps1` 仍不含 SDK 打包（`ci_sim.ps1` 已含，门禁未含）。
- **同型第二处调用点（见 §2.16）仅静态判定，未实施修复、未动态复现**。
  > **已于 2026-10-03 修掉**（见 §2.17）：`demo/main.c` 与 SDK 骨架共 3 处违规全部修复，
  > 并已负向对照证明门禁能抓住修复前的代码。**仍未动态复现**（可达性依赖 D2b + 部分解密状态）。

---

### 2.16 增量（2026-10-02）：T11 的**同型第二处** —— `apply_policy` 的 `else` 分支

**性质**：T11 根因修完后，按「加密目标的所有调用点是否都在解密窗口内」这一判据
把 4 个组 1（EXT）目标的全库调用点**逐个复查**，发现**同一缺陷类的第二处**。
**静态判定，未动态复现**（故不列为已验证缺陷，仅列为待判定项）。

**判据**：`prot_antidebug_apply_policy`（`src/antidebug.c:542`）**自身不是加密目标**
（不在 `DEFAULT_TARGETS` / `EXT_TARGETS` 内），但它**第一个动作**就是调用加密目标：

```c
src/antidebug.c:542  prot_status prot_antidebug_apply_policy(prot_policy pol) {
src/antidebug.c:548      prot_antidebug_scan(&rep);   /* <- 组 1 加密目标 */
```

⇒ **`apply_policy` 的合法性完全取决于调用方是否已开窗口**
（`src/antidebug.c` 全文 `selfcrypt` / `sc_ext` 命中数 = **0**，
即它自己不开窗口）。而它的两个调用点：

| 调用点 | 上下文 | 窗口 |
|---|---|---|
| `demo/main.c:611` | `if (sc_ext_enter() == PROT_OK) { … }` 内 | ✅ 开 |
| `demo/main.c:614` | 同 `if` 的 **`else`** 分支 | ❌ **未开** |

```c
demo/main.c:610      if (sc_ext_enter() == PROT_OK) {
demo/main.c:611          prot_antidebug_apply_policy(PROT_POLICY_EXIT);
demo/main.c:612          sc_ext_leave();
demo/main.c:613      } else {
demo/main.c:614          prot_antidebug_apply_policy(PROT_POLICY_EXIT);   /* <- 无窗口 */
demo/main.c:615      }
```

**可达性**：`sc_ext_enter()` 失败要求 D2b 且 `sc_do_range` 返回非 OK
（`src/selfcrypt.c:325-331`：`st = sc_do_range(i,1); if (st != PROT_OK) break;
g_sc_state[i] = 1u;` —— **失败项之前的目标已被解密、失败项及其之后未解密**）。
D2a 下 `prot_selfcrypt_enter` 首行即 `return PROT_OK`，`else` 分支不可达。
故与 T11 同样**只在 D2b（Release）下存在**。

**为什么它比 T11 更难触发、也更难归因**：走到该分支时组 1 处于
**部分解密**状态 —— `prot_antidebug_scan` 恰好排在已解密的那一段时
**碰巧执行明文而不崩**，排在失败项之后时才执行密文。即
**崩不崩取决于"哪一个 idx 先失败"**，比 T11 的"密文首字节是否恰为 `ret`"
更多一层偶然。

**建议修法（二选一，均未实施）**：
1. `apply_policy` 内部自带窗口（`enter`/`leave` 包住 `:548` 那次 `scan`）——
   自洽，不依赖调用方；注意与调用方已开的窗口**嵌套**
   （`g_sc_state` 只有 0/1 两态、**无嵌套计数**，见 `src/selfcrypt.c:83-86`，
   内层 `leave` 会提前把组重新加密 ⇒ 需先补嵌套语义）；
2. `main.c:614` 的 `else` 分支改为**不调用** `apply_policy`（失败即按
   `PROT_EXIT_*` 直接终止，不进入加密目标）。

**教训（与 T11 合起来看）**：真正的不变量不是「加密目标不得被直接 `E8` 调用」
（那是 P5 的字面判据，`main.c:544` 的直接调用一直合法存在），而是
**「每一处对加密目标的调用都必须在配对 `enter`/`leave` 之间」** ——
该不变量**目前仍无任何静态门禁覆盖**，且它已经产生了 **2 处**违规。
（另 1 处在 `demo/main.c:614` 的 `else` 分支，合计 3 处。）

> **已于 2026-10-03 补上并清零**（见 §2.17）：门禁 `window_check` 已入库为第 11 项，
> 上述 3 处违规全部修复，并有负向对照证明它抓得住修复前的代码。

---

### 2.17 增量（2026-10-03）：**把那条不变量做成门禁** —— `window_check` + 3 处违规清零

**性质**：§2.15 ⑩ 与 §2.16 末尾都把「加密目标调用点须落在配对 `enter`/`leave` 之间」
列为**没有静态门禁覆盖**的缺口。本轮把它补上，并顺手清掉已知的 3 处违规。

**判据（`tools/window_check.py`，入库为门禁第 11 项）**：
对每个对 selfcrypt 加密目标的调用点，断言执行它时该目标所在的组必须已解密。
**为什么 P5 挡不住**：P5（`tests/protchain_check.py` 的 `p5_indirect_no_direct_call`，
`scan_e8_calls` @`tests/protchain_check.py:285`）**只扫 `0xE8` 直接调用**，
而 T11 那处是 `call rax`（经 `g_ad_scan_fn` 函数指针）。
**声明式的组清单来自单一事实来源**：`tools/selfcrypt_proto.py` 的
`DEFAULT_TARGETS`（组 0 = VM 4 个）/ `EXT_TARGETS`（组 1 = 当时 EXT 4 个；
2026-10-05 revoke 补入后为 5 个 —— 见 §2.28），
用 `ast.parse` 抽取，**不硬编码**。

**三类"看似不是目标调用、实际是"的形态**（判据必须展开）：
1. **宿主窗口包装**：`demo/main.c:91-94` `sc_ext_enter` = 恰好一次
   `prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_EXT)`，`:96-99` `sc_ext_leave` 同形；
   `prot_sdk/skeleton/app_main.c:140-148` 同形。识别判据 = 体内恰好一次 enter
   （或 leave）、参数是组常量、**`{` 之后无其它调用**。
2. **函数指针别名**：`src/integrity.c:141-142`
   `typedef prot_status (*prot_ad_scan_fn)(prot_antidebug_report*); static prot_ad_scan_fn volatile g_ad_scan_fn = prot_antidebug_scan;`
   ⇒ `:216 g_ad_scan_fn(&ad)` 就是**组 1 目标调用**（T11 本体）。
3. **间接槽位**：`PROT_INDIRECT_CALL(PROT_INDIRECT_LICENSE, …)` 经
   `modules.json` 的 `indirect_slots` 解析到真实符号。
   ⚠️ **键名没有 `PROT_INDIRECT_` 前缀**（实测 = `LICENSE` / `VM_RUN` / `REVOKE` /
   `HOSTID`）—— 首版按全名查恒 None，**所有间接站点被静默丢弃**
   ⇒ 被间接调用的宿主函数不在 `called_names` ⇒ 其内部合法调用被误报 3 处。

**必须区分"取地址"与"调用"**：`src/integrity.c:624-627` 的 `g_guard_static[]`
装 `(const void*)&prot_integrity_check_self`、`demo/main.c:658` 的 `host_hooks` 装
`(const void*)&prot_license_verify` —— 两张表只被快照
（`guard_snapshot_init()` @`src/integrity.c:682`），**从不 call**。
⇒ 判据在**挖掉签名与函数体之后**的文件文本上搜 `\bname\b(?!\s*\()` 判"取地址"。

**解析范式的三条硬教训**（全部由实测假阳性逼出来）：
1. **先清注释**：注释里的示例代码会被词法匹配当成真代码 ——
   与缺陷 8 的 `tools/winproc.py` docstring 造出"自己依赖自己"同型。
2. **单行函数**：`src/vm.c:643 static prot_status vm_h_add(prot_vm_rt* s)  { return vm_rt_binop(s, 0x06); }`
   正文与 `{` 同行 ⇒ 若按"整行挖签名"会把正文一起挖掉，`vm_rt_binop`
   于是从未出现在 `called_names` 里、被判成"真入口"。
   必须用 `body_only(func)`（按 `body_ln`/`body_col` 精确截）。
3. **跨行的间接调用**：`demo/main.c:793` 是 `PROT_INDIRECT_CALL(\n    PROT_INDIRECT_LICENSE, …`
   ⇒ 逐行扫会漏**全部**间接站点。改为在函数体全文上 `finditer` 再换算行号。

**🔴 负向对照抓出的假阴性（本轮最重要的发现）**：
`build/_wc_negctl.py`（不入库）把 `git show 18d29da:src/integrity.c`
（= `e6917a2` 的父提交，A5 块仍在 `leave(EXT)` 之后）放进仓库副本跑同一判据。
**首跑：修复前的树也只报同样 3 处 §2.16 违规，`src/integrity.c` 一处都没报** ——
即门禁**不可能**发现 T11。机制：`indirect_call_groups()` 的返回键是**文件**，
`src/integrity.c` 因定义了组 1 目标且有函数指针调用而**整个文件**被标记；
`watchdog_thread`（`src/integrity.c:144-292`，`static`，唯一引用是
`:805 prot_plat_thread_create(watchdog_thread, NULL, &g_wd_thread)` 传**实参**）
同时满足"static + 不在 called_names + 取过地址 + 文件有派发表" ⇒
整个函数体获得组 1 ambient ⇒ 那处**真正执行密文的**调用被无条件赦免。
**教训**：把**文件**级的粗筛当成**对象**级的豁免依据，就会让门禁对
"恰好与合法目标同处一个文件"的真实违规完全失明。豁免必须落到
"这个函数名真的在表里"这一粒度 —— 新增 `file_scope_table_names()`
（清掉所有函数体后取文件作用域聚合初始化表里的标识符）。
`src/vm.c` 实测：表内标识符 ∩ 本文件函数 = **47 个**（全部 `vm_h_*`/`vm_store_h*`），
`vm_rt_binop` / `vm_wfetch32` **不在表里** ⇒ 修法精确无损。

**修完之后的实测（三份对照全部通过）**：

```
tools/window_check.py --selftest         rc=0   12/12 项
tools/window_check.py                    rc=0   0 违规
build/_wc_negctl.py（负向，真实修复前代码） rc=0   4/4 项
  修复前 watchdog_thread: enter<163> scan<226> leave<189>  => enter<scan<leave = False
  当前   watchdog_thread: enter<163> scan<216> leave<231>  => enter<scan<leave = True
  修复前报出 T11 那处 [X] src/integrity.c:226 watchdog_thread() -> prot_antidebug_scan() [fptr:g_ad_scan_fn]
  违规总数 修复前 - 修复后 = 1 (只有 T11)   1 -> 0
```
负向对照的**唯一自变量**就是 `integrity.c` 的新旧（两棵树其余部分完全相同，
含已修好的 §2.16 三处）⇒ 违规数之差只能归因于 T11。

**修掉的 3 处违规（判据在修复前恰好报出这 3 处）**：

| 位置 | 形态 | 修法 |
|---|---|---|
| `demo/main.c:614` | `if (sc_ext_enter()==PROT_OK) { apply_policy; leave(); } **else** { apply_policy; }` | `else` 分支改为 `else if (prot_antidebug_detected(&rep)) exit(PROT_EXIT_DEBUG_DETECTED);` —— **窗口打不开就不再调 `apply_policy`**（它内部要调 `prot_antidebug_scan`，组 1 加密目标） |
| `prot_sdk/skeleton/app_main.c:555` | 裸调 `prot_antidebug_scan(&rep)` | 加窗口（与 `demo/main.c:540-545` 同形）：`sc_ext_enter() != PROT_OK` 即 `exit(1)`，成功则 scan + `sc_ext_leave()` |
| `prot_sdk/skeleton/app_main.c:624` | 裸调 `prot_antidebug_apply_policy(PROT_POLICY_EXIT)` | 同上改为窗口包住 + `else if (detected) exit(...)` 兜底 |

**验证**：`build.ps1 -Config Dev -SkipSign` rc=0（`selfcrypt_proto: patched build\demo.exe
(8 fns in-place, meta@0x33e00 hdr=196)`；`prot_vm_run` rva=0x1e80 crc=0xdc691b32 /
`prot_antidebug_scan` rva=0x7f30 crc=0x4c9463cf group=1）；`tests/e2e.py` rc=0。

**本地门禁实跑**：`powershell -ExecutionPolicy Bypass -File .\tools\release_check.ps1
-SkipDirtyCheck` → `[release_check] PASS: 31 项检查全通过`，含 `[ok] 加密封装窗口
(window_check)`；`[skip]` 0 / `[info]` 3（三个 `-With*` 开关项）。
另 `tools/mutate_check.py` rc=0、`tests/vmc_tests.py` rc=0、`git diff --check` clean。

**CI 第十跑（`c8a4799` → run `37096941944`）四 job 全绿**：
`linux-portability` 5/5、`build-and-verify` **22/22**（`Full release gate` 步在同一份
`release_check.ps1` 下通过）、`reproducible` 6/6、`sdk-package` 7/7；
唯一 `skipped` 仍是 `Publish GitHub Release`（`ci.yml:283` tag 门控，设计如此）。
⇒ 新门禁在真实 CI 上生效且不误报。

**门禁项数随之 33/30 → 34/31**（新项插在 `protchain P1-P6` 之后 ⇒ 其后项序号 +1）：
`tools/doccheck.py` 的 `GATE_TOTAL = 34` / `GATE_DEFAULT = 31`，并同步
`README.md`（badge `:9` / 命令注释 `:107` / `:132-153` 示意块）、`CONTRIBUTING.md:67`/`:95`、
`ShardVase-展示文档.md:140`/`:163`、`docs/BLUEPRINT.md:128`、
`.github/PULL_REQUEST_TEMPLATE.md:16`、`.github/workflows/ci.yml:67`、
`publish/01-关于ShardVase.md:63`、`publish/02-项目档案.md:116`/`:168`、
`docs/DEBUG_CONSOLE_PLAN.md:8`、`docs/CONTINUATION_PLAN.md`（含 §6.3 ③ 表后补的位移说明）。
`doccheck` 实跑：`检查数字 474 处, 错误 0, 警告 0`；`docclaim_check` 8/8 PASS
（`gate-count 文档声称与实际一致: **34 项**（2 份文档）`）。

**仍未验证的**：
- **机制 D（跨线程 enter/leave 互拆窗口）代码级成立，但因概率性未动态复现。**
- **§2.16 第二处的可达性未动态复现**（要求 D2b + `sc_do_range` 部分失败）。
- `window_check` **只看"调用点在不在窗口内"，不看 `exit` 是否漏了 `leave`** ——
  `demo/main.c:540-543` 与 `app_main.c:632-637` 的 `exit` 先于 `leave`
  属**已知可接受**写法（进程即将终止），门禁不报，这是**有意为之的判据边界**。

---

### 2.18 增量（2026-10-03）：缺陷 ⑥ —— 门禁里"没人比对的产物"

**性质**：**冗余 + 语义混乱**，不是正确性漏洞。但"白烧一次构建"掩盖了
一条**从未被任何断言覆盖**的前提。定位靠实测，不靠读代码。

**原形态**（`tools/release_check.ps1` 第 3/4 项）：

```
:250  Check 'Release 构建'  -> build.ps1 -Config Release -RecordSeeds -SkipSmoke
                              （无 -SeedsFile ⇒ 随机盐，且**会签名** ⇒ 产物 A）
:254  Check '可复现'        -> repro_check.ps1（无参）
                              （形态 A: 自己再建两次 -SeedsFile -SkipSign ⇒ B, C，
                               **只断言 B == C**）
```

一次门禁做 **3 次** Release 构建，其中 **A 的 `demo.exe` 从未与任何东西比过**。

**A/B/C 对照实测**（`build/_def6_abc.py`，三次真实构建）：

| | 命令 | 用时 | `demo.exe` SHA-256（前 24） |
|---|---|---|---|
| A | 门禁第 3 项原样（`-RecordSeeds`，签名） | 97.8s | `3EBCDE6D065520432268257D` |
| B | `-SeedsFile build\seeds.json -SkipSign` | 79.1s | `197550898E83063A977B4D61` |
| C | 同 B（repro_check 的第二次） | 78.4s | `197550898E83063A977B4D61` |

`A == B` **False** / `A == C` **False** / `B == C` **True**；
`vm.blob` A==B==C **True**；`seeds.json` A==B==C **True**（B/C 用 `-SeedsFile`
**不改写**它 ⇒ **A 写的那份才是被 CI 上传的**）；`manifest.json` 三者各不相同（含 timestamp）。

**先排除"正确性漏洞"**：把门禁跑完留在磁盘的 `build\` 产物 + 它留下的
`seeds.json` 拿去重放 CI reproducible job 的形态
（`repro_check.ps1 -BaselineDir build\_gateart\build`）→ `REPRO-RC=0`，
`demo.exe: identical` / `vm.blob: identical`。⇒ 留在磁盘上的那份**自洽**
（因为留下的本来就已经是 `-SeedsFile` 重建的产物）。**⑥ 不是错，是浪费 + 混乱。**

**D1–D4：找到那条没人管的前提**。问"`-RecordSeeds` 记下的种子表，
能否重建出记下它的**那个**产物" —— 这正是 CI reproducible job 依赖的前提
（它拿上传的 `seeds.json` 重建，再跟上传的 `demo.exe` 比），而**此前无任何断言覆盖**：

| | 命令 | 用时 | 结论 |
|---|---|---|---|
| D1 | `-RecordSeeds -SkipSign -SkipSmoke` | 99.7s | exe `D96D11B8…`，种子表 S1 |
| D2 | `-SeedsFile S1 -SkipSign -SkipSmoke` | 116.0s | exe **与 D1 完全相同** ⇒ **★ D1 == D2** |
| D3 | `-SeedsFile S1 -SkipSmoke`（**不 SkipSign**） | 128.0s | exe `CAA4164D…` ⇒ D1 != D3（签名因子） |
| D4 | `-RecordSeeds -SkipSmoke` | 197.8s | exe `16DF2FAE…` ⇒ D4 != D1（盐每次随机） |

**签名开销实测 ≈ +98s**（D1 99.7s vs D3 128.0s 是同一份种子的带/不带签名之差；
D4 197.8s 另含随机盐分支）。附带发现：`build/keys/codesign.pfx` **本机存在** ⇒
第 3 项在本机会真的走 signtool，但**它的产物马上被 repro_check 覆盖**，
而第 14 项 `签名 (Authenticode)` 看到的一直是**未签名**产物
（`Test-Path` 为真 ⇒ 进 `Get-AuthenticodeSignature` 分支 ⇒ 报
「未签名 — 可复现构建产物」，恒 PASS）⇒ **签名路径在门禁里被演练了但结果被丢弃**。

**修法**（`tools/release_check.ps1`）：让第 3 项成为**唯一权威构建**，
第 4 项拿它当基线。

```powershell
Check 'Release 构建 (build.ps1 -Config Release)' {
    powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -RecordSeeds -SkipSign -SkipSmoke
    if ($LASTEXITCODE -ne 0) { return $false }
    # 快照本次产物当第 4 项的基线 —— repro_check 会用 -SeedsFile 重建并
    # **覆盖** build\demo.exe, 所以必须先存下来。
    $snap = 'build\_gate_baseline'
    Remove-Item -LiteralPath $snap -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $snap | Out-Null
    Copy-Item -LiteralPath 'build\demo.exe' -Destination (Join-Path $snap 'demo.exe')
    Copy-Item -LiteralPath 'build\vm.blob'  -Destination (Join-Path $snap 'vm.blob')
    return $true
}
Check '可复现 (repro_check)' {
    powershell -ExecutionPolicy Bypass -File .\tools\repro_check.ps1 -BaselineDir build\_gate_baseline
    $LASTEXITCODE -eq 0
}
```

- 第 3 项加 `-SkipSign`。**这不改变上传物** —— 原形态下 A 签出来的 exe
  本来就会被 repro_check 的第一次构建 100% 覆盖，磁盘上留的一直是未签名产物。
- 第 4 项改 `-BaselineDir build\_gate_baseline`（CI reproducible job 的**同一种形态**）
  ⇒ 只重建**一次**，断言 A' == Y。
- 断言由此换成**更强**的那条：不只是"同命令跑两次一致"，
  而是「`-RecordSeeds` 记下的种子表足以重建出记下它的那个产物」（实测 D1 == D2）。
- 纯"同命令两次一致"（旧 B==C）在 CI 由 reproducible job 独立覆盖。
- **净效果：3 次构建 → 2 次，且两次的产物都承重（0 个无人比对的产物）。**
- **代价（如实记）**：门禁内**不再演练 signtool 路径**。签名验证改由
  第 14 项 `签名 (Authenticode)` 观测 + 发版流程"确认可复现后单独签名"承担。
  CI runner 无 pfx，本就不演练。

`tools/repro_check.ps1` 头注释同步改写：明确区分**形态 A**（无 `-BaselineDir`，
自建两次，判据较弱，仍被 `verify.ps1 -Reproducible` 与 `ci_sim` 使用）与
**形态 B**（`-BaselineDir`，**现为门禁第 4 项的默认形态**，判据更强），
并警示形态 B 会**覆盖** `build\demo.exe`、故基线必须由调用方事先快照。

**验证**：门禁实跑 `GATE-RC=0`，用时 **487.9s**；
`[release_check] PASS: 31 项检查全通过`；`[ok]` 31 / `[X]` 0 / `[skip]` 0 / `[info]` 3。
日志里 `基线快照 -> build\_gate_baseline（供下一项比对）`，
第 3/4 项均 `[ok]`。构建次数由"3 次 Release"降为"2 次"的**旁证**：
快照 `demo.exe` mtime **14:47:02** vs 重建后 `build\demo.exe` mtime **14:48:46**
（两者内容相同 ⇒ `snapshot==current = True`，`vm.blob` 亦然）。
门禁外回归全绿：`doccheck` rc=0 · `docclaim_check` rc=0 · `window_check --selftest` rc=0 ·
`sdk_pack --selftest` rc=0 · `mutate_check` rc=0 · `skeleton_check` rc=0 ·
`tests/vmc_tests.py` rc=0 · `comment_lint` rc=0 · `git diff --check` rc=0。

**仍未验证的**：无。门禁的这次改动已在 CI 上验证 ——
**CI 第十三跑（`82011fe` → run `37107965249`）四个 job 全绿**：
`build-and-verify` **24/24**（含 `Full release gate` 步，用的就是本次改过的
`release_check.ps1`）、`linux-portability` 8/8、`reproducible` **8/8**
（含 `Compare SHA-256 with first build`）、`sdk-package` 9/10
（唯一 `skipped` 仍是 `Publish GitHub Release`，tag 门控，设计如此）。
⇒ 门禁内"第 3 项快照 → 第 4 项比对"这条新链路在真实 CI 上生效且不误报；
CI 的 `reproducible` job 与本改动正交（它比对 `build_artifacts`），两条路径同时绿。
随后的回填提交（`c32c59f` → run `37109031897`，第十四跑）同为四 job 全绿
（`build-and-verify` 24/24、`linux-portability` 8/8、`reproducible` 8/8、
`sdk-package` 9/10）。

### 2.19 增量（2026-10-03）：计划与文档**现值复核** —— 把「声称」逐条对回实测

**缘起**：用户问「计划全部完成了吗，核实完毕了吧？文档更新了吗？」。
回答这个问题不能靠读一遍计划点头 —— 计划里的每一条「现值陈述」都要**回到实测**
（门禁实跑日志、`Select-String` 实测行号、探针重跑），因为本轮的前几次改动
（`window_check` 插在第 11 位、缺陷 ⑥ 改了第 3/4 项）**已经把文档里大量序号与行号
悄悄变旧**。本轮把 `docs/CONTINUATION_PLAN.md` 与相邻文档全部复核了一遍。

#### 复核方法（每一条都必须有实测证据）

| 断言类型 | 实测手段 | 权威来源 |
|---|---|---|
| 门禁项数 / 默认项数 | `Select-String "^\s*Check '"` 逐项枚举 | `tools/release_check.ps1` |
| 「第 N 项是 X」 | 同上枚举表按序读第 N 行 | 同上 |
| 「`某文件:行号` 处是 Y」 | `Select-String -LiteralPath <file> -Pattern <Y>` | 源文件本身 |
| 门禁扫不到的漂移量 | 重跑 `build/_q4_census.py` | 探针输出 |

**权威枚举（34 项，改后行号）**——本表是本轮所有「第 N 项」断言的唯一依据：
1 git 工作区干净 `:234` / 2 manifest.json 版本非占位 `:243` / 3 Release 构建 `:279` /
4 可复现 repro_check `:292` / 5 e2e T1-T28 `:296` / 6 attacks A1-A12 `:297` /
7 vm_unit `:298` / 8 vmc `:299` / 9 example E1-E7 `:300` / 10 protchain P1-P6 `:305` /
**11 加密封装窗口 window_check `:316`** / 12 模块契约 modcheck `:321` /
13 攻防记录 drills lint `:323` / 14 对外材料 doccheck `:337` / 15 签名 Authenticode `:359` /
16 mutate_check `:384` / 17 conformance `:396` / **18 Linux 编译覆盖 linux_compile_check `:419`** /
**19 C 注释词法 comment_lint `:514`** / 20 mojibake 全库回归 `:543` /
21 平台层契约 `:561` / 22 攻击技契约 attackcheck `:604` / 23 skeleton_check `:622` /
24 migration_gate `:642` / 25 check_state_platform `:667` / 26 _platform `:689` /
27 verify_lock `:704` / **28 文档断言一致性 docclaim `:730`** / 29 deploy_harden `:746` /
30 perf_baseline `:758` / 31 guard_selftest `:783` / 32 prot_dbg `:808` /
33 gate_log `:822` / 34 prot_dbg live `:848`。

#### 查实并修掉的过期陈述（8 处，逐条列证据）

**① 计划页脚与文件头自相矛盾（最严重）**
`docs/CONTINUATION_PLAN.md` 文件头 `:3` 写「v7 · **✅ 全部完成**」，
页脚却写「v6 · Q0–Q5 完成（**Q6 阻塞于用户提供仓库地址**）· 按 §9 顺序**推进中**」。
同一文件里两个互相否定的状态。⇒ 页脚改为 v7 / Q6 已完成（附解除日期与仓库名）/
「本计划无未排程的后续动作 —— 后续增量记在 `docs/HANDOVER.md` §2.11+」。

**② 风险表里的 Q6 条目已失效**
`:677`「**Q6 无 remote** | CI 永远不实跑 | 已明确**阻塞于用户**」。
实际 Q6 早已完成（仓库 `jurecoasertkrocket777/shardvase`，CI 十四跑四 job 全绿）。
⇒ 整行改为删除线 + 「✅ **已解除（2026-10-02）**」。

**③ `comment_lint` 的序号与行号双错**
`:194` 写「门禁**默认第 20 项**，`release_check.ps1:257`」。
实测：`comment_lint` 是**第 19 项**（`window_check` 插在第 11 位使其 +1），
定义在 **`:514`**；而 `:257` 现在是缺陷 ⑥ 注释块内的普通文字。
⇒ 改为「门禁第 19 项，`tools/release_check.ps1:514`」+ 更正说明块。

**④ Q4 普查数字口径漂移**
`:506`/`:510`/`:675` 记「**288 处**（门禁 132 项 / 118 N/N / 38 轮）」「**33 个文件**」。
重跑同一探针（`build/_q4_census.py` → `build/_audit_census.txt`）实测：
基准已变 `门禁 34 项 (默认 31)`，输出 `非现值断言总数: 门禁 169 项 / 123 N/N / 56 轮`
（相加 **348 处**），不在扫描范围内 **31 个文件 / 166 处**。
⇒ 代码块内的 288/33 **保留为当时的实测原文**（沿革），旁加「现值复测」块quote 说明；
风险表 `:675` 的现值口径改为 31/348 并标注原值。

**⑤ `§7.3 实现落点` 的 `src/integrity.c` 行号整体 +28 失效**
原记 L609/L610/L630/L645/L684/L696/L704/L814，实测现值
**L637/L638/L658/L673/674/L712/L724/L732/L842**。根因：T11 根因修复（`e6917a2`）
在 `watchdog_thread` 里插入了注释块与语句，其后所有行号位移。
⇒ 全部换成现值并保留旧值对照。

**⑥ `ci.yml` 注释里的两处行号**
`:40` 与 `:191` 写「门禁 `release_check.ps1:250`」⇒ 实为 **`:279`**；
`:192` 写「紧跟的 `:253` `repro_check.ps1`（`:24`/`:34`）」⇒ `:253` 实为 **`:292`**，
且 `repro_check.ps1` 里的 `-Config Release` 实测在 **`:52`（形态 B）/ `:92` / `:102`（形态 A）**。
（YAML 语法经 `yaml.safe_load` 复验：4 个 job 名不变。）

**⑦ `docclaim_check.py` 的自引用行号**
`:116` 与 `:591` 都写「`tools/release_check.ps1:79` 注释里的示例文本」⇒
该示例 `Check 'X' { & $tool; $LASTEXITCODE -eq 0 }` 实测现在 **`:170`**。
连带 `tools/release_check.ps1:353` 的同款注释也一并改正。
⚠️ 这两处记录的「断言得 31 而真实调用点 30」是**当时**的数字（现值 34/31），
已标注为沿革 —— **判据改用行锚定后与行号无关**，改行号不影响判据有效性。

**⑧ `docs/DECISION_REDUNDANCY_PLAN.md` 交付状态未回填（且它不受门禁保护）**
文件头 `:7` 写「v1 · 状态：**📋 待确认**」，`:516`（§11.5 第 3 条）写
「**仍未做**：在 EXIT 策略下的端到端演示 → 留给 R3.2-d/DRILL9」。
**但 DRILL9 早已交付**：`acbdb94` → `docs/ATTACK_DRILL9.md`（244 行，
判定点 patch + **重算 CRC** 后**仍被守卫抓住**，EXIT 策略端到端实测）。
⇒ 文件头状态改为「**🟡 部分交付**」，`:516` 加删除线 + 交付证据，
文末新增「交付状态注（2026-10-03 复核）」表。
**⚠️ 该文件不在 doccheck 的 24 个 TARGETS 内 ⇒ 它的漂移无任何门禁保护** ——
这正是 §6.4 量化的那个结构性缺口的一个真实受害者。

#### 顺便查清的一个**假**「过期」（不得"顺手修"）

`docs/LINUX_PORT_PLAN.md:510` 写「门禁含该检查项 | ✅ **第 22 项**」。
按现枚举实测 `Linux 编译覆盖 (linux_compile_check)` 是**第 18 项**（`tools/release_check.ps1:419`）；
**回溯 `window_check` 入库前的 33 项枚举，它同样是第 18 项**（当时定义在 `:379`）。
⇒「22」**对不上任何一次枚举**，是原始记录里就存在的错误引用，而非本轮位移造成。
已在原位加注「**序号存疑**，按现枚举为第 18 项」并**保留原文**，不改写（Q3 §5.3 第 1 条：
历史记录豁免而非改写）。

#### 一条新学到的**判据**教训（doccheck 报了我的错）

给 §6.4 加「现值复测」块quote 时，我先把探针输出原样贴进一个 **blockquote 内的围栏代码块**：

    > 基准已是「门禁 34 项 / 默认 31」。……
    > ```
    > 非现值断言总数: 门禁 169 项 / 123 N/N / 56 轮
    > ```

`tools/doccheck.py` 立刻报错：

    [X] docs/CONTINUATION_PLAN.md:525 门禁项数声称 169 项, 实际 34

根因：`doccheck` 的 `代码块` 豁免按**行首 ```** 判定，而 `> ``` ` 的行首是 `>`
⇒ **blockquote 内的围栏不被认作代码块**，里面「门禁 169 项」被当成一条现时断言。
**修法**：改写成不触发 `(?:release_check|门禁)[^
]{0,24}?(\d+)\s*项` 的叙述形式
（写成「探针输出『非现值断言总数』现在是 **169 / 123 / 56**（分别是项数口径、N/N 口径、
轮次口径）」）—— 门禁不是绕过豁免，而是**这个数字本来就不该长得像一条门禁项数断言**。

#### 验证

- `tools/doccheck.py` rc=0：`检查数字 488 处, 错误 0, 警告 0`；
  `豁免 145 处: 代码块 67 / 日期语境 64 / 沿革 4 / 自带日期 4 / 转述他文 3 / 计划验收 2 / 规划交付物 1`
- `tools/docclaim_check.py` rc=0：`PASS (8/8)`
- `tools/bom.py check` + `ParseFile`：`tools/release_check.ps1` 经 `edit` 后又丢 BOM
  ⇒ `bom.py add` ⇒ **`parse errors: 0`**（未加 BOM 前 26 个假错误）。**第 N 次复发**。
- `.github/workflows/ci.yml`：`yaml.safe_load` 通过，4 个 job 名不变
- 触达文件 BOM 状态：`.py`/`.md`/`.yml` BOM=False（**正确**，只有 `.ps1` 需要 BOM）

#### 仍未验证 / 仍开着的

- **R3.2-c（多副本 + OR 聚合）确实仍未做** —— 这次复核把它与「已交付」区分开了：
  `Select-String '副本|聚合|replica|aggregate' src/integrity.c` **零命中**；
  `git log --all --grep='R3.2-c'` 无提交。`:196` 指出的单点失效
  （「patch **1 处**判定副本**不再足够**」）至今成立。
  > **⚠️ 此条已被 §2.20 更新（2026-10-03）**：R3.2-c 当日交付 ——
  > 3 副本 + 非短路 OR 聚合器 + 门禁第 35 项；单点失效**已解除**（6 组单点变异漏报 0 例）。
  > 本节保留复核当时（2026-10-03 早些时候）的原结论，以便对照。
- Q4 建议的「把门面纳入 `PUBLIC_MATERIAL`」**仍未实施**（复核确认仍为真）。
- §2.17/§2.18 里那三条「仍未验证」（机制 D 概率性、§2.16 第二处可达性、
  `window_check` 不看 `exit` 是否漏 `leave`）**状态不变**。

---

## 2.20 增量（2026-10-03）：**R3.2-c 判定多副本 + 交叉聚合**落地 —— 单点 patch 不再足够

> 本节是 `docs/DECISION_REDUNDANCY_PLAN.md` 的**最后一项未交付子项**（§3 R3.2-c）。
> 它在 §2.19 的复核里还被明确记为「❌ 仍未做」——**本节即对该结论的更新**。
> 计划侧完整记录见该文档 **§12「R3.2-c 落地实证」**。

### 缘起：DRILL7 步骤 4 的单点失效

`docs/ATTACK_DRILL7.md` 步骤 4 实证：`prot_antidebug_detected` 函数头被 3 字节
`31 C0 C3`（`xor eax,eax; ret`）覆盖后，**盾永久失效**（DETECTED → clean，持续）。
R3.2-b 的序言快照守卫堵住了「patch 后重算 CRC」这条链，但**没改变单点性质**：
攻击者只要把判定函数打成恒 0，判定就不再发生。R3.2-c 解决的就是这个。

### 修法：3 个逐位等价副本 + 非短路 4 路 OR 聚合

| 部件 | 位置 | 说明 |
|------|------|------|
| 副本 `r2` | `src/antidebug.c`（文件尾追加段）| 展开式顺序 OR（无状态机）|
| 副本 `r3` | 同上 | 状态机但**逆序**遍历、状态编号不同 |
| 副本 `r4` | 同上 | 归约式 `(acc \| (0u - acc)) >> 31`（**无分支**）|
| 聚合器 | `prot_antidebug_detected_multi`（`src/antidebug.c:686-705`）| **非短路** 4 路位或 |

**为什么必须非短路**：写成 `a \|\| b \|\| c \|\| d` 会让后续副本永不执行 ——
攻击者只需让**先执行的那个**返回 0 即跳过其余副本，冗余归零。
故用 `hit \|= f(rep);` 连续四次（`\|\|` 被 `tools/replica_check.py` 静态拒绝）。

**为什么四个调用不会被优化掉**：每个副本首条语句是**局部 `volatile` 写入**
（`volatile uint32_t k = PROT_AD_R*_SALT;`），volatile 访问是副作用，
编译器不得消除/合并/跨副本复用。

**抗 `/OPT:ICF`**：Release 的 `$linkHard` 含 `/OPT:ICF`（`build.ps1:526`），
会把等价函数折叠成同一地址 —— 那样副本就白做了。故每个副本绑**各自专属的立即数**：
`PROT_AD_R2_SALT 0x5A17C3E9u` / `PROT_AD_R3_SALT 0x1B873593u` /
`PROT_AD_R4_SALT 0x9E3779B9u`。
**注意 `PROT_BUILD_SALT` 做不到这件事** —— 它是全局同一值（`prot_noise.h:59`），
所有副本会一起变，彼此仍等价。

### 接线：6 处宿主调用点 + 守卫表 2→6 条

宿主统一改调**契约入口** `prot_antidebug_detected_multi`：

| 文件 | 位置 |
|------|------|
| `src/antidebug.c` | `:549`（`prot_antidebug_apply_policy` 内）|
| `src/integrity.c` | `:217`（看门狗 A5 复查，在 EXT 窗口内）|
| `demo/main.c` | 3 处 |
| `prot_sdk/skeleton/app_main.c` | 3 处 |
| `examples/tool_demo/main.c` | `:261` |
| `prot_sdk/dotnet/Native/gate.c` | `:64` |

`src/integrity.c` 的 `g_guard_static[]` 由 **2 条扩为 6 条**
（本体 + r2/r3/r4 + multi + `prot_integrity_check_self`）；
`PROT_GUARD_N` 由 `sizeof` 自动跟随，**未改容量**（`PROT_GUARD_CAPACITY 12u` 仍够）。

### 验收实证（这是本节的核心，数字全为实测）

**① 单点 patch 不再足够**（`tools/replica_check.py` 判据 4）——
对 3 个副本各用 2 种手法打掉，共 **6 组单点变异**：

| 手法 | 含义 |
|------|------|
| `stub-ret0` | 函数体换成 `{ (void)rep; return 0u; }` —— 与 DRILL7 的 `31 C0 C3` **同效** |
| `drop-key-bit` | 把某个关键位读取换成 `0u` —— 该副本对那个位**失明** |

结果：**6 组全部「契约入口漏报 = 0」**（输入域 12325 例，其中阳性样本 **12276** 例）。
**对照（判据必须能失败）**：把 4 个入口 + 聚合器**全**换成 `return 0u` 后，
漏报 **12276** 例 ⇒ 判据不是恒真。

**② P1 语义等价有机械判据**（判据 1）——借 `antidebug.h` 只依赖 `protdef.h`，
把副本区独立切片编译成差分 harness：

```
cases=12325 mismatch=0 oracle_bad=0 entry_bad=0 range_bad=0 folded=0
```

- `mismatch=0`：4 个实现**逐位同输出**；
- `oracle_bad=0`：本体与**独立 oracle**（`any(7 个关键位) != 0`）一致 ——
  **纯差分对「全体一起错」是盲的**，故必须有独立 oracle；
- `folded=0`：harness 自身的函数指针两两不同（防差分退化成「一个函数和自己比」）。

**头文件漂移防护**：关键位/咨询位的归属靠 `antidebug.h` 里字段行尾的 `(咨询项)`
标注解析，解析结果**必须 7 关键 / 5 咨询**，否则报错 —— 不静默接受漂移。

**③ 抗 ICF**（判据 2）——`build/demo.map` 里 5 个符号 VA 两两不同：
`prot_antidebug_detected 0x140005fe0` / `_r2 0x140006180` / `_r3 0x1400061c0` /
`_r4 0x140006290` / `_multi 0x1400060b0`。

**④ 负向对照**（判据 3）——摘掉 r2 的 `debug_object` 后差分报 **35** 处不一致
（证明判据有判别力，不是「只会通过的检查器」）。

**⑤ 活体复核**（`tools/prot_dbg.py watch g_guard_hits --patch <符号>`）——
**5 个符号逐个**单独 patch 序言，`g_guard_hits` 均 `0 -> 1`：

| 被 patch 的符号 | hits | 命中耗时 |
|----------------|------|----------|
| `prot_antidebug_detected`（本体）| `0 -> 1` | 3.84s |
| `prot_antidebug_detected_r2` | `0 -> 1` | 3.67s |
| `prot_antidebug_detected_r3` | `0 -> 1` | 3.23s |
| `prot_antidebug_detected_r4` | `0 -> 1` | 3.08s |
| `prot_antidebug_detected_multi` | `0 -> 1` | 4.26s |

⇒ **每个副本各自被守卫快照守护**。这一点**不能**由 `guard_selftest` 证明 ——
它默认只挑**第一个**掩码区外候选（即本体）去 patch。

### 门禁与回归

- **新增门禁第 35 项**「判定多副本等价性 (replica_check)」（`tools/release_check.ps1`）；
  项数 **34/31 → 35/32**（`tools/doccheck.py:149-155` 已同步，全库现值文档同批更新）。
- `tools/ci_sim.ps1` 同步接线（`Step '判定多副本等价性 (replica_check)'` + `py_compile` 列表）；
  `.github/workflows/ci.yml` 的 `py_compile` 列表也已加入。
- **门禁实跑**：`[release_check] PASS: 32 项检查全通过`（35 顶层 = 32 ok + 0 X + 0 skip + 3 info），
  含新增的 `[ok] 判定多副本等价性 (replica_check)`。
- **3 连建**：build 1/2/3 各 `rc=0`、日志均 `DONE` 且 **0 warning / 0 error**（`/W4 /WX`）。
- **CI 实跑（`d6f1f8d` + 回填 `7da95f1` → run `37158617592`）四个 job 全绿**：
  `build-and-verify` 24/24（含用本次改过的 `release_check.ps1` 跑的 `Full release gate`，
  其 `[ok]` 里可见 **`判定多副本等价性 (replica_check)`**）、
  `linux-portability` 8/8、`reproducible` 8/8（含 `Compare SHA-256 with first build`）、
  `sdk-package` 9/10（唯一 skipped 仍是 tag 门控的 `Publish GitHub Release`）。
  ⇒ 新增的门禁项在 **CI 上真跑并通过**（不是"只在本地生效的门禁"）。
  该跑的门禁行：`[release_check] PASS: 28 项检查全通过`；
  35 个顶层项 = **28 `[ok]` + 0 `[X]` + 4 `[skip]` + 3 `[info]`**
  （CI 环境没有 WSL 发行版也不构建 linux/perf 产物，故 4 项按前置不满足 SKIP，
  与既有的 `[skip]` 口径一致；SKIP 不计入 PASS 分子。另有 1 行
  `[skip] 4 项因前置不满足未验证` 是收尾汇总，不是检查项本身）。
  （本行不复用「第 N 跑」编号 —— 上文的跑次编号沿用本轮之前的写法，此处只引 run id。）

### 诚实边界（不掩饰）

- **4 个副本全 patch 仍能关闭判定** —— 判据 4 的「全打掉对照」正是这一点的实证
  （漏报 12276 例）。**冗余提高成本，不是不可破。**
- **原「副本位置由构建期 seed 决定」的缺口已补（2026-10-04，§2.21）** —— 填充前实测
  间距恒为 `+208/+416/+480/+688`（3 个 shuffle seed 下逐字节相同），现由
  `PROT_PAD_STEP()` 阶梯让间距随构建盐变化。**边界仍在**：4 份副本同处一个 `.text`
  段与同一编译单元，位置抖动提高的是**定位成本**，拿到 PDB 或全段扫描仍可一次找出全部。
- **等价性判据覆盖当前 12 个字段**（7 关键 + 5 咨询）；**未来新增字段不在覆盖内** ——
  已写入 `modules.json` 的 `known_limits`。
- **聚合下沉进 VM（`// @vmcalc`）未做**（原计划即标为「可选，先不做」）。
- §5 风险表预留的「只加函数**不重排**已有函数」**已遵守**：新代码全部追加在
  `src/antidebug.c` 文件尾，未移动任何既有函数（位置抖动补做时也只在该文件**已存在的
  5 个函数体内**插入 `#if` 阶梯，未改变函数顺序，也未重排其他文件）。

---

## 2.21 增量（2026-10-04）：R3.2-c 的**位置抖动**补做 —— 副本间距不再跨构建固定

> **缘起**：§2.20 的「诚实边界」里写明「副本位置由构建期 seed 决定」**未实现**。
> 随后量化这一步的**实际影响**，发现它不是纸面担忧。

### 问题（实测，不是推测）

`--shuffle-seed`（R3.1）只随机化**源文件/目标文件的链接顺序**；而 5 个符号
（本体 + r2/r3/r4 + 聚合器）**全在 `src/antidebug.c` 一个编译单元内**，`cl /O2`
在该 TU 内的函数排布与函数间距**与链接顺序无关**。三个 shuffle seed 实测：

| 符号 | seed `0x11111111` / `0x22222222` / `0x33333333` 的偏移 |
|------|--------------------------------------------------------|
| `prot_antidebug_detected` | `0` / `0` / `0` |
| `prot_antidebug_detected_multi` | `+208` / `+208` / `+208` |
| `prot_antidebug_detected_r2` | `+416` / `+416` / `+416` |
| `prot_antidebug_detected_r3` | `+480` / `+480` / `+480` |
| `prot_antidebug_detected_r4` | `+688` / `+688` / `+688` |

⇒ 绝对地址变（ASLR 之外还有布局随机化），但**相对偏移逐字节相同**。攻击者只需
定位**任意一个**副本，其余 4 个的地址即可用常量推算，无需符号表 —— R3.2-c 的
「多副本」在**同一次发布内**对定位成本的贡献接近于零。

### 修法

- `include/protect/prot_noise.h` 新增 `PROT_PAD_STEP()`：语义恒等（局部 `volatile`
  读-改-写、结果丢弃），由调用方用 `#if` 阶梯控制**语句条数** ⇒ 机器码**长度**随构建变化。
  **为什么必须 `#if` 阶梯**：`switch` 的**所有 case 体都会被编译出来**（长度恒定）；
  常量界循环是否展开由优化器决定（不可控）。只有**预处理期**条件编译才真正改变
  被编译的代码量。
- `PROT_PAD_4/2/1()` 把 3 bit 分解成 4+2+1 ⇒ 恰好 0..7 步，调用点只需 3 个 `#if` 块。
- `src/antidebug.c` 的 **5 个函数各取一个互不重叠的 3 bit 位段**（本体 9..11 /
  r2 0..2 / r3 3..5 / r4 6..8 / 聚合器 12..14）⇒ 各函数尺寸扰动**互相独立**。
- **为什么 5 个函数全填**：首次只填 3 个副本时 `delta(r2)` 纹丝不动 —— 基线与聚合器
  未变，首个副本的偏移仍含固定基线（实测教训）。

### 实测（4 个盐，各一次完整 Release 构建，均 `rc=0`）

| 盐 | 偏移向量 `(本体, multi, r2, r3, r4)` |
|----|-------------------------------------|
| `0x12345678` | `(0, 304, 736, 800, 1232)` |
| `0xFF00FF00` | `(0, 432, 736, 800, 1008)` |
| `0x0F0F0F0F` | `(0, 432, 528, 800, 1040)` |
| `0xAAAAAAAA` | `(0, 368, 784, 912, 1280)` |

4/4 得到 **4 个互不相同**的偏移向量；扫描**两两**间距的残余可预测性 = **无**。

### 机械判据（`tools/replica_check.py` 判据 5）

3 个盐各编译一次差分 harness（`/MAP:` 出图），断言偏移向量**互不相同**；
**负向对照**必须成立：摘掉填充阶梯后偏移向量**退化为恒定**，否则说明本判据测的
不是填充，**不得**据此宣称位置抖动已生效。

```
判据 5: 3 个盐得到 3 个不同偏移向量 -> [(0,304,368,800,896), (0,432,496,704,896),
        (0,432,704,944,1136)]; 负向对照 (摘掉填充) 退化为恒定 (0,208,272,480,544)
        (判据有判别力); 任意两符号的间距都随构建盐变化 (无残余常量间距)
```

**诚实边界**：判据 5 度量的是「间距**是否**随盐变化」，**不度量熵的大小** —— 若将来
填充被削弱到只剩 1 bit，本判据仍可能通过（每次构建的盐是随机 4 字节，实际空间远大于
判据里用的 3 个）。

## 2.22 增量（2026-10-04）：CI 第 16 跑红项 —— `gate_log` T1 是**拿调度抖动当缺陷**

> **缘起**：`04340f4`（位置抖动）推送后，CI 第 16 跑 `37164875743` 的
> `build-and-verify` job 报 `Full release gate` 失败，门禁 `FAIL: 1/28`。
> 唯一失败项 = `[X] 门禁日志自检 (gate_log)`，且**只有 T1 红**（T2..T5 全 ok）：
> `[X] T1 开启转录 rc=0 且返回文件已创建`。
> **本轮新加的 `replica_check` 在 CI 上是通过的**（`[ok] 判定多副本等价性`），
> 即这次失败与 R3.2-c 无关，而是一个**既有的间歇性缺陷**恰在此轮暴露。

### 根因（实测，不是推测）

`Start-Transcript -Path P` **返回时文件可能还不存在** —— 转录文件是**异步**落盘的。
T1 的判据是「开启后立刻 `Test-Path`」，于是它测到的是**文件系统/会话调度的抖动**，
不是「开启失败」。

决定性证据（`build/_glP2.ps1`，把 T1 依赖的原语单独拿出来，紧接 `Start-Transcript`
就 `Test-Path`）：

```
iter 36: rc=0 exists=False msg=[] files=[st.log]
=== primitive (plain) fails: 38/40 ===     # 有外层转录时 40/40
```

注意 `exists=False` **但 `files=[st.log]`** —— 文件明明已经在了，只是 `Test-Path`
那一刻还没看见。可见延迟实测（`build/_glRace.ps1`）：

```
=== delays(ms): 0,18,7,25,25,25,25,23,28,20,21,2 ===
```

即 **0..28 毫秒**。真 T1 里在 `Start-Transcript` 与本断言之间还隔了一次脚本调用 +
`Get-Variable`，通常已足够刷出 ⇒ **本机几乎总是通过**，但它是**间歇性**的：
CI 上命中一次就红一整轮。

**为什么此前没被发现**：这是「本地几乎总是过、失败无现场」的典型形态。本项目的
门禁日志工具（本文件 §2.9/§2.10）存在的理由正是「判据失败要留下证据」；而
T1 失败时留下的证据只有 `[X]` 一行，看不到 `exists=False` 这个关键字段。本轮
靠**插桩副本**（`build/_mk_dbg.py` 从 `tools/gate_log.ps1` 生成 `build/_gl_dbg.ps1`，
在 T1 体内打印 `rc`/`p`/`exists`）才把签名抓出来，用**同一个签名**在本地复现：
第 4 次迭代 `rc=0 p=[…] exists=False`。

### 修法

- 新增有界等待 `Wait-Path`（默认 2000 ms，20 ms 轮询）。
- T1 改为 `($rc1 -eq 0) -and ($p -ne '') -and (Wait-Path -Path $p -TimeoutMs 2000)`。
  **判据没有放松**：真正「开启失败」的路径由 `$p -ne ''` 挡住 ——
  `Start-Transcript` 抛错时 `$p` 根本不会被赋值（`gate_log.ps1:180-181` 在
  `try` 内、赋值在 `Start-Transcript` 之后）。
- 顺带修掉一个**潜在陷阱**：原 T1 在同一 scriptblock 里用 `$LASTEXITCODE`，
  中间还夹着 `Get-Variable`；改为**立刻**取 `$rc1 = $LASTEXITCODE` 再断言。
- 新增 **T6 负向**：把「等待」本身也证伪一次 ——
  `Wait-Path` 对**不存在的**路径必须返回假（且耗时 ≥ 阈值）、对**空串**必须返回假
  且不抛异常。没有这一条，T1 的等待就等于**把断言取消掉**（本仓库反复记名的
  「看似在测、其实没测」）。自检从 **5 项（含 3 负向）** 增至 **6 项（含 4 负向）**。
- 文件头「设计要点」补一条：转录文件异步落盘，任何「开启后立刻检查文件」的断言
  必须用有界等待。

### 验证

```
A) powershell -File tools\gate_log.ps1 -Selftest            -> rc=0
   ok T1 / ok T2 / ok T3 / ok T4 / ok T5 / ok T6
   [gate_log-selftest] PASS: 6 项（含 4 负向）

B) build\_glStress.ps1（外层转录 + 40 次 fork，改后）-> ok T1 行 40 / [X] T1 行 0
   PASS 行 40 / FAIL 行 0
```

> **一处须更正的说法**：`build\_glprobe.ps1` 打印的 `T1=?` 与
> `=== T1 failures: 12/12 ===` 都是**探针自身的产物** —— 它用 `@(& …)` 捕获成功流，
> 而子进程的逐项结果走 `Write-Host`＝信息流，故 `$t1` 恒为 `'?'`、计数永不刷新。
> 因此「改前 12/12 FAIL」**不能作为缺陷复现的证据**，判读须看逐次回显的 `ok T1` 行。
> 改前真正站得住的证据是 §A 的原语隔离探针（`38/40`，有外层转录时 `40/40`）与
> `exists=False` 而 `files=[st.log]` 的并存现象；改后证据是 B 的 `40/40`。
> 教训：**探针与被测对象都要各自被证伪一次** —— 失败形态与 CI 一致，不等于探针正确。

C) CI 第 17 跑 `37167298806`（head `cc6fbb0`）-> 四个 job 全绿；
   `Full release gate` step 19 success（第 16 跑即败于此步），
   `[gate_log-selftest] PASS: 6 项（含 4 负向）` / `[ok] 门禁日志自检 (gate_log)`
   / `[ok] 判定多副本等价性 (replica_check)` / `[release_check] PASS: 28 项检查全通过`。

**未验证**：`Wait-Path` 的 2000 ms 上限是从实测最大 28 ms 留了约 70× 余量，
**不是**从原理推导出来的上界；T6 也没有构造「文件超 2000 ms 才出现」的真实场景
（那需要人为制造远超实测的落盘延迟）。

---

## 2.23 增量（2026-10-04）：`.protxec` 盲区**收口** —— 第 4 个段 CRC 目标 + 门禁第 36 项

> **缘起**：`docs/ATTACK_DRILL9.md` §5（2026-10-02）实测发现 —— 守卫检查器
> `prot_integrity_check_guards` 落在 **`.protxec`** 节（不是 `.text`），
> 而段 CRC 只覆盖 `.text`/`.rdata`/`.pdata` ⇒ **直接 patch 检查器函数头即可恒返回
> `PROT_OK`，且无需任何 CRC 重算**（用例 F/G/H 全链复现）。当时只提了三个建议方向，
> 未实施。本轮按**建议 ②** 实施并收口。

### 决策：为什么选 ② 而不是 ①

| 方案 | 做法 | 否决/采纳理由 |
|------|------|----------------|
| ① | 把检查器（或整个守卫快照实现）移进 `.text` | **否决**：会把已稳定的 `.text` 布局整体挪动。本仓库有硬约束「**只增函数、不重排**」（R3.2-c 刚把副本间距抖动做成不变量，`docs/DECISION_REDUNDANCY_PLAN.md:184` 已记 `.text` 布局漂移风险）。代价真实且立即 |
| ② | 把 `.protxec` 加为**第 4 个段 CRC 目标** | **采纳**：**零搬移**，且覆盖面更大 —— `.protxec` 里除检查器外还有 `iat_snapshot_init` / `check_iat` / `register_guard` / `start_watchdog` |

关键判断：自引用问题在 ② 下**并未新增**（`prot_crc32_step` 本就在 `.text` 内，
既有实现已接受该残余；`.protcrc` 烧录表自身不被覆盖是**刻意**设计）。
Linux/ELF 侧**刻意保持 3 个目标**：`include/protect/prot_compiler.h:273-276` 的
`PROT_CODE_SEG()` 在非 MSVC 下展开为空 ⇒ ELF 侧检查器本就落在 `.text`、已被下标 0 覆盖
⇒ 不对称是**显式设计**，不是漏配。

### 改动落点（5 处契约必须同步）

| 文件 | 改动 |
|------|------|
| `tools/hashpatch.py` | `MAGICS` 加 `b'PROTCRCX'`；`TARGET_NAMES` 加 `.protxec`；**新增 `TARGET_LOGICAL = (None, None, None, 'protxec')`** 与 `resolve_target_names()`；`load_magics` 由 3 元组改 4 元组；`ELF_TARGET_NAMES` **刻意保持 3 项** |
| `src/integrity.c` | `g_prot_baked_crc[3]` → `[4]`，追加 `{ PROT_MAGIC_XEC_BYTES, 0, 0 }`；两处 `j < 3u` → `j < 4u` |
| `include/protect/prot_sections.h` | 新增 `PROT_MAGIC_XEC` / `PROT_MAGIC_XEC_BYTES` |
| `tools/gen_sections.py` | magics 3 元组 → 4 元组 + 头文件写入顺序 |
| `src/platform/prot_platform_win.c` | `prot_plat_crc_target_name()` 第 4 节 = `PROT_SEC_XEC` |

### ⚠️ 本轮**最重要的坑**：静默 skip（`TARGET_LOGICAL` 的必要性）

阶段 1 起 `.protxec` 的**节名每构建随机**（`tools/gen_sections.py` 写
`#undef PROT_SEC_XEC` + `#define PROT_SEC_XEC ".xxxxxxxx"`）。
若 `tools/hashpatch.py` 只用常量名 `.protxec` 去找节，生成路径下 `next(...)` **永远返回
None** ⇒ 走 `print('hashpatch: %s section absent — skip' % target_names[i]); continue`
分支 ⇒ **CRC 字段恒为 0、不报错、构建成功、门禁全绿**。

> **这比不修更危险**：形态是「**表的条数对得上，语义对不上**」——
> 只数条数的检查器（`doccheck` / `docclaim_check`）看不见，人工也看不见。
> 与「门禁项数看起来完全正确」属同一类事故。

### 防漂移：新增门禁**第 36 项** `tools/check_crc_targets.py`

被检查的不变量 = 「下标 → 节名 → magic」映射在**四处**一致：
① `tools/hashpatch.py`（`MAGICS`/`TARGET_NAMES`/`TARGET_LOGICAL`/`ELF_TARGET_NAMES`）
② `src/integrity.c`（`g_prot_baked_crc[]` + 两处 `j<N` 循环上界）
③ `src/platform/prot_platform_{win,linux}.c`（`prot_plat_crc_target_name()` 的 `names[]`）
④ `include/protect/prot_sections.h`（`PROT_MAGIC_*` / `_BYTES`）+ `tools/gen_sections.py` 生成顺序。

- **全纯文本正则解析，不 import 被测文件**（自检要对文本做变异）。
- **13 条判据** + **8 条负向自检**（`--selftest`，实测 `8/8 变异被抓`）。
- 平台不对称**被判据显式接受**：Linux 侧 3 项不含 `PROT_SEC_XEC`，或 4 项末位为它。
- 接入 `tools/release_check.ps1`（两段式，与 `attackcheck` 同形）；
  `tools/ci_sim.ps1` 同步加一步；`.github/workflows/ci.yml` 的 py_compile 列表追加。
- **教训（已写进代码注释）**：**数量类判据必须比「实际元素个数」，声明长度是可被说谎的
  元数据** —— 自检变异 M8（「`names[]` 声称 4 项却塞 4 个别的元素」）首跑未被抓，
  根因就是判据比的是声明长度 `names[N]` 而不是 `len(items)`。

### 实测证据

**用例翻转**（同一探针 `build/_drill9_probe.py --verbose`，`rc=0`）：

```
             收口前(2026-10-02)   收口后实测
F_checker_recalc   exit=1(成功)    exit=2989 (0xBAD，被段 CRC 拦)
G_checker_no_recalc exit=1(成功)   exit=2989
H_full_chain       exit=1(盾失效)  exit=2989
A 基线 exit=1 / B exit=2989 / D exit=1 (证明重算确实生效) / E hits=3   全 [ok]
```

**构建实测**（3 连建均 `rc=0`，第 4 个目标每次都烧录，节名每次不同）：

```
#1 protxec -> .fpmhwjo  crc=0xa6347550  raw [141312, +2573)
#2 protxec -> .b7ogh7p  crc=0xf51f5c76  raw [141824, +2573)
#3 protxec -> .lf7t0q3  crc=0x5ba64a79  raw [141312, +2562)
```

首建 `merge_baseline` 报 `protcrc vsize 0x30 -> 0x40`（烧录表 3×16 → 4×16 字节），
属**预期的节尺寸变化**（`tools/gen_padding.py:211` 基线只增不减，自动提升）。
烧录表自身仍住 `.protcrc` 且**不被任何段 CRC 覆盖**（避免自引用），该设计未变。

### 门禁项数口径同步（35/32 → **36/33**）

`tools/doccheck.py:149-155` 的 `GATE_TOTAL = 36` / `GATE_DEFAULT = 33` 及其 6 处自检用例；
另同步 `docs/CONTINUATION_PLAN.md`、`docs/DEBUG_CONSOLE_PLAN.md`、`publish/01-关于ShardVase.md`、
`publish/02-项目档案.md`、`.github/workflows/ci.yml`、`tools/ci_sim.ps1`。
另新增 `docs/ATTACK_DRILL9.md` §5.4/§5.5、更新 `docs/ATTACK_MATRIX.md` DRILL9 行、
`docs/COST_ASYMMETRY.md` 杠杆表第 10 行、`docs/OPEN_SOURCE_COMPENSATION.md:78-91` 覆盖清单。

### ⚠️ 收口后的**残余边界**（不可过度声称）

```
=> F/G/H 被拦住 != "第二道不可移除"。
=> 攻击者若**同时中和段 CRC**（使 .protxec 的校验失效，例如 patch 比对逻辑
   或直接改烧录表），仍可关掉检查器。
=> prot_crc32_step 自身在被校验段内（自引用边界），与 .text 同理，属既有残余。
=> 本条把攻击成本从"patch 一个函数头"提高到"必须同时中和第 4 个段的 CRC"
   —— 是**成本提高**，不是**不可破**。
```

**未验证**：未在 **Linux/ELF** 侧跑过（本轮改动不触及 ELF 的 3 目标路径，
仅由门禁第 36 项的判据 ⑥/⑥' 在**文本层**守护其不对称性）；
未做**运行期**攻击复现「同时中和第 4 段 CRC」（残余边界是从代码结构推导，非实测）。
## 2.24 增量（2026-10-05）：e2e T3 的**孤儿调用** —— `DebugAttacher` 被删但调用点留着

> **缘起**：门禁实跑（`build/logs/release_check_20261004_200612.log`）报
> `[X] e2e T1-T28`，诊断行 `| T3 debug-detect  FAIL  (NameError("name 'DebugAttacher' is not defined"))`。
> 此前该用例在本机**一直是 SKIP**（`env denies process debugging (winerror 5/0x5)`），
> 本轮环境允许调试 ⇒ 首次走进真实附加分支 ⇒ 暴露一个**潜伏 7 天**的缺陷。

### 根因（git 定案，非推测）

```
e5ea2d5            init baseline      -> tests/e2e.py:120 class DebugAttacher(object) 存在
22826c5 (09-28)    feat(C-3) e2e 全量移植 …… C 阶段完成
                   -> 整块删除 DebugAttacher，但 调用点 :515 未同步删除  => 孤儿调用
15a0dd5 (S6)       只改同区域附近的 preflight，未恢复该类
```

- **为何一直没被发现**：`22826c5` 之后 T3 的 preflight 是
  `DebugActiveProcess(os.getpid())` —— Windows **禁止进程调试自身** ⇒ preflight
  必然失败 ⇒ 一直走 SKIP，`:509 else:` 分支（`:515 dbg = DebugAttacher()`）
  **从未被执行过**。`15a0dd5` 把 preflight 改成对**派生子进程**
  (`cmd /c timeout /t 3 /nobreak`) 附加后，只要环境允许调试就**必然**走到 `:515`。
  `git log -G DebugAttacher` 全历史只有 `e5ea2d5`（加）与 `22826c5`（删）两个提交。

### 修法：从删它的那个提交的父提交逐字恢复

`git show 22826c5^:tests/e2e.py:216-255` 取回 `class DebugAttacher`，插入
`tests/e2e.py:389 def main():` **之前**（与历史位置一致），并在前置块注释里写明
六点（被谁误删 / 调用点未同步删 / `py_compile` 抓不到 / S6 改 preflight 后才暴露 /
恢复来源 / 守护工具）。依赖已具备：`:108-121` 已有模块级 `KERNEL32 = ctypes.WinDLL(...)`
及 5 个 argtypes/restype 预设。

### ⚠️ 为什么 `py_compile` 抓不到，以及本轮的补救

`py_compile` **只查语法**，未定义名要**运行到那一行**才炸。本轮因此新增
**全库静态「未定义全局名」审计** `build/_undef.py`（`ast` 逐作用域建模：
模块 / 函数 / 类体 / lambda / 推导式；绑定含 import、形参、赋值、
`except ... as`、`global`/`nonlocal`；类作用域对方法体**不可见**）。
在 86 个 `.py` 上跑出**恰好 1 处命中**（就是 `tests/e2e.py:515 DebugAttacher`），
零假阳；修复后复跑 **0 处**。

> **该工具随后立刻抓到本轮自己引入的第二个缺陷**（见 §2.25）——
> 它值这一次的存在。

### 4 个迭代教训（假阳根源，全部已写进代码注释）

1. **绑定列表混入不同元数** ⇒ 打印时 `ValueError: not enough values to unpack`。
2. **`ast.arg` 的属性是 `node.arg` 而非 `node.id`**。
3. **`split_scope` 必须把嵌套作用域节点本身也当作本作用域的绑定** ——
   否则 `try:` 内 `class OSVERSIONINFOEXW` 的名字不被绑定，后续
   `OSVERSIONINFOEXW()` 被误报。**一次性消掉 18 处假阳**。
4. **必须 `encoding='utf-8-sig'` 读文件** —— `tests/attacks.py` / `tests/e2e.py`
   带 BOM，否则报 `invalid non-printable character U+FEFF`。

**未验证**：`build/_undef.py` **尚未接入门禁**（仍是一次性探针）。
`tests/e2e.py:104-107` 有一条残留注释称「Linux 侧用 ptrace（DebugAttacher / C-1 的
tracer）」，但**该 tracer 从未存在**；本轮只恢复 Windows 路径（T3 在
`tests/e2e.py:442 if _PLATFORM != 'win'` 已被 PLATFORM_NA 守卫）。


## 2.25 增量（2026-10-05）：`guard_selftest` 的**假红** —— 拿固定 `sleep` 赌宿主就绪

> **缘起**：CI 第 16 跑（`37164875743`，head `04340f4`）唯一红项
> `[X] 判定点快照校验自检 (guard_selftest)`，诊断
> `| **FAIL** 负向(patch -> hits 必须 > 0)  exit=2989  hits=0  <- 判据未满足`。
> 本机连跑 **12/12 + 4/4 全绿**（负向 `hits=2/3/4`），**稳定不复现**。

### 根因（用可证伪实验锁定，非推测）

探针 `build/_gs_race.py` 用 `importlib` 装载被测工具、只替换 `_spawn`
以追加 `--wait-ms N`（把 demo 的看门狗启动推后），**逐位复现红项签名**：

```
=== 基线(不推迟, --wait-ms 0) ===
  negative … dyn_n=3  wrote=True 序言=31 c0 c3  exit=None  hits=3
=== 推迟 start_watchdog (--wait-ms 5000) ===
  negative … dyn_n=0  wrote=True 序言=31 c0 c3  exit=2989  hits=0   <== 红项签名
```

**机制**：工具在固定 `SETTLE_S = 1.2` 秒后就把 `g_wd_policy` 写成
`PROT_POLICY_CONTINUE(0)`，**赌**宿主已调完 `prot_integrity_start_watchdog`。
而该函数在 `src/integrity.c:827 g_wd_policy = pol;`（demo 传
`PROT_POLICY_EXIT`，见 `demo/main.c:679`）会把 CONTINUE **覆盖回 EXIT**。
若覆盖发生在工具写之后（**慢机器如 CI runner 上 1.2s 不够**）⇒ patch 破坏
`.text` 段 CRC ⇒ 看门狗首轮 `src/integrity.c:200 prot_integrity_check_self()`
失败 ⇒ EXIT 分支 `:203 prot_plat_terminate(PROT_EXIT_TAMPERED = 0xBAD = 2989)`
⇒ 进程在同一 tick 内死亡 ⇒ `g_guard_hits` **从未自增** ⇒
自检报 `exit=2989 hits=0` = **假的「守卫失效」**。

### 修法：把「固定 sleep」换成**可观测的就绪哨兵**

```c
/* src/integrity.c:810 prot_integrity_start_watchdog() */
:815  if (interval_ms == 0) return PROT_ERR_INVALID_ARG;
:818-821  策略合法性校验
:822  if (g_wd_thread != NULL) return PROT_OK;
:826  atomic_exchange(&g_wd_stop, 0)
:827  g_wd_policy = pol;          <-- 会把工具的 CONTINUE 冲掉
:828  g_wd_interval = interval_ms; <-- 就绪哨兵（工具从不写它）
:833  prot_integrity_check_iat();
:836  prot_plat_thread_create(watchdog_thread, NULL, &g_wd_thread)
```

- 新增 `READY_SYM = 'g_wd_interval'` + `READY_TIMEOUT_S = 25.0`，`_wait_ready()`
  轮询至哨兵非 0（或进程退出）后才动目标。
- **为什么不用 `g_wd_policy` 当哨兵**（第一版修法正踩此坑，12/12 恒报"未就绪"）：
  该变量零初始化且 `PROT_POLICY_CONTINUE == 0`
  （`include/protect/protdef.h:48-52`），**而本工具自己要写它** ⇒
  拿它当信号等于**自毁证据**：宿主已就绪（真实值 EXIT）时先把 0 写进去，
  "已就绪"与"未就绪"就无法区分。`g_wd_interval` 工具从不写 ⇒ **单调、无歧义**。
- **附带加固**：`:828` 只在参数校验**之后**执行 ⇒ `g_wd_interval != 0`
  还额外证明「宿主已通过参数校验」。

### 顺手修掉的**假绿**

原判据只拦负向的 `wrote is False`。**未就绪时正向 `hits` 必然为 0** ⇒
若不拦，正向会被读成「通过」。现改为：`ready is False` ⇒ **两个方向都判 FAIL**，
并打印「未能等到看门狗就绪（自检无判别力）—— **不要**读成"守卫失效"」。

### 验证

| 场景 | 结果 |
|------|------|
| 修复后 `--wait-ms 0 / 5000`（原红项签名） | 两者都 `exit=None hits=3` ⇒ **红转绿** |
| 夹具 `build/_gs_fixture.py`（`--wait-ms 30000` + 就绪超时 3s） | rc=1，输出「未能等到看门狗就绪」且两方向均 FAIL，**诊断正确 = True** |
| `build/_gl_loop.ps1` 12 连跑 | **12/12 rc=0 PASS**，`exe`/`map` 时间戳全程未变（同一构建） |
| 全门禁 `tools/release_check.ps1 -Quiet` | `[ok] 判定点快照校验自检 (guard_selftest)`；仅剩 `[X] git 工作区干净`（改动未提交，预期） |

### ⚠️ 好教训：本工具自己抓出了本轮的第二个缺陷

修完诊断输出后用 `build/_undef.py` 复跑，报：

```
UNDEF    :557   exit_pol
UNDEF    :559   cont
```

`cont`/`exit_pol` 是 `run_by_hits()` 的**局部名**，却在 `main()` 的诊断分支里被引用
（未就绪时才炸 ⇒ **又是一条只在失败路径上执行的代码**，与 §2.24 同型）。
改为就地 `_policy_value(...)`，复跑 **0 处**。

> **通用教训**：**「只在失败路径上执行的代码」是最难测的一类** ——
> 正常路径永远不碰它。静态审计（而非运行测试）才是它的正确防线。

**未验证**：未在 **CI runner** 上复跑验证（本地已 12/12 绿 + 红项签名已复现并转绿）；
未改 `SETTLE_S`（保留为「PE 加载完成的最短等待」，语义已改正）。

---

## 2.26 增量（2026-10-05）：全门禁挂死 1h45m —— T3 的 `DBG_CONTINUE` 常量写错

### 2.26.1 现象

2026-10-05 07:06 起的全门禁在 `e2e T1-T28` **挂死 1h45m**（日志自 07:20:58
起不再增长）。进程树：`powershell`(门禁) → `python tests\e2e.py` →
`build\demo.exe --wait-ms 4000`，**三者都活着但零 CPU**（demo
`CPU=0.03125`/`WS=5.0MB`，python `CPU=0.359375`）。线程态：
python 单线程 `Wait/UserRequest`，demo 4 线程全 `Wait/Executive`。
⇒ **不是慢，也不是偶发。**

### 2.26.2 取证

`build/_t3hang.py` —— `faulthandler.enable(file=_fh, all_threads=True)` +
`faulthandler.dump_traceback_later(75, exit=True, file=_fh)`，日志逐行
flush 到 stderr。拿到决定性栈：

```
File "D:\environment\PYTHON\Lib\subprocess.py", line 1606 in _wait
File "D:\environment\PYTHON\Lib\subprocess.py", line 1280 in wait
File "...\build\_t3hang.py", line 129 in main
```

即卡在 T3 的 `proc.wait()`（**无 timeout**）。

> **教训（工具形态）**：`build/_t3probe.py` 只在函数末尾一次性落盘，
> 一卡死就**零证据**。诊断脚本必须**逐步 flush**，或用 `faulthandler`
> 直写 fd。同一坑在 §2.25 也踩过（未就绪路径无输出）。

### 2.26.3 根因：`DBG_CONTINUE` 不是 `2`

`DebugAttacher.DBG_CONTINUE` 写的是**裸整数 `2`**。Win32 的
`DBG_CONTINUE` 是 **`0x00010002`**（`DBG_EXCEPTION_NOT_HANDLED` 才是
`0x80010001`）。`build/_t3cont.py` 逐值实测：

```
=== 裸 2 (现状 e2e 用法) ===        Continue -> 0  err=0x57
=== DBG_CONTINUE 0x00010002 ===     Continue -> 1  err=0x0
=== DBG_EXCEPTION_NOT_HANDLED ===   Continue -> 1  err=0x0
```

`0x57` = `ERROR_INVALID_PARAMETER` ⇒ **`ContinueDebugEvent` 从未成功**
⇒ 调试对象**从未被恢复运行**，永久停在初始断点：

  · `ExitCodeProcess = 0x103`（`STILL_ACTIVE`）
  · 附加期间 `cpu = 0`、**stdout 一个字都没有**
  · `poll()` 恒 None

**后果链**：`--wait-ms` 永不生效 ⇒ 进程处于**调试暂停态**，连
`proc.kill()` 都终结不了它 ⇒ 无界 `proc.wait()` **永久阻塞** ⇒ 全门禁挂死。

### 2.26.4 三处伴随缺陷（同一次修复一并处理）

| # | 缺陷 | 证据 |
|---|---|---|
| ① | **preflight 探针对象错**：S6 用 `cmd /c timeout` 探测能力 | 该探针本环境 **8/8 被拒**（`err=0x5`），而**真实目标 `demo.exe` 可以附加**（`build/_t3preflight.py`）。⇒ 探针恒 SKIP、**真缺口永不执行**；且它**偶发成功**（07:20:59 那次就跑进 `else`，于是暴露挂死）——「拿错误的对象做能力探测」，与 `SETTLE_S` 同型 |
| ② | **`pump_and_read` 超时契约缺陷** | `TimeoutExpired` 时只 `return (None,'','')`，**既不 kill 也不 wait**，把活进程 + PIPE 句柄留给调用方（调用方随后做了无界 wait） |
| ③ | **`pump` 在 `EXIT_PROCESS` 时直接 return, 不 Continue** | 留下悬挂的调试对象；且 `WaitForDebugEvent` 无事件时实际返回 **`0x79 = ERROR_SEM_TIMEOUT`**（**不是** `WAIT_TIMEOUT = 0x102`），原实现只认 `0x102` ⇒ 在正确线程上泵就把它当致命错误 break |

### 2.26.5 修法（仅 `tests/e2e.py` 一文件）

  · `DBG_CONTINUE = 2` → **`0x00010002`**（新增 `DBG_EXCEPTION_NOT_HANDLED` 备查）。
  · `pump()` 返回 `(n_events, saw_exit, exit_code, cont_fails)`；
    **先 `ContinueDebugEvent` 再判 EXIT**；`exit_code` 取 `DEBUG_EVENT`
    **offset 16**；新增 `TIMEOUT_ERRNOS = (0x79, 0x102, 0x5B4)`。
  · **删除整个 `cmd /c timeout` preflight**，直接用真实目标探测：
    附加失败即带 errno 记 SKIP（保留「环境限制，非未做」语义）。
  · T3 改为**同线程泵**（不起子线程）+ **先 detach 再 kill** + 有界回收；
    新增 `_reap(proc, timeout=5)`，`pump_and_read` 超时路径也改用它。

**判据未变**（仍是 `exit == 0xDB` 且 stdout 含 `MSG_DBG`）。

### 2.26.6 验证

  · **修后是真检出，不是残留**：`build/_t3cont.py` 实测 `Continue -> 1
    err=0x0`，事件序列 `CREATE_PROCESS / LOAD_DLL / CREATE_THREAD×3 /
    LOAD_DLL…`，**附加期间** stdout 已含 `反调试扫描: 发现可疑` +
    `MSG_DBG`，并收到 `EXIT_PROCESS` 且 offset16 退出码 = **`0xdb`**。
  · **判别力对照**（`build/_t3resid.py`）：附加后**零驻留**
    （dwell=0.05s）即 `rc=219 MSG_DBG=True`；**不附加**仅冻结 4.0s 得
    `rc=1 MSG_DBG=False`。
  · `python -X utf8 tests\e2e.py`：**28 PASS / 0 FAIL / 0 SKIP / 0 NA**，
    **51s**（此前挂死 1h45m+）。T3 行：
    `T3 debug-detect PASS (exit=219 ev_exit=0xdb events=23 cont_fail=0)`。
    ⇒ **T3 首次从 SKIP 转为真测 PASS**（此前恒 27P/1S）。
  · 全门禁：`FAIL: 1/33`，**唯一红项 = `git 工作区干净`**（提交前预期）。
  · `py_compile` rc=0；`tools/bom.py check tests\e2e.py` = **BOM=True**
    （`edit` 工具会剥 BOM，已补回）；`build/_undef.py` **0 处**。

### 2.26.7 CI 复核（2026-10-05，已推翻本节原来的「未验证」）

本节最初写「**CI runner 上 T3 是否也能真跑** —— runner 无交互桌面会话，
`DebugActiveProcess` 很可能仍被拒」。**该推测已被 CI 实跑推翻**：

```
build-and-verify  Run e2e suite (T1-T28)
  T3 debug-detect  PASS   (exit=219 ev_exit=0xdb events=21 cont_fail=0)
  [e2e] 平台=win  总计 28: PASS 28 / FAIL 0 / SKIP 0 / NA 0
build-and-verify  Full release gate
  [release_check] PASS: 29 项检查全通过
```

（CI 运行 `37314958939`，`head=17b1215`，8m59s success。）

⇒ **CI runner 上 T3 也真跑并 PASS**（`cont_fail=0` = `ContinueDebugEvent`
次次成功）。**「runner 无交互桌面 ⇒ 必 SKIP」是旧结论** —— 之前之所以
恒 SKIP，是因为 `cmd /c timeout` 探针恒被拒（`err=0x5`），**而我们从未
真正试过附加 `demo.exe`**。这与 §2.26.4 的缺陷①同源：**错的是探针对象，
不是环境能力**。

> **教训（通用）**：**「环境限制」的结论必须用「正确对象的尝试」支撑**
> —— 用一个无关代理（`cmd /c timeout`）失败就断言环境无能力，
> 会把**自己的缺陷**记成**环境的限制**，从此不再尝试。本仓库此前
> 至少 5 处文档（`docs/PHASE2.md` / `docs/PLAN.md` / `docs/ROADMAP.md`
> / `docs/VERIFY_PLAN.md` / `docs/THREATMODEL.md`）据此把「T3 真机验证」
> 列为待办 —— **那些待办可以直接销掉**。

**仍未验证**：

  · `DBG_EXCEPTION_NOT_HANDLED` 分支未被 T3 使用（仅实测其同样能
    `Continue` 成功），未接入任何判据。
  · 本机 T3 用时约 19s（`events=23`），CI 约 21 个事件 —— 事件数随
    环境 DLL/线程数浮动，**判据未依赖事件数**（只依赖退出码与文本）。


---

## 2.27 门禁第 37 项：静态未定义名审计（`tools/check_undef.py`，2026-10-05）

### 2.27.1 缘起：两起同型的 `NameError`，都只在失败路径上执行

门禁从 36 项增至 37 项，新增的不是运行期用例，而是**纯静态**审计。它由本轮修 bug 时
踩到的两起真实事故催生，两起**形态完全相同**：

| # | 事故 | 潜伏期 | 为什么没人发现 |
|---|---|---|---|
| 1 | `tests/e2e.py` T3 调用 `DebugAttacher()`，而该类已被 `22826c5`（2026-09-28, C-3）整块删除 | **7 个月** | 旧 preflight 用 `DebugActiveProcess(os.getpid())`，Windows 禁止自附加 ⇒ 那条 `else` 分支从未执行；直到 S6 把 preflight 改成附加派生子进程，它才**第一次**被走到 |
| 2 | `tools/guard_selftest.py` 的诊断分支引用 `run_by_hits()` 的局部名 `cont` / `exit_pol` | 同轮 | 诊断分支只在"未能就绪"这条失败路径上执行，本地恒绿 ⇒ 永不可达 |

共同点：**代码只在失败路径 / 异常路径上执行**。这解释了为什么既有防线全都漏掉：

- `py_compile` 只查语法 —— `DebugAttacher()` 语法完全合法；
- 运行测试只覆盖**走到的**路径 —— 失败路径恰恰是"测试全绿时不会走"的分支。

⇒ **唯一有效的防线是静态名字绑定分析**（与是否执行无关）。这就是第 37 项的理由。

### 2.27.2 做法

`tools/check_undef.py`（纯 `ast`，无第三方依赖，396 行）。对每个函数/类/模块作用域收集
绑定名，再检查每个 `Name` 载入是否可见。**只读源码、不导入被测文件、不执行任何代码、不写产物**
—— 因此它对恶意或者只是副作用强的模块也安全，可以无条件跑。

实现要点 6 条（每条都对应一次实测踩坑）：

1. **类体的名字对方法体不可见** —— `class C:` 内 `x = 1`，方法里 `x` 是**未定义**（Python 语义）。
2. **推导式首个 iterable 在外层作用域求值** —— `[i for i in xs]` 的 `xs` 用外层绑定，之后的 `if`/表达式用内层。
3. **装饰器与默认值在外层求值** —— `@dec` / `def f(a=CONST)` 的 `dec`/`CONST` 在**定义处**作用域解析。
4. **`global` / `nonlocal` 声明的名字算已绑定**。
5. **嵌套作用域节点本身也是本作用域的绑定** —— 漏掉这条曾**一次性造成 18 处假阳**（`try:` 内定义的
   `class OSVERSIONINFOEXW` 名字不被绑定，后续 `OSVERSIONINFOEXW()` 被误报）。
6. **`ast.arg` 的属性是 `node.arg`，不是 `node.id`**；读文件必须 `encoding='utf-8-sig'`
   （否则带 BOM 的 `tests/attacks.py` / `tests/e2e.py` 报 `invalid non-printable character U+FEFF`）。

### 2.27.3 负向自检（9 项）

自检 **4 条变异必须全部被抓 + 4 类已知假阳源必须不报**，另有 1 项计数断言：

```
[check_undef-selftest] PASS: 9 项（4 变异 / 4 假阳防线）
```

**踩坑记录**：最初第 2 条变异写成"删掉 `total = a + b`"并期望抓到 `total`，但该函数后面有
`total += r` —— `AugAssign` 的目标本身就是一个 `Store`，名字**仍被绑定** ⇒ 实得 `[]`，
selftest FAIL（自检抓到了自检自己的错误）。改为 `_NESTED_LOCAL` 样本（内层函数的 `token`
在外层被引用）后才正确。**教训：断言"某变异必须被抓"时，必须确认该变异真的消除了绑定，
而不是只消除了某一行文本。**

### 2.27.4 验证

```
$ python -X utf8 tools\check_undef.py --quiet
[check_undef] PASS: 扫描 87 个 .py, 疑似未定义引用 0 处
$ echo $LASTEXITCODE
0
```

- 全库 87 个 `.py`，**0 处**疑似未定义引用（两起事故的名字都已被修掉）。
- 第 37 项已接入 `tools/release_check.ps1`（紧接 `CRC 目标表一致性 (crc_targets)` 之后，
  两段式：`--selftest --quiet` 再 `--quiet`），并同步进 `tools/ci_sim.ps1` 与
  `.github/workflows/ci.yml` 的 `py_compile` 显式清单。
- 项数口径全库同步 **36/33 → 37/34**（含 `tools/doccheck.py` 的 `GATE_TOTAL`/`GATE_DEFAULT`
  与 selftest 漂移字面量重挑 —— 硬约束：漂移用例的值**不能**等于这两个常量）。

### 2.27.5 仍未验证

- 本审计是**保守**的：它只报"作用域内完全找不到该名字"，不做跨模块名解析，
  因此**不能**发现"导入了但拼错属性名"或"运行期 `getattr` 才出现的名字"。
- 动态代码（`exec` / `eval` / `globals()` 注入）产生的绑定不在分析范围内；
  若将来引入，需在 `check_undef.py` 里显式豁免并注明理由。
- 第 37 项在 **CI runner** 上的实跑结论以本轮推送后的 CI 结果为准（本地 rc=0）。


---

## 2.28 S1 收口：revoke 纳入 selfcrypt（2026-10-05）

### 2.28.1 缘起：待办清单与实施记录自相矛盾

`docs/DEFENSE_DEEPEN_PLAN.md:229` 长期挂着「S1 剩余（antidebug/integrity/revoke）」，
而同一文件的 `:184-185` / `:112-113`（§12.5）已记 antidebug/integrity 落地。
逐项核对代码后确认：**真正未覆盖的只有 revoke 一枚**（`tools/selfcrypt_proto.py`
的 `EXT_TARGETS` 原为 4 项，含 antidebug/integrity，不含 revoke）。

revoke 的唯一阻力是同一文件 `:108-109` 的「**根因最终闭环**：`prot_revoke_check`
与 `main` 同页（0x5000）——VP 切 RW 禁执行 main 自伤，**不可解**」。

### 2.28.2 为什么该结论必须重新实证，而不能直接引用

该结论写于 **2026-08-30**。此后 `.text` 布局相关机制又经历了多项改动：
节名随机化（阶段 1 第二支柱）、`.protpad` 填充节、`.protxec` 第 4 段 CRC（DRILL9）、
`merge_baseline` 基线提升。**一条写死"不可解"的布局类结论，在布局机制变更后
即失去效力** —— 它的前提（同页）是一个可由构建改变的偶然事实，不是不变量。

### 2.28.3 证伪实验（零代码改动）

`build.ps1:36` 早已提供 `-ExtraSelfCrypt <逗号分隔函数名>`，`tools/selfcrypt_proto.py`
的 `--extra` 以 `setdefault(en, 1)` 并入 EXT 组 —— **无需改任何源码**即可复验：

```
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Config Release `
    -ExtraSelfCrypt prot_revoke_check
```

| 观测项 | 结果 |
|--------|------|
| 构建 | `rc=0`；`prot_revoke_check rva=0x2ba0 size=154 ... group=1 (in-place)` |
| 目标数 | `patched build\demo.exe (9 fns in-place, meta@0x34a00 hdr=220)`（8 → **9**） |
| 页冲突安全网 | **未触发** —— revoke 落页 `0x2`，与 `main` **不同页**（原判断前提已不成立） |
| smoke | `build: smoke test PASS (correct serial accepted)` |
| `demo.exe --selftest` | `rc=1`（正常"序列号无效"路径）—— **无 0x5d0d 崩溃、无 0xBAD TAMPERED** |
| e2e | `总计 28: PASS 28 / FAIL 0 / SKIP 0 / NA 0` |
| attacks | `总计 12: PASS 12 / FAIL 0 / NA 0`，含 `A11 selfcrypt-dump PASS (plaintext-fns=none)` |
| window_check | `加密目标 9 个` ⇒ `PASS: 全部加密目标调用点都在配对 enter/leave 窗口内` |

### 2.28.4 阻断已解的真因：修了、也记了，但旧结论无人回收

`src/selfcrypt.c:39-41` 的注释就是修复本身：

```
/* S1 专项 (2026-08-30): .protpad 填充节 — 把 .protxec 推后一页,
 * 使其与 .text 尾部加密段 (revoke) 分页, 消除
 * 页粒度 VP 禁执行自伤。 */
```

即 §12.5 那次"页冲突安全网"的**同批改动已经解掉了 revoke 的同页问题**，
只是实施记录没有回头销掉 revoke 的排除结论。

⇒ **通用教训：修复与销账是两件事。** 一条"某目标不可用/永久排除"的结论，
在它所依赖的机制被改动后，必须由**改动方**主动回收；否则它会以"技术债"的
形态留在待办里，让后续的人重复排查一个已经不存在的问题。
本轮的触发器不是新攻击面，而是**待办清单与实施记录自相矛盾**这个信号 ——
自相矛盾的计划文档本身就是缺陷指示器。

### 2.28.5 落地

- `tools/selfcrypt_proto.py` 的 `EXT_TARGETS` 增加 `'prot_revoke_check': 1`
  （含复验数据与"为何原判不可解"的注释）。
- `tools/window_check.py:107-129` 的 `load_targets()` **从该文件动态读清单、
  不硬编码** ⇒ 新增目标自动进入调用点窗口校验（实测 `加密目标 9 个`，PASS）。
- `demo/main.c:829-837` 的调用点**本就已在 `sc_ext_enter()/sc_ext_leave()`
  窗口内**（§8 已为"未来 EXT 加密预留"），**宿主代码零改动**。
- `modules.json` 中 revoke 的 `known_limits[0]`（原「因与 main 同页, 无法参与
  selfcrypt 加密 (永久排除)」）与 selfcrypt 模块的同款论断一并更正。
- `docs/DEFENSE_DEEPEN_PLAN.md`：版本头状态改为 S1 5/5；待办勾除；
  §12.5 的"不可解"标注为已证伪；新增 §14 复验与收口记录。

### 2.28.6 顺带修掉的同型缺陷（静态自检里的硬编码）

`tools/window_check.py` 的 self-test 原断言：

```python
case('目标清单 = 8 个', len(r['targets']) == 8)
case('8 个目标分布 4+4', sorted(r['targets'].values()) == [0,0,0,0,1,1,1,1])
```

目标增至 9 个后**这两条自检立刻失效**。这与 `load_targets()` 存在的理由
（其 docstring：「硬编码会在目标增删时**静默失准**」）**完全同型** ——
判据本体做到了不硬编码，判据的**自检**却硬编码了。

改为与源声明比对 + 只断言结构性质（非空、仅 0/1、两组都出现），
增删目标时自动跟随：

```python
case('目标清单与 selfcrypt_proto 声明一致', sorted(r['targets']) == sorted(_src))
case('目标分组仅 0/1 且两组均非空', set(_src.values()) <= {0,1} and 0 in _src.values() and 1 in _src.values())
```

`tools/selfcrypt_proto.py` 的 docstring 里「**8 个目标函数**」同样写死，
已改为"全部目标函数"并注明该等价性结论与个数无关。

### 2.28.7 验证

- 3 连建稳定性门槛（布局敏感纪律，见 §2.7 纪律提醒）：**3/3**
  `build rc=0` + `smoke PASS` + `e2e 28 PASS/0 FAIL/0 SKIP`。
  ⚠️ 三轮 exe SHA 各不相同 —— 这是**预期**：阶段 1 起节名每构建随机；
  可复现性由 `repro_check` 的 `-SeedsFile` 重建单独守护（同轮已 `[ok]`）。
- 全门禁：`FAIL: 1/34`，**唯一红项 = `git 工作区干净`**（提交前预期）；
  `[ok] 可复现 (repro_check)` / `[ok] 加密封装窗口 (window_check)` /
  `[ok] e2e T1-T28` / `[ok] attacks A1-A12` / `[ok] 静态未定义名审计 (undef_check)` 全绿。

### 2.28.8 诚实边界

- revoke 是**低频 + 间接表 + 签名兜底**的模块（`docs/DEFENSE_DEEPEN_PLAN.md`
  自评"加密收益最低"）。本次纳入的**主要价值是消除一处"已修未销"的陈旧阻断记录**，
  安全增益有限 —— 不应把它描述成一次能力升级。
- D2b 下窗口 = 调用周期；窗口外 revoke 仍是密文，符合设计意图。
- **未做**：revoke 加密后的**真机 Defender 复测**（`docs/DEFENSE_DEEPEN_PLAN.md:231`
  待办末条）仍挂账；本次只覆盖本机 e2e/attacks 与构建门禁。

---

### 2.29 增量（2026-10-06）：**mock 目标的结论不能外推** —— DRILL7 真实 demo.exe 闭环

**性质**：`docs/ATTACK_DRILL7.md` §3 的「patch 判定函数头 → "盾"**永久失效**」
自 2026-08-30 起被当作既成结论，并在 `tools/attacker/winpe_sympatcher/README.md`
的「实证结论」里复述。但它成立的**前提**（实证对象 `test_target.c` 是模拟盾：
无完整性校验、无副本冗余）从未被写进结论本身。§5「后续建议」第 1 条
「对真实 demo.exe（Dev 构建带 MAP）跑完整闭环（含 watchdog 对抗）」挂了近 5 周。

**工具链成熟度检查（先排除"工具没做成"）**：两个攻击侧工具实际早在
`c941c9c feat(attacker): WinPE/Android symbol-patcher toolchain + release
antidebug fix + phase summary` 就已落地（`tools/attacker/winpe_sympatcher/`
含 `symparse.c` 13799 B + `mempatch.c` + `main.c` + `test_target.c` + `build.ps1`
+ 已构建的 `winpe_sympatcher.exe` 187392 B；`tools/attacker/android_jniptrace/`
含 `elfparse/elfparse.c` + `patcher_jni.c` + `ptrace_patcher_cli.c`）。
`docs/MEMPATCH_PLAN.md`（2026-08-30 v1「规划待拍板」）的 **8/8 验收盒全未勾**
—— 与 §2.28 的 S1 revoke **完全同型**：**实施与销账是两件事**。

**方法**（探针 `build/_drill7_clean.py`，只读诊断未入库）：
`winpe_sympatcher.exe --map build\demo.map --sym <name>` 定位 →
`ReadProcessMemory` 确认序言 → `VirtualProtectEx` + `WriteProcessMemory`
写 `31 C0 C3` → **喂 stdin 使目标自然退出**。

**四组实测**（同一构建，`real_base=0x7ff6d37d0000`，`PREF=0x140000000`）：

| 组 | 操作 | 符号 / 运行时 VA / 序言 | 写入 | 退出码 | `完整性校验失败` |
|----|------|------------------------|------|--------|------------------|
| A | 基线（不附加、不写） | — | — | `1` | ✗ |
| D | 附加 + 定位，**只读不写** | `prot_antidebug_detected` @`0x140001420` → `0x7ff6d37d1420`，序言 `48 83 ec` | ✗ | `1` | ✗ |
| B | patch `prot_antidebug_detected` 头 | 同上 | ✅ 读回 `31 c0 c3` | **`2989`(0xBAD)** | **✓** |
| C | patch `prot_antidebug_detected_multi` 头 | `_multi` @`0x1400015b0` → `…15b0`，序言 `48 89 5c` | ✅ 读回 `31 c0 c3` | **`2989`(0xBAD)** | **✓** |

四组均 `natural=True`（**无强杀**）。

**根因（为什么 mock 上的"永久失效"不成立）**：
`prot_antidebug_detected` / `_multi` 的 `demo.map` 段号都是 `0001` = `.text$mn`，
而 `.text` 正是 `src/integrity.c` 的 `g_prot_baked_crc[0]`（baked-CRC 第 0 个目标，
覆盖含调零掩码）。改它**必然**被段 CRC 抓到 ⇒ 看门狗/自检路径以
`PROT_EXIT_TAMPERED (0xBAD=2989)` 终止。**这是 DRILL3 的罪证在真实目标上的复现**：
mock 目标没有这一层，所以补丁"生效"了。

**结论（三条，均可外推的判据）**：
1. **符号定位能力在真实目标上成立** —— MAP 通道给出编译时 VA，
   `Toolhelp32` 取模块基址做 ASLR 换算后序言与预期一致。
   ⚠️ **必须走 `Toolhelp32`**：拿 `PREF` 硬读会全部 `err=299
   (ERROR_PARTIAL_COPY)` ⇒ 采样为空 ⇒ **极易被读成"符号不存在"**
   （此坑 `tools/guard_selftest.py:256-261` 早有记载，本轮复现）。
2. **附加本身不再触发检测** —— 组 D 只定位不写，退出码与基线同为 `1`、无
   `MSG_DBG`。（**旁注**：与 e2e T3 用 `DebugActiveProcess` 附加派生进程得
   `exit=219`(0xDB) 不矛盾 —— T3 由调试器持有线程、形态不同；此处不深挖，
   **如实记为观察**而非结论。）
3. **patch 判定函数在真实目标上不再静默生效** —— 写入成功（读回一致），
   但目标打印 `完整性校验失败，程序可能已被篡改。` 并以 `2989` 退出。
   ⇒ §3 的"盾失效"须**限定为"无完整性校验的 mock 目标"**。

**顺带修掉的同型缺陷**：无（本轮未改工具代码）。**已销账**：
`docs/MEMPATCH_PLAN.md` 状态行 v1「规划待拍板」→ v2「两个工具均已落地」；
WinPE 四条验收盒勾上（附证据），**Android 四条如实保留未勾**并注明
"代码就绪、真机未测"（`docs/EXTENSION_PLAN.md` 的 T1 逐行核对后**已如实**，未改）。

**方法论教训（本轮最值钱的一条）**：
**mock 目标上的攻击结论不能外推** —— 每一条攻击结论都必须问
「**实证对象的哪些属性是这条结论的前提**」。此处前提是"无完整性校验"，
而真实目标有 `.text` 段 CRC。这与 §2.28 的「布局类结论不是不变量」互补：
前者是**对象属性**没写进结论，后者是**结论依赖的机制**被后续改动推翻。

**诚实边界**：
- 只测**单点 patch**；"同时中和 `.text` 段 CRC + R3.2-c 的 4 副本 + 位置抖动"
  的完整对抗链**未测**（DRILL9 §5 已记 F/G/H 由此翻转为 `0xBAD`，属另一条线）；
- **有 `demo.map` 是前提**：无 MAP/PDB 时 MAP 通道失效，`/DEBUG:NONE` 下
  COFF 通道同样为空（§5 边界表第 1 条）；
- 组 D「附加不触发检测」只测了一个构建一个时刻，**未做多次/多形态**；
- Android 侧真机仍未测（需 NDK + root）。

*2026-10-06 v1*

## 2.30 门禁第 38 项：Android 交叉编译（`tools/android_compile_check.py`，2026-10-06）

### 2.30.1 缘起：Android 侧**从未被编译过**

本节的触发点是一件与 §2.28/§2.29 **完全同型**的事：**做过了，但没人对账**。

2026-10-06 为了给 `docs/MEMPATCH_PLAN.md` 的验收 1 补证据（原文要求的是
**NDK 产物 `libprot.so`**，此前只有合成样本），在本机找到了真 NDK
（`D:\environment\android-sdk\ndk\28.2.13676358`，`Pkg.ReleaseName = r28c`，
clang 19.0.1），于是顺手把 Android 侧全量编了一遍 —— **一编就出 5 处缺陷**：

  · `tools/attacker/android_jniptrace/patcher_jni.c` / `ptrace_patcher_cli.c`
    —— 裸调 `process_vm_writev`，而 bionic 的 `<sys/uio.h>` 把它标为
    `__INTRODUCED_IN(23)`；本项目 Android 侧下限是 **API 21**。
    另有一处 include 路径写成 `"../elfparse/elfparse.h"`（上一级没有该目录）。
  · `examples/cross_platform/android/libprot.c` / `selfcrypt_android.c`
    —— `-Wall -Wextra -Werror` 下 unused parameter / ignored qualifiers /
    unused function。

**根因不是"没写好"，而是"没人编"**（三处独立证据，均实测）：

  1. `tools/linux_compile_check.py:88 SCAN_DIRS = ['src']` —— **只扫 `src/`**，
     Android 侧代码在 `tools/attacker/` 与 `examples/` 下，**根本不在扫描面内**；
  2. `.github/workflows/ci.yml` 搜 `ndk|NDK|android|aarch64` **零命中**
     —— CI 从没编过 Android；
  3. 工具作者自己的 `README.md` 那句「宿主编译验证」，逐行核对后**只编了
     `elfparse.c` + `elfdump.c` 两个文件**，而 Android 侧有 8 个 `.c`。

⇒ **声称的覆盖与实际覆盖是两个集合，而没有任何机制比对这两个集合。**
这正是本项目已记名的教训「**表的条数对得上，语义对不上**」
（`hashpatch.py` 的 `TARGET_LOGICAL` 静默 `section absent — skip`，
见 §2.26 的 DRILL9 条）在**编译覆盖**上的重演：
"我编过了" 与 "我编了哪些" 不是同一句话。

### 2.30.2 本项最关键的判据：**必须在最低 API 上编译**

同一份源码，三个 API 级别的实测结果（2026-10-06，NDK r28c）：

| 形态 | api21 | api23 | api28 |
|------|-------|-------|-------|
| 裸 `process_vm_writev`（未修） | **rc=1** | rc=0 | rc=0 |
| 仓库实际的 `syscall` 回退（已修） | rc=0 | rc=0 | rc=0 |
| 晚定义 `_GNU_SOURCE`（另一类缺陷） | **rc=1** | - | **rc=1** |

**这个缺陷在 API 23 及以上完全看不见。** 任何"挑一个现代 API 编一遍"的门禁
都会**放它过去** —— 而这正是它潜伏至今的原因（也解释了为什么 README 的
"宿主编译"没抓到：宿主 glibc 上 `process_vm_writev` 一直可见）。

⇒ 判据锚定**文档声明的最低 API（`docs/EXTENSION_PLAN.md`: API 21+）**，
即 `DEFAULT_APIS = (21, 28)`，且 **21 必须在前**
（`tools/android_compile_check.py:123`，它才是有判别力的那一遍）。
api28 那一遍不是冗余：它把"真的错"与"只是 API 高于下限"分开 ——
api21 失败但 api28 通过 ⇒ 归因为 `API_GATED`，**这是可行动的诊断**，
而不是一句笼统的"编译失败"。

### 2.30.3 工具设计（判据 ①–⑤）

`tools/android_compile_check.py`（696 行，BOM=False）：

  ① **清单完整性**：`SCAN_DIRS`（2 个目录）下每个 `.c` 必须在 `TARGETS`
     （8 项）里或在 `EXCLUDE`（当前为空）里显式豁免 —— 否则报 `UNLISTED` 并失败。
     **查的是实际集合 vs 声明集合，不是声明条数**（见 2.30.1 的教训）。
  ② **最低 API 编译**（`DEFAULT_APIS[0] = 21`）：每个目标文件必须编过。
  ③ **现代 API 编译**（28）：同上，用于差分归类。
  ④ **差分归类**：`API_GATED` / `MISSING_HEADER` / `WINDOWS_HEADER` /
     `UNLISTED` 各归各因。
  ⑤ **无 `-D_GNU_SOURCE` 命令行注入**：仓库 Android 侧源码**自己**在文件头
     `#define _GNU_SOURCE`。若某文件只在"命令行替它定义"时能编过，说明它的
     `#define` 位置太晚（被 bionic 头冻结）—— 与 `linux_compile_check` 的
     第二遍**同一条判据**，故本工具**不加**该宏
     ⇒ 本地与 CI 不可能对同一份源码得出相反结论。

**自检 18 项（T1–T13，含 T2b/T3b/T3c/T7b/T8b）**，全部为**负向注入**：
"能报出失败"才是自检，其中 `T3c 该缺陷在 API 28 确实看不见` 直接钉住 2.30.2
的判据 —— 它断言"**最低 API 那一遍不可省**"，而不只是断言工具能报错。

**为什么不用"拓宽 `linux_compile_check.SCAN_DIRS`"代替本项**（实测）：
把 `src` 换成全部目录会引入 **7 个永久 FAIL** ——
需 `jni.h`（NDK 才有）2 个、需 `-I elfparse` 1 个、
Windows-only（`windows.h`）4 个。它们**全是"本平台不适用"，不是"代码有错"**。
把"环境不对"报成"代码有错"只会训练人忽略门禁
（与 `tools/linux_compile_check.py:266` 同款纪律）⇒ 故采用
**显式清单 + 每文件自己的 include 目录**，而不是盲目递归。

**两工具互补而非重叠**：`linux_compile_check` 抓 glibc 的**特性宏冻结**
（`<features.h>` 首次遇到系统头即冻结），本项抓 bionic 的 **API 级别门控**
（`__INTRODUCED_IN(N)`）。同型不同因，不可互相替代。

### 2.30.4 门禁接线：**追加到末位**（一个结构性决定）

`tools/release_check.ps1` 新增第 38 项，**默认跑、不 gated** ⇒
`tools/doccheck.py` 的 `GATE_TOTAL 37 -> 38` / `GATE_DEFAULT 34 -> 35`
（`:159-160`，`GATE_OK` 引用变量故无需改）。

**⚠️ 关键决定：插在末位，而不是语义相邻的第 19 位。**
最初把 Android 项插在 `linux_compile_check`（第 18 项）之后
—— 语义上最近，但这样做会让**其后 19 个序号全部 +1**。而门禁序号被
约 10 处文档/工具注释**按序号引用**：`docs/HANDOVER.md:2011`（第 36 项）、
`docs/HANDOVER.md:2349`（§2.27 标题）、`docs/COST_ASYMMETRY.md:255`、
`docs/ATTACK_DRILL9.md:266`/`:326`、`docs/DECISION_REDUNDANCY_PLAN.md:9`/`:592`、
`docs/CONTINUATION_PLAN.md:194`、`tools/prot_dbg.py:130`、
`tools/doccheck.py:531-534`、`tools/release_check.ps1:882-883`/`:1067`/`:1075-1076`。

**仓库惯例 = 追加到末位**：第 33 / 35 / 36 / 37 项**全部如此**；
唯一一次中段插入（`window_check` 第 11 位）迫使
`docs/HANDOVER.md:1579-1582` 留下了一条「序号更正」记录。
⇒ 19 个序号的文档 churn 成本远高于"语义相邻"的收益，故**末位**。

**搬移过程本身也留了两条教训**（都在 `tools/release_check.ps1` 上）：

  · 字符串拼接引入了 **1 个 bare LF**（byte 56913，在 `undef_check` 块尾
    `}` 与 Android 注释之间）。`.ps1` 的 CRLF-only 是仓库硬不变量，
    但 `edit`/脚本写入**不会**自动保证 —— 必须显式
    `b.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')` 归一化后复验。
  · `edit` 再一次**剥掉了 `.ps1` 的 BOM**（首字节 `23 20 74` = `# t`），
    导致 `Parser::ParseFile` 报 **`parse errors: 26`**（全是 BOM 丢失后
    PowerShell 按本地代码页读 UTF-8 中文的**连带假错**，不是真实语法错误）。
    修法照旧：`python -X utf8 tools/bom.py add <file>` ⇒ 首字节 `EF BB BF`
    ⇒ `parse errors: 0`。
    ⇒ **纪律重申：任何 `edit` 过 `.ps1` 之后必须 `bom.py add` + 复验 `ParseFile` 为 0。**

### 2.30.5 陈旧计数全库收口（`git log -S` 定下的处置原则）

计数从 37/34 变 38/35 后 `doccheck` 立刻报 **9 处红项**
（`docs/CONTINUATION_PLAN.md:441`/`:523`/`:616`/`:682`/`:710`、
`docs/DEBUG_CONSOLE_PLAN.md:8`、`publish/01-关于ShardVase.md:63`、
`publish/02-项目档案.md:116`/`:168`），全库另有 30 处命中。

**处置原则不是拍脑袋定的**：用 `git log --oneline -S '<字面量>'` 逐一回溯，
发现 `门禁默认 34 项 PASS`、`重跑门禁**（默认 34 项）`、
`门禁 **37** 项 · 提交见` **三处的最新改动提交统统是 `bc68b11`**
（即门禁第 37 项那次），`-S '…33 项…'` / `-S '…36 项…'` 同样命中 `bc68b11`。
⇒ **仓库既有惯例 = 每轮就地替换数字，不是逐处加注**。故本轮全部就地改为现值。

**唯一例外是漂移测试字面量**：`tools/doccheck.py:823-828` 的
`门禁 31/31` / `release_check 35 项` / `门禁 **35** 项` / `门禁 37/37 全通过` /
`门禁 21/37`。该文件 `:809-810` 已确立约束——**漂移字面量不得落在
`{GATE_TOTAL, GATE_DEFAULT}` 内**（否则自检会因"这个值恰好是对的"而失去
判别力）。现 `37/34` 不在 `{38,35}` 内 ⇒ **恰好仍然合法，不动**。

一并回填的两条元数据「最后核实」行：
`docs/CONTINUATION_PLAN.md:4`（`门禁默认 **34** 项实跑` → `35`）与
`docs/HANDOVER.md:18`（`门禁 **37** 项（默认 34）` → `38`（默认 35））。

**另须留意 `RE_GATE_NN` 只比分母**（`tools/doccheck.py:170`，
`:744 if claim in GATE_OK: continue`）：写 `38/38` 合法、写 `37/37` 红；
而夹在中间的数字任意值都放行（`门禁 21/38（唯一失败=未提交）` 合法）。

### 2.30.6 CI 接线与一个 bash 陷阱

`.github/workflows/ci.yml`：`linux-portability` job（`runs-on: ubuntu-latest`、
`timeout-minutes: 20`）新增第 6 步 `Android cross-compile (android_compile_check)`，
并把 `tools\android_compile_check.py` 加入 `:131` 的 `py_compile` 显式清单
（该清单是**逐文件列举**的，不是 glob —— 漏加就等于不检查）。

**⚠️ 踩到的陷阱：本块不能用 `set -e`。** 第一版照抄同 job 其它步骤的
`set -e` 开头，但本步要读 `rc=$?` 来分辨三态 —— `set -e` 会在
**退出码 2（SKIP）时于 `rc=$?` 之前就终止脚本**，把"未验证"误报成 job 失败，
恰是门禁纪律明文反对的。已改为不用 `set -e`、逐条显式判 rc
（`SKIP` ⇒ `::warning::` + `exit 0`；`!=0` ⇒ `::error::` + `exit $rc`）。
⇒ 教训：**`set -e` 与"我要看上一命令的退出码"是互斥的**，
在需要三态（PASS/FAIL/SKIP）的步骤里必须二选一。

`tools/ci_sim.ps1`（本地 CI 模拟器）同步：`Step` 映射注释加项、
新增同款步骤、`py_compile` 清单补项。该模拟器的 `Step` 只看
`$LASTEXITCODE -ne 0` ⇒ SKIP 时必须显式把 `$LASTEXITCODE` 归零，
否则"未验证"会被模拟器误报成失败（同款纪律，换了个宿主语言重演一次）。

### 2.30.7 验证

- 工具自检：`[android_compile_check-selftest] PASS: 可自证能正确判定`
  （**18 项 T1–T13** 全 `ok`，含 T3c「该缺陷在 API 28 确实看不见」）。
- 工具主跑：`--quiet` ⇒ **rc=0**（8/8 目标在 api21 与 api28 两遍均通过）。
- 门禁结构：`38 项均为顶层语句，无被嵌套项；其中 3 项由 -With* 显式开关控制
  （默认不跑），默认调用跑 35 项`。
- `tools/doccheck.py` ⇒ **`PASS`**（`检查数字 603 处, 错误 0, 警告 0`；
  `基准: 门禁 38 项, 轮次 9 个`）。
- `tools/docclaim_check.py` ⇒ **`PASS (8/8)`**。
- `build/_hygiene.py` ⇒ **15 个文件, 0 处异常**
  （`tools/release_check.ps1 bom=True crlf=1106 bareLF=0 bytes=64339`；
  `tools/ci_sim.ps1 bom=True crlf=155 bareLF=0 bytes=7318`）。
- `Parser::ParseFile` 对 `tools/release_check.ps1` 与 `tools/ci_sim.ps1`
  均 **`parse errors: 0`**。
- YAML 可解析：`yaml.safe_load` 后 `linux-portability` 有 6 个 step，
  末项为 `Android cross-compile (android_compile_check)`。

### 2.30.8 诚实边界

- **本项只证明"能编过"，不证明"能跑对"**。Android 侧的行为正确性
  仍**未在真机验证**（需 Android 设备 + root）；`docs/MEMPATCH_PLAN.md`
  的 Android 四条验收依旧保留未勾。
- 本机 NDK 只有 **28.2（r28c）**，而 CI runner 同时有 27.3 / 28.2 / 29.0。
  工具会打印实际选中的版本进报告与 JSON —— 因为**不打印版本，就无法判断
  "门禁绿了"是因为代码对，还是因为换了编译器恰好看不见**
  （判据 2.30.2 的实测表正是这种风险的实证）。
- `EXCLUDE` 当前为空。将来若有人加了豁免，**必须带原因**（工具的
  `EXCLUDE` 注释已写死这条纪律）—— 无原因的豁免就是静默通道。
- 8 个 `TARGETS` 是**手写清单**。判据 ① 的集合比对只在 `SCAN_DIRS`
  （2 个目录）范围内有效；`SCAN_DIRS` 本身仍是手工维护的，
  即"**谁定义扫描面**"这一层没有机制保护。
- 与 §2.29 同型的方法论风险依然存在：本轮再次印证
  「**做过了 ≠ 对过账了**」——`linux_compile_check` 建成时
  "Linux 可移植性已验证"是真的，但它被读成了"可移植性已验证"，
  于是 Android 侧在**没有任何人注意到的情况下**从未进过编译器。

*2026-10-06 v1*

## 2.31 计数硬编码的**第三次复发**：判据常量必须由集合推导（`tools/doccheck.py` 自检，2026-10-06）

### 2.31.1 现象：门禁红在一个"与本次改动无关"的项上

`f4b27f4`（门禁第 38 项）提交并推送后，本地全门禁与 CI 同时在
**第 14 项 `对外材料 (doccheck)`** 报红：

```
[doccheck] PASS                      ← 主检**过**
[doccheck-selftest] FAIL (5/20)      ← 自检**不过**
  [X] N 项漂移: 期望 1 条错误, 实际 0 条 ([])
  [X] N 项 + 强调漂移: 期望 1 条错误, 实际 0 条 ([])
  [X] 正确值不报: 期望 0 条错误, 实际 2 条 (['<selftest>:1 门禁项数声称 37, 实际 38'])
  [X] 分母正确/分子是失败数 -> 放行: 期望 0 条错误, 实际 1 条 (['<selftest>:1 … 37, 实际 38'])
  [X] publish/01-关于ShardVase.md 里既无 `37/37` 也无 `37 项` —— 负向用例失去锚点
```

**为什么"与本次改动无关"是错觉**：本次改动把 `GATE_TOTAL` 由 37 改成 38，
而 `selftest()` 里的漂移字面量是**硬编码**的 `35 项` —— `35` 在改动的**同一刻**
成了**合法默认值**（`GATE_DEFAULT` 由 34 变 35），于是"必须报错"的用例
零报错 ⇒ 判据失去判别力 ⇒ 自检失败。

### 2.31.2 这是同一件事的第三次，且**前两次都是靠人手工发现**

| 轮次 | 变更 | 失效的字面量 | 怎么发现的 |
|------|------|--------------|------------|
| ① | `32/31` -> … | `32` 曾是合法默认值 | 手工重挑（注释只留一句） |
| ② | 2026-10-05 `36/33` -> `37/34` | `34 项` 变成合法默认值 | 手工重挑 |
| ③ | 2026-10-06 `37/34` -> `38/35` | `35 项` 变成合法默认值 | **门禁抓到**（本次） |

`tools/doccheck.py` 旧注释（`:819-822`）把这件事记成了一句操作提示
——「每轮项数递增都要重挑这些字面量」。**一句提醒挡不住第三次**：
它要求改计数的人**同时记得**改自检里的 4 个字面量、并判断新值是否落在新容差内。
这是一条**靠记忆维持的不变量**。

### 2.31.3 根因：判据里出现了"必须不落在某集合内"的**硬编码常量**

```python
case('N 项漂移', 'release_check 35 项全通过\n', 1)   # 35 必须"不是合法值"
```

这条判据的语义是「35 不在 `{GATE_TOTAL, GATE_DEFAULT}` 里」，
但写成了字面量。⇒ **判据的成立条件会随 `GATE_TOTAL/GATE_DEFAULT` 漂移，
而字面量不会。** 集合一动，判据就悄悄失去判别力，**且不报错**
—— 一个恒返回空的检查器也能 PASS，这正是 `selftest()` 文档字符串
（`:807-811`）自己写下的理由。

### 2.31.4 修法：由集合推导，并加断言把它钉住

```python
DRIFT = max(GATE_TOTAL, GATE_DEFAULT) + 1
assert DRIFT not in (GATE_TOTAL, GATE_DEFAULT), '漂移字面量不得落在容差内'
case('N/N 漂移',            '门禁 %d/%d 全通过\n' % (DRIFT, DRIFT), 1)
case('N 项漂移',            'release_check %d 项全通过\n' % DRIFT, 1)
case('N 项 + 强调漂移',     '门禁 **%d** 项\n' % DRIFT, 1)
case('正确值不报',          '门禁 %d/%d 全通过\nrelease_check %d 项\n'
                            % (GATE_TOTAL, GATE_TOTAL, GATE_DEFAULT), 0)
case('分母正确/分子是失败数 -> 放行',
                            '门禁 21/%d（唯一失败=未提交）\n' % GATE_TOTAL, 0)
case('分母错误 -> 必报',    '门禁 %d/%d\n' % (GATE_TOTAL, DRIFT), 1)
```

**同时修掉的第二处同型缺陷**：真实文档锚点也是硬编码的

```python
for good, bad in (('38/38', '36/36'), ('38 项', '36 项')):   # 旧版: ('37/37','35/35')
```

它找的是 `publish/01-关于ShardVase.md` 里的**现值** `37/37`。本轮把文档
改成 `38/38` 后，锚点**静默消失** ⇒ `负向用例失去锚点`。改为
`('%d/%d' % (GATE_TOTAL, GATE_TOTAL), '%d/%d' % (DRIFT, DRIFT))`，
`bad` 直接取已断言的 `DRIFT`，不再凭记忆挑数字。

### 2.31.5 验证

- `py_compile` rc=0；`--selftest` ⇒ **PASS: 21 项（8 项负向注入 / 13 项合规豁免）**
  （改前 FAIL 5/20）；主检 ⇒ **PASS**（`检查数字 634 处, 错误 0, 警告 0`）。
- **判别力实测**（不是"看起来对"）：临时把 `DRIFT = max(...)+1` 改成
  `DRIFT = GATE_TOTAL`（即让字面量落回容差内），`--selftest` **rc=1**
  ⇒ 断言与用例真的在把关，不是装饰。

### 2.31.6 可外推的教训

1. **判据常量必须由判据所依赖的集合推导，不能硬编码字面量。**
   凡是"X 必须不在集合 S 里"的用例，X 应由 S 算出。
   与 §2.30 的 `TARGET_LOGICAL` 静默 `section absent — skip` 同型
   ——**"数量对得上、语义对不上"**，只是这次数量对不上的是"容差"。
2. **`--selftest` 必须串在主检之前跑**，否则判据失效只在自检里可见，
   而人只会看主检的 PASS。门禁第 14 项早已是
   `$st = & $py tools\doccheck.py --selftest` 在前、主检在后
   （`tools/release_check.ps1:337-342`），本轮正是这一条救了场。
3. **记成"操作提示"的教训会复发，记成"机制"的不会。**
   前两次都只在注释里写"记得重挑字面量"，第三次照旧发生。
   这次把不变量的成立条件写进代码（`assert` + 推导），
   **让越界在运行期直接抛错**，而不是留给下一轮的人去记。
4. 附带事实：`f4b27f4` **是本地门禁报红时提交的** —— 我先跑了 `git commit`
   再跑全门禁，实际顺序应当是「全门禁绿 → 提交」。
   该提交本身内容正确（红项在自检字面量，不在其改动），
   但**顺序错了**：若当轮 CI 是准入条件，这次会被挡下。

### 2.31.7 诚实边界

- 本修法只覆盖 `tools/doccheck.py` 的自检常量。**其余工具是否也有
  "硬编码了必须不在某集合内的常量"，本轮未全库审计** ——
  `tools/doccheck.py` 之外尚未发现实例（`build/_scan_counts.py` 扫过
  `tools/**/*.py` 的 `34/35/36/37` 计数形态，命中全部落在 `doccheck.py`），
  但该扫描的**模式只认计数**，不认其它形态的"集合外常量"。
- `DRIFT = max(...) + 1` 假定"比现值更大的数一定是漂移"。
  这在项数只增不减的当前演进下成立；若将来项数**减少**，
  该假设需要重新检查（届时自检会因 `正确值不报` 用例而报错，
  不会静默通过 —— 这正是把它写成 `assert` 而非注释的价值）。

---

## 2.32 阶段总结与「整理」：陈旧复选框的三种表现（2026-10-06）

### 2.32.1 缘起：m17465「在完成所有计划后进行总结，整理，记录，技术沉淀」

该要求有四步，本节的目的是把**四步各自落在哪里**记清楚，
使后来者不必回读对话就知道交付物在哪、边界在哪：

| 步 | 交付物 | 位置 |
|----|--------|------|
| **总结** | `docs/阶段总结-2026-10-06.md`（363 行） | 提交 `28287ea` |
| **整理** | `docs/BLUEPRINT.md` §9 + `docs/MODULAR_ARCH.md` 头部/§5 | 提交 `9e013ff` |
| **记录** | 本节 | 本提交 |
| **技术沉淀** | 阶段总结 §3（`3.1`-`3.8`）+ §7 元结论 + 仓外记忆 | 见 §2.32.4 |

**阶段边界**：`9f11975`（2026-09-30）-> `0331f97`（2026-10-06），**72 个提交**，
`git diff --shortstat` = `107 files changed, 15970 insertions(+), 977 deletions(-)`。
前序为 `docs/阶段总结-2026-09-30.md`（`3600ecf` -> `9f11975`，14 提交）。

**本阶段门禁 28 -> 38**（新增 10 项、移除 0 项），逐轮：

```
9f11975 = 28
b700574 = 29  + 调试控制台自检 (prot_dbg)
795dd12 = 30  + 门禁日志自检 (gate_log)
5e7340b = 32  + 调试控制台活体自检 (prot_dbg live)  [同轮把内联签名块转正为 Check 项 -> 一次 +2]
2f48ab1 = 33  + mojibake 全库回归 (mojibake_check)
c8a4799 = 34  + 加密封装窗口 (window_check)          [唯一中段插入: 第 11 位]
d6f1f8d = 35  + 判定多副本等价性 (replica_check)
2d16b61 = 36  + CRC 目标表一致性 (crc_targets)
bc68b11 = 37  + 静态未定义名审计 (undef_check)
f4b27f4 = 38  + Android 交叉编译 (android_compile_check)
```

`GATE_TOTAL` / `GATE_DEFAULT` 由 `33/30`（`2f48ab1`）-> `34/31` -> `35/32` -> `36/33`
-> `37/34` -> `38/35`。gated 3 项 = 第 16 / 23 / 24 项；默认跑 35 项。

### 2.32.2 「整理」发现的第三种表现：同一文件内的两处记录互相矛盾

`docs/BLUEPRINT.md` 的 §9「成功判据」长期写着：

```
**当前进度**：M3 部分达成（阶段 1），其余待做。
```

而**同一文件**的 `:140-150` §3.4.1 早在 **2026-09-21** 就实测记着「**5/5 通过。**」。
两者并存了半个月，没有任何机制发现。

把它与前两次同型缺陷并排看，**「没人比对」有三种表现**：

| # | 表现 | 实例 | 记档 |
|---|------|------|------|
| 1 | 代码在，**调用点**不在（或反之） | e2e T3 孤儿 `class DebugAttacher` | §2.24 |
| 2 | 结论在，**结论所依赖的机制**已变 | S1 revoke 的阻力理由；MEMPATCH 已落地却 8/8 未勾 | §2.28 / DRILL7 |
| 3 | **同一文件内**，旧状态与新实测并存 | `BLUEPRINT.md` §9 vs §3.4.1 | 本节 |

**三者共同的根因**：状态是**手写**的，且**从不被机器比对**。
`tools/doccheck.py` 只扫 24 个自声明「最后核实」的文件，
而 `docs/BLUEPRINT.md` / `docs/MODULAR_ARCH.md` **都不在其扫描面内** ——
于是这两份文档里的任何陈旧陈述，门禁永远看不见。

### 2.32.3 本轮改了什么、为什么其余一律不动

**改了**（只改有实测证据的）：

- `docs/BLUEPRINT.md:762-772`：M1-M5 五个 `- [ ]` -> `- [x]`，
  删掉与 §3.4.1 矛盾的那一行，换成**本轮实跑**的逐条证据表
  （`drills.py lint` 125 条 0 错误 / `modcheck` 13/13 / `modcheck` 门禁第 12 项
  / `doccheck` 门禁第 14 项 + 642 处 0 错误）。
- 同一处**加了 M5 的措辞边界**：判据原文写「由内部数据**生成**」，
  但落地的是 `doccheck` 的**检查** + `docclaim_check` 的 8 条可执行断言，
  **不是**自动**产出**文档。记 ✅ 的判据是「无手工漂移」这一可验证部分。
  **不加这条，"5/5 达成"就成了一次过度声明。**
- `docs/MODULAR_ARCH.md`：头部状态行「设计提案，待评审（未动代码）」-> 已落地；
  §5 进度行 阶段 2/3 -> ✅；阶段 2 补「原待补两项」现状表；阶段 3 补证据；
  **阶段 4 保留 ⬜**（`tools/cost_model.py` 实测不存在），
  并加区分说明：既有的 `migration_cost.py` / `migration_gate.py` /
  `migration_inventory.py` 是 **W5.6/W5.7 迁移成本**（门禁第 24 项），
  **不是** MODULAR_ARCH §4 所指的成本模型。

**有意不改**（逐条核过）：

- `docs/CONTRACT.md:591-594`（4 条 `- [ ]`）= §8「提交前自检清单」，
  **每次提交复用的模板**，不是待办。
- `docs/WORKBENCH_ROADMAP.md:521-529`（W5.4/W5.5/W5.6 标「未做」）：
  该节即「W5 剩余（下一阶段）」的**带日期阶段快照**；
  同文 §10.6（`:621-629`）与 §11.7（`:741-743`）已逐条更新为 ✅。改它等于伪造当时结论。
- 真待办一律不动：`docs/PHASE2.md` 8 条 + `docs/MEMPATCH_PLAN.md:105/107/108`（需硬件）、
  `docs/HISTORY_REWRITE_PLAN.md` 5 条（**不可逆**）、
  `docs/marketing/LAUNCH_HANDBOOK.md` 4 条（发布动作）、
  `docs/commercial/README.md` 4 条（商务拍板）。

### 2.32.4 「技术沉淀」落在哪里

- **仓内**：`docs/阶段总结-2026-10-06.md` §3（`3.1`-`3.8` 八条沉淀，标 ⭐ 重要度）
  与 §7 元结论；其 §8「过程改进项」给出两条**尚**未实施的机制建议：
  `8.1`「集合外常量」全库审计、`8.2` **陈旧复选框同步机制**。
- **仓外**：写入项目记忆（Hindsight），文档题名
  「阶段总结 2026-10-06：门禁 28->38 + 判定点冗余闭环 + 攻击侧真机实证」。
- ⚠️ **诚实边界**：`8.2` 的机制**本轮没建** —— 只手工修正了两个实例。
  这正是本类缺陷第 3 次出现的直接原因。**下一次会不会复发，取决于机制是否补上，
  而不取决于这份记档写得多详细。**

### 2.32.5 「所有计划」的处置口径

阶段总结落笔时对 `docs/**/*.md` 做了 `- [ ]` 全库普查：**39 处**，
分布在 10 份文档（`PHASE2.md` 8 / `HISTORY_REWRITE_PLAN.md` 5 / `BLUEPRINT.md` 5
/ `LAUNCH_HANDBOOK.md` 4 / `commercial/README.md` 4 / `CONTRACT.md` 4 / `N1_PLAN.md` 3
/ `MEMPATCH_PLAN.md` 3 / `DEFENSE_DEEPEN_PLAN.md` 2 / `PLAN.md` 1）。
按性质分类后，**技术上可做而未做的只剩两项**：

1. `docs/PLAN.md:203` 加壳 / 外部文件装载（blob 加密签名绑定、网络下发）—— 可选升级；
2. `docs/DEFENSE_DEEPEN_PLAN.md` S2-S5 —— 但**其阻力理由需先按 §2.28 的教训重新核对**
   （该文档的 S2 阻塞理由同样基于"追加函数会漂移 `.text`"，而「只增函数、不重排」
   纪律 + `merge_baseline` 已落地）。

其余 = 需硬件（真机矩阵）/ 不可逆（历史重写）/ 发布动作 / 商务拍板 / 纯陈旧复选框（已整理）。

### 2.32.6 诚实边界

- 本轮 `docs/BLUEPRINT.md` 的 M1-M5 复核**除 M2/M3/M5 的计数外，多数结论转述自
  §3.4.1 的 2026-09-21 实测**，只有 `drills lint`（125/0）、`modcheck --all-compositions`
  （13/13）、`doccheck`（642/0/0）三处是本轮**新跑**的。
  M1「任意参考拼装图可一键构建」的**穷举性**未重验 —— 只核了四档预设 + §3.4.2 的
  自定义组合案例存在。
- §2.32.2 的"第三种表现"是我的**归类**，不是既有术语。三者是否真属同一根因
  （"手写状态 + 无机器比对"），可供后来者质疑。
- 全库普查的 `39 处` 只覆盖 `docs/**/*.md`，**未含** `README.md` / `CONTRIBUTING.md`
  / `.github/**` / `publish/**`；这些位置的复选框未统计。
- 阶段 4（成本模型）标 ⬜ 的依据仅是 `tools/cost_model.py` **文件不存在**；
  未排查是否有**别的文件**已等价实现了该模型。

*2026-10-06 v1*

---

## 2.33 「机制在、测试不在」的第 3 次复发：补齐 e2e T29（2026-10-06）

### 2.33.1 缘起：复核 N1_PLAN 时数出来的一个空洞

复核 `docs/N1_PLAN.md`（§2.32 的「整理」步）时发现三处"真没做"的缺口，
其中一处与既有缺陷同型、且**当天就能闭合**：

**II-1 解密态 CRC 校验在 `73f2381`（2026-08-22）就落地了，
但 `tests/` 里从来没有一处篡改 `.protcry` 的元数据去触发它。**

机制是齐的、终止路径也是齐的：

```
src/selfcrypt.c:290-314   prot_selfcrypt_init() 逐条 sc_do_range(i, 1) 并比对
src/selfcrypt.c:240       if (got != crc) { ... return PROT_ERR_INTEGRITY; }
demo/main.c:525-529       if (sc != PROT_OK) { MSG_TAMPER; exit(PROT_EXIT_TAMPERED); }
```

但 e2e 的 26 个用例 ID（T1–T8、T11–T28）没有一个碰 `.protcry`：

| 位置 | 对 `.protcry` 的操作 |
|------|---------------------|
| `tests/e2e.py:387 make_tampered_copy()` | 只翻 `.text` / `.rdata` / `.pdata` |
| `tests/attack_drill.py` D2/D3 | 只有**读** |
| `tests/protchain_check.py:149 selfcrypt_meta()` | 只有解析 |

⇒ 用户可见的 `MSG_TAMPER` + `0xBAD` 这条路径，**从未被自动化验证过**。

这是「没人比对」的**第 3 次复发**。§2.24（e2e T3 的 `DebugAttacher` 被误删后
无人发现）是"代码在、调用点不在"；§2.27（`guard_selftest.py` 的 `exit_pol`
未定义名）是同一个测试文件里的空洞。**共同点：失败路径的代码最难被测试碰到** ——
要触发它必须主动构造一个"看起来像攻击"的输入，而没人有动力主动写这个。

### 2.33.2 修法与一个关键设计：三跑对照

`tests/e2e.py` 新增 120 行（提交 `80db8ba`）：

1. docstring 用例清单补 T29 一行；
2. 两个模块级助手 —— `cry_section_name()`（从
   `demo/gen/<plat>/prot_sections.json` 的 `sections.protcry` 取**构建期随机化后
   的真实节名**）与 `make_meta_tampered_copy(sec_off, rel_off)`（按节内偏移翻 1 字节）；
3. T29 块 —— 篡改目标 = 第 0 条 entry 的 **crc32 字段首字节**（节内偏移 `4+0*24+16`，
   对齐写入侧 `tools/selfcrypt_proto.py:441-444`）。

⚠️ **只断言"篡改后必须 0xBAD"是不够的。** `.protcry` 不在
`tools/hashpatch.py:112 TARGET_NAMES = ('.text','.rdata','.pdata','.protxec')` 内，
所以存在一个必须排除的替代解释：**"随便翻这个节里的任意字节都会 0xBAD"**。
若成立，T29 就退化成"证明翻过文件 = 会报错"，与 meta CRC 无关。

因此判据是**三跑对照**：

```
base_ok = (code_b == 0) and (msg_ok in out_b)        # 基线必须正常
ctrl_ok = (code_c == code_b)                          # 翻节尾填充 == 基线  ← 关键
hit     = (_norm_exit(code_m) == _norm_expect(PROT_EXIT_TAMPERED)
           and msg_tamper in out_m)                   # 翻 meta crc32 -> 0xBAD
ok = base_ok and ctrl_ok and hit
```

`ctrl_ok` 证明**变红来自 meta 内容本身，不是来自"动过这个节"**。

**这是本条的通用教训**：写"篡改必须被检测到"这类测试时，
**必须同时给出一个"篡改但不该被发现"的对照**，否则测的是"文件被动过"，
不是"目标校验逻辑生效"。

### 2.33.3 验证（含变异验证）

| 项 | 结果 |
|----|------|
| `python tests/e2e.py` | **总计 29: PASS 29 / FAIL 0 / SKIP 0 / NA 0**，rc=0 |
| `T29 meta-crc` 详情 | `PASS (exit=2989 ctrl=0 base=0 meta_n=9)` |
| 基线/对照/本体 | `exit=0` / `exit=0`（同基线）/ `exit=2989 (0xBAD)` + `完整性校验失败` |
| 实测节信息 | `protcry=.b3locz1` `ptr_raw=0x34800` `crc_len=0x4000` `n=9` `meta_end=0xdc` |
| **变异验证** | 篡改点退回 `crc_len-1` ⇒ **`T29 meta-crc FAIL (exit=0 ctrl=0 base=0)`**，`总计 29: PASS 28 / FAIL 1`，rc=1；逐字节恢复（`bytes=66943 bom=True 一致=True`） |
| `py_compile` / `bom.py add` | rc=0 / `+BOM` |
| `build/_hygiene.py` | `15 个文件, 0 处异常` |
| `tools/doccheck.py` | **PASS**（`检查数字 664 处, 错误 0, 警告 0`） |
| `tools/docclaim_check.py` | **PASS (8/8)** |

变异验证的意义：证明 T29 **可判伪**，不是"只会通过的检查器"
（呼应 `docs/阶段总结-2026-10-06.md` §3.8）。

### 2.33.4 顺带做的：计数面同步（并暴露判据问题）

T29 落地后，「T1-T28」字样成为陈旧值。全库普查命中 41 处，
按**语义**分成两类：

- **现值**（门禁清单 / 单项命令注释 / CI step 名）⇒ **改**，共 **8 处**：
  `tools/release_check.ps1:296`（`Check 'e2e T1-T28'`）/ `tools/ci_sim.ps1:9,:75` /
  `.github/workflows/ci.yml:45` / `tools/verify_linux_runtime.py:293,:296,:320,:322` /
  `README.md:140` / `CONTRIBUTING.md:76` / `publish/02-项目档案.md:119` /
  `docs/阶段总结-2026-10-06.md:257`。
- **历史**（带日期 / 某轮输出快照 / 已勾选的计划验收行）⇒ **一律不动**，共 30 处：
  `docs/HANDOVER.md` 7 处 / `docs/CI_PLAN.md` 6 处 / `docs/compat-matrix.csv` 3 处 /
  `docs/PILLAR2_OBSERVABILITY_PLAN.md` 3 处 / `docs/PORTABILITY_ASSESSMENT.md` 2 处 /
  `docs/ATTACK_PLAN.md` / `docs/BLOB_SIGN_PLAN.md` / `docs/INFRA_PLAN.md` /
  `docs/MODULE_PROTOCOL_DECISIONS.md` / `docs/REVIEW_MODULE_PROTOCOL.md` /
  `docs/WORKBENCH_ROADMAP.md` / `docs/部署档案-ShardVase.md` 各 1 处 +
  `tools/release_check.ps1:92,:96`。

⚠️ **`:92`/`:96` 是最容易改错的两处**：它们不是"门禁清单"，
而是 `gate_log` 限长规则**事故本身**的叙述（2026-10-02，`e2e T1-T28` 失败时
被测脚本先打印 27 行用例，"末 12 行"全是 `T16..T26 PASS` 噪声，
含 `FAIL` 的那一行被当作"前 N 行"省略）。**改掉它会让自检叙事失实。**

**标签溯源**（`build/_t29label*.py` 逐提交比对）：
`Check 'e2e T1-T28'` 自门禁创建提交 `e68a762` 起就是 `T1-T28` 且**再未改过**
（`git log -S "e2e T1-T28" -- tools/release_check.ps1` 只命中 `e68a762` 与
`f9285bf` 的**文字引述**，后者 `f9285bf^` 与 `f9285bf` 逐字相同）。
`e68a762` 时 e2e 实际 ID 集合 = `[1..8, 11..28]`，`max=T28` ⇒ 标签当时准确。
⇒ **本仓库没有"标签随用例增长同步改名"的先例**；但 T1-T28 是**区间上界**，
加了 T29 后上界变为 T29，故现值为「T1-T29」更诚实。

**判据层面的问题**：`tools/doccheck.py` 与 `tools/docclaim_check.py`
**都不解析「T1-T28」字样**（doccheck 只在 `:157` 注释里提到 T3/DebugAttacher）。
⇒ 这 41 处**没有任何机器强制**同步，也无任何机制**发现**漏改 ——
它与 §2.32 记录的"陈旧复选框"是**同一根因**（手写状态 + 无机器比对），
只是这次我自己既是引入者又是发现者。

### 2.33.5 诚实边界

- **仍未在真机 / 企业环境验证**（与 `docs/N1_PLAN.md` §10 第 5 条同一挂账）；
  `0xBAD` 证据是 **Windows x64 本机构建**下的。
- **Linux 侧未跑**：`build/linux/` 下没有 demo 产物 ⇒ `--platform linux` 时
  T29 会走 `section_bounds()` 的 `RuntimeError` 分支变 **FAIL**
  （如实报错，不是假绿）；待 Linux 产物齐备后需复跑。
- **`PROT_SELFCRYPT_DISABLE` 构建下 T29 记 SKIP**（`n == 0` ⇒ 无 meta），
  该分支**未实测**。
- **T29 只覆盖 II-1 的"解密态"一半**：密文态 CRC（`PROTCRYP` 第 4 烧录标记）
  **从未实现**（`tools/hashpatch.py:47 MAGICS` 只有 4 个，全库搜 `PROTCRYP` 零命中）；
  `prot_selfcrypt_leave()`（`src/selfcrypt.c:347`）走 `sc_do_range(i, 0)`
  **不校验**，故 T29 只覆盖 `init`/`enter` 路径。
- **T30（密文态篡改）仍未实现**；**D2c 看门狗周期重加密仍未实现**
  （`docs/N1_PLAN.md:139` 的折中方案，`src/` 内零命中）。
- **未重跑全门禁**：本条提交时 `release_check.ps1` 另行后台跑，结果见后续提交或本节后续补记。
- 计数面同步用的是 `build/_t29sync.py`（逐条 `(old, new, expected_count)` 断言，
  任何不符即整体中止不写盘）；其末尾的**自证断言过严**（对
  `tools/release_check.ps1` 因保留历史注释而误报），写盘已在断言之前完成，
  不影响结果 —— 但这是一个**应当记下的脚本缺陷样本**。


---

### 2.34 e2e T30 补齐 —— 「密文态篡改」≠「密文态 CRC」（2026-10-06）

#### 2.34.1 缘起：`docs/N1_PLAN.md` 里的 T30 一直只是编号

§2.33 闭合了 T29（II-1 解密态 CRC 的 meta 篡改回归）。当时 `docs/N1_PLAN.md`
§11 如实写着「`T30` 仍只是计划里的编号」。本节的目的是把 T30 也变成真用例。

难点在于**先要弄清 T30 与已有的 T4 有什么不同** —— 如果答案只是「再翻一个
字节」，那 T30 就只是 T4 的副本，没有存在价值。这个区别不在测试代码里，
而在**构建期的掩码**里。

#### 2.34.2 承重机制：selfcrypt 区间被段 CRC 掩码剔除

`tools/hashpatch.py:383-386`：

```python
# N1 (D1b): selfcrypt 加密段同样掩码 (与运行侧 build_selfcrypt_mask 一致)
for (mrva, mlen) in EXCLUDE_MASKS:
```

`build.ps1` 的步骤 6（selfcrypt 原位加密）会把被加密的函数区间写进
`build/selfcrypt_mask.txt`；步骤 7（烧录段 CRC32）把同一份掩码以 `--mask rva,len`
传给 `hashpatch.py`，于是**这些区间被从 `.text` 段 CRC 的覆盖范围里排除**。

实测 `build/selfcrypt_mask.txt` 8 行与 `.protcry` meta 的 8 条 `rva/len`
**逐字一致**（`0x7a00,125` / `0x81a0,977` / `0x8970,290` / `0x8870,248` /
`0x50a0,212` / `0x5040,95` / `0x1a60,62` / `0x48a0,154`）。

⇒ 结论：**落在这些区间内的篡改，段 CRC 原理上检不出，唯一能抓住它的是
II-1 的解密态 CRC**。这就是 T30 与 T4 的分界线：

| 用例 | 翻什么 | 谁抓住它 | 拒止点 |
|------|--------|----------|--------|
| T4 | `.text` 末字节（CRC 覆盖内） | 段 CRC | `demo/main.c:631 prot_integrity_check_self()` |
| T29 | `.protcry` meta 的 crc32 字段 | II-1 解密态 CRC | `demo/main.c:525 prot_selfcrypt_init()` |
| **T30** | **密文函数体本身**（掩码剔除区） | **II-1 解密态 CRC** | **`demo/main.c:525`（同上）** |

T29 验的是「**meta 里存的那个值被信任**」；T30 验的是「**密文确实被解密、
并且按 meta 的明文 CRC 重算了一遍**」。两者都不能由对方替代。

#### 2.34.3 判据：三跑 + 一个顺序判别器

T30（`T30 cipher-crc`，`tests/e2e.py`）跑三次：

1. **基线** → `exit=0`，stdout 含 `反逆向保护套件演示`；
2. **本体**：选掩码区间里**最大**的那条，翻它的中点 → 期望 `0xBAD` + `MSG_TAMPER`；
3. **对照**：翻 `.text` 末字节（走 T4 的段 CRC 路径）→ **也**是 `0xBAD`。

对照也返回 `0xBAD`，所以**仅凭退出码无法区分两者** —— 这正是本节最值得记的
一点。真正的判别器是**拒止点的先后**：

- `demo/main.c:520-521` 打印 BANNER；
- `:525 prot_selfcrypt_init()` ← **II-1 在这里就能拒止**；
- `:544 prot_antidebug_scan()` → `:546` 打印 `反调试扫描: …`；
- `:631 prot_integrity_check_self()` ← 段 CRC 在这里才拒止。

⇒ **若密文态篡改在 `反调试扫描` 之前就被抓住，说明拦它的是 II-1，不是段 CRC。**
实测：

```
T30 cipher-crc  PASS   (exit=2989 ctrl=2989 base=0 n=8 off=0x7388 early=yes)
```

`early=yes` = stdout 里**没有** `反调试扫描`（基线里有）。退一步说，即使退出码
相同，这个顺序差也把两条路径分开了。

代码里还加了两条**结构性断言**，防止用例悄悄退化成 T4 副本：

```python
if not any(mrva <= rva0 and rva0 + len0 <= mrva + mlen for mrva, mlen in ranges):
    raise RuntimeError('掩码区间不自洽: rva=0x%x len=%d not in %r' % ...)
if any(mrva <= t_va + ctl_off < mrva + mlen for mrva, mlen in ranges):
    raise RuntimeError('对照偏移 0x%x 落在掩码区间内' % ...)
```

`early_ok` 是**条件式**断言：只有当基线 stdout 里确实出现过 `反调试扫描`
时才要求本体里没有它 —— 不去硬编码「antidebug 模块一定已编入」这个假设。

#### 2.34.4 验证

| 项 | 实测 |
|----|------|
| 全量 e2e | `[e2e] 平台=win  总计 30: PASS 30 / FAIL 0 / SKIP 0 / NA 0`（28 → 29 → **30**） |
| T30 明细 | `exit=2989 ctrl=2989 base=0 n=8 off=0x7388 early=yes` |
| 变异验证 | 把 `tgt_off = off0 + len0 // 2` 退回 `tgt_off = t_crc - 1`（即退化成 T4 路径）⇒ **`T30 cipher-crc  FAIL   (exit=2989 ctrl=2989 base=0 n=8 off=0x2235f early=no)`**，`总计 30: PASS 29 / FAIL 1`，e2e rc=1；`finally` 逐字节恢复（`bytes=75493 bom=True 一致=True`） |
| 掩码一致性 | `build/selfcrypt_mask.txt` 8 行 == meta 8 条 `rva/len` |
| 门禁 | `[release_check] PASS: 35 项检查全通过`，含 `[ok] e2e T1-T30` |
| 卫生 | `build/_hygiene.py` 15 文件 0 异常；`py_compile` rc=0；两个 `.ps1` parse errors 0 |
| 文档 | `doccheck` PASS（686 处 0 错误）；`docclaim_check` PASS (8/8) |

变异后的 `early` 由 `yes` 变 `no` 是关键：这时拒止点从 `:525` 退到了 `:631`，
用例立刻变红。⇒ **T30 不是「只会通过的检查器」**（呼应
`docs/阶段总结-2026-10-06.md` §3.8）。

#### 2.34.5 计数面与诚实边界

计数面同 §2.33.4 的做法：现值 9 处 `T1-T29` → `T1-T30`（`tools/release_check.ps1:296`
/ `tools/ci_sim.ps1:9,:75` / `.github/workflows/ci.yml:45` /
`tools/verify_linux_runtime.py:293,:296,:320,:322` / `README.md:140` /
`CONTRIBUTING.md:76` / `publish/02-项目档案.md:119` /
`docs/阶段总结-2026-10-06.md:257`），外加 `29 项` → `30 项`（`tools/verify_linux_runtime.py:296`
/ `publish/02-项目档案.md:119`）。历史记录（30 处 `T1-T28` 和
`docs/HANDOVER.md:3185` 的 §2.33.4 结论）一律不动。

诚实边界：

- **T30 ≠ 密文态 CRC**。`tools/hashpatch.py:47 MAGICS = (b'PROTCRCP', b'PROTCRCD',
  b'PROTCRDP', b'PROTCRCX')` 只有 4 个，搜 `PROTCRYP` 全库零命中 ⇒
  **密文态 CRC 从未实现**，`docs/N1_PLAN.md` §4 阶段 3 如实保留未勾。
  「T30 密文态篡改」= 篡改密文、由**解密态** CRC 抓住；「密文态 CRC」= 对
  密文形态本身独立校验 —— 两回事，本轮特意在 `docs/N1_PLAN.md` §6 加注分清。
- **不证明加密不可逆**：密钥 `key0` 仍明文存在 meta 里（`tools/selfcrypt_proto.py:442-444`）。
- **掩码是构建产物**：`build/selfcrypt_mask.txt` 缺失时 T30 记 **SKIP**
  （`未验证 != 通过`），该分支**未实测**。
- **D2c 看门狗周期重加密仍未实现**（`docs/N1_PLAN.md:139` 的折中方案，`src/` 内零命中）。
- `tests/e2e.py` 里 `n=8` 而 §2.33 记的 `n=9` 并非矛盾 —— 期间重新构建过
  （节名也从 `.b3locz1` 变为 `.bmrihpa`）。
- 与 §2.33 同：**真机 / 企业环境仍未验证**，证据是 Windows x64 本机构建下的。

#### 2.34.6 补记：本节落地后的全门禁与 CI

§2.34 的「未验证」里原写「§2.34 自身落地后的全门禁尚未重跑」。现已重跑，
结果如下（这正是本仓库反复吃过的「记录会过时」——所以当场回填）：

- **全门禁**：`[release_check] PASS: 35 项检查全通过`（rc=0），日志
  `build/logs/release_check_20261006_070951.log`，其中逐字含
  **`[ok]  e2e T1-T30`** —— 证明改名后的门禁标签确实被执行到（不是只改了
  字符串而用例没跑）。
- **CI**：run `37386864350`（head `7e02954`）`completed success`，
  四 job 全绿：`build-and-verify|success` / `linux-portability|success` /
  `sdk-package|success` / `reproducible|success`。
- 提交链：`80db8ba`（T29）→ `ed7d838`（§2.33）→ `efb81b7`（T30）→
  `7e02954`（§2.34），均已推送 `origin/master`。
- 唯一噪音是 CI 的 Node.js 20 弃用告警
  （`actions/checkout@v4` 等被迫跑在 Node.js 24 上），与本次改动无关。

---

## 2.35 D2b 的**真实缺口**与 D2c 收口 —— 承诺说「间隙是密文」，实测间隙是明文（2026-10-06）

### 2.35.1 缘起：一条被 `[x]` 盖住的验收

`docs/WIN_ENHANCE.md:123-124` 的验收行写着：

> `[x] W1a：build.ps1 Release 默认 D2b + -NoD2b 回退（实测 enter/leave`
> `     有实体 = D2b 生效）。`

验收判据是「**enter/leave 有实体**」。这条判据只回答「包装函数在不在」，
**没有回答**「不在窗口里的那些时刻，内存里到底是密文还是明文」—— 而后者才
是 D2b 的全部卖点（`docs/N1_PHASE2_PLAN.md:63`：运行期非调用时刻内存中函数
为密文，dump 抓不到明文引擎）。

本轮把后半句真正测了。结论是：**commit 前，后半句不成立。**

### 2.35.2 承重机制：`prot_selfcrypt_init` 解了密就不再上锁

`src/selfcrypt.c` 的 `prot_selfcrypt_init` 原实现（简化）：

```c
/* D2a: 全部解密并校验; D2b: 只解密组 0 一次 (enter/leave 接管后续) */
for (i = 0u; i < n; i++) {
    prot_status st = sc_do_range(i, 1);
    if (st != PROT_OK)
        return st;
    g_sc_state[i] = 1u;
}
#ifdef PROT_SELFCRYPT_D2B
g_sc_d2b_enabled = 1u;
#endif
```

注释声称 D2b 下「只解密组 0」，**实现是无条件解密全部 n 条**，而且解密后
`g_sc_state[i] = 1u` 把它们标记为「当前明文」。此后每条要一直等到自己所属组
的 `leave(组)` 被调用才会重新加密。

于是从 `prot_selfcrypt_init()` 返回到**首次** `leave(组)` 之间存在一段
**全量明文驻留窗口**。实测（`demo.exe`，Release，9 条目标；判据 = 内存字节
vs 磁盘密文，见 §2.35.4）：

| 路径 | 组 0（VM 引擎，条目 0-3） | 组 1（EXT，条目 4-8） |
|------|---------------------------|-----------------------|
| 自然路径（总时长 ~0.67 s） | 明文 `0.005s` → `0.666s`（**661 ms**） | 0.005 起明文，仅 0.313-0.346 一段回密 |
| `--wait-ms 6000`（总时长 ~6.7 s） | 明文 `0.004s` → `6.717s`（**6713 ms**） | 0.004 起明文，6.323 后开始周期性开合 |

组 0（`prot_vm_run` / `vm_build_keymaps` / `vm_wb` / `vm_var`）在**整个运行期
的前 99.9%** 都是明文，只在进程退出前最后 1-2 ms 的 `leave(VM)` 才短暂回密。
注意自然路径下 `0.666 C C C C P P P P` 这一行：`leave(VM)` 先把组 0 回密，
紧接着 `leave(EXT)` 又把组 1 解开 —— 这说明两个组各自独立开合，而组 0 的
明文期**几乎覆盖全程**。

`--wait-ms` 这个钩子的睡眠点在 `demo/main.c:533-536`，**在 init 之后**
（`:525`）—— 也就是说，一个「启动后先等一会儿」的产物，其引擎明文在内存里
躺了 6.7 秒。Procdump 在这个窗口里抓一次，`prot_vm_run` / `vm_build_keymaps` /
`vm_wb` / `vm_var` 全部是明文。

**这正是 D2a 的形态，不是 D2b 的形态。** 换句话说：D2b 的调用期
enter/leave 确实工作（§2.35.4 给出证据），但它前面挂着一整段 D2a。

### 2.35.3 修法：D2c 的最小实现 —— 校验后立即回密

`docs/N1_PLAN.md:143-144` 把 D2c 定义为「看门狗周期重加密」。本轮先说清
**这个定义的前提已经不成立**：看门狗每一轮本来就已经
`enter(EXT)` / `leave(EXT)`（`src/integrity.c:188` / `:256`），组 1 的周期
重加密**早就在跑**（实测组 1 在 5.9 s 周期里约 95.6% 时间是密文）。

真正的缺口是 init 那一次**解完不锁**。所以 D2c 的最小实现不是新建机制，
而是给 init 补齐收尾：

```c
for (i = 0u; i < n; i++) {          /* ① 逐条解密 + 逐条 CRC 校验 */
    prot_status st = sc_do_range(i, 1);
    if (st != PROT_OK)
        return st;
    g_sc_state[i] = 1u;
}
#ifdef PROT_SELFCRYPT_D2B
g_sc_d2b_enabled = 1u;
for (i = 0u; i < n; i++) {          /* ② 校验完立即回密 */
    (void)sc_do_range(i, 0);
    g_sc_state[i] = 0u;
}
#endif
```

三个设计约束，每条都有实测依据：

- **回密必须限定在 `PROT_SELFCRYPT_D2B` 下。**
  D2a 构建的 `prot_selfcrypt_enter` / `prot_selfcrypt_leave` 在开口就
  `if (!g_sc_d2b_enabled) return PROT_OK;` 早退（`src/selfcrypt.c:321-322` /
  `:341-342`）。若 D2a 下也回密，函数体会**永久停在密文**，调用即执行垃圾
  指令 —— 即 §2.16 / T11 记录过的 `0xC0000005` 形状。
  *这条约束被一次**误操作意外验证**了*：本轮第一次重建误用了 `-Release`
  （`build.ps1` 的参数是 `[string]$Config`，没有 `-Release` 开关），产物按
  Dev 配置编译、D2B 未定义；探针显示 9 条**全程明文** —— 与「D2a 下回密会
  崩」的预测方向一致（该次没崩只是因为回密块整体被 `#ifdef` 摘掉了）。
- **不能牺牲「启动即拒止」。** 仍保持「逐条解密 → 逐条 CRC 校验 → 任一条
  不过就返回错误」，调用方 `demo/main.c:526-530` 退
  `PROT_EXIT_TAMPERED(0xBAD)`。回密放在校验**之后**，拒止时点不变。
- **回密后不得踩空。** 全部加密目标的跨模块调用点都在配对 enter/leave
  窗口内 —— `tools/window_check.py`（门禁第 11 项）静态覆盖 24 文件 / 308
  函数 / 9 个目标，PASS。组内私有函数（`vm_build_keymaps` / `vm_wb` /
  `vm_var`）只在 `prot_vm_run` 体内被调用，随 VM 组窗口一并解密。

### 2.35.4 验证

**判据不是状态数组，而是内存字节 vs 磁盘密文。** 这一点是本轮的方法学要点：
`g_sc_state[]` 是**实现自己的记账**，它可能与内存真实状态不符（本轮第一版
探针就是这么被误导的，见 §2.35.5）。终版探针 `build/_d2c_truth.py` 对每个
条目取 `build/selfcrypt_mask.txt` 的 `(rva,len)`，把**进程内存字节**与
**磁盘上的密文**逐字节比对：相等 = 当前密文，不等 = 当前明文。

修复后（Release，9 条，同一判据）：

| 路径 | 组 0（条目 0-3） | 组 1（条目 4-8） |
|------|------------------|------------------|
| 自然路径 | **全程 C C C C**（0.001 s → 退出） | 窗口内 P，其余 C |
| `--wait-ms 6000` | **全程 C C C C**（0.001 s → 6.845 s 退出） | 6.017 s 起才见窗口 |

关键对照 —— **同一份源码、同一构建配置、同一条命令，改前 vs 改后**：

| 命令 | 改前组 0 | 改后组 0 |
|------|----------|----------|
| 自然路径 | 明文 `0.005s → 0.666s`（661 ms） | 全程密文 |
| `--wait-ms 6000` | 明文 `0.004s → 6.717s`（6713 ms） | 全程密文 |

即 **`--wait-ms 6000` 把组 0 的明文窗口从 6713 ms 压到 0**。改前那组数字是在
`git stash` 掉修法、用同一 `-Config Release` 重建后测的（9 条目标、同一探针），
不是引用旧构建，故可直接对比。

回归（全部在修复后的同一产物上）：

| 项 | 结果 |
|----|------|
| `tests/e2e.py` | `[e2e] 平台=win  总计 30: PASS 30 / FAIL 0 / SKIP 0 / NA 0` |
| T11 watchdog-stable | PASS `(exit=0 (14s residency))` |
| T29 meta-crc | PASS `(exit=2989 ... meta_n=9)` |
| T30 cipher-crc | PASS `(exit=2989 ... off=0x1b68 early=yes)` |
| `tools/window_check.py` | `作用域 24 文件 / 308 函数; 加密目标 9 个` + PASS |
| `tools/guard_selftest.py` | PASS（正向 hits=0 / 负向 hits=3） |
| `build/_hygiene.py` | 15 文件 0 异常 |
| 全门禁 | 34/35 通过；**唯一未过的是第 1 项 `git 工作区干净`**（本次改动尚未提交）。其余 34 项含 e2e / attacks / vm_unit / vmc / example / protchain / window_check / conformance / linux_compile / undef_check / android_compile 全绿。 |

T30 的 `early=yes` 是**必须保住**的一条：它证明密文篡改仍然在
`demo/main.c:525 prot_selfcrypt_init()` 就被抓住（拒止点没有因为回密而
后移）。若这条变成 `no`，说明校验被推迟了 —— 那是本修法**不允许**发生的。

### 2.35.5 我自己第一版探针的 confound（必须记下）

本轮最初的结论是**错的**，而且错得很有代表性，如实记录：

第一版探针用 `subprocess.Popen(argv, stdin=subprocess.PIPE)` 启动 `demo.exe`，
**但没有写入序列号**。`demo/main.c:764` 是
`fgets(mem.serial, sizeof(mem.serial), stdin)` —— 进程就**卡在那里**，
根本没走到 `:777` 的 `prot_vm_run` 调用点。于是探针观察到「组 0 从 init 到
退出一直是明文、`leave(VM)` 从未执行」，得出了「**D2b 对 VM 组失效**」的
错误结论。

修正方式是从 `demo/vm_build.json` 读出 `serial` 写进 stdin。喂入之后
`g_sc_state` 立刻显示 `leave(VM)` 确实把组 0 归 0（`:664 [0,0,0,0,0,0,0,0]`）。

**教训**：探针的「没观察到」必须先排除「**根本没跑到**」。这与 §2.25
（拿固定 `sleep` 赌宿主就绪）同型 —— 都是**观测装置本身**成了错误来源，
而不是被观测的机制。

第二次误读同样值得记，而且**方向相反**：改用 `g_sc_state[]` 后有一轮读到
「`init` 后全 1、到退出都不变」，我据此写下「修法没生效」。那一轮探针跑的是
**误用 `-Release` 的那份 Dev 产物**（`$isRelease = ($Config -eq 'Release')`
为假 ⇒ 该构建未定义 `PROT_SELFCRYPT_D2B` ⇒ `enter/leave` 是空操作 ⇒ 状态位
自然一直停在全 1）。换到真正的 Release 产物后，同一个探针读到的是
`0.009 [1,1,1,1,1,0,0,0,0]`（init 解密途中）→ `0.011 [0,0,0,0,1,1,1,1,1]`
（init 回密后只剩组 1 的扫描窗口）→ 此后组 0 恒 `[0,0,0,0]`。

**两次误读的共性**：我都拿「一个**间接**信号」当结论 —— 第一次是
「进程没输出期望的调用痕迹」，第二次是「一个自报的记账数组」。而
`g_sc_state` 的语义恰恰是「**本实现认为**谁是明文」，回密又是它和内存
在**同一个循环**里一起改的；只读它，等于让被检查者自己出证词。所以终版
判据必须落到**外部可验证的量**：进程内存字节 vs 磁盘密文（§2.35.4）。

### 2.35.6 诚实边界

- **无独立的新用例覆盖这条不变量。** 本轮是用 `build/_d2c_truth.py` 手工
  验的，该脚本在 `build/` 下（gitignored）。门禁里**没有**「非调用时刻内存
  必须是密文」的自动判据 ⇒ 这条不变量**回归了不会有测试变红**。与
  §2.32「陈旧复选框」、T11 的「P5 只判不得直接 E8 调用，不判调用点是否在
  窗口内」同型：**机制在、门禁不在**。
- **`examples/tool_demo` 是裸调用面。** `examples/tool_demo/main.c` 有 5 处
  未开窗调用（`:206` / `:260` / `:267` / `:278` / `:312`）。当前无害，仅因为
  `examples/tool_demo/build_example.ps1` 的构建链**从不接 selfcrypt**
  （全文搜 `selfcrypt_proto` 零命中 ⇒ `.protcry` 条目数 n=0 ⇒ init 早退）。
  一旦给它接上 selfcrypt，这 5 处会全部踩空；而
  `tools/window_check.py:86-87 SCOPE_DIRS = ('src', 'src/platform', 'demo',
  'prot_sdk/skeleton')` **不含 `examples/`** ⇒ 该风险**无静态门禁覆盖**。
- **D2a 下明文驻留是设计使然，不是缺陷。** 本修法只在 D2B 下回密；D2a
  构建（`-NoD2b` / Dev）行为一字未变。
- **窗口内仍是明文。** 回密把「非调用时刻」收窄到真正的窗口边界，但
  enter/leave 之间的那条缝隙依然存在（组 1 实测约 4.4% 采样落在窗口内）。
  这是 D2b 的固有代价，不是本修法能消除的。
- **真机 / 企业环境（杀软 EDR 对高频 SMC 的反应）仍未验证**，证据全部来自
  本机 Windows x64。与 §2.34.6 同。
- **密文态 CRC（`PROTCRYP`）仍未实现**：`tools/hashpatch.py:47 MAGICS` 只有
  4 个标记。这是 N1 的另一条独立缺口，与本轮无关。

### 2.35.7 提交后的全门禁与 CI 实测

修法提交 `c2666b9`（`fix(selfcrypt)!: D2c 收口`）后复跑：

- **全门禁 `tools/release_check.ps1`：35/35 PASS**（`[release_check] PASS: 35 项检查全通过`，
  日志 `build/logs/release_check_20261006_193841.log`）。
  提交前同一套门禁是 **34/35**，唯一未过的就是第 1 项 `git 工作区干净`
  （改动未提交）—— 提交后该项转绿，其余 34 项两次全绿。
  3 项按设计 SKIP（`-WithMutation` / `-WithSkeleton` / `-WithMigration`），
  门禁日志里显式写作「未验证 != 通过」。
- **`tools/doccheck.py`**：提交 `c2666b9` 时实测 `检查数字 707 处, 错误 0, 警告 0`，
  豁免 178 处 ⇒ PASS（改前 699 处）。
  写出本节后又跑一次：**715 处**（本节新增 8 处）⇒ 仍 0 错误、PASS。
  ⇒ 这类「检查器报的自己的计数」**每加一段文档就变**，写进正文必然立刻过期；
  此处两个数字都保留，用来说明该数字**不是**稳定判据。
- **`tools/docclaim_check.py`**：PASS（8/8）。
- **`build/_hygiene.py`**：15 文件 0 异常。
- **CI run `37459442189`（head `c2666b9`）`completed success`**，四个 job 全绿：
  `build-and-verify` 9m32s / `linux-portability` 12s / `reproducible` 49s /
  `sdk-package` 45s。

> **一个自找的回归**（值得记）：我一开始把头部「最后核实」行的提交字段写成
> `· 基线提交 6c52733`，想表达「这是本轮的基线，不是本次提交」。结果
> `tools/docclaim_check.py` 的 `RE_COMMIT = re.compile(r'·\s*提交\s*`([^`]+)`')`
> 要求 `·` 后**紧跟**「提交」，判为 `docs/HANDOVER.md(缺提交字段)` ⇒ 整项 FAIL
> （7/8）。改回「提交」后立刻 8/8。
> **教训**：受机器解析的字段里**不能夹带自己的语义修饰**。这条与 §2.31
> （硬编码判据常量）同型 —— 都是「表达欲」撞上「解析器」。

## 2.36 门禁第 39 项：selfcrypt 驻留期密文态 —— 把 §2.35.6 自己记名的空白补上（2026-10-06）

### 2.36.1 缘起：一条被我**写进诚实边界、却没去补**的缺口

§2.35.6 逐字写着：

> **无独立的新用例覆盖这条不变量。** 本轮是用 `build/_d2c_truth.py` 手工验的，
> 该脚本在 `build/` 下（gitignored）。门禁里**没有**「非调用时刻内存必须是密文」
> 的自动判据 ⇒ 这条不变量**回归了不会有测试变红**。

写下来是一回事，补上又是另一回事。这一节就是把那句话兑现：新增
`tools/selfcrypt_residency_check.py`，入库为**门禁第 39 项**。

它的**价值定位**和 §2.32「陈旧复选框」、T11 的「P5 只判不得直接 `E8` 调用」
是同一类：**机制在、门禁不在**。这类缺口的共同形态是「承诺写进了注释块与
文档，验证只发生在写它的那一轮」—— 下一轮谁把
`src/selfcrypt.c:348-354` 的回密循环挪走、或把 `#ifdef PROT_SELFCRYPT_D2B`
改坏，**没有任何测试会变红**，而 `docs/N1_PHASE2_PLAN.md` 与
`docs/ADVANCED2.md` 里「非调用时刻内存是密文」的承诺照样挂着。

### 2.36.2 判据：为什么是「内存 == 磁盘密文」而不是「解密一次看 CRC」

`src/selfcrypt.c:114-122 sc_xor_range` 是**对合**的：

```c
k = k * PROT_KS_MUL + PROT_KS_ADD;
dst[j] = (uint8_t)(dst[j] ^ (uint8_t)(k >> 56));
```

同一密钥流 XOR 两次回到原文 ⇒ **「内存字节 == 磁盘字节」本身就是
「当前处于密文态」的正当判据**，不需要解密、不需要知道密钥流对不对
（流错了反而两边一起错、恰好相等 —— 但那种情况在磁盘侧就不可能是
`tools/selfcrypt_proto.py` 写进去的那份密文，因为参考来自**产物文件本身**）。

判据四条：

1. **组 0 条目数 > 0** —— 否则判据空转，直接 FAIL；
2. **`g_sc_d2b_enabled == 1`** —— 回密循环在 `#ifdef PROT_SELFCRYPT_D2B` 内
   （`src/selfcrypt.c:348-354`）。单列这条是为了让**「没编译进来」**与
   **「回归了」**在报告里可区分，而不是笼统一句 FAIL；
3. **采样轮数足够** —— 「读不到」≠「不存在」：一条采样都没拿到、或读内存
   失败，必须 FAIL，不许被读成「没发现问题」；
4. **每一轮里组 0 每一条目的内存字节都逐字节等于磁盘密文** —— 任何一条
   不符即 FAIL，并报出**首个不符的轮次与字节位**（可定位「只回密了一部分」
   那种情形）。

判据是**失效安全**的：地址算错 / 节名解析错 / 读内存失败 / 读错区间，
结果一律是「内存 != 磁盘」⇒ **红**。**绿**只有一种达成方式 —— 地址对、
字节真的一致。**这一点是本项敢进默认门禁的前提**：一个可能因管道缺陷
而假绿的门禁项，比没有更危险（§2.30 的 `--quiet` 仍 rc=0 就是同一个坑）。

**组 1（EXT 扩展组）不在判据内**：看门狗每轮自己开/关一次 EXT 窗口
（`src/integrity.c:188` enter / `:256` leave），窗口内它**就该**是明文。
工具把「组 1 明文出现多少轮」打出来做**诊断** —— 这不是装饰：它是
「采样器确实能分辨明文/密文两态」的**活体对照**。实测 `--observe-s 12`：
组 1 明文出现 **6/120 轮**，同期组 0 **120/120 全密文**。

### 2.36.3 复用而非重写：三处既有解析入口

新工具刻意**不写第四份**同类实现：

- **meta 解析** → `tests/protchain_check.py:149 selfcrypt_meta(data, secs)`
  （唯一入口，`SC_ENTRY_SIZE`/`SC_ENTRY_GROUP_OFF` 常量在 `:70-71`；
  自己重写步长会漂移成魔数）。**分组按 meta 的 `group` 字段**，不依赖
  `build/selfcrypt_mask.txt` 的文件行序 —— 本次实测两者**恰好一致**
  （9 行 mask 的 `(rva,len)` 与 meta 逐条相同），但一致是**巧合而非契约**。
- **节表 / 磁盘偏移换算** → `tests/protchain_check.py:257 sections_of` +
  `:337` 的形式 `text['ptr_raw'] + (rva - text['virtual_addr'])`
  （**这正是 `p1_selfcrypt_ciphertext` 已在用的换算**）。
- **符号取址** → `tools/mapfile.py:107 parse()`（MSVC 第 2 列是节内偏移、
  第 4 列才是绝对 VA 的历史坑，已在 `tools/mapfile.py:126-143` 记档；
  `tools/guard_selftest.py:162 _sym_va` 是**第三份**自写正则，属既有债，
  本工具**不再制造第四份**）。
- **运行时基址** → `tools/guard_selftest.py:256 _module_base`（Toolhelp32）。
  ⚠️ 这一步踩到一个**真实的既有债**，见 §2.36.5。

另有一条纪律照抄 `tools/prot_dbg.py:601-604`：复用 `protchain_check` 前
必须把 `pc._CURRENT_EXE` 指向**本次被测产物**，否则 `load_section_names()`
会去解析**另一个平台**的 `prot_sections.json`，拿到静默错误的随机节名
⇒ `.protcry` 找不到 ⇒ 条目恒空 ⇒ 看起来像「这个构建没有加密目标」。

### 2.36.4 负向自检：判据是纯函数，所以变异可以只在内存里做

`judge(entries, samples, refs)` 是**纯函数**（只吃条目 / 采样 / 磁盘参考），
因此 4 条变异**不启进程、不写盘、不编译**：

| 变异 | 语义 | 实测 |
|---|---|---|
| M1 组 0 某条某一轮内存 != 磁盘 | **回密没生效的签名** | 被抓 |
| M2 采样列表清空 | 无证据不得通过 | 被抓 |
| M3 组 0 某条某一轮取不到 | 只等到一部分 | 被抓 |
| M4 磁盘参考改 1 个字节 | 证明是**逐字节**比较 | 被抓 |

基线（真实形态的合成数据）**必须全绿** —— 只红不绿的判据同样是坏的。
实测 `[selfcrypt-residency-selftest] 4/4 变异被抓`。

**诚实边界**：负向自检证明的是**比较器与判据**有判别力（纯数据变异），
**不是**端到端地另编一个「无 D2c」的产物来证明「回归必然变红」。那需要
第二次构建，与本项目「门禁只读、不编译」的纪律冲突。端到端那一半由本项的
**正向运行**背书：它真的起进程、真的读内存、真的与磁盘逐字节比。

### 2.36.5 途中踩到的既有债：`_module_base` 的 ctypes 原型不完整

复用 `tools/guard_selftest.py:256 _module_base` 时，第一版直接崩在
`ctypes.ArgumentError`：

```
File "tools\selfcrypt_residency_check.py", line 402, in run
    base = guard_selftest._module_base(k32, p.pid, os.path.basename(exe))
File "tools\guard_selftest.py", line 268, in _module_base
    if not k32.Module32First(snap, ctypes.byref(me)):
ctypes.ArgumentError: argument 1: OverflowError: int too long to convert
```

**根因**：`_module_base` 自己**从不设置** `CreateToolhelp32Snapshot` /
`Module32First` / `Module32Next` 的 `argtypes`/`restype`，它的调用点
（`tools/guard_selftest.py:290-310 run_by_hits`）也没设。默认 `restype`
是 32 位 `c_int`，**本机快照句柄恰好小**，所以侥幸没出事。
我在新工具里把 `CreateToolhelp32Snapshot.restype` 正成 `wt.HANDLE` 之后，
同一个函数立刻炸 —— 因为句柄现在是个真 64 位值了。

**教训（与 §2.32「测量类错误」同族）**：这不是「`_module_base` 有 bug」，
是「**一个靠默认 32 位返回值的巧合在跑的实现**」。修法是在新工具里把三个
原型**成对**补齐（只补一个反而把它从「侥幸能跑」变成「必然崩」），并在
代码里留逐字记录。`tools/prot_dbg.py:283-285` 是**第三份** Toolhelp32 实现
且它**设了** argtypes —— 三份实现、两种原型纪律，这就是本项目一贯记名的
「同一件事的多份实现会各自漂移」。本工具**没有**去改 `guard_selftest.py`
（那会动到已入库门禁第 31 项的行为），只是把债务记在明处。

### 2.36.6 门禁项数口径同步（38/35 → **39/36**）

按仓库约定**追加到末位**（唯一一次中插是 `window_check` 第 11 项，见
`docs/HANDOVER.md:1579-1582` 的「序号更正」记录）。同步的面：

- `tools/doccheck.py:166-168`：`GATE_TOTAL 38 -> 39` / `GATE_DEFAULT 35 -> 36`，
  并在 `:149-165` 的沿革块按同格式续写一行；
- 「现时值口径」13 个文件共 20 处（`CONTRIBUTING.md` / `README.md` /
  `ShardVase-展示文档.md` / `.github/PULL_REQUEST_TEMPLATE.md` /
  `.github/workflows/ci.yml` / `docs/BLUEPRINT.md` / `docs/CONTINUATION_PLAN.md` /
  `docs/DEBUG_CONSOLE_PLAN.md` / `docs/DECISION_REDUNDANCY_PLAN.md` /
  `docs/HANDOVER.md` / `publish/01-关于ShardVase.md` / `publish/02-项目档案.md`）；
- `tools/ci_sim.ps1:119` 的 `py_compile all` 清单加入新工具；
- **历史记录一律不动**（`docs/HANDOVER.md` 的 §2.x 逐轮记录、
  `docs/阶段总结-2026-*.md`、`docs/PLATFORM_ISOLATION_PLAN.md` 的
  `38/38`（那是**当时备份文件数**，同形异义）等）。

同步方式不是手改：写了 `build/_sync39.py`，每处都**断言旧串恰好出现一次**，
找不到即报错退出，不做静默跳过。

> **本轮自找的回归（值得记）**：该脚本图省事，把写回的每个文件都统一成了
> **CRLF**。而本项目的卫生纪律（`build/_hygiene.py`）是
> **`.ps1` ⇒ BOM=True + CRLF only；其余一律 BOM=False + LF only**
> ⇒ 12 个 `.md`/`.yml` 立刻变成「BOM=False crlf=N bareLF=0」的异常项，
> 门禁第 20 项 `mojibake 全库回归` 之外的 `build/_hygiene.py` 报 12 处。
> 修法：`build/_fixeol.py` **按 `git show HEAD:<file>` 里的原风格**逐个还原
> （而不是假设「非 .ps1 就是 LF」—— 假设本身就是本轮出错的原因）。
> 这类「同步脚本顺手改了不该改的东西」与 §2.33.4 的
> 「**批量写入必须断言，不能假设**」同型。

### 2.36.7 实测

`tools/selfcrypt_residency_check.py` 本体（`build/demo.exe`，9 条条目 =
组 0 四条 + 组 1 五条）：

```
=== selfcrypt_residency_check（D2c 驻留期密文态）===
  exe=demo.exe  条目 9 条（组 0: 4 条）  采样 120 轮 × 100 ms（窗口 12.0s）
  就绪: g_wd_interval=[0, 5000]（等了 0.76s）基址=0x7ff688e60000  g_sc_d2b_enabled=1
  [组 1 诊断] 明文出现 6/120 轮（组 1 不在判据内）
  [ok] 组 0 条目数 > 0  (组 0 4 条 / 组 1 5 条)
  [ok] 采样轮数 >= 10  (120 轮)
  [ok] 组 0 每条目都有磁盘参考  (ok)
  [ok] 组 0 在全部采样轮次均为磁盘密文  (全部 120 轮逐字节一致)
[selfcrypt-residency] PASS: 组 0 4 条 × 120 轮 全部逐字节等于磁盘密文
```

就绪哨兵取 `g_wd_interval != 0`（`src/integrity.c:828`），**不是**
`g_wd_policy` —— 后者 `guard_selftest` 自己要写（CONTINUE=0），拿它当信号
会**自毁证据**（`tools/guard_selftest.py:129-132` 记着这次教训）。
哨兵非 0 证明「init + blob 装载 + `start_watchdog` 都已走完」，采样因此落在
`--wait-after` 驻留窗口内，而**不是** init 内部那段「解密以校验」的瞬时明文
（那段是 D2c 设计固有的，不该被判据抓）。

### 2.36.8 提交与 CI 实测

- 主提交 `7062039`（`feat(gate)!: 门禁第 39 项`）：16 文件 / +821 −31；
- 补提交 `458c3f5`（`docs: 门禁清单补上第 39 项 + CI py_compile 同步新工具`）。

**本地全门禁**：`tools/release_check.ps1 -SkipDirtyCheck` ⇒
`[release_check] PASS: 36 项检查全通过`（`[ok]` 36 / `[X]` 0 / `[skip]` 0），
含 `[ok]  selfcrypt 驻留期密文态 (selfcrypt_residency)`；
日志 `build/logs/release_check_20261007_201141.log`。
`tools/doccheck.py` PASS（734 处 0 错误）· `tools/docclaim_check.py` PASS 8/8
（`gate-count` = **39 项**）· `build/_hygiene.py` 15 文件 0 异常。

**CI run `37631637848`（head `7062039`）`completed success`**，四个 job 全绿：
`build-and-verify` 10m20s / `linux-portability` 17s / `reproducible` 59s /
`sdk-package` 1m6s。**runner 上实测出现**
`[ok]  selfcrypt 驻留期密文态 (selfcrypt_residency)` ——
即新项在 CI 的 MSVC 14.51 / Python 3.12 环境下**同样工作**，不只是本机
（本机是 MSVC 14.44 / Python 3.13.13）。

> **一处清单类漏项（值得记）**：第 39 项入库时，「数字断言」全部同步了，
> 但两处**枚举式清单**漏了：
> 1. `README.md:135-154` 的「默认跑的全部 N 项」ASCII 清单 ——
>    这是门禁项清单的**权威展示面**；
> 2. `.github/workflows/ci.yml:131` 的 `Python syntax check (all tools)` ——
>    该列表是**逐字枚举**、不是 glob ⇒ 新工具不进这张表，CI 就**从不检查
>    它的语法**。`tools/ci_sim.ps1:113-122` 的本地镜像已经同步，CI 侧却漏了，
>    而 `ci_sim.ps1` 存在的理由本身就是「CI 的本地镜像」。
>
> 根因是同一个：**能被机器校验的东西（数字）改了，靠人眼维护的枚举漏了**。
> `tools/doccheck.py` 只判计数、不判这两张清单的成员 ⇒ 两处都不红。
> 与 §2.32「陈旧复选框」同型 —— **数字对了不等于清单对了**；
> 修法是补提交 `458c3f5`。

## 2.37 `PROTCRYP` 缺口定性：**已记名**的可利用面，首次端到端实证（2026-10-06）

### 2.37.1 缘起：一条被记名至少三处、却从未被端到端利用的缺口

`docs/N1_PLAN.md:263-268` 自己挂着一个未勾项：

> - [ ] **仍缺的是密文态 CRC（`PROTCRYP` 第 4 标记）**：`T30` 验的是"密文被
>   解密后按 meta 明文 CRC 重算"，**不是**"密文形态本身有独立 CRC"。
>   后者从未实现 …… ⇒ 如实保留未勾，**不把"机制在"读成"验收过"**。

同一件事在 `docs/OPEN_SOURCE_COMPENSATION.md:87-96` 里被写得更重：

> - 覆盖：**`.text` / `.rdata` / `.pdata` / `.protxec`** 共 4 段
> - **未覆盖**：`.data` `.protcrc` `.protcry` `.protpad` `.fptable` `.rsrc` `.reloc`
>
> **完全开源后**，攻击者读源码即知"改哪个区域不会被校验发现"。
> 尤其 `.data` 与 `.protcry`（可写区）**未被覆盖** —— 这是可利用面。

`docs/PILLAR2_OBSERVABILITY_PLAN.md:251` 也记了同一条，并给出**为什么没做**：
`覆盖 .protcry（selfcrypt 密文区）会导致自身改写触发误报 | 需排除"运行期必然变化
的区域"，或改为"校验后再解密"`。

**所以本轮的第一件事是自我纠正**：这不是"发现了一个没人注意的洞"。
**边界早就被记名了**（三处）。本轮的新增量**只有**一件事 ——
**第一次把它端到端利用到 `rc=0`**。DRILL9 验的是另一条路
（patch `.text` 段内容 + 重算段 CRC / patch 检查器），**没有**验"翻密文 +
同步改 meta"这一路（见 `docs/ATTACK_DRILL9.md:88-95` 的八用例表）。

### 2.37.2 判据与算式：为什么"翻密文 + 同步改 meta"是自洽的

`src/selfcrypt.c:114-122 sc_xor_range` 的密钥流是**逐字节递推**的：

```c
k = k * PROT_KS_MUL + PROT_KS_ADD;
dst[j] = (uint8_t)(dst[j] ^ (uint8_t)(k >> 56));
```

`key0` 是**进入循环前的种子**，故第 j 字节用的是第 j+1 次迭代的 `k`。
用 Python 复算（`MUL = 0x5851F42D4C957F2D`，`ADD = 0x14057B7EF767814F`；
⚠️ Python 十六进制字面量**不带 `u` 后缀**，写 `...F2Du` 会
`SyntaxError: invalid hexadecimal literal`）后，实测：

```
zlib.crc32(解密后明文) == meta 里存的 crc32   ->  True
```

⇒ **算式无歧义**，且 meta 的 `crc32` 字段就是**解密后明文**的 CRC32。
于是攻击者只需：① 翻 `.text` 里该函数密文的任意一字节；
② 把新明文重算 CRC32，写回 `.protcry` meta 该条的 `crc32` 字段
（节内偏移 `4 + index*24 + 16`）。两处都改完，`sc_do_range` 解密后
`got == crc`，`src/selfcrypt.c:240` 的 `PROT_ERR_INTEGRITY` 分支**不会触发**。

### 2.37.3 三对照实测（`build/_protcryp_final.py`，同一次运行）

```
entry[8] g1 len=154 off=0  (旧明文CRC=0xf3877c04 -> 新明文CRC=0xf8e05580)
  只翻密文, meta 不动 : rc=2989        MSG_TAMPER=True  protcrc未变=True  out=119B
  翻密文 + 同步 meta  : rc=3221225477  MSG_TAMPER=False protcrc未变=True  out=662B

entry[0] g0 len=125 off=122  (旧明文CRC=0x338b19f1 -> 新明文CRC=0x324973c6)
  只翻密文, meta 不动 : rc=2989        MSG_TAMPER=True  protcrc未变=True  out=119B
  翻密文 + 同步 meta  : rc=0           MSG_TAMPER=False protcrc未变=True  out=725B

entry[8] g1 len=154 off=151  (旧明文CRC=0xf3877c04 -> 新明文CRC=0xf2451633)
  只翻密文, meta 不动 : rc=2989        MSG_TAMPER=True  protcrc未变=True  out=119B
  翻密文 + 同步 meta  : rc=0           MSG_TAMPER=False protcrc未变=True  out=725B
```

读法：

* `MSG_TAMPER` = stdout 里有没有 `完整性校验失败`（`demo/main.c` 的
  `PROT_STR_MSG_TAMPER`）—— 它区分**"被完整性层拦下"**与**"走到别处才崩"**；
* `out=119B` + `rc=2989` = 控制组，被 `demo/main.c:526-530` 的
  `MSG_TAMPER; exit(PROT_EXIT_TAMPERED)` 拦下；
* `rc=0` + `MSG_TAMPER=False` + `out=725B` = **完整性层一个字都没报，
  且程序正常结束**（`rc=3221225477` 是 `0xC0000005`，改坏了函数序言）；
* ⭐ **`protcrc未变=True` 三行全部成立** —— 见下节。

### 2.37.4 ⭐ 决定性字段：绕过**不触碰信任锚**

前三轮的探针（`build/_protcrc_forge.py`）先回答了一个更基本的问题：
**`.protcrc`（烧录表）本身能不能被攻击者重算？**

可以。在 `.text` 翻**非掩码**字节，用 `tools/hashpatch.py` **自己的**
`compute_section_crc()` 重算，写回 `.protcrc` 第 0 项，**5/5 未被 integrity 拦**：

```
rel=0x200   in-mask=False rc=3221225477  MSG_TAMPER=False
rel=0x1000  in-mask=False rc=3221225477  MSG_TAMPER=False
rel=0x8000  in-mask=False rc=0           MSG_TAMPER=False   <<< 完全通过且正常结束
rel=0x1f000 in-mask=False rc=0           MSG_TAMPER=False   <<< 完全通过且正常结束
rel=0x22000 in-mask=False rc=0           MSG_TAMPER=False   <<< 完全通过且正常结束
```

`tools/hashpatch.py:455-487` 的写回逻辑本身就说明了原因：`field_off = off + 8`，
`if current == 0:` 就 `struct.pack('<I', crc)` 写盘 ——
**明文 CRC32 字段，写入侧零密钥**。再加两条佐证：

* `(Get-AuthenticodeSignature build\demo.exe).Status == NotSigned`；
* `src/**/*.c` 与 `tools/*.py` 搜 `WinVerifyTrust|Authenticode|GetSignature`
  **零命中** ⇒ 运行期**不验自身签名**。签发材料 `build/keys/codesign.pfx`
  是**自签**的。

这与 `docs/THREATMODEL.md:107` 已记名的 L3 边界**同类**：
`verify_license.py 信任锚 = 使用的 DER 文件本身；攻击者换 der 自签`。

⇒ **本节的结论（也是"该不该做 `PROTCRYP`"的答案）**：
`.protcry` 那份 meta **与 `.protcrc` 同属"无密钥信任根"**。
补一个 `PROTCRYP`（无论落在 `.protcrc` 里、还是另立第 5 段）如果仍然
**没有带密钥的信任根**，攻击者同样重算即可 ⇒ **对磁盘改写者零收益**。
所以缺口是**设计后果**（无密钥信任根 + 密文/明文两态可互校），
**不是"忘了实现一个机制"**。要做就得引入密钥（HSM/签名/外部锚），
那是另一条路线，不是补一个 magic 常量。

反过来说，`protcrc未变=True` 这个字段把性质说清楚了：
**这一路的绕过比 DRILL9 更省事** —— DRILL9 至少要"重算段 CRC 再写回"，
而这里只需改 `.protcry` 里一个 4 字节字段，**段 CRC 那条路根本不经过**
（因为 9 个 selfcrypt 密文区间**全部已被 D1b 掩码剔除**，
`tools/hashpatch.py:383-387`；实测 9 条 `(rva,len)` 全部落在 `.text` 内）。

### 2.37.5 我自己的两处过度声称（更正，必须记）

落笔前我一度把本轮写成"文档自相矛盾"。逐条复核后**推翻了两条**：

1. `docs/DECISION_REDUNDANCY_PLAN.md:388` 逐字「故"重算 CRC"与"落在掩码区"
   **两种规避都无效**」—— **不是被证伪的断言**。它的主语是 **R3.2-b 的
   快照校验**（`它不依赖 CRC`），讲的是"重算 CRC 对**快照校验**无效"，
   **完全正确**，与 DRILL9 用例 C（重算后仍 `0xBAD`）一致。
   我把主语读成了"完整性校验"。**读错了主语**。
2. `docs/OPEN_SOURCE_COMPENSATION.md:154-157` 的「CRC 链式 | 段间 CRC 互相依赖」
   —— **不是现状断言**。该表的表头是 `| 手段 | 说明 |`，所在章
   `### 4.x` 的小节性质是「**修法**」（同章 `### 4.1` 的表头就是
   `| 特征 | 现状 | 修法 |`）⇒ 它在**提出要做什么**，不是**声称已做了什么**。
   我把表格性质读错了。（真实现状确实是 4 段**互相独立**、无链式，
   `src/integrity.c:485-524` 每节各自与 `read_baked_crc(j)` 比对 ——
   但"文档声称有链式"这件事不成立。）

**教训**：`docs/DECISION_REDUNDANCY_PLAN.md:394-397` 自己就写了更正纪律的范例
（`🚫 本节结论已被 §11 推翻 —— 见 §11.4 的逐条更正` + `保留原文的理由:
**"记录会过时"** 是本项目已记名 6 次的形态`）。**引用文档断言前必须读主语**
—— 尤其是"规避无效""必须重算"这类**评分/成本陈述**，它们和
"某处没被覆盖"这种**事实陈述**是两类东西。

### 2.37.6 探针自身的一处标注 bug（如实记）

第一版 `build/_protcryp_layer.py` 输出里有一行 `base`（基线），标着
`rc=2989 MSG_TAMPER=True`，与 `cipher` 行**完全相同**，看起来像"基线也被拦了"。
根因是探针的 `make()` **无论 `sync` 与否都翻了一个字节** ⇒
`base` 实际等价于 `cipher`。**这是标注 bug，不是结论 bug** ——
该次运行的**决定性证据是 `sync` 行**（`rc=3221225622` / `MSG_TAMPER=False` /
输出 662 字节，尾部含 `请输入序列号:` ⇒ 程序走完反调试与 VM 检测才崩）。
定论版 `build/_protcryp_final.py` 把三对照放进**同一次运行**并**去掉了
`base` 行**，才得到 §2.37.3 那张干净的表。

⇒ 与 §2.36.5（`_module_base` 的 ctypes 原型不完整）同型：
**探针自己也会说谎**，而且探针的错会**伪装成被测对象的性质**。

### 2.37.7 结论与边界

* **定性**：`PROTCRYP` 缺口 = **已记名的可利用面**（三处记名）+ 本轮**首次
  端到端实证**。不是新发现的洞，也不是文档自相矛盾。
* **不做的理由（有据）**：补 `PROTCRYP` 若仍无带密钥信任根 ⇒
  与 `.protcrc` 一样可重算 ⇒ **零收益**。真要做需要外部信任锚（另一条路线）。
* **什么时候会重新评估**：一旦引入带密钥的信任根（签名/HSM/外部锚），
  本条应重开 —— 那时"密文态 CRC"才**第一次**具备实际增量。
* **未验证**：本轮**未跑完整门禁**（改动面是文档，且门禁第 39 项已覆盖
  驻留期不变量）。`.protcry` 的**运行期**利用（不是磁盘改写）未测 ——
  它需要写进程内存，属另一类攻击面。
* **构建漂移**：本节引用的 rva/len 是**本次 `build/demo.exe`** 的实测值
  （`[0] 0x76e0/125` … `[8] 0x4f50/154`）。⚠️ 早前一轮记录的是
  `0x4e70/0x5610` 一组 ⇒ **产物在此期间被重建过**，引用数值必须注明构建。
### 2.37.8 还债：`tools/guard_selftest.py` 的 Toolhelp32 原型补齐（同日）

§2.36.5 记了这笔债却没还 —— 当时刻意**不动** `tools/guard_selftest.py`，
理由是"会动到已入库门禁第 31 项的行为"。本轮把它还掉，并实测**门禁第 31 项
行为未变**。

改法是**三个原型一起补**（`tools/guard_selftest.py:311-326`）：

```python
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Module32First.restype = wt.BOOL
k32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
k32.Module32Next.restype = wt.BOOL
k32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
```

**为什么必须一起补**：只把 `restype` 正视成 `wt.HANDLE` 会让 Python 把
64 位句柄按 `c_int` 传给 `Module32First` ⇒
`ctypes.ArgumentError: argument 1: OverflowError: int too long to convert`
（这正是 §2.36.5 里新门禁第一次跑本体撞到的形态）。
**只补一个，反而从"侥幸能跑"变成"必然崩"** —— 这个非线性是本节最值得记的点。

验证（实测）：

```
tools/guard_selftest.py --quiet
  ok   正向(不 patch -> hits 必须 = 0)         exit=None   hits=0
  ok   负向(patch -> hits 必须 > 0)           exit=None   hits=3
  [guard_selftest] PASS（守卫命中计数可自证: 正向 0 / 负向 > 0）   rc=0
```

⇒ **判据数值与改前一致**（正向 0 / 负向 3），即补齐原型**没有**改变被测行为，
只是把一个依赖"句柄值恰好小"的巧合换成确定的原型。

同时 `tools/prot_dbg.py:283-285` 那份实现**本来就设了**原型 ⇒
至此三份 Toolhelp32 实现（`guard_selftest` / `prot_dbg` /
`selfcrypt_residency_check`）**原型纪律统一**。
`build/_hygiene.py` 15 文件 0 异常。
### 2.37.9 提交与 CI 实测

本轮两个提交：

| 提交 | 内容 | 改动面 |
|------|------|--------|
| `bdd42cb` | `docs: §2.37 —— PROTCRYP 缺口定性` | `docs/HANDOVER.md` / `docs/N1_PLAN.md`（+200 −2） |
| `51a49c9` | `fix(guard_selftest): 补齐 Toolhelp32 三件套 ctypes 原型` | `docs/HANDOVER.md` / `tools/guard_selftest.py`（+57） |

**本地全门禁**（`-SkipDirtyCheck`）：

```
[release_check] PASS: 36 项检查全通过        ([ok] 36 / [X] 0 / [skip] 0)
```

日志 `build/logs/release_check_20261008_022734.log`。含
`[ok]  selfcrypt 驻留期密文态 (selfcrypt_residency)`。

**CI**：

| run | head | 结果 |
|-----|------|------|
| `37664133662` | `bdd42cb` | `completed success`，四 job 全绿 |
| `37666667742` | `51a49c9` | `completed success`，四 job 全绿 |

⇒ §2.37.8 的原型补齐在 **CI 的 MSVC 14.51 / Python 3.12** 环境下同样通过
（本机是 MSVC 14.44 / Python 3.13.13）—— 这一条对本节尤其重要：
**"本机句柄值恰好小所以侥幸能跑"这类巧合，正是跨环境才会暴露的**。

### 2.37.10 本轮留下的两条一般性教训

1. **引用文档断言前必须读主语。** §2.37.5 那两条过度声称都源于此：
   `docs/DECISION_REDUNDANCY_PLAN.md:388` 的「两种规避都无效」主语是
   **R3.2-b 快照校验**（不依赖 CRC，说法正确）；
   `docs/OPEN_SOURCE_COMPENSATION.md:154-157` 是**修法建议表**、
   非现状断言。**"评分/成本陈述"与"事实陈述"是两类东西**，
   前者可以讨论、后者才能被证伪。
2. **探针的错会伪装成被测对象的性质。** §2.37.6 的 `base` 行标注 bug
   让"基线"看起来也被拦；§2.36.5 的 ctypes 原型缺失让"读不到变量"
   看起来像"变量不存在"。**两次都是工具说谎，而不是被测对象。**

> 这两条与 §2.32「陈旧复选框」、§2.36.8「清单类漏项」同属一个族：
> **验证的失败模式，比被验证的对象更容易骗人。**
## 2.38 「Python syntax check (all tools)」只检查了 23/95 个文件 —— §2.36.8 记的枚举漏项，机器可查的部分收口（2026-10-06）

### 2.38.1 缘起：§2.36.8 记了名，但只补了那一处

§2.36.8 记的形态是：

> 根因是同一个：**能被机器校验的东西（数字）改了，靠人眼维护的枚举漏了**。
> `tools/doccheck.py` 只判计数、不判这两张清单的成员 ⇒ 两处都不红。

当时补的是**那两处**（`README.md` 的 ASCII 清单、`ci.yml` 的
`py_compile` 枚举）。§2.36.8 自己没说的是：**这类漏项是机制性的，
补一次只解决一次**。本节把它收口 —— 不是再补一遍清单，而是**换掉机制**。

### 2.38.2 实测：那一步名不副实

`.github/workflows/ci.yml:130` 这步的名字一直是
`Python syntax check (**all tools**)`，实现是一条**逐字枚举**：

```
run: powershell -Command "python -m py_compile tools\vmenc.py tools\strgen.py ...
     tools\selfcrypt_residency_check.py tests\e2e.py tests\attacks.py
     tests\vmc_tests.py tests\protchain_check.py examples\tool_demo\test_example.py"
```

实测（`build/_enum3.py` / `build/_enum4.py` / `build/_enum5.py`）：仓库**活体**
源码共 **95 个 `.py`** —— `tools/` 73 + `tests/` 15 + `examples/` 1 +
`sdk_service/` 5 + `prot_sdk/` 1；该枚举只列了 **23 个**（全部确实落在活体集内，
无幻影条目）⇒ **72 个从未被语法检查过**。漏掉的里面包括：

* **`tools/window_check.py`** —— 门禁**第 11 项**；
* **`tools/guard_selftest.py`** —— 门禁**第 31 项**；
* **`tools/mutate_check.py`（第 16 项）与 `tools/migration_gate.py`（第 24 项）**
  —— 这两项是 `-With*` 开关下的**受控门禁**，其语法错在 CI 上同样不可见；
* 其余**被 `Check` 体直接调用**的门禁工具（清单由 `build/_gatewho.py` 从
  `tools/release_check.ps1` 的 39 个 `Check` 体里反向抽出，非凭记忆）：
  `tools/check_state_platform.py`（第 25 项）/ `tools/comment_lint.py`（第 19 项）/
  `tools/mojibake_check.py`（第 20 项）/ `tools/skeleton_check.py`（第 23 项）/
  `tools/prot_dbg.py`（第 32/34 项）/ `tools/attackcheck.py`（第 22 项）/
  `tools/docclaim_check.py`（第 28 项）/ `tools/perf_baseline.py`（第 30 项）/
  `tools/check_crc_targets.py`（第 36 项）/ `tools/check_undef.py`（第 37 项）/
  `tools/conformance.py`（第 17 项）/ `tools/replica_check.py`（第 35 项）等；
* **全部 5 个 `tests/attack_drill*.py`** 与 `tests/_platform.py`、
  `tests/attack_sdk_matrix.py`、`tests/attacks_linux.py`、
  `tests/c2vasm_golden.py`、`tests/http_platform_test.py`、
  `tests/vmcalc_flow_test.py`；
* 整目录 `sdk_service/`（5 个）与 `prot_sdk/wizard/prot_wizard.py`。

后果正是这一步**上方 4 行**自己引用的 P3 教训
（`ci.yml:66-67`「阶段 1/3/5 新增的门禁项必须也在 CI 里跑 —— 否则等于
"本地才生效的门禁", 与 P3 教训相悖 (可绕过的门禁会掩盖缺陷)」）：
**一个门禁工具自己有语法错，CI 全绿，只在本地炸。**

### 2.38.3 修法：从"维护清单"换成"遍历目录"

不是把人眼清单补全 —— 那下一次新增还会漏（`458c3f5` 刚补过
`selfcrypt_residency_check.py`，历史里同类补丁已发生多次）。
改成按**目录**遍历，新增文件自动纳入：

```yaml
- name: Python syntax check (all live sources)
  run: powershell -Command "python -m compileall -q tools tests examples sdk_service prot_sdk"
```

`tools/ci_sim.ps1:113-123` 的本地镜像**同步**换成同一条
（它存在的理由就是"CI 的本地镜像"，两侧不一致等于镜像失效）：

```powershell
Step 'py_compile all' {
    & $py -X utf8 -m compileall -q tools tests examples sdk_service prot_sdk
    if ($LASTEXITCODE -ne 0) { throw 'py_compile all failed' }
}
```

**为什么 `compileall` 而不是 `py_compile` 加 glob**：`py_compile` 只接受
文件列表，要用它就必须继续枚举；`compileall` 接受**目录**并递归。
实测 5 个根耗时 **189 ms**（可忽略）。

**刻意排除 `archive/` 与 `dist/`**：前者是历史快照（5 个 `.py`），
后者是构建产物（23 个 `.py`）—— 都不是活体源码，
其语法错**不应**阻断 CI。

### 2.38.4 验证（含负向）

| 检查 | 结果 |
|------|------|
| 正向：`compileall -q tools tests examples sdk_service prot_sdk` | `rc=0`，189 ms |
| **负向：塞一个 `def f(:` 进 build 临时目录** | `rc=1` + `SyntaxError: invalid syntax` |
| **⭐ CI 原样形态：`powershell -NoProfile -Command "<python> -m compileall -q <坏目录>"`** | 外层 **`rc=1`**（证明失败能穿透 `powershell -Command` 到达 CI） |
| **⭐ 同一形态换好目录** | 外层 **`rc=0`** |
| `compileall` 对**不存在的目录** | 打印 `Can't list ...` 但 **`rc=0`** |
| YAML 解析（`yaml.safe_load`） | 步骤名/命令读取正确 |
| `tools/ci_sim.ps1` PowerShell 解析 | `parse errors: 0` |
| `build/_hygiene.py` | 15 文件 0 异常（`ci_sim.ps1` 补回 BOM=True + CRLF） |
| `tools/doccheck.py` | PASS（751 处 0 错误 / 豁免 196） |
| `tools/docclaim_check.py` | PASS (8/8) |

> 那一行"CI 原样形态"是本步**唯一值得单独测**的东西：一个只会在
> 本地红、在 CI 上恒绿的检查器，等于没有。实测 `powershell -Command`
> 确实把内层原生命令的非 0 退出码传播到外层 `$LASTEXITCODE`
> （另用 `powershell -Command "cmd /c exit 7"` 单独验过该机制本身）。
> ⚠️ 本机无法用 `powershell -Command "python ..."` 原样跑（本机 PATH
> 上的 `python` 是 WindowsApps 桩，会打成 `Python was not found...`），
> 故上表用绝对路径 `D:\environment\PYTHON\python.exe` 替代 `python`；
> CI runner 的 PATH 有真 python，命令原文形式即为可执行形式。

⚠️ **诚实边界（负向验证发现的一条）**：`compileall` 对**不存在的目录**
只打印 `Can't list 'X'` 而**返回 rc=0** —— 即"目录被删/改名"时本步会
**静默少覆盖**而不是变红。（负向只对"目录内存在语法错"变红。）
本轮 5 个根都是 git 跟踪目录，故当前不触发；但这是本步**已知的失效模式**，
如实记在此处，不假装它是全封闭的。

### 2.38.5 与 §2.36.8 的关系

| | §2.36.8 | §2.38（本节） |
|---|---|---|
| 发现 | 两处枚举清单漏了新工具 | 同一处机制漏了 **72 个文件** |
| 修法 | **补清单**（补那两处） | **换机制**（遍历目录，清单不再存在） |
| 残留风险 | 下次新增还会漏 | 只剩"目录不存在时静默少覆盖" |

> 一条可迁移的判据：**凡是"靠人维护的清单"，都要问一句
> 「能不能改成从事实推导」。** 能推导的（数字来自 `GATE_TOTAL`、
> 文件集来自目录遍历）就不该有清单；推导不出来的（README 里那份
> 带中文名与 `[ok]` 的**展示面**）才保留清单，并由
> `tools/doccheck.py` 的计数断言兜底。

### 2.38.6 改了机制之后：哪些文字要跟、哪些不能动

换机制会牵动一批**描述这步的文字**。实测清点如下（`build/` 只读探测）：

| 位置 | 原文 | 处置 |
|------|------|------|
| `.github/workflows/ci.yml:151` | 步骤名 `Python syntax check (all tools)` | **改**为 `(all live sources)`（原名已名不副实） |
| `tools/ci_sim.ps1:113-123` | `Step 'py_compile all'` 枚举体 | **改**为同一条 `compileall`（镜像必须一致） |
| `docs/CI_PLAN.md:19` / `:57` | `py_compile（5 个工具）` / `py_compile (扩展: + indirect.py + ...)` | **不动** —— `:19`/`:57` 属该计划**当时的步骤描述**，`:140`/`:150`/`:174` 是已勾的完成项记录 |
| `docs/OSS_TAIL_PLAN.md:265` | `C8 \| Python 文件语法自检（py_compile 全部） \| 38 个文件` | **不动** —— 已完成的步骤结果表，"38 个文件"是**当时**的实测数 |
| `docs/PORTABILITY_ASSESSMENT.md:1262` | `语法检查 \| 每个文件 py_compile 通过` | **不动** —— 属 §14.5 那批 23 文件替换的**回滚策略记录** |

判据与 §2.36.8 / §2.32 同一条：**"现时值口径"要同步，
"当时的记录"不能改**（改了就是篡改历史，且这类文件里的数字
本来就带日期语境）。本步真正要同步的只有**活体配置**两处
（`ci.yml` 与 `ci_sim.ps1`），文档侧零改动。
### 2.38.7 提交与 CI 实测（2026-10-06）

提交 **`c1b6703`** `ci(gate)!: 语法检查步从逐字枚举改为 compileall —— 原先只覆盖 23/95 个文件`
（3 files / +176 -12：`.github/workflows/ci.yml` + `tools/ci_sim.ps1` +
`docs/HANDOVER.md`）；`git push origin master` ⇒ `500f08b..c1b6703`。

**CI `37673432129`（head `c1b6703`）`completed success`，四 job 全绿**：

| job | 结果 |
|-----|------|
| `build-and-verify` | success（22 步全绿） |
| `linux-portability` | success |
| `reproducible` | success |
| `sdk-package` | success |

关键是新步骤本身在 CI 上是**真的跑了且真的过了**：
`build-and-verify` 的 step 列表里 `Python syntax check (all live sources)` = **success**。

⚠️ 这里有一条**只有 CI 才能给的证据**：本机跑 compileall 用的是
**Python 3.13.13**，而 CI runner 上是 **Python 3.12.10**（`linux-portability`
job 是 **3.12.3**，`python3 --version` 实测）。改之前那 72 个文件
**从未在 3.12 上编译过** —— 换句话说，本节之前的"本地全绿"里
有 72 个文件是**新纳入**的，它们跨 3.12/3.13 两个解释器都能编译，
这一条由本 CI run 背书（而不是由我的本机背书）。

> 这也是本节最值得记的一点：**换机制的收益不只是"以后不会再漏"，
> 还立刻兑现了一次 —— 72 个文件在 CI 上首次被编译，且通过。**
> 若其中有任何一个用了 3.13 才有的语法，本 CI run 就会红。

*2026-10-06 v10*
