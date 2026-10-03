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
> **最后核实**: 2026-10-03 · 方法: tools/docclaim_check.py（8/8 PASS）+ replica_check 四条判据（含 6 组单点变异 + 全打掉对照）+ 门禁 **35** 项（默认 32）· 提交 `d6f1f8d`（R3.2-c 判定多副本 + 非短路交叉聚合落地后更新）


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

`release_check` 全量实跑（现已可裸跑）／Android NDK 实编 + T1 攻防矩阵／
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
| 平台延申 | **Android 原生 SO（A）+ 跨平台许可服务化（C）—— 完备计划见 docs/EXTENSION_PLAN.md**（C1/**A1/A2/A3 已完成源码，NDK 实编待环境） | 源码就绪 |
| 基础设施完善 | **I1-I6 全部完成（2026-08-26）**：ci_sim 本地 CI 模拟 / repro_check 统一 / release_check gate / build.ps1 --help+校验 / clean_build / changelog —— 见 docs/INFRA_PLAN.md | 完成 |
| **剩余待办（迁移）** | ① release_check 全量实跑 **✅ 已完成（2026-10-02 复跑：默认 30 项全 PASS，含 `-With*` 共 33 项）** ② Android T1 攻防矩阵（需 NDK/真机）③ GitHub 真实 push 后 CI 实跑替换 ci_sim ④ EXTENSION A 的 NDK 实编 ⑤ Windows 侧 W2 长驻留实跑验证 + Release D2b 真机确认 | 见对应文档 |
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
      tools/gate_log.ps1（**门禁落日志**: start/-Stop/-Selftest；自检 5 项含 3 负向；
      检测到外层转录时自检自动换子进程）
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
（最后提交均 `c941c9c`、**无任何文件引用它们** ⇒ 博客发布稿存底, 非活文档）。
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
`DEFAULT_TARGETS`（组 0 = VM 4 个）/ `EXT_TARGETS`（组 1 = EXT 4 个），
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
- **「副本位置由构建期 seed 决定」未实现**：三个副本是源文件里固定位置的独立函数，
  地址**不随** `--shuffle-seed` 变化。原设计（`DECISION_REDUNDANCY_PLAN.md` §3 R3.2-c
  关键设计③）的这条留作后续。
- **等价性判据覆盖当前 12 个字段**（7 关键 + 5 咨询）；**未来新增字段不在覆盖内** ——
  已写入 `modules.json` 的 `known_limits`。
- **聚合下沉进 VM（`// @vmcalc`）未做**（原计划即标为「可选，先不做」）。
- §5 风险表预留的「只加函数**不重排**已有函数」**已遵守**：新代码全部追加在
  `src/antidebug.c` 文件尾，未移动任何既有函数。
