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
> **最后核实**: 2026-10-06 · 方法: tools/docclaim_check.py（8/8 PASS）+ tools/doccheck.py（0 错误；自计数随文档增长，见 §2.36.7；含门禁结构 + README 清单成员 + **阈值常量 vs 文档声明**对账（§2.45）+ **ci.yml 项数口径**对账（§2.46）+ **源码 file:line 引用**逐条出生对比（§2.47，14 处已修）+ `ci_sim` 工具集 vs `ci.yml`（§2.48，补 5 步 + 3 项明写豁免）+ `run_demo` 超时回收（§2.50，四处同型缺口已修））+ replica_check **五条判据**（含 6 组单点变异 + 全打掉对照 + 位置抖动）+ crc_targets **13 条判据**（含 8 负向变异）+ gate_log 自检 6 项（含 4 负向）+ e2e T1-T30 + android_compile_check T1-T13 + selfcrypt_residency_check **4 条判据**（含 4 负向变异）+ migration_cost **M3adv 7 条用例**（对抗口径诊断，见 2.44）+ 门禁 **41** 项（默认 38）· 提交 `6c52733`（阶段总结 28287ea + 陈旧复选框整理 9e013ff/ed398ac/ed669fe + e2e T29 补齐 80db8ba + e2e T30 补齐 efb81b7 + D2c 收口见 §2.35）


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
## 2.39 README 门禁清单的**成员集合**没有门禁在守 —— §2.38.5 那句"推导不出来"只说对了一半（2026-10-06）

### 2.39.1 缘起：我把自己的结论当假设去复查

§2.38.5 立了一条可迁移判据：

> 凡是靠人维护的清单，都要问能不能从事实推导。

同一节里我顺手把 `README.md` 那份门禁清单判为**推导不出来、只能人眼维护**。
本轮把这句话本身当成待验证假设去实测（`build/_readmelist.py`）——
**结论：它只说对了一半。**「成员集合」完全可推导，「展示排版」才不可推导。

这也与 §2.37.10 记的第一条教训同型：**结论会被下一次真实运行证伪，
而"顺手写下的判断"没人会再去算。**

### 2.39.2 实测：成员与事实**完全一致**，但这一致性无人守

`README.md:130-155` 的结构：

* `:132-133` —— 一句「`tools/release_check.ps1` 跑 **36 项**（默认；加
  `-WithSkeleton`/`-WithMutation`/`-WithMigration` 后共 **39 项**），
  全绿才算通过。默认跑的全部 36 项：」
* `:135-155` —— 围栏内 **两列 ASCII 清单**（`[ok] XXX` 形式，左列 18 行 + 右列 18 行）

把该清单块按 `[ok]` 切分与 `tools/release_check.ps1` 的
`^\s*Check\s+'([^']+)'` 实测名比对：

| 量 | 实测值 |
|---|---|
| `release_check` 实际 `Check` 数 | **39** |
| 受 `-With*` 控制的项数 | **3**（`mutate_check` / `skeleton_check` / `migration_gate`） |
| README 清单成员数 | **36** |
| 「README 有、实际无」（幽灵项） | **0** |
| 「默认跑、README 未列」（漏项） | **0** |

⇒ **36 = 39 − 3，双向零差**。唯一不是逐字相等的是两处**有意缩写**：

    manifest.json 版本非占位                 -> 版本非占位
    Release 构建 (build.ps1 -Config Release) -> Release 构建 (build.ps1)

**但这一致性没有任何门禁在守。** `tools/doccheck.py` 的数字漂移判据
（`RE_GATE_NN` / `RE_GATE_N`）**只比数字**：

    RE_GATE_NN  = (?:release_check|门禁)[^\n]{0,24}?(\d+)\s*/\s*(\d+)
    RE_GATE_N   = (?:release_check|门禁)[^\n]{0,24}?(\d+)(?:\*\*)?\s*项

两处都只看那个 `36`。于是 **README 清单漏列一项、而总数仍写 36，
`doccheck` 不会红。** 与 §2.36.8（枚举式清单漏项）、§2.32（陈旧复选框）
是同一族缺陷：**能被机器校验的东西改了，靠人眼维护的部分没改，而判据只看前者。**

### 2.39.3 判据：四条，全部由事实推导，无硬编码名单

新增 `check_readme_gate_list()`（`tools/doccheck.py`）：

1. 清单条数 == `Check` 总数 − gated 项数（**两边都是算出来的**）
2. 每个默认跑项在清单里**恰好**命中一条（0 条 = 漏项；>1 条 = 歧义）
3. 清单里每一条都**恰好**命中一个默认跑项（0 条 = 幽灵项 / 措辞漂移）
4. gated 项**不得**出现在「默认跑」清单里（它默认不跑，列进去就是错的）

②③ 各要求「恰好 1」，合起来即**双向唯一匹配** —— 比「存在某个匹配」强得多，
后者会被一个足够短的清单项蒙混过关。

**gated 集合由 PowerShell 结构推导，不硬编码那 3 个名字**
（`gated_check_names()`：取每个 `if ($With*)` body 内的 `Check` 名）。
理由与 `selftest()` 里漂移字面量由 `GATE_TOTAL` 推导同源（那里已实测失效 3 次）：

* 硬编码 {mutate_check, skeleton_check, migration_gate} 的写法，在**下一次
  新增可选门禁**时会把「正确的省略」误报成漏项；
* 若有人真把新项补进 README，硬编码集合反而**放行**。

**名单是会被漂移的东西，结构不是。** 且 `check_gate_structure()` 已断言
「每个 `if ($With*)` body 里最多一个 `Check`」，故取 body 内的名字是良定义的。

匹配用**基名连续子串**（`_gate_base()` 去掉尾部括注并压平空白）来容忍上表
那两处排版缩写。它**不是**模糊匹配；过短的基名会同时命中多项，
由 ②③ 的「>1 = 歧义」报出来，而不是静默放行。

### 2.39.4 负向自检：5 条新用例，且**一起打印一起计数**

负向用例（`selftest()`，基准 `Check` 名 / gated 集合 / README 原文**全部现读**）：

| 用例 | 期望 |
|---|---|
| 真实 README 清单 | 0 条（不报） |
| 漏列一项 | 2 条（计数 + 漏项） |
| 幽灵项 | 2 条（计数 + 幽灵） |
| gated 项混进默认清单 | 7 条 |
| 清单块结构被破坏（无围栏） | 1 条 |

> ⚠️ 这批用例走的是**另一个入口**（`check_readme_gate_list`），不能塞进
> `cases` —— 那批会经 `check_text` 跑**数字漂移**判据，语义不同。
> 但它们**必须一起打印、一起计数**：否则只是暗处运行、看起来不存在。
> 自检总数 21 → **26**（12 项负向注入 / 14 项合规豁免）。

### 2.39.5 端到端变异：证明新判据在生产路径上真的起作用

`--selftest` 验的是独立入口；主检里那次调用走的是另一条路。
故 `build/_readmemut.py` 做**真文件变异**：

    python tools/doccheck.py                       -> rc=0  PASS
    删掉 README 里 `[ok] mojibake 全库回归 (mojibake_check)`
      （同形替换成空格，**文件长度不变、任何数字都没动**）-> rc=1  FAIL
        [X] README.md 清单 35 条，但默认跑的门禁项有 36 项
            （39 个 Check − 3 个 -With* 控制项）—— 计数或成员已漂移
        [X] README.md 未列出默认跑的门禁项 `mojibake 全库回归 (mojibake_check)`（清单漏项）
    还原 -> rc=0，且**逐字节相同 = True**

**这正是"旧判据不红、新判据红"的分界**：数字一直是对的，红的只有成员。

### 2.39.6 ⚠️ 途中修掉一个我自己引入的潜在崩溃

0b 的 README 判据要用 `_n` / `_opt`（`Check` 数与 gated 数）。我最初把它俩
写在 `check_gate_structure()` 的 `else` 分支里 —— 于是**结构断言失败时**
（`else` 不执行）0b 会引用未绑定名抛 `NameError`，**把「结构错了」这条真错误
替换成一个崩溃**，而结构红的时候正是最需要看清 0b 结论的时候。

修法 = 把 `_n` / `_opt` 提到结构断言**之前**计算。
证据（`build/_dcstructneg.py`，monkeypatch `check_gate_structure` 返回一条假错误）：

    rc = 1
    结构错误被报出            = True
    0b 走到了(有 README 结论)  = True
    无 NameError 崩溃          = True
        [X] 人造结构事故: 第 N 项被嵌套进 if ($WithX)

**这条是"新代码在异常路径上的行为没人测就一定会崩"的又一例**
（前两例见 §2.36.5 的 ctypes 原型、§2.37.6 的探针标注 bug）。

### 2.39.7 顺带清掉一处注定过期的注释

`tools/release_check.ps1` 里 `对外材料 (doccheck)` 项上方写着
「逐条注入缺陷并要求报错(**8 项负向**), 且要求合规写法不被误报(**13 项**)」。
本轮自检 21 → 26 项后它立刻成了假陈述。

**处置 = 删掉数字，而不是改成新数字** —— 理由与 §2.36.7 同一条：
把可变数字写进**被它自身检查/随它变化**的文件，必然在下一次失效。
改为「逐条注入缺陷并要求报错(负向注入)…要数字就直接看 `--selftest` 的输出行」。

全库其余「21 项 / 8 项负向 / 13 项」命中**全部位于历史记录**
（`docs/HANDOVER.md:769`/`:771`/`:798`/`:2912`、`docs/CONTINUATION_PLAN.md:376-385`、
`docs/阶段总结-2026-10-06.md:75`/`:108`、`docs/BLUEPRINT.md:780`）——
记的是**当时**的自检规模，**一律不动**（判据同 §2.36.8 / §2.38.6）。

### 2.39.8 对 §2.38.5 那句的精确化

原话「README 那份清单**推导不出来**、只能人眼维护」应改为：

> **成员集合可推导（并可由机器断言），展示排版不可推导（人维护）。**

排版（两列对齐、`[ok]` 前缀、为对齐而做的缩写）确实只能靠人；
但「清单里该有哪 36 个名字」是一个**从 `release_check.ps1` 结构算出的事实**，
不该由人眼保证。现在它有了门禁。

### 2.39.9 验证

    tools/doccheck.py --selftest : PASS 26 项（12 项负向注入 / 14 项合规豁免）
    tools/doccheck.py            : PASS（错误 0, 警告 0；自计数随文档增长，
                                   写死会立刻过期，见 §2.36.7）
      [ok] README 门禁清单: 36 条成员与默认跑的 36 项双向唯一匹配
    py_compile tools/doccheck.py : rc=0
    build/_parsechk3.ps1         : tools/release_check.ps1 parse errors: 0 / tools/ci_sim.ps1 parse errors: 0
    build/_hygiene.py            : 15 个文件, 0 处异常
    build/_readmemut.py          : rc=0（删一项 -> 红 -> 还原逐字节相同）
    build/_dcstructneg.py        : rc=0（结构失败时不崩，0b 仍给结论）
    全门禁（-SkipDirtyCheck）     : PASS: 36 项检查全通过（[ok] 36 / [X] 0 / [skip] 0）
### 2.39.10 提交与 CI 实测

提交 `b0b601e`（3 files / +453 −13）：

| 文件 | 改动 |
|---|---|
| `tools/doccheck.py` | 新增 `gated_check_names()` / `parse_readme_gate_list()` / `_gate_base()` / `_gate_match()` / `check_readme_gate_list()`；主检加 0b 节；自检加 5 条用例并纳入打印与计数；修掉 `_n`/`_opt` 的作用域崩溃 |
| `tools/release_check.ps1` | doccheck 项上方注释删掉会过期的用例条数（同 §2.36.7 处置） |
| `docs/HANDOVER.md` | 本节 |

推送 `a73eeb7..b0b601e`；CI run **`37679557390`**（head `b0b601e`）**`completed success`**，
四 job 全绿（`build-and-verify` / `linux-portability` / `reproducible` / `sdk-package`）。

> ⭐ **关键证据**：`build-and-verify` 的 **`Public-material drift (doccheck)`**
> step = `success`。该步先跑 `doccheck.py --selftest`（把关 5 条新用例能否抓到注入）
> 再跑主检（把关 README 清单的 36 条成员）—— 两者在 CI 的 Python 3.12 上**都过**。
> 于是新判据不只是"本机能跑"，而是**跨环境成立**。

同一 run 里 `Python syntax check (all live sources)` 亦 `success`
（§2.38 换的机制），两个连续改动在同一 run 上共同验证。

## 2.40 doccheck 的扫描面是**自声明**的 —— 读者当下照着做、却不写那行元数据的文件，永久不被检查（2026-10-06）

### 2.40.1 缘起：把上一节的"未验证"当成假设

§2.39 收尾时留了一条未验证项：「未普查其它文档是否还有第二处『默认跑全清单』」。
本节先做那次普查，结果顺带暴露了一个**比清单漏项更靠底层**的问题：
`doccheck` 的扫描面本身是**自声明**的。

### 2.40.2 普查：真·清单块 10 处，只 1 处需要守

探针 `build/_gatelist_audit2.py`（判据 = 连续多行、每行含一个**不同**的门禁名核、
不同名数 ≥10；初版 `build/_gatelist_audit.py` 把散文提及也算清单，太松）命中 10 处：

| 位置 | 名数 | 判定 |
|---|---|---|
| `docs/阶段总结-2026-10-06.md:253-271` | 34 | 阶段快照，历史 |
| `README.md:136-154` | 31 | **现时应然，须守** |
| `docs/HANDOVER.md:1564-1575` | 29 | 沿革记录，历史 |
| `docs/阶段总结-2026-09-29.md:135-138` | 17 | 阶段快照，历史 |
| `docs/STAGE_AUDIT.md:32-36` | 15 | 审计快照，历史 |
| `docs/HANDOVER.md:4104-4112` | 14 | §2.38 注释块转述，历史 |
| `docs/阶段总结-2026-10-06.md:341-345` | 14 | 阶段快照，历史 |
| `docs/STAGE_AUDIT.md:39-44` | 11 | 审计快照，历史 |
| `docs/阶段总结-2026-09-29.md:141-145` | 11 | 阶段快照，历史 |
| `.github/workflows/ci.yml:132-140` | 10 | §2.38 刚写的注释块，历史 |

⇒ §2.39 的未验证项**可以关闭**：没有第二处需要守的"默认跑全清单"。

### 2.40.3 ⭐ 真正的问题：扫描面是 opt-in，而"现值口径"是应然

`tools/doccheck.py:77 build_targets()` 只收三个来源：`publish/*.md`、
`docs/marketing/*.md`，以及 `docs/**/*.md` 中头部**显式写 `> **最后核实**`** 者
（`header_declares_current()`，`:66-74` 限定首个二级标题之前）。
设计理由是承重的且**写得很清楚**（`:58-62`）：新文档默认不被检查，是有意为之 ——
想被检查就先声明；历史文档记的是当时的真实值，改成现值即篡改历史。
**这一段判据本身没有错。**

错的是它的**外延**：自声明是 opt-in，而"现值口径"是**应然**
（凡是声称现值的都该被守）。二者不匹配的后果是
——**一个读者当下照着做、却不写那行元数据的文件，永久不被检查**（它无须自称任何东西：不进面的唯一条件是"没写那行元数据"）。

实测（`build/_readmenum_mut.py` + `build/_readmenum2.py`）：

| 变异点 | 旧判据 |
|---|---|
| `README.md:133` `默认跑的全部 **36** 项：` → `37` | **rc=1**（§2.39 的新判据 ⑤ 抓到） |
| `README.md:132` `跑 **36 项**（默认` → `37` | **rc=0，零报错** ★ |

第二行是本节的关键证据：**同一个文件、同一句话里的另一个数字，没有任何人守。**
根因不是判据写错，而是 `README.md` **根本不在 `TARGETS` 里**
（实测 `os.path.join(REPO,'README.md') in TARGETS` = `False`）。

同类盲区实测（`build/_scanface_gap.py`）：**改面之前**面内 7 个文件含计数断言、
**面外 42 个**；**改面之后**复跑同一探针为 **面内 12 / 面外 37**
（并进 9 个文件里含断言的 5 个进了面内；两个数都实测，不取其一）。
原始面外名单里包括 `README.md`(3) / `CONTRIBUTING.md`(2) / `ShardVase-展示文档.md`(1) /
`docs/阶段总结-2026-10-06.md`(18) / `.github/PULL_REQUEST_TEMPLATE.md`(1) …
更刺眼的一例：`docs/阶段总结-2026-10-06.md:251` 逐字写
「**门禁 38 项全清单**（权威顺序载体 = `README.md` / `docs/HANDOVER.md` / `tools/release_check.ps1`）：」
—— 它**指名**三份文件为权威顺序载体，而其中**排第一的 `README.md` 当时不在扫描面内**。
即：一份历史快照知道该以谁为准，而被指为准则的那份文件却不受任何判据保护。

> 📌 更正（我上一稿的误读）：我最初把这一句读成"该文件自称权威"，
> 据此写下「自称权威的载体，自己不受任何判据保护」。**这是误读** ——
> 括号里的"权威顺序载体"是**宾语**（以那三处为准），不是主语；该文件并没有自称权威。
> 另外 38 项在它成文时是**正确值**（它记的是 28 → 38 的演进），属历史记录，
> 把它排除在扫描面之外**是对的**。上面的表述已按实测改写。

### 2.40.4 修法：把"恒为现时"的那一类从自声明换成**位置推导**

不选"再补几处自声明"——那仍是一次性的、靠人眼的纪律（同 §2.36.8 / §2.38 的教训）。
改的是**类的定义**：根目录 `*.md` 与 `.github/*.md` 与 `publish/` 同理 ——
它们是读者**当下照着做**的说明，**不是历史快照**：

```python
ts = sorted(glob.glob(os.path.join(REPO, '*.md')))
ts += sorted(glob.glob(os.path.join(REPO, '.github', '*.md')))
ts += sorted(glob.glob(os.path.join(REPO, 'publish', '*.md')))
ts += sorted(glob.glob(os.path.join(REPO, 'docs', 'marketing', '*.md')))
```

并入 9 个文件（8 个根目录 `.md` + `.github/PULL_REQUEST_TEMPLATE.md`）：
`TARGETS` **24 → 33**，豁免 **196 → 197**（日期语境 +1），检查数字从 795 起涨（本节写入前实测 853 处；写入后更高，理由见 §2.36.7 —— 自计数不能写死在被它数的文件里），
**0 新错误**。判据一条没改，只是把文件放进来看。

### 2.40.5 我此前记录的一处**错误判断**（如实更正）

在 `build/_readme_face_exp.py` 之前，我曾据一次内存实验记下结论：
「`RE_GATE_N` 只认 `GATE_TOTAL`=39，故把 `README.md` 纳入扫描面会**误报 2 处**
（`:132`/`:107` 的合法双数表述『36 项（默认…共 39 项）』），必须先改正则」。
**这个判断是错的。** 实测 `tools/doccheck.py:967` 逐字：

```python
claim = int(m.group(2))
if claim in GATE_OK:
    continue
```

`GATE_OK = (GATE_TOTAL, GATE_DEFAULT) = (39, 36)` —— **两个数都在容差内**，
`RE_GATE_NN` 同理（`:979`）。双数表述本就合法，`build/_readme_face_exp.py`
实跑（README 并入 TARGETS 后跑完整 `main()`）**基线与变异前均 `rc=0`、0 错误**，
直接推翻了我那条"必须先改正则"的前提。若照那条前提走，会去改一个**没坏的正则**，
并把真正的病根（README 不在面内）留着。

教训与 §2.37.10 两条是同一族：**结论会被下一次真跑证伪，而前提从来不重算。**
我在没有重跑的情况下，把"一个实验里的变异结果"读成了"基线的性质"。

### 2.40.6 扫描面自身的守卫：判据的判据

上面所有判据都建立在"该文件**在面内**"之上。若扫描面哪天被移出去，
判据会**全绿而失明** —— 正是本节实测到的历史状态（README 长期不在面内，而 doccheck 一直 PASS）。
故把"恒为现时的 front door 必须在面内"本身断言成自检用例：

```python
_must = ['README.md', 'CONTRIBUTING.md', '.github/PULL_REQUEST_TEMPLATE.md']
for _m in _must:
    if os.path.join(REPO, _m.replace('/', os.sep)) not in TARGETS:
        fails.append('扫描面守卫: `%s` 不在 TARGETS 内 —— '
                     '它是恒为现时的 front door, 移出即失明' % _m)
```

负向验证 `build/_faceguard_neg.py`：正常态 `selftest rc=0`；
内存里把 `README.md` 移出 `TARGETS` ⇒ **`selftest FAIL (1/27)`**、
报 `[X] 扫描面守卫: README.md 不在 TARGETS 内 —— 它是恒为现时的 front door, 移出即失明`。
**一个不会失败的守卫等于没有守卫**，故这条也做了注入。

### 2.40.7 未纳入的，以及为什么

`docs/阶段总结-*.md` / `docs/STAGE_AUDIT.md` / `docs/BLUEPRINT.md` /
`docs/WORKBENCH_ROADMAP.md` / `docs/OSS_TAIL_PLAN.md` / `docs/LINUX_PORT_PLAN.md`
**仍不纳入**。实测把它们并进来会报 14 条错，逐条看**全部是历史值**
（如 `docs/OSS_TAIL_PLAN.md:103` 的 `门禁 14/14`、`docs/WORKBENCH_ROADMAP.md:140` 的 `门禁项数声称 14`）
—— 它们记的是**当时的真实值**，纳入即**篡改历史**。
这正是 `build_targets()` 原注释 `:51-56` 已经写明的边界，那一段判据继续有效。

> ⚠️ 诚实边界：本节修的是「**恒为现时**的 front door 不在面内」，
> **不是**"扫描面覆盖了全库"。全库 141 个 Markdown 里 109 个在面外，
> 其中 **16 个含门禁计数断言**（面内是 8 个），阶段总结类占多数。
> 的现时值**仍然无人守** —— 它们的定性是"历史记录"。

#### 2.40.7.1 那"历史/现时"的定性，其实**可推导**（本节补做）

上面那句原稿写的是"这个定性本身靠人判断"。实测把它推翻了一半：
全库**文件名含日期**的 Markdown（`20\d\d[-_]?\d\d[-_]?\d\d`）共 **6 个**，

```
docs/迁移核验-2026-09-20.md          docs/阶段总结-2026-09-30.md
docs/阶段总结-2026-08-30.md          docs/阶段总结-2026-10-06.md
docs/阶段总结-2026-09-29.md          docs/项目文件分类-2026-08-30.md
```

**6 个全部不在扫描面内**（`cur=False` ×6），且**逐一核对全是历史快照**
（`迁移核验` / `阶段总结` / `项目文件分类`）。⇒ 判据「**文件名含日期 ⇒ 历史快照，不纳入**」
与现有事实 **6/6 一致**，是可推导的、不需要人逐个判断。

反过来也有对照：面内那 33 个文件**没有任何一个**文件名带日期。
⇒ **日期命名与"历史/现时"这个划分在同侧收敛**。这条判据**已写成断言**并入
`selftest()`（与上一条 front-door 守卫并排），带**负向验证**：

```python
_dated = re.compile(r'20\d\d[-_]?\d\d[-_]?\d\d')
for _p in TARGETS:
    if _dated.search(os.path.basename(_p)):
        fails.append('扫描面守卫: `%s` 文件名含日期, 却出现在 TARGETS 内 —— '
                     '它记的是当时的真实值, 放进面内会要求篡改历史文档'
                     % os.path.relpath(_p, REPO).replace(os.sep, '/'))
```

负向验证 `build/_datedguard_neg.py`（内存里把 `docs/阶段总结-2026-10-06.md`
塞进 `TARGETS`，不碰磁盘）：正常态 `selftest rc = 0`；注入后 **`rc = 1`**、
`FAIL (1/27)`，报 `[X] 扫描面守卫: docs/阶段总结-2026-10-06.md 文件名含日期,
却出现在 TARGETS 内 —— 它记的是当时的真实值, 放进面内会要求篡改历史文档`。

> 仍属人判断的残余：**不带日期**的历史性文档（若有）无法由此判据识别。
> 本节的证据只支持"含日期 ⇒ 历史"这**一个方向**，故只对这**一个方向**下断言。

### 2.40.8 验证

| 项 | 结果 |
|---|---|
| `tools/doccheck.py` 主检 | `错误 0, 警告 0` / 豁免 197 / `[doccheck] PASS`（自计数随文档增长，写死即立刻过期，见 §2.36.7） |
| `tools/doccheck.py --selftest` | `PASS: 27 项（13 项负向注入 / 14 项合规豁免）` |
| 端到端变异 `build/_readmemut2.py` | 基线 `rc=0`；`:132` `36→37`（同形、清单不动）⇒ **`rc=1`**，报 `[X] README.md:132 门禁项数声称 37 项, 实际 39`；还原后逐字节相同 = True、`rc=0` |
| 守卫负向 `build/_faceguard_neg.py` | 正常 `rc=0`；README 移出 TARGETS ⇒ `FAIL (1/27)` |
| 反向守卫负向 `build/_datedguard_neg.py` | 正常 `rc=0`；带日期的历史快照塞进 TARGETS ⇒ `rc=1`、`FAIL (1/27)` |
| 误读更正 `build/_fix240claim.py` | §2.40.3 那句「自称权威」已改成实测表述 + 📌 更正块 |
| `tools/docclaim_check.py` | `PASS (8/8)` |
| `build/_hygiene.py` | 15 个文件, 0 处异常 |
| 全门禁（`-SkipDirtyCheck`） | `PASS: 36 项检查全通过`（含 `[ok] 对外材料 (doccheck)`） |

### 2.40.9 提交与 CI 实测（2026-10-06）

本轮分两次提交，两次都推送并核验了 CI：

| 提交 | 内容 | 规模 |
|---|---|---|
| `db3f788` | `feat(doccheck)!: 扫描面从自声明改为位置推导` —— §2.40.1–§2.40.8 与 `build_targets()` 改造、front-door 正向守卫 | 2 files / +215 −11 |
| `bb3fc6a` | `feat(doccheck): 扫描面反向守卫` —— 按文件名推导的历史快照不得进入面内，外加本节记的三处自我更正 | 2 files / +73 −10 |

两次都是先本地跑完四道复核再提交，提交后立即 `git push origin master`
（`8a4fbc7..db3f788`、`db3f788..bb3fc6a`，两次 rc=0），再 `gh run watch '<id>' --exit-status` 等 CI。

| CI run | head | 结果 |
|---|---|---|
| `37688754737` | `db3f788` | `completed success`，四 job 全绿 |
| `37694044916` | `bb3fc6a` | `completed success`，四 job 全绿 |

两次的 `build-and-verify` 里都有两个 step 直接关涉本轮改动，且都是 **success**：

- ⭐ `Public-material drift (doccheck)` —— 先跑 `--selftest`（含正向守卫与反向守卫的
  27 项），再跑主检（33 个文件的计数断言）。**新判据在 CI 的 Python 3.12 上同样成立**，
  不只是本机（3.13.13）。
- `Python syntax check (all live sources)` —— §2.38 换掉的机制，本轮继续绿。

> 两次 CI 的四 job 分别是 `build-and-verify` / `linux-portability` / `reproducible` /
> `sdk-package`；`linux-portability` 跑在 `ubuntu-latest`，其余三个在 `windows-latest`。
> 输出里有 `ubuntu-latest` 标签迁移的 deprecation 提示，与本轮无关。


## 2.41 阶段总结 §8.1/§8.2 两条过程改进项的实测复核 —— 一条不可机械判定，一条候选面数错（2026-10-06）

### 2.41.1 缘起

`docs/阶段总结-2026-10-06.md` §8 留了**两条过程改进项**（写的时候是"建议"，没有实施）：

- **§8.1**：「集合外常量」还需要一次全库审计 —— 建议给每个带 `--selftest` 的检查器加一条
  通用判据：「把被判定的常量改到边界内，自检必须变红」。
- **§8.2**：陈旧复选框的同步机制 —— 建议 `docclaim_check` 增加一类断言：
  「若同一文档内出现 `✅ 已完成/已落地`，则同文档不应存在与之矛盾的 `- [ ]`」。

两条都写在**历史快照**里（该文件按 §2.40 的判据属"文件名含日期 => 历史"，**刻意不在
doccheck 扫描面内**），所以它们不会因为过时而变红。本节把它们当**待验证假设**实测。

### 2.41.2 §8.2 宽版：被数据直接反证

`build/_boxclaim.py` 全库扫「含 `- [ ]` 的 .md」并统计同文档是否也出现完成语
（`✅|已完成|已落地|已实现|已收口|全部完成`）：

| 文档 | 未勾框 | 完成语行 |
|---|---|---|
| `CONTRIBUTING.md` | 2 | 1 |
| `docs/DEFENSE_DEEPEN_PLAN.md` | 1 | 8 |
| `docs/MEMPATCH_PLAN.md` | 3 | 1 |
| `docs/N1_PLAN.md` | 1 | 12 |
| `docs/PLAN.md` | 1 | 12 |
| `sdk_service/SERVER_TODO.md` | 3 | 3 |

**6 个文档同时具备两者，且逐一读上下文全部合法**：

- `sdk_service/SERVER_TODO.md:50` 是 `- [x] ... 已落地（2026-08-28）`，
  `:51-53` 是**未来的运营动作**（每季度离线备份 / 正式客户端集成 / 时钟回拨在线锚点）。
- `docs/MEMPATCH_PLAN.md:105/107/108` 是 Android **真机未测**三条，而 `:104` 是
  `- [x] ELF 符号解析器定位 JNI 导出符号 —— 已达成`。两者说的是**不同的事**。
- `docs/PLAN.md:195` 是 P2 父项未勾，`:196-202` 是 7 个 ✅ 子项。

⇒ **「同文档有完成语」与「有未勾框」是正交的两件事**。按 §8.2 原样写断言，
上面 6 个文档会**全部误报**。宽版**不成立**。

### 2.41.3 §8.2 窄版：只命中 1 处，而那一处也是假阳性

宽版失败后试一个更窄的、看起来能推导的版本（`build/_boxparent2.py`）：

> 父项 `- [ ]`，其**严格更深缩进**的子项里完成标记（`[x]` 或 `✅`）> 0 且未勾框 == 0
> => 该父项是陈旧的未勾。

全库命中 **1 处**：`docs/PLAN.md:195`。读上下文：

```
195 - [ ] P2｜生产增强（演示可扩展方向，非契约内）：
196   - ✅ 离线段 RSA 签名 license（A1，2026-08-10 完成）
...
202   - ✅ VM 镜像外部装载 vm.blob（技术债 #3，2026-08-14 完成）
203   - 加壳/外部文件装载（blob 加密/签名绑定、网络下发，可选升级）
```

`:203` 那个**真正的剩余子项不是复选框**（是普通 bullet），所以父项的 `- [ ]`
**是正确的**。⇒ 窄版唯一的命中就是它的假阳性。**窄版也不成立。**

> ⚠️ 记录一处探针纠错：窄版 v1（`build/_boxparent.py`）的完成标记正则只认 `- [x]`，
> 而 `docs/PLAN.md:196-202` 是 `- ✅ ...`（无方框）⇒ v1 报 **0 命中**，
> 差一点让我得出"根本没有这种形态"的相反结论。**是探针的形态假设太窄。**

### 2.41.4 §8.2 的结论：这条建议应当**撤回为机制**，而不是实现为断言

两条表述都被反证，且失败原因不是措辞不够精细，而是**复选框状态本身是语义判断**：
"这项做完了没有"依赖子项的类型（复选框 / 普通 bullet）、该文档的记录风格、
以及"未勾"到底是"没做"还是"不需要做"。这三者都**不能从文档自身推导**。

这与本项目已有的判别力原则一致（`docs/阶段总结-2026-10-06.md` §3.8「一个只会通过的
检查器，比没有更危险」）：**一个会误报的检查器比没有更危险**——它会让作者去勾掉
本来正确的框，把记录改坏。

⇒ 处置：**不实现**。§8.2 的价值退回它原本的形态——**一条操作提示**
（"改完要顺手销账"），并如实记下"它不可机械判定"。按
`docs/阶段总结-2026-10-06.md` §7 的第 ⑦ 条元结论：「记成"操作提示"的教训会复发，
记成"机制"的不会」—— 这条**只能**是提示，因为机制在此不成立。

**可机械判定的部分（已有）**：计数漂移由 `doccheck`（判据 ⑤ 与门禁清单成员）
+ `docclaim_check` 守；本节只否定了"复选框语义"那部分。

### 2.41.5 §8.1 的候选面：实测数字与阶段总结的估计不符

§8.1 说候选面是"所有带 `--selftest` 的检查器"，列了 11 个名字。实测
（`build/_selfdetect3.py`，按**真实 argparse 注册**判定）：

| 口径 | 数量 |
|---|---|
| 源码里**真实注册** `add_argument('--selftest')` 的工具 | **26** |
| 有 `selftest*()` 函数但**未注册**参数（`compat` / `mapfile` / `mojibake` / `observability` / `vcvars` / `winproc`） | 6 |
| 仅**注释**里提到 `--selftest`（如 `mutate_check` / `skeleton_check` / `verify_linux` 写"见 `winproc.py` 的 `--selftest`"） | 不属于候选面 |

⇒ 候选面 = **26 个**（不是 11 个，也不是按文本搜索得到的 40 个）。
这条本身是**可机械判定**的，故它才是 §8.1 里真正能落实的部分。

### 2.41.6 顺带发现：阶段总结自己的债务表已过期一行

`docs/阶段总结-2026-10-06.md` §6 的"所有计划处置"表里有一行：

```
| docs/BLUEPRINT.md | 5 | §9 成功判据 —— §3.4.1 已实测 5/5 通过，§9 是陈旧的复选框残留（未同步）|
```

实测现值（`build/_boxaudit2.py`）：`docs/BLUEPRINT.md` **完全没有未勾框** ——
`:766-770` 五项全部是 `- [x]`（M1-M5 成功判据）。⇒ 那一行**已经过时**：
后来有人把 §9 的框勾上了，而债务表没跟着改。

这与 §2.32「陈旧复选框」、§2.36.8「枚举式清单」**同型**，且因为它在一个
**刻意排除在扫描面外**的历史快照里（`docs/阶段总结-2026-10-06.md`，文件名含日期），
**没有任何机制会发现它**。这属于 §2.40 已记名的边界：历史快照记的是当时真值，
**不应当**被要求同步 —— 故本节只把它**记名**，不改该文件。

### 2.41.7 本轮我自己的三次探针错误（同一类，第三次）

| # | 探针 | 错法 | 后果 |
|---|---|---|---|
| 1 | `build/_selfdetect.py` | 用**措辞**正则找"期望失败"用例 | 把 `attackcheck`（写着「负向测试: 每条规则必须能抓错」）、`check_crc_targets`（M1-M8 变异表）、`window_check`（「裸调用 -> 应被识别为未在窗口内」）全判成"无负向用例" |
| 2 | `build/_selfdetect2.py` | 检查 `'--selftest' in t`（**文本**包含） | 把只在注释里提到该参数的工具（`mutate_check`/`skeleton_check`/`verify_linux`）数进候选面 |
| 3 | `build/_boxparent.py` | 完成标记只认 `- [x]`，漏掉 `- ✅` | 窄版报 0 命中，与真值（1 处）相反 |

三次都是**同一类**：**探针的错伪装成被测对象的性质**（§2.36.5 的 ctypes 原型、
§2.37.6 的 `base` 标注 bug、§2.40 的 `SystemExit` 假报，这是第 4~6 次）。
可迁移判据：**探针给出"零"或"全"这类极端结果时，先怀疑探针的形态假设。**

### 2.41.8 验证

| 项 | 结果 |
|---|---|
| `tools/doccheck.py` | 错误 0, 警告 0 / PASS（自计数随文档增长，写死即立刻过期，见 §2.36.7）|
| `tools/doccheck.py --selftest` | `PASS: 27 项（13 项负向注入 / 14 项合规豁免）` |
| `tools/docclaim_check.py` | `PASS (8/8)` |
| `build/_hygiene.py` | 15 个文件, 0 处异常 |
| 全库未勾框现值 | 13 个 .md / 49 条（模板与动作项 19 / 其余 30）|
| 本轮机械改动 | **无**（§8.1/§8.2 均为记录与判定，不动产品代码）|

## 2.42 26 个注册 `--selftest` 的工具里，11 个的自检从未被任何自动化面跑过 —— §8.1 唯一真正能落实的那部分（2026-10-06）

### 2.42.1 缘起：把 §2.41.5 的数对了之后，下一个问题

§2.41.5 数清了「§8.1 候选面 = 26 个真实注册 `--selftest` 的工具」。但**注册了自检**和
**自检真的被跑过**是两件事。本节的问句是：**这 26 个的自检，有没有人跑？**

判据：逐字扫调用面（`.ps1` / `.sh` / `.yml`）里「**同一行**既有工具名又有 `--selftest`」，
且**跳过 `#` 注释行**（注释里的示例不算执行）。探针 `build/_allsel.py`。

### 2.42.2 实测：15 个被跑过，11 个从未被跑过

**自检被跑过（15 个）**：`android_compile_check` / `attackcheck` / `check_crc_targets` /
`check_state_platform` / `check_undef` / `comment_lint` / `conformance` / `doccheck` /
`linux_compile_check` / `mojibake_check` / `perf_baseline` / `prot_dbg` / `sdk_pack` /
`selfcrypt_residency_check` / `verify_linux_runtime`。

**自检从未被跑过（11 个）**：`docclaim_check` / `genpaths` / `hostgen` / `identity` /
`migration_cost` / `migration_gate` / `modcheck` / `replica_check` / `solve_profile` /
`vmc_linux` / `window_check`。

更宽口径（`build/_selstyles.py`，同时认 argparse 注册与 `'--selftest' in sys.argv` 两种风格）
⇒ 提供自检的文件 **28 个**，自检从未被跑 = **13 个**（上述 11 + `compat` + `mapfile`）。

### 2.42.3 这 11 个的自检**全都有判别力**（不是空壳）

逐个实跑（`build/_orphanrun.py` / `build/_orphanrun2.py`），全部 rc=0 且输出自证其能抓错：

| 工具 | 自检输出（末行） |
|---|---|
| `genpaths` | `PASS: 两平台/两布局/负向均可自证` |
| `identity` | `PASS: 派生确定且各层隔离`（含「雪崩: 32 字节中差异 >= 20」） |
| `migration_cost` | `PASS: 度量可自证能抓错`（「单字节不同 -> 相同字节数 8191」） |
| `migration_gate` | `PASS: 阈值判定可自证能抓错`（「空串不匹配 got=False want=False」） |
| `modcheck` | `PASS: 全部协议规则可自证能抓错`（R17 变异后警告=1 / 基线报错=0） |
| `replica_check` | `PASS: 提取/解析/聚合器形态/抗折叠/位置抖动判别均已自证` |
| `solve_profile` | `PASS: 求解器可自证能抓错`（「顺序无环 got=[] want=[]」） |
| `vmc_linux` | `PASS`（「T1 假断言用例被正确判为**不通过**（RESULT 0）」） |
| `window_check` | `PASS: 判据与解析均按预期`（「目标清单与 selfcrypt_proto 声明一致」） |
| `hostgen` | `PASS: 生成器可自证正确性`（`#ifdef/#endif` 配对） |
| `docclaim_check` | `PASS: 1 正向 + **5 负向** + T6 占位符判据 + T7 计数形态判据均可自证` |

⇒ **判别力的证明早就存在，只差一次调用。**

> ⚠️ 我自己的探针在这里错了一次：初版给全部 11 个都传了 `--quiet`，其中 **5 个不接受该
> 参数**（`genpaths` / `identity` / `migration_cost` / `replica_check` / `window_check`）
> ⇒ rc=2 + `unrecognized arguments: --quiet`，差点读成「这 5 个的自检本身是坏的」。
> 去掉 `--quiet` 后全部 rc=0。**又一次「探针的参数假设太宽，伪装成被测对象的失败」。**

### 2.42.4 耗时与副作用：接进门禁的代价近乎为零

`build/_orphantime.py`（基线 `git status` 为空）⇒ 11 个全部 rc=0、**全部不写脏工作区**：
`genpaths` 0.05s / `hostgen` 0.05s / `identity` 0.06s / `replica_check` 0.07s /
`solve_profile` 0.07s / `migration_cost` 0.09s / `docclaim_check` 0.10s /
`migration_gate` 0.11s / `modcheck` 0.11s / `window_check` 0.50s / **`vmc_linux` 7.22s**。
除 `vmc_linux` 外全在 0.6s 内。

### 2.42.5 分类：A 类「本体在门禁里跑、却从不带 `--selftest`」= 5 个

`build/_orphanclass.py`（只扫 `release_check.ps1` / `ci_sim.ps1` / `ci_linux.ps1` / `ci.yml`
的非注释行）：

- **A 类（5 个）**：`window_check`（门禁第 11 项）/ `modcheck`（第 12 项）/
  `migration_gate`（第 24 项，受 `-WithMigration`）/ `docclaim_check`（第 28 项）/
  `replica_check`（第 35 项）。**本体被门禁调用，但从没跑过自检。**
- **B 类（6 个）**：`genpaths` / `hostgen` / `identity` / `migration_cost` /
  `solve_profile` / `vmc_linux` —— 这四个调度面里看不到它们。
- **C 类（已带 `--selftest`）= 0 个。**

> ⚠️ **B 类的「零调用」是我的探针面太窄**（`build/_bclass_verify.py` 把面扩到 118 个
> 脚本/配置文件）⇒ 实测：`genpaths` **32 处引用**（`build.ps1:319`/`:329`、`build.sh:83`/`:89`，
> 被 `tests/e2e.py` / `tests/protchain_check.py` / `tools/prot_dbg.py` 等 import）、
> `identity` 6 处、`migration_cost` 7 处、`solve_profile` 14 处、`vmc_linux` 5 处。
> **它们不是孤儿，只是从不跑自检。** 唯一真孤儿是 `hostgen`：全库 462 个文件里只有
> 4 处**提及**、零执行，它是「缺口 #1 原型」（`tools/hostgen.py:3` 自述「只生成、不替换」）。

### 2.42.6 修法：只接 A 类那 5 个（**不改门禁项数**，只加深 body）

B 类里 `genpaths` / `identity` / `migration_cost` / `solve_profile` 在构建与模组求解的
关键路径上，但它们**没有对应的门禁项**，接进去就是新增门禁项（另一件事）。A 类的 5 个
已经有门禁项，缺的只是「证明自己有判别力」这一步 —— 与已入库的第 11 / 31 / 36 / 37 / 39 项
做法一致。故本轮只接 A 类。

`tools/release_check.ps1` 五处（第 11 / 12 / 24 / 28 / 35 项）与 `tools/ci_sim.ps1` 两处镜像
（`window_check` / `replica_check`）统一改成「先自检、再主体」：

```powershell
Check '加密封装窗口 (window_check)' {
    # 含负向自检: 先跑 --selftest 证明本判据有判别力(自检不通过即本项 FAIL), 再跑主判据。
    & $py tools\window_check.py --selftest | Out-Null
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py tools\window_check.py; $LASTEXITCODE -eq 0
}
```

**两个细节是实测逼出来的，不是选出来的**：

1. `window_check` 与 `replica_check` 的 argparse **不接受 `--quiet`** ⇒ 给它们传会 rc=2
   被当成 FAIL。故这一条用 `| Out-Null` 抑制输出，而**不加** `--quiet`。
2. `migration_gate` 上面紧邻的是 `if ($WithMigration) {`，**不是注释块** ⇒ 说明文字落在
   **body 内首行**。这不是权宜：`Check '文档断言一致性 (docclaim)' {` 的下一行（原 `:743`）
   本来就是注释 ⇒ 这已是本仓库既有的写法。

文件：`tools/release_check.ps1` 69811 → **70428 B**（crlf 1185 → **1190**，bareLF 0）；
`tools/ci_sim.ps1` 7888 B。`build/_chk39b.py` ⇒ **仍是 39 项**，序号与名称一个没变；
`--selftest` 出现次数 25 → **30**。

### 2.42.7 验证：怎么证明这 5 行接线是**承重的**，不是装饰

「加了一行 `--selftest`」本身很容易，难的是证明它**真的会拦下东西**。方法是差分：
造一个强制失败的 shim（`build/_shim/py.cmd`，凡是含 `--selftest` 的命令一律 `exit /b 3`），
把它分别喂给**接线前**（`git show HEAD:tools/release_check.ps1` 的副本）和**接线后**
（工作树）的**真实 Check body**，按 `Check()` 自身的语义取值（`$out[-1]`）：

| Check 项 | 接线前 + shim | 接线后 + shim | 正基线（真 python） |
|---|---|---|---|
| `window_check` | True | **False** | True |
| `modcheck` | True | **False** | True |
| `migration_gate` | False | False | False |
| `docclaim` | True | **False** | True |
| `replica_check` | True | **False** | True |

**4 项构成干净差分**（接线前 shim 抓不到、接线后被抓到）⇒ 这 4 行承重。

第 5 项 `migration_gate` 的布尔值**被一个既有失败污染**（真 python 下也是 False，见 §2.42.8），
故布尔值对它没有证明力。改用**计时**这个它自己伪造不了的信号：

```
HEAD (接线前) + shim      105.18s   verdict=False
worktree (接线后) + shim    0.41s   verdict=False
```

接线后 body 在 `--selftest` 行（rc=3）就短路了，**根本走不到**那 12 次构建的度量；
接线前必须把整轮度量跑完（~90-105s）。⇒ 该行同样承重。

> ⚠️ 这里我又踩了一次同一个坑：`build/_mgbody.ps1` **硬编码了真 python**，首次计时得
> `HEAD 93.64s / worktree 90.36s` 两个都慢、**看似无差分**；改成 `-Py` 参数把 shim 传进去
> 后差分立刻出现。**探针的参数没接上，再一次伪装成「被测对象没有差异」。**

### 2.42.8 顺带发现：`migration_gate` 在本机 FAIL、在 CI PASS（**我第一稿的定性是错的**）

验证第 5 项时撞见：

```
[migration_gate] FAIL: M3 15.6% > 12% 保护函数可被特征定位 -> 迁移成本低
```

- 代码事实：`tools/migration_gate.py:92-93` = `MAX_M3 = 12.0` / `MAX_M1 = 12.0`。
  `:81-93` 详注收紧理由：初版取 **25%** 时，**禁用 6/16 文件的部分移除**只让 M3 升到
  **20.6%** ⇒ 仍在阈值内 ⇒ **漏检**。实测已知点：全部注入 **5.9%** / 移除 6/16 **20.6%** /
  无注入 **55.9%** ⇒ 故收紧到 **12%**。
- ⚠️ **但两处记述还是旧的 25%**：`tools/migration_gate.py:19-25` 的 docstring 阈值表仍写
  `| **M3 保护函数命中** | 55.9% | **5.9%** | **<= 25%** |`；
  `tools/release_check.ps1` 该项注释块仍写「M3 <= 25%（当前 5.9%）」。
  > **已修**（同日，见 §2.43.2）：两处现均为 **12%**，并补记了本机/CI 的抖动原因。
  > 本节以下文字描述的是本节写作当时的状态。
#### ⚠️ 更正（我第一稿把这件事定性错了，两处都错）

第一稿写的是「**被 `-WithMigration` 门控遮住的既有回归**」。补测 CI 日志后发现：

1. **它没有被遮住**：`.github/workflows/ci.yml:103-105` 有**独立一步**
   `Migration cost gate` = `python tools\migration_gate.py --quiet` ——
   **不受 `-WithMigration` 门控，每次 CI 都跑**。（`release_check.ps1` 里那第 24 项
   另有一份同样的调用，受开关控制；这是**两条路径**，我只看到了一条。）
2. **CI 上它通过**：run `37697874609` 的该步输出
   `[migration_gate] PASS: M3=6.2% M1=5.8%（迁移成本可接受）`。

⇒ 所以这是**本机与 CI 的偏差**，不是仓库级回归。已知环境差异是
**本机 MSVC `14.44.35207`（`D:\environment\VS2022BuildTools`）vs CI `14.51.36231`**；
CI 与本地用的 `migration_gate.py` / `migration_cost.py` 是同一份代码。

本机 3 对实测：`15.6% / 12.5% / 15.6%`，中位数 **15.6%**（其中一对只高出阈值 0.5 个百分点）
⇒ 像是**小幅工具链漂移把中位数推过阈值**，而不是能力整体回退。

> 诚实边界：我**没有**查明 M3 从 5.9% 到 15.6% 的确切机理，也**没有**判定该改代码、
> 改阈值还是该改文档。**已确证的只有**：① 该步在 CI 上真跑且真过；② 本机真红；
> ③ 两处记述（`tools/migration_gate.py:19-25` docstring 表、`release_check.ps1`
> 该项注释块）仍写 **25% / 当前 5.9%**，与代码 `MAX_M3 = 12.0` 及实测值都不符。

### 2.42.9 与 §2.36.8 / §2.38 / §2.40 的关系

四节的形状同源：**判据存在 ≠ 判据被执行**。

| 节 | 判据在哪 | 为什么没生效 |
|---|---|---|
| §2.36.8 | `tools/ci_sim.ps1` 的枚举清单 | 清单是**逐字枚举**，新工具不进表就永远不被检查 |
| §2.38 | `ci.yml` 的语法检查步 | 同上，改成目录遍历才收口 |
| §2.40 | `doccheck` 的扫描面 | 扫描面是**自声明 opt-in**，不写元数据就永久不被扫 |
| **§2.42** | **各工具的 `--selftest`** | **自检写好了、有判别力，但从没被任何自动化面调用** |

可迁移判据（§2.38.5 那条的延伸）：**「能用」不等于「在用」** —— 凡是发现一个
「已经写好的能力」，都要问一句「谁在跑它」。

### 2.42.10 验证表

| 项 | 结果 |
|---|---|
| `build/_hygiene.py` | **15 个文件, 0 处异常**（`release_check.ps1` bom=True crlf=1190 bareLF=0） |
| PS 语法（`build/_parsechk3.ps1`） | `ci_sim.ps1: 0` / `release_check.ps1: 0` |
| 门禁项数（`build/_chk39b.py`） | **39 项**，序号与名称一个没变；`--selftest` 出现 **30** 次 |
| `tools/doccheck.py --selftest` | **27 项（13 项负向注入 / 14 项合规豁免）** 全通过 |
| `tools/doccheck.py` | `[ok] 门禁结构: 39 项均为顶层语句…默认调用跑 36 项` / `[ok] README 门禁清单: 36 条成员与默认跑的 36 项双向唯一匹配` |
| 全门禁 | **`[release_check] PASS: 36 项检查全通过`** |
| 接线承重性 | **5/5**（4 项布尔差分 + 1 项计时差分） |

| 本轮机械改动 | 值 |
|---|---|
| `tools/release_check.ps1` | 5 个 Check body 加深（+5 行注释 +10 行调用），**项数不变** |
| `tools/ci_sim.ps1` | 2 个 Step 镜像加深 |
| 新增门禁项 | **0**（判据本身没变，变的是"证明它有判别力"这一步被自动跑了） |

## 2.43 M3 = 15.6% 的机制查明：判据窗口只有 32 字节，而位置抖动落在第 33~47 字节（2026-10-06）

### 2.43.1 缘起：§2.42.8 留下的三件事

§2.42.8 记下「`migration_gate` 在本机 FAIL（M3 = 15.6%）、在 CI PASS（6.2%）」，
并诚实写了三条边界：① 机理未查明；② 两处记述仍写旧的 `25% / 当前 5.9%`；
③ 没有判定该改代码、改阈值还是改文档。本节把这三条逐条收掉。

方法上刻意**先修记述、再查机理**：因为「记述与代码不符」是**可机械确认**的事实，
而「机理」需要新的实验；把前者先钉死，后面的实验才有可信的参照物。

### 2.43.2 先修记述：`25% / 当前 5.9%` -> `12%`（**两处现时值口径**）

`build/_m3claims.py` 全库普查（`.md/.py/.ps1/.json/.yml/.csv/.txt/.c/.h`，
跳过 `.git`/`build`/`archive`）共 **47 处**命中 M3 阈值相关字样。逐条判读后分三类：

| 类别 | 处数 | 处置 |
|---|---|---|
| **现时值口径**（读者会照它做判断） | **2** | **已修为 12%** |
| 历史叙述（W1.6 成果「55.9% -> 5.9%」） | 4 | 不动（是成果记录，不是阈值） |
| 历史记录（含当时真值的时间戳条目） | 41 | 不动（§2.40 已确立：历史快照记当时真值） |

两处**现时值口径**的具体改动：

1. `tools/migration_gate.py:18-25` 文件头 docstring 的阈值表：
   旧 `| **M3 保护函数命中** | 55.9% | **5.9%** | **<= 25%** |` /
   旧 `| M1 地址复用率 | — | 1.1% | <= 25% |` /
   旧「阈值留了余量（25% vs 实测 5.9%）」
   ⇒ 新表为 `无注入基线 / 全注入 / 阈值` 三栏，**M3 与 M1 都是 `<= 12%`**，
   并写明「12% 不是初版 25%」的标定依据（移除 6/16 只升到 20.6% ⇒ 25% 会漏检）
   与本机/CI 抖动的机制指针。
2. `tools/release_check.ps1` 第 24 项注释块（第 647~649 行附近）：
   旧 `M3 保护函数特征命中率 <= 25%    （当前 5.9%；无注入时 55.9% 必被抓）` /
   旧 `M1 地址复用率         <= 25%    （当前 1.1%）`
   ⇒ 新为 `<= 12%` + 「阈值是 12% 不是 25%」的理由 + 抖动说明。

改动后 `tools/release_check.ps1` 由 **70428 B → 71074 B**（`bom=True crlf=1198 bareLF=0`；
`.ps1` 卫生纪律），旧串 `<= 25%` 残留 **0**、新串 `<= 12%` 计 **2**。
PS 语法 `parse errors: 0`；`py_compile tools/migration_gate.py` rc=0；
`tools/migration_gate.py --selftest --quiet` **12 条全 ok**（6 条阈值判定 + 6 条正则/畸形），
其中阈值判定与代码 `MAX_M3 = 12.0` **一致**：`5.9<=12 True` / `20.6<=12 False` /
`55.9<=12 False` / `12.0<=12 True` / `12.1<=12 False` / `0<=12 True`。

> 注意一个反直觉点：**`--selftest` 一直是绿的**，因为它的判据取自 `MAX_M3` 常量
> ——它证明的是「阈值判定逻辑能抓错」，**不能**证明「文档写的阈值是对的」。
> 文档与常量的漂移，自检看不见。这正是 §2.36.8 / §2.38 / §2.40 那条
> 「能被机器校验的东西改了、靠人眼维护的地方会漏」的第 5 次同型。

### 2.43.3 机制：首差字节落在第 33~47 字节，而判据只看前 32 字节

复现方式（**不重跑 12 次构建**）：`build/_m3dbg.py` 用固定种子表 + 两个 salt
（A = `0x11111111` / B = `0xAAAAAAAA`）各构建一次，产物留在临时目录；
后续全部探针都读这一对产物。

`tools/migration_cost.py` 的 M3 定义是 **`FEATURE_LEN = 32`**：
取 A 构建中该函数**入口起 32 字节**，在 B 构建的映像里 `find`。
于是「首差落在第几字节」直接决定是否命中。`build/_m3window.py` + `build/_m3win2.py`
实测全部 **32 个保护函数**：

```
prot_license_build_message   首差@47   32B 特征相同 = True
prot_antidebug_detected_r3   首差@46   32B 特征相同 = True
prot_antidebug_detected_r4   首差@35   32B 特征相同 = True
prot_antidebug_detected_r2   首差@33   32B 特征相同 = True
prot_selfcrypt_init          首差@33   32B 特征相同 = True
其余 27 个：首差 @2 .. @29  ⇒ 32B 特征 NOT 相同
```

⇒ **首差 >= 32 的恰好是 5 个，与 M3 命中的 5 个完全同一批**
（`build/_m3list.py` 的命中清单与 `_m3window.py` 的集合逐一相同）。
所以 M3 = 15.6% 的分子不是「别的函数偶然匹配」，而是这 5 个函数的
**前 32 字节跨构建逐字节相同**。

字节级对照（`build/_m3win2.py`，前 48 字节 A vs B）——差异的位置一望可知，
且差异内容就是构建 salt 本身：

```
prot_antidebug_detected_r2   A.rva=0x004fd0 B.rva=0x002de0 首差@33
  +32  A 10 11 11 11 11 8b 4c 24 10 ...   B 10 aa aa aa aa 8b 4c 24 10 ...
prot_antidebug_detected_r4   A.rva=0x005140 B.rva=0x002fd0 首差@35
  +32  A 44 24 10 11 11 11 11 8b 4c 24 ...  B 44 24 10 aa aa aa aa 8b 4c 24 ...
prot_selfcrypt_init          A.rva=0x024200 B.rva=0x024200 首差@33
  +32  A 50 11 11 11 11 8b 44 24 50 ...   B 50 aa aa aa aa 8b 44 24 50 ...
```

`11 11 11 11` 与 `aa aa aa aa` 就是 A/B 两个 `PROT_BUILD_SALT` 的立即数
（`mov dword [rsp+N], imm32`），即 `PROT_NOISE()` 的产物 —— 只是它**出现得太靠后**。
`prot_license_build_message`（首差@47）与 r3（首差@46）同理。

### 2.43.4 ⭐ 对抗口径：判据 5/32 = 15.6%，但攻击者自选窗口可达 26/32 = 81.2%

判据固定「从入口取 32 字节」，而攻击者**不受这个约束**：他可以从函数任意偏移取特征，
只要该特征在 B 构建里能重新找到即可用于定位。`build/_m3adv.py`（v1）与
`build/_m3adv2.py`（v2，加唯一性过滤）实测：

| 口径 | 结果 |
|---|---|
| **判据口径**：入口起 32B，在 B 映像命中 | **5 / 32 = 15.6%** ← 与 M3 现值一致（复核通过） |
| 对抗口径 v1：任一 32B 窗口在 B **同名函数内**找到 | 27 / 32 = 84.4%（**过宽**） |
| **对抗口径 v2：窗口在 B 整镜像中唯一 + 在 B 同名函数内** | **26 / 32 = 81.2%** |

v1 之所以过宽：填充/重复字节（例如 `cc cc cc cc`）也能"找到"，
但那种窗口在 B 里出现多次，**不能用于定位**，只有唯一签名才算。
v2 的「唯一」在**整镜像**上判（不是只在 `.text` —— 见 §2.43.7 的探针更正）。

**最早可命中的 `start`**（步长 1，仅列命中者）：

```
+0   prot_antidebug_detected_r2 / r3 / r4 / prot_license_build_message / prot_selfcrypt_init
+8   prot_dbiguard_suspicious / prot_vmdetect_suspicious
+12  prot_vm_rekey
+21  prot_antidebug_detected_multi / prot_selfcrypt_leave
+25  prot_integrity_check_self / prot_selfcrypt_enter
+27  prot_license_verify          +29  prot_revoke_check
+33  prot_vm_blob_load / prot_vmdetect_scan      +35  prot_indirect_resolve
+37  prot_antidebug_apply_policy  +44  prot_antidebug_scan
+53  prot_sys_nt_query_information_process / prot_sys_nt_query_system_information / prot_vm_run
+64  prot_hostid_get              +74  prot_dbiguard_scan
+110 prot_integrity_check_guards  +111 prot_integrity_start_watchdog
```

⇒ **把观察窗口往后挪 8 字节，可定位的保护函数就从 5 个变成 7 个；挪到 +112 之后是 26 个。**
仍不可定位的 6 个：`prot_antidebug_detected` / `prot_integrity_check_iat` /
`prot_integrity_register_guard` / `prot_integrity_set_watchdog_callback` /
`prot_sys_available`，以及 `prot_antidebug_fake_active`（估算长度仅 **16 字节**，短于窗口，
取不出 32 字节特征）。

**这条比 M3 现值本身更重要**：它说明 `M3 <= 12%` 这个判据**测的是"最容易被利用的
取法"，而不是"攻击者的最优取法"**。判据绿，不代表攻击者定位不到。
这是一条**判据口径的诚实边界**，不是判据失效（判据本来就写了"从入口取 32 字节"）。

### 2.43.5 量化机制：窗口长度与起点扫描（**不是修法**）

`build/_m3len.py` 固定 A/B 一对构建，改变 `FEATURE_LEN` 与窗口起点：
判据口径（起点 +0）下，窗口越长命中越少；一旦越过随机化区，反而回升。

```
LEN=8   28/32 = 87.5%      LEN=32   5/32 = 15.6%  <-- 判据现值
LEN=16  15/32 = 46.9%      LEN=40   2/32 =  6.2%
LEN=24  10/32 = 31.2%      LEN=48   0/32 =  0.0%   LEN=64/96/128 = 0/32
固定 LEN=32，改变起点:
  start@+0   5/32 = 15.6%   start@+16  3/32 =  9.4%
  start@+4   2/32 =  6.2%   start@+32  7/32 = 21.9%
  start@+8   4/32 = 12.5%   start@+48 11/32 = 34.4%   start@+64 15/32 = 46.9%
```

⇒ **LEN = 48 起命中归零**（32 个保护函数在 48 字节内两两不同）；
起点后移到 +64 反而升到 46.9%，因为已经**越过随机化区、进入稳定的函数主体**。
两个方向都印证同一件事：**变化只发生在有限的一段区域里**。

> ⚠️ **调大 `FEATURE_LEN` 不是修法**，只是把机制的边界量出来。判据的语义
> （"攻击者取函数入口特征"）是有意选的保守口径；改它等于改判据定义，
> 而不是修防护。这条写进脚本 docstring，避免后人误读成"建议改 32 -> 48"。

### 2.43.6 代码根因：`PROT_PAD_*` 落在 NULL 检查之后

- `include/protect/prot_noise.h:68-74` `PROT_NOISE()` = 一个局部 `volatile`
  立即数 + 一个永不成立的分支 ⇒ **只覆盖函数序言（约 15 字节）**。
- `include/protect/prot_noise.h:100-124` `PROT_PAD_STEP()/PROT_PAD_4/2/1()` =
  `volatile prot_pad1_ = 0u; volatile prot_pad2_ = PROT_BUILD_SALT; prot_pad1_ += prot_pad2_;`
  ⇒ 这是**第二批**变化源，由调用方用 `#if` 阶梯（`PROT_BUILD_SALT` 的位段）控制条数，
  于是改变的是**代码长度**。
- `src/antidebug.c:625-651`（r2）的实际布局：`:626 volatile k = PROT_AD_R2_SALT;`
  → `:629` 抗 ICF 比较 → `:630-632 if (rep == NULL) return 0u;` →
  **`:633-642` 才是 `PROT_PAD_*`**。r3（`:655-697`，位段 3..5）、
  r4（`:703-723`，位段 6..8）同布局。
- 于是 `PROT_PAD_*` 生成的指令落在**机器码第 33 字节之后**，
  而 32 字节特征窗口**恰好只覆盖 `PROT_NOISE` 的立即数**。
  `prot_selfcrypt_init`（`src/selfcrypt.c:290-292` 的 `PROT_NOISE();` 之后紧跟
  `blob` 取值与长度检查）与 `prot_license_build_message` 同属"序言很短"这一类。

**这不是新发现的缺陷** —— `include/protect/prot_noise.h:40-44` 自己就写了：

> · 只覆盖函数**首部**（约 15 字节）。攻击者若用**函数中部/尾部**的更长
>   特征仍可能匹配 —— **已知局限**，需在 migration_cost 度量中复核。
> · 注入位置规律（都在序言）本身是可学习的模式；攻击者可"跳过前 N 字节"
>   再匹配 —— 这会降低（但不消除）本宏的效果。

本节等于**执行了它要求的"在 migration_cost 度量中复核"**，并首次给出
精确落点（第 33 / 35 / 46 / 47 字节）与对抗口径的量化（81.2%）。

**为什么 `PROT_PAD_*` 不放在最前面**：它当前的位置在 `rep == NULL` 早退之后，
有语义原因（先判空再做事）。把它前移到 NULL 检查之前会改变早退路径的机器码，
属**改防护代码**，须重跑 e2e / `replica_check` / 全门禁 —— 本节**没有做**，
如实列为未验证。

### 2.43.7 我自己的探针错误（同类第 3 次）

1. **`mc.read_sections()` 的返回形状**：它返回 `(data, sections)`，`sections` 每项是
   **5 元组** `(name, vsize, size_raw, ptr_raw, virtual_addr)`，**不是 dict**。
   我按 dict 写了 `s['name']` ⇒ `TypeError: tuple indices must be integers or slices, not str`。
2. **唯一性搜索的节范围**：v1 只在 B 的 `.text` 里找唯一签名，于是
   `prot_selfcrypt_init` 报 `n=0`（"入口 32B 在 .text 里不存在"）。
   实测其 RVA `0x024200` 落在随机名节 **`.q7d7jk6(+0x200)`**（即 `.protxec`），
   **selfcrypt 组根本不在 `.text`**。改成整镜像后 `n=1`。
   ⇒ 这不是"selfcrypt_init 没被随机化"，是**口径把它的所在节排除了**。

同型第 3 次（前两次：§2.37.6 的 `base` 行标注 bug、§2.42.7 的 `migbody.ps1` 硬编码真 python）。
一般化表述：**探针的口径错会伪装成被测对象的性质** —— 而且因为结论"看起来合理"，
它比工具崩溃更难发现。

**顺带复核一条**：`build/_m3chk.py` 逐条定位 5 个命中，**全部**满足
`db.find(sig0) == B 中同名函数的入口偏移`（r2 `0x0043d0→0x0021e0`、
r3 `0x004430→0x002260`、r4 `0x004540→0x0023d0`、
license_build_message `0x004c70→0x004470`、selfcrypt_init `0x022800→0x022a00`）
⇒ 判据命中的**确实是对应函数的入口**，不是"窗口偶然落在别处"的假阳性。
（`_m3where.py` 曾输出 `off2rva` 的 `sec=None`，那是该探针的元组解包瑕疵，不影响此结论。）

### 2.43.8 结论与未决

**已确证：**

1. **本机 M3 = 15.6% 不是防护能力退化，是判据窗口比随机化落点短。**
   5 个命中函数的首差都在第 33~47 字节，而 `FEATURE_LEN = 32`；
   命中处确为对应函数入口（非假阳性）。
2. **CI 6.2% 与本机 15.6% 的差异可由同一机制解释**：工具链
   （本机 MSVC `14.44.35207` vs CI `14.51.36231`）改变的是**序言长度**，
   从而改变"首差落在第几字节"；门槛恰在 32/33 附近 ⇒ 同一份代码落到阈值两侧。
   这是**阈值附近的抖动敏感，不是能力差异**。
3. **判据显著低估攻击者的能力**：判据 5/32 = 15.6%，攻击者自选窗口
   26/32 = **81.2%**（唯一签名）。
4. **`include/protect/prot_noise.h:41-42` 自己写明的已知局限，本节首次量化并定位。**
5. **两处现时值口径（`25% / 当前 5.9%`）已修为 `12%`**，并补记抖动原因；
   全库 47 处中其余 45 处为历史叙述/记录，按 §2.40 原则不动。

**未做（诚实边界）：**

- **没有改防护代码**（未把 `PROT_NOISE` / `PROT_PAD_*` 前移进 32B 窗口）。
  理由：① 属改防护，影响面大（须重跑 e2e / `replica_check` / 全门禁）；
  ② `PROT_PAD_*` 在 NULL 检查之后有语义原因；
  ③ **即使前移，也只压低判据的 15.6%，攻击者自选窗口的 81.2% 依然存在** ——
  要治后者需要**整函数长度抖动**，那是另一个量级的改动。
  `docs/LINUX_PORT_PLAN.md:1398` 的旧工作项「给剩余 5 个保护函数补 `PROT_NOISE`
  或纳入 selfcrypt」正是针对这同一批函数（2026-09-25 记为 19.2%，5/26），**至今未做**。
- **本机 vs CI 的对照实验无法在本机做**（需要 CI 的 MSVC 14.51 工具链）；
  §2.43.8 第 2 条是**机制解释跨越已知环境差异**，不是直接对照实验。
- 未验证 `docs/LINUX_PORT_PLAN.md:1398` 那条工作项做完后 M3 会到多少。

### 2.43.9 验证表

| 项 | 结果 |
|---|---|
| `tools/migration_gate.py --selftest --quiet` | **12 条全 ok**（6 阈值判定 + 6 正则/畸形），rc=0 |
| `py_compile tools/migration_gate.py` | rc=0 |
| `tools/release_check.ps1` 语法 | `parse errors: 0` |
| `tools/release_check.ps1` 卫生 | `bom=True crlf=1198 bareLF=0`；`70428 -> 71074 B` |
| 旧串 `<= 25%` 残留 | **0**（新串 `<= 12%` 计 2） |
| M3 判据口径复核 | 探针复算 **5/32 = 15.6%**，与门禁实测值一致 |
| 命中清单一致性 | `_m3list.py` 命中集合 == `_m3window.py` 首差>=32 集合（5/5） |
| 命中处是否同名入口 | `build/_m3chk.py` **5/5 True** |

*2026-10-06 v17*

### 2.44 M3adv：把"对抗口径 81.2%"从一次性探针提升为生产工具指标（2026-10-06）

#### 2.44.1 缘起：一个只有我能复现的数字

§2.43.4 给出了一条比判据更重要的结论 —— 判据 M3 的 15.6% **显著低估**了攻击者的真实
能力，攻击者只要**不从入口取特征**、改为自选窗口并加唯一性过滤，就能跨构建定位
**26 / 32 = 81.2%** 的保护函数。

这条数字当时只存在于 `build/_m3adv2.py`（gitignored 探针）里，而它的输入是
`build/_m3dbg.py` 留在系统临时目录的一对构建：

```
C:\Users\devuser\AppData\Local\Temp\m3dbg_35833og9\
```

事后复访，该目录已 **`PermissionError [WinError 5] 拒绝访问`** —— A.exe / A.map /
B.exe / B.map 四个文件全部读不到。

> 也就是说：**§2.43.4 的核心结论，除了我之外任何人都无法复现，包括我自己。**

这正是本工作链条从 §2.36 起一直在堵的同一类缺陷（「能用」不等于「在用」）的一个新面
孔：这次的失效不是"判据没被门禁执行"，而是 **"度量只存在于一次性探针的输出里"**。
探针删了、临时目录清了、机器换了，结论就变成不可验证的断言 —— 而 `docs/HANDOVER.md`
的读者没有任何办法把它与"我编了一个数"区分开。

#### 2.44.2 修法：提升为 `tools/migration_cost.py` 的一等指标 M3adv

**`tools/migration_cost.py`**：

  · 新常量 `FEATURE_SCAN_MAX = 256` —— 对抗口径自选窗口的扫描上限。
  · 新函数 `fn_extents(secs, data, m, funcs)` → `{符号: (rva, 文件偏移, 可用长度)}`。
    长度用**下一个函数的 RVA** 近似。
  · 新函数 `adv_window_hit(fa, fb_image, fb_off, fb_len, flen=FEATURE_LEN,
    scan_max=FEATURE_SCAN_MAX)` → 首个命中窗口起点，或 `None`。
  · `analyse()` 新增 `res['m3a'] = {'prot_total', 'prot_located', 'prot_rate',
    'located', 'starts'}`。
  · `main()` 新打印段 `--- M3adv 对抗口径（攻击者自选窗口 + 唯一签名）---`。

语义（三条同时成立才算"可定位"）：

  ① 窗口取自 **A 的函数字节**，起点可以**不是** 0（攻击者自选窗口）；
  ② 该 `flen` 字节窗口必须在 **B 的整个映像**里**唯一**出现；
  ③ 那次唯一出现必须落在 **B 的同名函数范围**内。

⚠️ **为什么必须加唯一过滤**（这是 v1 → v2 的全部差别，且差的正是判据的成败）：

    不过滤唯一性: 27 / 32 = 84.4%
    加唯一性过滤: 26 / 32 = 81.2%

差的那 1 个正是**被重复/填充字节（`cc cc cc cc`）救下**的 —— 那种窗口在 B 里出现多次，
**不能用于定位**，算进"可定位"是把自己的探针口径放宽成虚假战果。

⚠️ **唯一性必须在整个映像上判，不能只在 `.text`**：

    selfcrypt 组（`prot_selfcrypt_init` / `_enter` / `_leave`）经 `PROT_CODE_SEG` 落在
    `.protxec`（本构建随机节名 `.q7d7jk6`，RVA `0x024200`），**不在 `.text`**。
    只在 `.text` 里数出现次数，会把 `prot_selfcrypt_init` 的签名出现次数**误报为 0**。
    （v1 就报过这个 0；这是本轮探针第 3 次"工具的口径错伪装成被测对象的性质"。）

**`tools/migration_gate.py`**：`measure()` 的 `if not quiet:` 块内新增诊断行 ——

```
  ⚠️ 诊断 M3adv（自选窗口 + 唯一签名）: 26 / 32 (81.2%)
     这是判据 M3 的**诚实边界**: 攻击者不必从入口取特征。把 M3 判据窗口收紧**不改变**
     M3adv（对抗口径不受判据约束）。
```

#### 2.44.3 M3adv **不设阈值、不参与 PASS/FAIL**（刻意的设计决定）

门禁只看 `M3 <= 12%` 与 `M1 <= 12%`。M3adv **只打印**。

理由：M3adv 量的是**判据的诚实边界**，不是"产品是否合格"。把它变成阈值只有两种后果，
两种都坏：

  · 按当前值（81.2%）设阈值 ⇒ 门禁**永远 FAIL**，于是要么被加进豁免、要么把阈值调到
    90% —— 两种都是"让检查器学会通过"。
  · 设一个宽松阈值（比如 85%）⇒ 它变成一个**从不失败**的检查，比没有更危险
    （§3.8 的同一条原则）。

要真正压低 M3adv，需要的不是改判据窗口（§2.43.5 已实测：窗口收紧只动 M3，不动 M3adv），
而是**整函数长度抖动** —— 让函数体本身在两次构建间不同长。那是另一个量级的改造
（§2.43.8 已记为未决）。在那之前，M3adv 的正确定位是**诚实的诊断输出**。

#### 2.44.4 自检：`adv_window_hit` 的 7 条语义用例

`selftest()` 新增 7 条，**正反都测**（否则"恒返回 0"的实现也能通过）——
玩具数据 `flen=4`：

| 用例 | 期望 |
|---|---|
| `[A]` 唯一且在同名函数内 | 命中 `@0` |
| `[B]` 签名在 B 出现 2 次（重复/填充） | `None`（不能定位） |
| `[C]` 唯一但在**别的函数**内 | `None`（范围过滤生效） |
| `[D]` 需往后挪窗口才唯一 | 命中 `@4`（证明"自选窗口"真的在扫） |
| `[E]` 唯一签名落在映像后半（非 `.text` 区） | 命中 `@0`（整映像判唯一性） |
| 空函数体 | `None`（不崩溃） |
| 窗口长于函数体 | `None`（不崩溃） |

实测 **7/7 ok**，`[migration_cost-selftest] PASS: 度量可自证能抓错`，rc=0。

#### 2.44.5 验证：数字从探针复现到工具

重新建一对构建（`build/_m3a/`，`PROT_BUILD_SALT` = `0x11111111` / `0xAAAAAAAA`，
`build.ps1 -Config Release -SkipSmoke -SkipSign -Composition full -SeedsFile <seed>`），
跑**生产工具**：

```
--- M3adv 对抗口径（攻击者自选窗口 + 唯一签名）---
  ⚠️ **不是门禁判据** —— 报告判据 M3 的诚实边界

  判据口径（入口起 32B）: 5 / 32 (15.6%)
  对抗口径（自选窗口）  : 26 / 32 (81.2%)

  -> 差值 = 判据**低估**的部分: 攻击者不必从入口取特征
     实测结论: 判据测的是"最容易被利用的取法", 收紧判据窗口不改变对抗口径
```

⇒ 与 §2.43.4 的两个数字**逐一相同**。结论从"探针里的一次性数字"变成**工具可复现输出**：
任何人 `python tools/migration_cost.py A.exe B.exe --map-a A.map --map-b B.map`
都能自己看到 15.6% 与 81.2%。

`tools/migration_gate.py` 侧实跑：

```
  第 1 对: M3= 15.6%  M1=  5.8%
  第 2 对: M3= 12.5%  M1=  0.0%
  第 3 对: M3= 15.6%  M1= 10.9%
  -> 中位数（3 对）: M3=15.6%  M1=5.8%
  ⚠️ 诊断 M3adv（自选窗口 + 唯一签名）: 26 / 32 (81.2%)
```

（`FAIL: M3 15.6% > 12%` 是本机 MSVC 14.44.35207 的**既有已知现象**，机制见 §2.43.3；
CI 的 14.51.36231 上为 6.2% PASS。它与本轮改动无关。）

#### 2.44.6 诚实边界

  · **M3adv 只在 Windows PE 上有意义**：`fn_extents` 依赖 map 符号与节表，
    与 `migration_cost.py` 既有的平台假设一致。
  · **函数长度是近似的**（取"下一个函数 RVA"）。这个近似是**保守**的 —— 长度偏大只会让
    "窗口落在函数范围内"更容易成立，因此**不会把可定位误判成不可定位**；但理论上存在
    把"跨越函数边界的窗口"算成命中的可能，故 81.2% 应读作**上界附近**而不是精确下界。
  · **M3adv 不覆盖 `examples/` / `sdk_service/`**，与 `migration_cost.py` 既有扫描面一致。
  · 本轮未改任何防护代码：§2.43.8 的"是否把变化源前移"仍然未决。

#### 2.44.7 验证表

| 项 | 结果 |
|---|---|
| `py_compile tools/migration_cost.py` | rc=0 |
| `python tools/migration_cost.py --selftest` | **7/7 ok**（M3adv 段）+ 既有段全 ok |
| `[migration_cost-selftest]` | `PASS: 度量可自证能抓错` |
| `py_compile tools/migration_gate.py` | rc=0 |
| `tools/migration_gate.py --selftest --quiet` | **12 条全 ok**，rc=0 |
| 真实数据复现 | `5 / 32 (15.6%)` 与 `26 / 32 (81.2%)`，与 §2.43.4 一致 |
| `tools/migration_cost.py` 卫生 | `bom=False crlf=0 bareLF=588 bytes=24956` |

#### 2.44.8 途中发现：`M3adv` 原本叫 `M3a`，与 `tools/vmc.py` 撞名（已改名）

**这是本轮唯一一次真的改错名字，且是实现完成、自检通过之后才发现的。**

实现时我把新指标命名为 `M3a`（"M3 的对抗口径"）。写完、自检 7/7 通过之后，为确认
没有遗漏的引用点，做了一次全库搜索 —— 结果撞上两个早已存在的用法：

```
tools/vmc.py:302:  """M3a: 0x40..0xF8 的 24 个槽位, Fisher-Yates 打乱 (确定性)."""
tools/vmc.py:670:  help='stack-slot randomization seed (M3a; 0=sequential)',
tools/vmc.py:671:  help='control-flow flattening (M3b; dispatch-loop + ...
```

⇒ **`M3a` / `M3b` 已被 VM 指令集变异占用**（栈槽随机化 / 控制流平坦化），
与 `migration_cost` 的 M1 / M3 / M4 度量是**完全不同的命名空间**。

沿用下去的后果很具体：README / HANDOVER / 事故排查里搜 `M3a` 会同时命中
"栈槽随机化"和"对抗口径特征定位"两个毫无关系的东西，而两者的**失败含义完全不同**
（一个是 VM 引擎变异没生效，一个是迁移成本判据被低估）。

**修法**：改名 **`M3adv`**（M3 的 *adversarial* 口径）。全库实测
`M3adv|M3-adv|M3_adv|M3adversarial` 命中 **0**，无冲突。三个文件共 26 处
（`tools/migration_cost.py` 6 / `tools/migration_gate.py` 3 / `docs/HANDOVER.md` 17）。

**教训（与本链条前几次同型）**：§2.43.7 记的是"探针的**口径**错会伪装成被测对象的
性质"，这次是"**命名**错会伪装成一个不存在的独立性" —— 自检全绿、度量正确、
打印漂亮，**没有任何一个检查器会因为名字撞车而变红**。仓库里当时没有、现在也仍然没有
任何机制检查"新引入的指标名是否已在别处使用"。这是一个**已知的、未做门禁**的空白
（与 §2.40 的"扫描面自声明"同类：都是靠人记得去看）。

#### 2.44.9 两条诚实边界：CI 上不打印 M3adv；跨工具链未测

**① CI 用 `--quiet`，所以 M3adv 不会出现在 CI 的门禁日志里。**

`.github/workflows/ci.yml:104-105`：

```yaml
      - name: Migration cost gate
        run: python tools\migration_gate.py --quiet
```

`--quiet` 抑制的正是 `measure()` 里那段 `if not quiet:` 的打印 —— 其中包含 M3adv
诊断行。因此 CI 的这一步**只给出 PASS/FAIL，不给出 M3adv 值**。

这不影响 §2.44 的目标（**任何人可复现**）：`tools/migration_cost.py` 的 M3adv 段是
**无条件打印**的，只要手里有一对构建，`python tools/migration_cost.py A.exe B.exe
--map-a A.map --map-b B.map` 就能看到，与 `migration_gate.py` 的 `--quiet` 无关。

但必须如实记下后果：**CI 的历史里没有 M3adv 的时间序列**。也就是说，如果将来 M3adv
发生漂移，没有任何自动记录能指出它是什么时候漂的 —— 只能靠人事后重跑。

**② M3adv 是否像 M3 一样对工具链敏感 —— 未测。**

§2.43.3 已实测：同一个判据 M3 在本机 MSVC `14.44.35207` 上为 15.6%（FAIL），
在 CI 的 MSVC `14.51.36231` 上为 6.2%（PASS）—— 机制是**序言长度**改变，使"首差落
在第几字节"跨过 32 字节门槛。

M3adv 的口径（自选窗口 + 唯一签名）**看起来**不该有同样的敏感度：它不依赖"首差是否
落在前 32 字节"，而依赖"存不存在一个 32 字节的唯一窗口"。但这只是**看起来** ——
工具链改变的不只是序言长度，还包括指令选择、寄存器分配、内联决策，这些**都可能**让
某些函数的可用窗口变少或变多。

我没有 MSVC 14.51 可用，**所以这条没有测**。它留在记录里作为已知未验证项，而不是
被含糊地写成"应当稳定"。

## 2.45 门禁阈值常量在文档里无人对账 —— 给 §2.43.6 自己记名的空白补上判据（2026-10-06）

### 2.45.1 缘起：§2.43 修好了数字，却没人守着它

§2.43.2 把 `tools/migration_gate.py` 的模块 docstring 与
`tools/release_check.ps1` 第 24 项注释块里的旧阈值 **25% 修成 12%**，
让它与 `MAX_M3` / `MAX_M1` 的真实值一致。§2.43.6 当时明确记下这条边界：

> 这两处**没有任何检查器在读**。下次谁改常量（或改回阈值），
> 两处文档会**再次静默过期**，而 `--selftest` 依旧全绿。

这条自我记名在本轮被当作待办执行了。它的形状与本链条从 §2.36 起反复出现的
那一条**完全相同**：

| 节 | 事实在哪 | 谁在读它 |
|---|---|---|
| §2.36.8 | `Check` 调用的实际清单 | 机器校验的是**数字**，**枚举清单**靠人眼 ⇒ 漏了 |
| §2.38 | 全库 `.py` 的实际文件集 | CI 里是**逐字枚举 23/95**，不是 glob ⇒ 漏了 72 个 |
| §2.40 | 「现值口径」该覆盖哪些文件 | 扫描面是**自声明**的 opt-in ⇒ 不写元数据就失明 |
| §2.42 | 26 个工具注册了 `--selftest` | 11 个的自检**从未被任何自动化面跑过** |
| **§2.45** | `MAX_M3` / `MAX_M1` 的真值 | **只有它们自己的 `--selftest` 在碰**，且是碰常量、不是碰文档 |

最后一行尤其隐蔽：`tools/migration_gate.py:220-225` 的自检写的是
`5.9 <= MAX_M3` 这种**用常量的表达式**，所以：

* 常量改成 15 ⇒ 自检**照样全绿**（它比的是常量与常量）；
* 文档写 25 ⇒ 自检**当然也绿**（它根本不读文档）。

⇒ `--selftest` 证明的是「**阈值判定逻辑能抓错**」，
**不是**「**文档里写的阈值是对的**」。这两件事此前被混为一谈。

### 2.45.2 修法：把真值源与两处声明对账（常量 → 文档）

`tools/doccheck.py` 新增三个函数，插在 `gated_check_names()` 与
`parse_readme_gate_list()` 之间：

* `gate_threshold_constants(src=None)` —— 从 `tools/migration_gate.py`
  **现读** `^MAX_M3 = N` / `^MAX_M1 = N`。返回 `(consts, why)`；
  `why` 非空 = 真值源被改名/换写法 ⇒ 调用方 FAIL，**不猜测**。
* `_LE_PCT` + `_threshold_claims(text, base=1)` —— 抽 `<= N%` / `≤ N%`
  形态的阈值声明，指标取 `<=` **之前最近**的那个 `M1`/`M3`
  （同一行写两个指标时不会错配）。
* `_comment_block_before(text, anchor, window=40)` —— **内容锚定**地
  定位 `release_check.ps1` 里迁移成本项的注释块。
* `check_threshold_claims(gate_src=None, ps_src=None, consts=None)` ——
  四条判据（见下），返回错误列表（空 = 一致）。

`main()` 里作为 **0c** 步紧跟 0b：

```
  [ok] 迁移成本阈值: M3/M1 = 12% / 12% 与 migration_gate.py docstring、release_check.ps1 注释块一致
```

#### 判据

1. `tools/migration_gate.py` **模块 docstring** 里 M3 / M1 各至少有一条
   `<= N%` 声明，且值 == 对应常量；
2. `tools/release_check.ps1` 迁移成本项的 `#` 注释块同样两条；
3. 任一面数到 **0** 条声明 ⇒ FAIL（锚点消失，**不得**读成"没有漂移"）；
4. 常量读不到 ⇒ FAIL（真值源被改动，**不猜**）。

判据 3 是本轮刻意加的 —— 与 §2.40.6「扫描面自身的守卫」同一条纪律：
**判据的判据**。若哪天有人把 docstring 里的阈值表整段删掉，
「没有声明」和「声明正确」在只判 1/2 的实现里**都是 0 条错误**；
加 3 之后前者变红。

#### 为什么只匹配 `<= N%`，而不是裸数字

实测（`build/_threshprobe2.py`）两处文档里都存在**叙述性**提到旧值 25% 的句子：

```
tools/migration_gate.py:24   阈值 **12%**，不是初版的 25%。2026-09-23 反向验证发现 25% 会漏检：
tools/release_check.ps1:651  # ⚠️ 阈值是 **12%** 不是 25%：2026-09-23 反向验证发现 25% 会漏检
```

按裸数字匹配会把这两句**历史叙述**当成现值声明来判，于是判据会要求
**篡改叙述**才能变绿 —— 那正是 §2.40 反向守卫（`_dated`）在防的同一类
错误。故正则**只**锚定 `<= N%` / `≤ N%` 这一种**唯一形态**。

`migration_gate.py:6` / `:12` 的「M3 从 55.9% 降到 5.9%」是**成果叙述、
不是阈值**，同样不在判据内。

### 2.45.3 途中踩到：定位器写错会伪装成"文档漂移"

第一版 `_comment_block_before` 是「从 `Check` 行往上收连续 `#` 行」。
在 `release_check.ps1` 里这**立刻坏掉**：注释块与 `Check` 之间隔着

```
if ($WithMigration) {
    Check '迁移成本 (migration_gate)' {
```

于是往上第一步就撞上 `if` 行（不是 `#`），收到**空块**，
判据对 M3 / M1 **两个**指标都报「找不到声明」——
**看起来完全像文档漂移，实际是定位器坏了**。

这是本项目记录在案的同一类错误第 **4** 次（§2.37.6 探针的 `base` 标注 bug、
§2.42 的 `migrate` 计时探针硬编码真 python、§2.43.7 的唯一性搜索只看 `.text`）：

> **工具的口径错会伪装成被测对象的性质。**

修法 = 改成**内容锚定**：先在 anchor 上方 40 行内找最近的**含 `<= N%`
的 `#` 行**作种子，再向上/向下扩到注释块边界。不硬编码行号。

### 2.45.4 验证：判据在**真实仓库文件**上承重

只跑合成用例不足以证明判据有用（合成数据是我自己造的，可能只覆盖我想到的形态）。
故在**真实文件**上注入缺陷，跑完整 `doccheck`，再逐字节还原
（`build/_threshload.py`）：

| 注入 | 结果 |
|---|---|
| 基线（不注入） | `rc=0` / 0 条错误 |
| **A** 真值源 `MAX_M3 = 12.0` → `15.0`（文档不动） | `rc=1` / **2** 条错误（docstring:21 + release_check.ps1:648 各一条） |
| **B** docstring 的 `**<= 12%**` → `**<= 15%**` | `rc=1` / **1** 条错误（docstring:21） |
| **C** 注释块的 `M3 … <= 12%` → `<= 25%` | `rc=1` / **1** 条错误（release_check.ps1:648） |
| 复原后 | **逐字节一致 = YES** / `rc=0` / 0 条错误 |

A 是最有说服力的一条：**只改常量、文档一个字不动**，两处声明各报一条 ——
这正是 §2.43.6 担心的漂移方向。

自检侧新增 **7 条**用例（走第三个入口 `check_threshold_claims`，
必须与 `cases` / `gl_cases` **一起打印、一起计数**，否则只是暗处运行）：
真实仓库不报、docstring 阈值漂移、docstring 声明整条消失、
真值源常量读不到、注释块 M1 漂移、注释块锚点消失、常量改 15 而文档仍 12
（**期望 2 条** —— 验证两处面各自独立报错）。

`--selftest` 由 **27 项** → **34 项（19 项负向注入 / 15 项合规豁免）**。

### 2.45.5 诚实边界

* **只对账这两个面**：`tools/migration_gate.py` 的模块 docstring 与
  `tools/release_check.ps1` 的迁移成本注释块。其它任何文档里若出现
  `M3 … <= N%`，本判据**看不见**。
* **只对账 M1 / M3**。`tools/migration_cost.py` 无阈值；
  `tools/migration_gate.py` 内部的**标定点**（5.9% / 20.6% / 55.9%）
  是叙述，不在判据内 —— 它们若漂移，判据不会红。
* **不判 M4**（结构稳定性）与 **M3adv**：前者无阈值，
  后者 §2.44.3 已刻意决定**不设阈值**。
* 匹配靠「`<=` 之前的最近 M1/M3 标签」。若有人把指标名换成别的写法
  （如 `保护函数命中`），判据会走判据 3 报「失去锚点」——
  这是**预期行为**（宁可红，不要静默失明）。

### 2.45.6 验证表

| 项 | 结果 |
|---|---|
| `py_compile tools/doccheck.py` | OK |
| `tools/doccheck.py --selftest` | `PASS: 34 项（19 项负向注入 / 15 项合规豁免）` |
| `tools/doccheck.py` | `[ok] 迁移成本阈值: M3/M1 = 12% / 12% …` / `检查数字 914 处, 错误 0, 警告 0` / `豁免 201 处` / `[doccheck] PASS` |
| 真实文件三注入 `build/_threshload.py` | 全部被抓，逐字节还原一致 |
| `build/_hygiene.py` | 15 个文件, 0 处异常 |
| 全门禁（`-SkipDirtyCheck`） | `[release_check] PASS: 36 项检查全通过`（见 §2.45.7） |
| CI | 见 §2.45.8 |

### 2.45.7 本地全门禁实测

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden \
  -File tools\release_check.ps1 -SkipDirtyCheck
```

⇒ `[release_check] PASS: 36 项检查全通过`（`[ok]` 36 / `[X]` 0 / `[skip]` 0），
含 `[ok]  对外材料 (doccheck)` 与 `[ok]  selfcrypt 驻留期密文态 (selfcrypt_residency)`。
日志 `build/logs/release_check_20261008_183434.log`。

本轮新增的 0c 步随 `doccheck` 项一起被门禁执行 —— 这也正是本节存在的理由：
**判据若不进门禁，就只是又一次"事实可得但没人用"**。

### 2.45.8 CI 实测

提交 `cd01626`，CI run `37765383185`：四 job（`build-and-verify` / `linux-portability` /
`reproducible` / `sdk-package`）全绿。

关键点：`build-and-verify` 里的 `Full release gate` 步会真的跑到
`tools/doccheck.py`，因此新判据在 CI 的 MSVC 14.51 / Python 3.12 环境下
**同样被执行**，不只是本机（MSVC 14.44 / Python 3.13）。

CI 上 `Migration cost gate` 是**独立一步**（`.github/workflows/ci.yml:105-106`
`run: python tools\migration_gate.py --quiet`），故 M3 在 CI 上的结论（PASS）
与本地（FAIL）不同 —— 那是 §2.43.3 已记录的**工具链差异**，与本节的
**文档-常量**对账无关：本节判据两个环境下读的都是同一对常量与同一段文档。





---

## 2.46 ci.yml 里的门禁项数注释：既不在扫描面内，也不被计数正则看见（2026-10-06）

### 2.46.1 缘起：第六个同型实例

§2.45 收口后继续沿"判据存在但没有任何东西在用它"这条线勘查，在
`.github/workflows/ci.yml` 里发现**同一类缺陷的第六次出现**。

`ci.yml:110-115` 原文（修复前逐字）：

```
      # ## 项数口径（2026-10-05 更新，此前写的是过期的「静态 36 / 默认 33」）
      #   静态 `Check` 调用点 **37** 个；默认运行 **34** 项（3 项 `-With*`
      #   门禁默认不跑，会打印 `[info] … 未运行 — 未验证 != 通过`）。
      #   运行期每项留下一枚证据行: `[ok]` / `[X]` / `[skip]` / `[info]`。
      #
      # ## 为什么允许 `[skip]` 而不是要求"34 项全绿"
```

而真值（`tools/release_check.ps1` 现数）= **静态 `Check` 调用点 39 个 /
`-With*` 3 项 / 默认运行 36 项**。三处数字（`:111` 的 37、`:111` 的 34、
`:115` 的 34）**全部过期**。

同文件 `:67` 的 `release_check 覆盖 39 项 (默认 36)` 是**同步好的** ——
说明有人改过 `:67` 却漏了 `110-115`，同一个文件里两处口径分道扬镳。

### 2.46.2 这不是第一次：`:110` 那句话就是自证

`:110` 逐字写着「此前写的是过期的『静态 36 / 默认 33』」—— 这句"更新说明"
本身就是**这个缺陷反复发生**的证据。`git log -L` 实测三次连续同型修正：

| 提交 | 变更 | 注释更新为 |
|---|---|---|
| `2d16b61` `.protxec` 段成为第 4 个 CRC 目标 | 门禁 35/32 → 36/33 | 「2026-10-03 更新」→ 静态 36 / 默认 33 |
| `bc68b11` 门禁第 37 项（`undef_check`） | 36/33 → 37/34 | 「2026-10-05 更新」→ 静态 37 / 默认 34 |
| `f4b27f4` → `7062039` 第 38/39 项（Android、`selfcrypt_residency`） | 37/34 → 39/36 | **没有再动这段注释** |

⇒ 停在 **37/34**，而真值已是 **39/36**。每次新增门禁项都会让它静默过期一次，
只能靠人偶然看见。

### 2.46.3 为什么没人抓到（两层同时失明）

**第一层：两个计数正则都不认这些行。** `tools/doccheck.py` 的
`RE_GATE_NN` / `RE_GATE_N` 都以 `(?:release_check|门禁)` 为**前缀锚**：

```python
RE_GATE_NN = re.compile(r'(?:release_check|门禁)[^\n]{0,24}?(\d+)\s*/\s*(\d+)')
RE_GATE_N  = re.compile(r'(?:release_check|门禁)[^\n]{0,24}?(\d+)(?:\*\*)?\s*项')
```

而 `:111` 写的是「静态 `Check` 调用点 **37** 个」、`:115` 写的是「要求
"34 项全绿"」—— 行里**既没有 `release_check` 也没有 `门禁`**。实测这两个
正则对 `.github/workflows/ci.yml` 的口径句**零命中**（全文件仅 3 处命中，
全在 `:67` 与无关行）。

**第二层：ci.yml 根本不在扫描面内。** `build_targets()`
（`tools/doccheck.py:90-112`）只收 `.md`：根目录 `*.md` / `.github/*.md` /
`publish/*.md` / `docs/marketing/*.md` / 头部含 `> **最后核实**` 的
`docs/**/*.md`。实测 `TARGETS = 33 个`，`.github` 下**只有
`.github/PULL_REQUEST_TEMPLATE.md` 在面内**，`ci.yml 在面内? False`。
`.yml` 从来不在面内（§2.40 只把"位置推导"扩展到 `.md`）。

两层都失明 ⇒ **机器完全看不见这三个数字**。与 §2.36.8（枚举清单靠人眼）/
§2.38（CI 逐字枚举）/ §2.40（扫描面自声明）/ §2.42（自检未被跑）/
§2.45（阈值常量无对账）**同型第六次**。

### 2.46.4 修法

**(a) 把三处数字改成真值**（`build/_cifix.py`，每处断言旧串恰好出现一次）：

| 位置 | 修复前 | 修复后 |
|---|---|---|
| `ci.yml:111` 静态调用点 | `**37**` | `**39**` |
| `ci.yml:111` 默认运行 | `**34**` | `**36**` |
| `ci.yml:115` | `"34 项全绿"` | `"36 项全绿"` |
| `ci.yml:110` 更新说明 | 「2026-10-05 更新…」 | 「2026-10-06 复核；此前两轮都写过期过：『静态 36 / 默认 33』→『静态 37 / 默认 34』。现由 doccheck 的 ci.yml 项数判据看住，见 docs/HANDOVER.md §2.46」 |

⚠️ 这里**改成新数字**而不是像 §2.39 那样删数字：这三行是解释"CI 为何会看到
`[skip]`"的必要背景，删掉数字读者无法判断规模；§2.39 删数字的适用条件是
"数字本身无信息量"。保留数字的前提是**另加判据让它不会再静默过期** ——
即下面的 (b)。

**(b) 加机器判据 `ci_count_claims()`**（`tools/doccheck.py`），只锚定
`.github/workflows/ci.yml` 这一个文件、用它的**专有措辞**匹配：

| 形态 | 正则 | 应当等于 |
|---|---|---|
| 静态调用点 | `静态\s*\`Check\`\s*调用点\s*\*{0,2}(\d+)\*{0,2}\s*个` | 总项数 |
| 默认运行 | `默认运行\s*\*{0,2}(\d+)\*{0,2}\s*项` | 默认跑项数 |
| 要求N项全绿 | `要求\s*["“]?\s*\*{0,2}(\d+)\*{0,2}\s*项全绿` | 默认跑项数 |

判据：① 三条形态**各自**必须至少命中一次，值 == 真值；② 任一形态数到
**0** 条 ⇒ FAIL（**措辞改了、判据失锚，不得读成"没有漂移"**）；③ 同一形态
多处出现则**逐处**判，不只看第一处。

真值不写死：`_gate_counts()` 每次现读 `tools/release_check.ps1` 数
`^\s*Check\s+'` 与 `^\s*if\s*\(\s*\$With\w+\s*\)`。

`main()` 新增 **0d** 步（紧跟 0c），打印
`[ok] ci.yml 项数口径: 静态调用点 39 / 默认运行 36 与 release_check.ps1 现数一致`。

**为什么只锚定这一个文件**：措辞族全库普查（`build/_cifamily.py`，六条正则）
共 **21 处**命中，其中大部分是**历史记录**（`docs/CONTINUATION_PLAN.md:480`
等记的是 Q4 把 14 项改成 33 项（默认 30）、`docs/HANDOVER.md:1599` 记
`门禁 34 项 (默认 31)` 的基准变更、`docs/HANDOVER.md:2772` 记 37→38 的修正）
与**同形异义**（`tools/android_compile_check.py:57-58` 是 API 21/28、
`tools/perf_baseline.py:228` 是采样次数默认 15）。全库匹配会要求**篡改历史
记录**才变绿 —— 正是 §2.40 反向守卫在防的那类错误。

### 2.46.5 承重验证：对**真实** ci.yml 注入漂移（`build/_ciload.py`）

不只看自检，而是直接改真实文件、跑完整 doccheck、再逐字节还原：

| 注入 | rc | 报错条数 | 报错逐字 |
|---|---|---|---|
| 基线（不注入） | 0 | 0 | — |
| **A** 静态调用点 `39 → 37` | 1 | 1 | `[X] .github/workflows/ci.yml:111 「静态调用点」写作 37，但真值 = 39（静态 Check 调用点）—— 注释已漂移` |
| **B** 默认运行 `36 → 34` | 1 | 1 | `[X] .github/workflows/ci.yml:111 「默认运行」写作 34，但真值 = 36（默认跑的项数（总 39 − -With* 3））—— 注释已漂移` |
| **C** `"36 项全绿" → "34 项全绿"` | 1 | 1 | `[X] .github/workflows/ci.yml:115 「要求N项全绿」写作 34，但真值 = 36（默认跑的项数（总 39 − -With* 3））—— 注释已漂移` |
| **D** 三条形态整条删除 | 1 | 3 | 三条 `找不到「…」形态的项数声明 —— 判据失去锚点，不得读成"没有漂移"` |
| 还原后 | 0 | 0 | **逐字节一致 = YES** |

**7/7 通过。**

### 2.46.6 自检用例（第四批 `ci_cases`）

`selftest()` 新增 **6 条**用例，走第四入口 `ci_count_claims`，与
`cases` / `gl_cases` / `th_cases` **一起打印、一起计数**（`total` 与 `neg`
两处都必须同改，否则"暗处运行、看起来不存在"—— 这条纪律写在
`tools/doccheck.py` 的打印循环注释里）：

- `真实仓库 ci.yml 项数口径 -> 不报`（期望 0）
- `ci.yml 静态调用点漂移(39->37) -> 必须报`（1，关键词 `静态调用点`）
- `ci.yml 默认运行漂移(36->34) -> 必须报`（1，关键词 `默认运行`）
- `ci.yml 要求N项全绿漂移(36->34) -> 必须报`（1，关键词 `要求N项全绿`）
- `ci.yml 三处全漂 -> 三处各报一条`（**3**，验证三形态各自独立报错）
- `ci.yml 口径句整条消失 -> 必须报`（**3**，验证失锚不静默）

自检总量：**40 项（24 项负向注入 / 16 项合规豁免）**（原 34 项）。

### 2.46.7 本轮探针自己踩的两个坑（同类第七、第八次）

**坑一：还原写在脚本体里 ⇒ 断言中断后把被测文件停在注入态。**
`build/_ciload.py` 首版把"还原"写成脚本体末尾的一条语句，D 用例的
`assert t.count(blk) == 1` 抛 `AssertionError` 后**直接退出，还原没执行** ——
`.github/workflows/ci.yml` 停在注入态（`:115` 残留 `"34 项全绿"`）。
修法 = 抽成 `restore()` 并放进 `finally`。**教训：凡探针会改被测文件，
还原必须在 `finally` 里，不能依赖脚本跑到末尾。**

**坑二：计数口径漏掉判据的一半文案 ⇒ 把"判据正常报错"读成"判据没报"。**
同一脚本用 `ci\.yml:\d+` 数错误条数，而**失锚类错误没有行号**（整份文件
失锚，无行可指）⇒ D 用例实测报 3 条却被数成 0，输出 `rc=1 … 报 0 条`，
看起来像判据失效。修法 = 改成"行首 `[X]` 且提到 ci.yml"。
**教训：计数口径必须覆盖判据的**全部**文案形态，否则会把自己的量具误差
当成被测对象的性质。**（与 §2.37.6 / §2.42 / §2.43.7 / §2.45.3 同型第
四、第五次。）

**坑三（小）：D 用例的块锚点漏了行首缩进。** 文件里是 6 空格 + `# `，而
探针把整块文本按无缩进拼接 ⇒ `0 次命中`，断言中断（并触发坑一）。修法 =
改成只删三条形态本身，不依赖缩进。

### 2.46.8 诚实边界

1. **只判 `ci.yml` 一个文件**。`tools/ci_sim.ps1` 是 ci.yml 的本地镜像，
   但它**没有**项数注释（`:122` 只讲为什么把逐字枚举换成 `compileall`）⇒
   本判据不覆盖它；若哪天镜像里也写项数，需扩展。
2. **只判这三种措辞**。换一种说法（例如"共 39 项门禁"）就落在判据外 ——
   但那时判据会**报失锚**（判据 ②），不会静默。
3. **不判 `:67` 的 `覆盖 39 项 (默认 36)`**：那行**已经在 `RE_GATE_N` 的
   射程内**（含 `release_check` 前缀），由既有数字漂移判据兜。本判据刻意
   不重复它。
4. **历史叙述刻意不匹配**：`:110` 修复后写的「此前两轮都写过期过：『静态
   36 / 默认 33』→『静态 37 / 默认 34』」**不在三条形态内**（写的是
   `静态 36 / 默认 33` 与 `静态 37 / 默认 34`，非 `静态 \`Check\` 调用点
   **N** 个`）⇒ 不会被误判为现值。

### 2.46.9 验证

| 项 | 结果 |
|---|---|
| `py_compile tools/doccheck.py` | OK |
| `tools/doccheck.py --selftest` | **PASS: 40 项（24 项负向注入 / 16 项合规豁免）** |
| `tools/doccheck.py` 生产跑 | `[ok] ci.yml 项数口径: 静态调用点 39 / 默认运行 36 …` / 检查数字 929 处, 错误 0, 警告 0, 豁免 201 / **PASS** |
| 真实文件注入 A/B/C/D + 还原 | **7/7 通过**，还原逐字节一致 |
| `build/_hygiene.py` | 15 个文件, 0 处异常 |
| `tools/docclaim_check.py` | PASS (8/8) |
| 全门禁 `release_check.ps1 -SkipDirtyCheck` | **PASS: 36 项检查全通过**（`[ok]` 36 / `[X]` 0 / `[skip]` 0） |

### 2.46.10 CI 实测

提交 `590f2bf`（`fix(doccheck)!: ci.yml 门禁项数口径的机器对账`，3 files /
+337 −7）推送后：

| 项 | 结果 |
|---|---|
| CI run | **`37780396166`**（head `590f2bf`）**`completed success`** |
| 四 job | `linux-portability` / `build-and-verify` / `reproducible` / `sdk-package` **全部 success** |
| `Public-material drift (doccheck)` 步 | success ⇒ **新判据 0d 在 MSVC 14.51.36231 / Python 3.12.10 的 runner 上同样执行** |

⚠️ 一个**新的观测**（诚实记录）：CI 上 `build-and-verify` 里 **`Migration cost gate`
这一步是 `success`**，而本机同一提交下 `tools/migration_gate.py --quiet` 报
`FAIL: M3 15.6% > 12%`。这不是矛盾，而是 §2.43.3 已记名的**工具链抖动**：
本机 MSVC 14.44.35207 的 M3 = **15.6%**、CI MSVC 14.51.36231 的 M3 = **6.2%**，
同一份代码落在阈值 12% 的两侧。本轮改动**没有触碰** `migration_gate`，故
两侧数字与 §2.43/§2.44 记录一致。

## 2.47 源码注释里的 `file:line` 交叉引用：两层失明，14 处已漂移（2026-10-06）

### 2.47.1 缘起：§2.46 普查的副产物

§2.46 查 `.github/workflows/ci.yml` 的门禁项数注释时，为了确认"哪些文件在
`doccheck` 的扫描面内"，顺手看了一眼 `tools/doccheck.py` 的豁免规则。结果发现
一条比项数过期更安静的东西：**仓库里大量注释用 `file:line` 指向别处的具体代码，
而没有任何检查器核对那个行号是否还指着原来那句。**

与 §2.36.8（枚举清单靠人眼）、§2.38（CI 逐字枚举）、§2.40（扫描面自声明）、
§2.42（自检未被门禁跑）、§2.45（阈值常量无对账）、§2.46（ci.yml 项数不在面内）
**同型，这是第七个实例** —— 载体从"清单""枚举""扫描面""自检""常量"换成了
"行号引用"，但形状一样：**事实在文件里，没有任何判据在用它。**

### 2.47.2 两层同时失明

**第一层：`doccheck` 根本不看这些文件。**

`build_targets()`（`tools/doccheck.py:90-112`）只收 `.md`：根目录 `*.md`、
`.github/*.md`、`publish/*.md`、`docs/marketing/*.md`、以及头部
`header_declares_current(t)` 为真的 `docs/**/*.md`。实测 `TARGETS = 33 个`，
`.github` 下**只有** `.github/PULL_REQUEST_TEMPLATE.md` 在面内。而本轮的引用
全在 `.py` / `.yml` / `.c` 里 —— 这些**从来不在面内**。

**第二层：即使看了，也会被豁免规则整类排除。**

`RE_XREF`（`tools/doccheck.py:218`）匹配形如 `文件:行号` 的串，
`exempt()` 的第四步最后一条（`:350-351`）是：

```python
        if RE_XREF.search(line):
            return '转述他文'
```

注释 `:214` 逐字写着 `# 转述他文: **必须带行号**才是转述别处`。于是
**任何带行号的引用所在行，整行都被判"转述他文"而豁免** —— 判据存在，但豁免
规则正好把这一整类排除在外。自检里还有一条对应用例
（`tools/doccheck.py:1353` `case('转述他文(带行号) -> 豁免', ...)`），说明这个
豁免是**有意设计**的，不是疏漏；只是没有人同时想到"那谁来核对被转述的那一行的行号"。

⇒ 结论：`tools/window_check.py` 这类源码注释里的过期引用，
**永远不会被任何检查器报红**。

### 2.47.3 普查方法（四轮收紧，最终只有一种可信）

| 探针口径 | 结果 | 为什么不可用 |
|---|---|---|
| 宽口径（含路径猜测） | 可解析 541 / 可疑 44 / 目标不存在 136 | 噪声太大：`ATTACK_DRILL.md:3` 是**轮次号**不是文件引用 |
| basename 全库解析 | 引用 373 / 可疑 31 / 不存在 2 / 正常 340 | 可用作**候选集**，但"可疑"仍含大量假阳 |
| token 重叠启发式 | 可解析 85 / 不共享 token 42 | 误报率过高：大量引用是"注释描述"而非"逐字摘录" |
| 窄口径（同行须同时有 `` `file:line` `` 与 `` `标识符` ``） | 命中 42 / 目标行不含该标识符 30 | 仍不可用：`window_check.py:27` → `demo/main.c:614` 目标行是 `/*`，而那正是 `else` 分支**注释块的起始行**，引用语义正确 ⇒ **结构性行 != 过期** |
| 全库 `git log -S` 出生对比 | 未解析 2 / 无法出生对比 77 / 未变 7 / 已变 1 | 覆盖面只有 8/87 ⇒ 不能当判据 |

⭐ **最终可信方法 = 逐条显式出生对比**：对每条引用执行
`git log -S '<引用串>' --format=%H -- <源文件>` 取**最早**提交；再
`git show <出生rev>:<目标文件>` 取该 revision 的目标行，与工作树目标行对比。
两者不同 ⇒ 真漂移；相同 ⇒ 引用仍正确。

对"**调用点留在 X**"这类**时态句**，还需要一个替代判据（因为目标行现在
当然不在 X）：遍历目标文件全历史，找**哪个 revision 的 X 行恰好等于该语句**；
命中即证明**写下时正确**，属历史叙述不得改。

### 2.47.4 修掉的 14 处（6 + 8）

**第一批 6 处**（`.github/workflows/ci.yml:32`、`tests/e2e.py:851`、
`tools/window_check.py:29` / `:699` 两处行号 + `:28` / `:62-63` 两处时态断言）：

| 源 | 旧 | 新 | 新行真值 |
|---|---|---|---|
| `.github/workflows/ci.yml:32` | `tools/ci_sim.ps1:61` | **`:71`** | `powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -RecordSeeds -SkipSign` |
| `tests/e2e.py:851` | `src/selfcrypt.c:347` | **`:389`** | `sc_do_range(i, 0); /* 重加密 (对称 XOR), 不校验 */` |
| `tools/window_check.py:29` | `src/antidebug.c:548` | **`:559`** | `prot_antidebug_scan(&rep);` |
| `tools/window_check.py:699` | `src/antidebug.c:548` | **`:559`** | 同上 |
| `tools/window_check.py:28` | 骨架**仍是**修复前的老写法 | 骨架**当时也是**老写法（已在本提交一并修复） | 时态断言：`c8a47994` 同一提交就修好了骨架 |
| `tools/window_check.py:62-63` | 那里的违规是**潜伏**的; 仍要修 | 那里**若出现**违规也是**潜伏**的 (不会当场崩), 但仍必须纳入扫描 | 原句在 `c8a47994` 修完违规后已无"违规可潜伏" |

**第二批 8 处**（同日稍后，由全库重跑普查发现的额外真漂移）：

| 源 | 旧 | 新 | 新行真值 |
|---|---|---|---|
| `tools/guard_selftest.py:35` | `src/integrity.c:163-173` | **`:188-198`** | `:188` = `if (prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_EXT) != PROT_OK) {`；`:198` = `continue;` |
| `tools/guard_selftest.py:527` | `src/integrity.c:173` + continue | **`src/integrity.c:198` + continue** | `:198` = `continue;` |
| `tools/mutate_check.py:323` | `tests/vmc_tests.py:176` | **`:250`** | `ok = out.startswith('RESULT 1')` |
| `tools/mutate_check.py:384` | `vmc_tests.py:176` | **`:250`** | 同上（该处引用**不带 `tests/` 前缀**，替换串分别构造） |
| `tools/prot_dbg.py:1065` | `demo/main.c:657` | **`:679`** | `prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000);` |
| `tools/release_check.ps1:459` | `.github/workflows/ci.yml:244-297` | **`:340-393`** | `:340` = `linux-portability:`；`:393` = `python3 tools/attackcheck.py --quiet` |
| `tools/selfcrypt_residency_check.py:424` | `tools/guard_selftest.py:338 _wait_ready` | **`:356 _wait_ready`** | `:356` = `    def _wait_ready(h, proc, va_rdy):` |
| `tools/window_check.py:492` | `src/integrity.c:142` | **`:167`** | `:167` = `static prot_ad_scan_fn volatile g_ad_scan_fn = prot_antidebug_scan;` |

**为什么第二批才有：** 第一批是靠"读 §2.46 时顺手看到"发现的，只覆盖了
`tools/window_check.py` 与 `ci.yml` 两处；第二批才是**全库普查**的产物。
这本身就是 §2.47 的主题的一次自证 —— 第一批的"看见"靠人眼。

### 2.47.5 ⭐ 刻意判定为"不改"的 5 条（假阳性）

普查报出的 13 条"已变"候选里，**5 条是历史叙述**，改写它们等于篡改历史记录：

1. `tests/e2e.py:518` 的恢复来源是 `` `git show 22826c5^:tests/e2e.py:216-255` ``
   —— 这是 `git show <rev>:<path>:<range>` 形态，**不是** `<file>:<line>`。
   实测 `22826c5^:tests/e2e.py` 共 866 行，`:216` = `class DebugAttacher(object):`
   ⇒ 语义正确。
2. `tools/check_undef.py:12` 与 `tools/release_check.ps1:969` 的
   「调用点却留在 `tests/e2e.py:515`」—— 实测 `tests/e2e.py:515` 在
   **`5d601c5`（2026-10-02）** 时**真的**等于 `dbg = DebugAttacher()`
   （遍历全历史，仅此一个 revision 命中），而 `tools/check_undef.py` 诞生于
   **`bc68b1129b`（2026-10-05）** ⇒ **写下时正确**，是描述当时事故的历史句。
   （`DebugAttacher` 调用点现址 = `tests/e2e.py:694`，类定义现址 = `:521`。）
3. `tools/docclaim_check.py:124` 的 `> **行号更正（2026-10-03）**：上述示例文本
   **当时**在 `tools/release_check.ps1:79`，现值在 **`:170`**`
   —— **显式带"当时/现值"双行号**，`release_check.ps1:170` 现值实测吻合 ⇒ 自洽。
4. `tools/docclaim_check.py:127` 的 `` `tools/doccheck.py:156-163` `` —— 描述的是
   **该函数当时**的行锚定实现（现已移到 `:451 actual_gate_count()`）⇒ 历史叙述。
5. 各处的 `22826c5` / `5d601c5` 提交号 —— 历史事实。

⇒ **探针只比"目标行现在 vs 出生时刻"，不读引用行是否自带"当时/现值"语境**
—— 这正是它产生假阳性的原因，也是它**不能升格为门禁判据**的第二个理由。

### 2.47.6 ⭐ 为什么不给它做门禁判据

三条候选判据的实测误报率（见 2.47.3 表）：token 重叠口径 42 → 30 假阳；
结构性行口径 8 条里含 `else` 分支注释起始行等真阳误判；`git log -S` 出生对比
覆盖只有 8/87。**没有一条达到"能进门禁"的精度。** 一个只会误报的检查器比
没有更危险（§3.8），故本轮**只修引用、不建判据**，与 §2.41 对陈旧复选框的
处置同型 —— 退回操作提示，而不是硬造一个不可靠的 gate。

### 2.47.7 诚实边界

- **`git log -S` 出生对比探针的汇总数字不可引用**：同一天同算法的两次运行
  给出 `无法出生对比 77 / 未变 7 / 已变 1` 与 `无法出生对比 4 / 未变 68 / 已变 13`
  —— 可出生对比数从 8 跳到 72。差异来源未完全定位（疑 `git log -S` 的 `--`
  路径限定或缓存状态）。**只有逐条 `git log -S <引用串> -- <源文件>` +
  `git show <rev>:<file>` 对照才可信**，汇总统计一律不采信。
- 本轮**只覆盖 `file:line` 形态**的引用。`docs/HANDOVER.md` 里的
  `§2.xx` 节号引用、`git show <rev>:<path>` 形态、以及不带行号的
  `` `file.py` `` 引用，**都不在本轮射程内**，未普查。
- 修完后**没有**新增任何自动判据 ⇒ **这 14 处将来还会再次漂移**，本轮只是
  把当前这一代修对。这是有意的取舍（见 2.47.6）。
- 全库还有多少处引用未被本轮覆盖，**没有可靠数字**（见上面第一条边界）。

### 2.47.8 验证

| 项 | 结果 |
|---|---|
| 8 处新引用指向的行 | **8/8 [ok]**（逐行实测：`src/integrity.c:188`/`:198`、`tests/vmc_tests.py:250`、`demo/main.c:679`、`ci.yml:340`/`:393`、`tools/guard_selftest.py:356`、`src/integrity.c:167`） |
| 残留旧串扫描 | **0**（8 个旧串在 6 个文件里全部无残留） |
| 文件字节 | 6 个文件**全部 delta 0 字节**（改的是行号数字，长度相同） |
| 卫生 | `build/_hygiene.py` **15 个文件, 0 处异常** |
| `tools/doccheck.py` | **PASS**（`检查数字 942 处, 错误 0, 警告 0`，豁免 204） |
| `py_compile` | 6 个改动的 `.py` **rc=0** |
| `tools/release_check.ps1` / `tools/ci_sim.ps1` | `parse errors: 0`（`[Parser]::ParseFile`） |
| 受影响工具自检 | `guard_selftest` PASS（正向 0 / 负向 3）；`window_check` PASS（24 文件 / 308 函数 / 9 目标）；`selfcrypt_residency_check --selftest` **4/4 变异被抓** |

### 2.47.9 CI 实测

提交 `b01cb8d`（`docs+fix: 源码注释里 file:line 交叉引用逐条核对 —— 14 处已漂移`，
9 files / +169 −16）推送后：

| 项 | 结果 |
|---|---|
| CI run | **`37797447952`**（head `b01cb8d`）**`completed success`** |
| job | `linux-portability` 15s / `build-and-verify` / `reproducible` / `sdk-package` **全部 success** |

⚠️ 本轮改动**只改注释里的行号数字**，未触碰任何可执行逻辑（6 个文件
delta 0 字节），故 CI 上与行号无关的步骤不受影响；`Public-material drift
(doccheck)` 步 success 说明 §2.47 新增的文档段落自身通过了 doccheck 的数字与
结构判据。


## 2.48 `ci_sim.ps1` 的"保持与 ci.yml 同步"：一句人工承诺，缺口已连犯数月（2026-10-06）

### 2.48.1 缘起

`tools/ci_sim.ps1:6` 逐字写着：

```
# 步骤映射 (保持与 ci.yml 同步; 每次改 ci.yml 必须同步这里):
```

这是**人工承诺**。§2.36.8 / §2.38 / §2.40 / §2.42 / §2.45 / §2.46 / §2.47
都在堵同一类缺陷（**事实可得，但没有任何判据在用它**），本节是第 8 个实例：
**`ci_sim.ps1` 到底有没有跟上 `ci.yml`，从来没有任何检查器问过。**

### 2.48.2 实测：它没跟上，而且缺的不是"慢"的那些

按**工具 basename** 比对 `ci.yml` 的 `build-and-verify` job（16 个工具）与
`ci_sim.ps1` 的 `Step` body（方法见 §2.48.4）：

| 工具 | ci.yml | ci_sim（修复前） | 本机实测耗时 |
|---|---|---|---|
| `modcheck.py` | `:69` | **缺** | 0.1s |
| `drills.py` | `:72` | **缺** | 0.1s |
| `doccheck.py` | `:75` | **缺** | 0.2s |
| `conformance.py` | `:88` | **缺** | 0.0s |
| `skeleton_check.py` | `:97` | **缺** | 17.4s |
| `mutate_check.py` | `:101` | **缺** | 187.5s |
| `migration_gate.py` | `:105` | **缺** | 107.7s |
| `release_check.ps1` | `:128` | **缺** | — |

⭐ **关键事实：缺的八个里有四个合计 <0.5 秒。** 这不是"为省时间而刻意排除"
——`ci_sim` 声称本地等效执行 CI 的步骤，却**从未跑过门禁本体**
（`release_check.ps1`），也从未跑过四个几乎不花时间的静态检查。
`docs/HANDOVER.md:1244` 只反向记了一句「`release_check.ps1` 仍不含 SDK 打包
（`ci_sim.ps1` 已含，门禁未含）」—— **没有任何记录说明这些缺口是刻意的。**
`docs/INFRA_PLAN.md:98` 的验收标准写的是「`ci_sim.ps1` 本地跑通**全部** CI 步骤，
PASS」。

### 2.48.3 修法

**(a) 补上 5 个步骤**（`tools/ci_sim.ps1`，紧跟 `Step 'protchain P1-P6'`，
与 `ci.yml` 同名同序）：

```
Step '模块契约 (modcheck)' { & $py -X utf8 tools\modcheck.py --all-compositions }
Step '攻防记录 (drills lint)' { & $py -X utf8 tools\drills.py lint }
Step '对外材料 (doccheck)' { & $py -X utf8 tools\doccheck.py }
Step '协议兼容性 (conformance)' {
    & $py -X utf8 tools\conformance.py --selftest
    if ($LASTEXITCODE -ne 0) { throw 'conformance selftest failed' }
    & $py -X utf8 tools\conformance.py modules.json
}
Step '骨架回归 (skeleton_check)' { & $py -X utf8 tools\skeleton_check.py }
```

**(b) 把三个刻意排除的步骤写进头部注释**（此前**根本没写**，等于默不作声）：

```
#   刻意**排除**的三个 ci.yml 步骤 (2026-10-06 复核):
#     · Checker mutation test (mutate_check) —— 本机实测 187s；
#     · Migration cost gate (migration_gate) —— 本机实测 108s, **且** M3 有
#       工具链抖动 (本机 MSVC 14.44 15.6% FAIL vs CI MSVC 14.51 6.2% PASS,
#       见 docs/HANDOVER.md §2.43) ⇒ 本地跑它会把 CI 的绿读成红。
#     · Full release gate (release_check.ps1) —— 门禁本体, 自己会做 Release
#       构建 + 39 项检查; `ci_sim` 已经跑了一遍 Build, 嵌套跑显著变慢且职责
#       重叠。由 CI 的 `:127 Full release gate` 负责。
```

第二项的理由值得单说：**`migration_gate` 在 CI 上是绿的、在本机是红的**
（§2.43.3 已记名的工具链抖动）。把这一步放进"本地 CI 模拟器"，只会让本地
读到一个 CI 不会给的红色 ⇒ **排除是正确决定，但必须写出来**，否则下一个人
会以为是漏了。

**(c) 给这句承诺配上机器判据**（`tools/doccheck.py` 新增 `ci_sim_sync()` +
第 5 个入口，`main()` 加 **0e** 步）：

- `ci_sim_tool_sets()`：现读 `ci.yml` 的 `build-and-verify` job 与
  `ci_sim.ps1`，各抽出**工具 basename 集合**（`ci.yml` 侧只取该 job 的
  `run:` 行，含 `run: |` 之后的缩进 body）；
- `_CI_SIM_EXEMPT = {'mutate_check.py': …, 'migration_gate.py': …,
  'release_check.ps1': …}` = **显式豁免，必须写理由**；
- 判据 ①：`ci.yml` 有而 `ci_sim` 无、且不在豁免表 ⇒ **FAIL**；
- 判据 ②：豁免项**其实已经在 `ci_sim` 里跑了** ⇒ **FAIL**（豁免过期；
  留着一个已满足的豁免会掩盖真的漏项）；
- 判据 ③：任一侧数到 **0** 个工具 ⇒ **FAIL**（解析前提被破坏，
  **不得**读成"没有差异"）。

### 2.48.4 为什么按**工具 basename** 比，不按步骤名比

两侧的步骤名措辞本来就不同 —— 按名字比会得到一片**假差异**：

| ci.yml | ci_sim.ps1 |
|---|---|
| `:45 Run e2e suite (T1-T30)` | `Step 'e2e T1-T30'` |
| `:68 Module contract (modcheck)` | `Step '模块契约 (modcheck)'` |
| `:96 Skeleton regression (DIY 路径)` | `Step '骨架回归 (skeleton_check)'` |

路径风格也不同（`tools/modcheck.py` vs `tools\modcheck.py`）。唯一**稳定可比
且机器可判**的键是**文件 basename**。

### 2.48.5 ⭐ 我自己的判据踩的坑：注释里的提及被当成"已覆盖"（同类第 12 次）

判据第一版把 `ci_sim.ps1` 侧写成 `set(_TOOL_RE.findall(sim_src))` —— **扫全文**。
于是第一次跑生产判据时报 `[ok] ci_sim 工具集: 14 / 16 … (2 项显式豁免)`：
`release_check.ps1` **看起来已经被覆盖**，而它**恰恰是当时唯一的真缺口**。

根因是我的**(b) 步注释自己**造成的：`tools/ci_sim.ps1:18` 写了
`` `tools/release_check.ps1 -With*` ``、`:94` 写了 `` `release_check.ps1` `` ——
**声明本身被当成了覆盖**。这与 §2.40「扫描面自声明」是**同一类错误**，
而我正是在写 §2.40 的判据时学到这一点的。

为什么 `--selftest` 全绿也照样漏：`sim_cases` 走 `ci_sim_sync()` 时传的是
**已解析的集合**（`_mk_sim`），**不经过文件扫描** ⇒ 扫描面这一层的缺陷
完全在自检的盲区外。

修法 = 新增 `_step_body_tools(text)`：**只收集 `Step` 块 body 里的工具**，
并且逐行剥掉 `#` 之后的**行内注释**。修后 `14 / 16` → **`13 / 16`**（真值），
并把这条扫描面本身断言成用例（走 `_step_body_tools()` 而非 `ci_sim_sync()`，
因为它测的是**扫描面**，不是判据）：

```python
_scn = ("# 注释里提到 release_check.ps1 与 mutate_check.py\n"
        "Step 'real' {\n"
        "    & $py tools\\modcheck.py --all-compositions  # 行内注释: mutate_check.py\n"
        "}\n")
_got = _step_body_tools(_scn)
if _got != {'modcheck.py'}:
    fails.append('ci_sim 扫描面守卫: `_step_body_tools` 把注释里的工具名也算进去了 …')
```

### 2.48.6 承重验证（对**真实**文件注入 → 跑完整 doccheck → 逐字节还原）

| 注入 | rc | 报错 |
|---|---|---|
| 基线 | 0 | 0 |
| **A** 从 `ci_sim.ps1` 删掉 `modcheck` 步骤 | 1 | 1（`缺 ci.yml 的步骤（工具 \`modcheck.py\`，ci.yml:69）`） |
| **B** 从 `ci_sim.ps1` 删掉 `doccheck` 步骤 | 1 | 1（同上，`doccheck.py`） |
| **C** 从 `ci.yml` 删掉 `modcheck` 步骤（真值源缩小） | 0 | 0（**正确的沉默**：两边都没有就不算不同步） |
| **D** 让豁免项 `mutate_check.py` 出现在 `ci_sim.ps1` | 1 | 1（`豁免过期，必须从 _CI_SIM_EXEMPT 删掉`） |
| 还原后 | 0 | 0 |

**逐字节还原一致 = True**（`ci_sim.ps1` BOM=True/crlf=187/bareLF=0/9424 B；
`ci.yml` BOM=False/crlf=0/bareLF=426/20477 B，两侧换行风格均未变）。

自检新增第 5 批 **`sim_cases` 5 条**，**必须与其余四批一起打印、一起计数**
（否则"暗处运行、看起来不存在"）⇒ `[doccheck-selftest] PASS: 45 项
（28 项负向注入 / 17 项合规豁免）`（原 40 项）。另加 §2.48.5 的扫描面守卫 1 条
（`fails` 通道，不增计数）。

### 2.48.7 端到端实测：新步骤真的跑了

`tools/ci_sim.ps1 -SkipTest -SkipSdk`（只验 Build + repro）与
**`tools/ci_sim.ps1 -SkipSdk`**（全量）均 **rc=0 / `[ci_sim] PASS (all steps)`**。
全量那次逐行可见五个新步骤**确实执行**：

```
[ci_sim] step: 模块契约 (modcheck)
[ci_sim] step: 攻防记录 (drills lint)
[ci_sim] step: 对外材料 (doccheck)
[ci_sim] step: 协议兼容性 (conformance)
[ci_sim] step: 骨架回归 (skeleton_check)
…
[e2e] 平台=win  总计 30: PASS 30 / FAIL 0 / SKIP 0 / NA 0
[repro_check] PASS: reproducible (demo.exe + vm.blob SHA-256 identical)
[ci_sim] PASS (all steps)
```

### 2.48.8 诚实边界

1. **只判"工具集覆盖"，不判"顺序/参数/开关"**：判据看不见步骤顺序错了、
   参数变了（如 `--quiet` 被去掉）、或 `$SkipTest` 门控范围不同。
2. **判据看不见"两边都漏"**：若 `ci.yml` 删掉某步、`ci_sim` 同步删掉，
   判据报 0 条（这**正是** §2.48.6 的 C 用例 —— 刻意的正确沉默）。
3. **`linux-portability` job 不在判据内**：它需要 gcc/WSL，
   `tools/ci_sim.ps1:29-30` 已写明由 Linux runner 负责。
4. **`release_check.ps1` 是"明写的豁免"而不是"已覆盖"**：本轮**没有**把它
   加进 `ci_sim`。它现在在 `_CI_SIM_EXEMPT` 里并写明理由（§2.48.3(b)）。
   ⇒ **`tools/ci_sim.ps1` 至今仍不是"全部 CI 步骤"**，
   `docs/INFRA_PLAN.md:98` 那句「本地跑通全部 CI 步骤」**依然不成立** ——
   区别只是这条边界**从沉默变成了记名**。
5. **豁免表是"人写的理由"**：判据只能保证"豁免项不在跑"，保证不了
   "豁免的理由还成立"。`migration_gate` 那条（本机红 / CI 绿）就是靠 §2.43
   的工具链抖动，工具链一变它就该被重审。


### 2.48.9 CI 实测

提交 `c3902bc`（3 files / +446 −5）推送后：

| 项 | 结果 |
|---|---|
| CI run | **`37810000352`**（head `c3902bc`）**`completed success`** |
| 四 job | `build-and-verify` / `linux-portability` / `reproducible` / `sdk-package` **全部 success** |
| 门禁日志 | `build/logs/release_check_20261008_*.log` ⇒ `[release_check] PASS: 36 项检查全通过` |

本地同提交的全门禁逐项亦全绿（`[ok]` 36 / `[X]` 0 / `[skip]` 0），其中
`对外材料 (doccheck)` 项即新判据的宿主 —— 它在本机与 CI 两侧都执行，
故 `ci_sim_sync()` 不只在开发机上有效。

补充一条**观测**（诚实记录）：`tools/ci_sim.ps1` 本身**不在 CI 里跑**
（CI 跑的是 `.github/workflows/ci.yml`）。所以"补进 `ci_sim` 的 5 个步骤在
CI 上验证过"这句话**不成立** —— 它们是在**本机**由
`tools/ci_sim.ps1 -SkipSdk` 全量实跑验证的（rc=0 / PASS，§2.48.7）。
新判据 `ci_sim_sync()` 则**在** CI 里跑（它是 `doccheck` 的一部分）。


## 2.49 doccheck 自检自身的漏洞：批次被掏空时"PASS: N 项"照样是绿的（2026-10-06）

### 2.49.1 缘起：§2.48 的教训指向了它自己的自检

§2.48 记下一条一般性错误：**"声明被当成覆盖"** —— `tools/ci_sim.ps1` 的注释里
提了一句 `release_check.ps1`，判据就以为那个工具已经被覆盖了。那次错误发生在
**判据的扫描面**上。

本节是同一类错误出现在**另一个位置**：`tools/doccheck.py` 的 `selftest()`。
它的收尾统计是这么写的（本节写作时的原文）：

```python
    total = (len(cases) + len(gl_cases) + len(th_cases) + len(ci_cases)
             + len(sim_cases))
    ...
    print('[doccheck-selftest] PASS: %d 项（%d 项负向注入 / %d 项合规豁免）'
          % (total, neg, total - neg))
```

`total` 与 `neg` **都是长度**。于是：清空一个批次、或把一个批次的用例砍掉一半，
**不会报错**，只会让打印出来的数字**变小**。而 `PASS: 20 项` 与 `PASS: 45 项`
长得一样绿 —— **没有任何人记得该是多少**。

这正是本链条从 §2.36 起一直在堵的那件事的**最内层版本**：判据存在、判据在跑、
判据是绿的，但**判据的覆盖面本身没有人看**。

### 2.49.2 修法：非空 + 紧贴当前值的总数下限

`tools/doccheck.py` 的 `selftest()` 在算出 `total` 之后、`if fails:` 之前新增：

```python
    _BATCHES = (('cases', cases), ('gl_cases', gl_cases), ('th_cases', th_cases),
                ('ci_cases', ci_cases), ('sim_cases', sim_cases))
    for _bn, _bl in _BATCHES:
        if not _bl:
            fails.append('自检批次 `%s` 被清空 —— ...' % _bn)
    _TOTAL_FLOOR = 45
    if total < _TOTAL_FLOOR:
        fails.append('自检用例总数 %d 低于下限 %d —— 有用例被删或被掏空。'
                     '（下限**紧贴当前值**：删用例须显式下调此数字并说明理由）'
                     % (total, _TOTAL_FLOOR))
```

**为什么下限紧贴当前值，而不是留几项余量** —— 见 2.49.4，那是本轮最有价值的一条实测。

### 2.49.3 诚实边界

- 它**只**防"用例被删/被掏空"，**不**防"用例写错"：一条断言写反了的用例照样计数。
  后者由 §2.48 那类**扫描面守卫**（直接断言 `_step_body_tools()` 自身）与承重验证
  （对真实文件注入、看判据是否变红）覆盖，不是这条守卫的职责。
- `_TOTAL_FLOOR` 是**手写数字**，删用例时必须人肉下调。这是刻意的：删用例是重大
  动作，值得被强制看见一次。代价是**新增**用例时不必改它（只会上抬实际值），
  但**删**用例时若忘了下调，门禁就会拦住你 —— 这正是想要的方向。
- 它看不见"批次之间的**语义**重叠"：把一个批次的用例复制到另一个批次，总数不变、
  覆盖面其实缩小了。仍然回到那句话 —— 一个只会通过的检查器比没有更危险。

### 2.49.4 ⭐ 我自己的守卫第一版是太弱的（负向实测抓到）

第一版写的是 `_TOTAL_FLOOR = 40`（当时实际 45，**留了 5 条余量**）。负向用例 =
"把 `sim_cases` 从 5 条砍到 1 条"，实测：

```
基线                rc=0  ['[doccheck-selftest] PASS: 45 项（28 项负向注入 / 17 项合规豁免）']
A 掏空 sim_cases(留1条) rc=0  ['[doccheck-selftest] PASS: 41 项（24 项负向注入 / 17 项合规豁免）']
B 彻底清空 sim_cases   rc=1  ['[X] 自检批次 `sim_cases` 被清空 ...']
```

A 行**仍然全绿** —— 砍掉 4 条用例（含 4 条负向验证）换来的是 `PASS: 41 项`，
看上去完全正常。**我为了避免"每次加用例都要改数字"，给守卫留了余量；而余量
恰恰使它对自己要防的那件事失明。** 改为 `_TOTAL_FLOOR = 45` 后：

```
基线                rc=0  ['[doccheck-selftest] PASS: 45 项（28 项负向注入 / 17 项合规豁免）']
A 掏空 sim_cases(留1条) rc=1  ['[X] 自检用例总数 41 低于下限 45 —— 有用例被删或被掏空。...']
B 彻底清空 sim_cases   rc=1  ['[X] 自检批次 `sim_cases` 被清空 —— ...',
                              '[X] 自检用例总数 40 低于下限 45 —— ...']
还原后              rc=0  ['[doccheck-selftest] PASS: 45 项（28 项负向注入 / 17 项合规豁免）']

逐字节还原一致 = True
```

B 行报了**两条**（批次被清空 + 总数低于下限），这是对的：两道判据各自独立成立。

### 2.49.5 承重验证（对**真实** `tools/doccheck.py` 注入 → 跑 `--selftest` → 逐字节还原）

脚本 `build/_stguard.py`，**还原写在 `finally` 里**（§2.46.7 坑 1 的纪律：脚本体里的
还原会在断言中断时把被测文件停在注入态）。

| 注入 | rc | 命中 |
|---|---|---|
| 基线 | 0 | `PASS: 45 项（28 负向 / 17 豁免）` |
| **A** `sim_cases` 5 条 → 1 条 | **1** | `自检用例总数 41 低于下限 45` |
| **B** `sim_cases` 彻底清空 | **1** | `自检批次 sim_cases 被清空` + `自检用例总数 40 低于下限 45` |
| 还原后 | 0 | `PASS: 45 项（28 负向 / 17 豁免）`；**逐字节还原一致 = True** |

### 2.49.6 验证

| 项 | 结果 |
|---|---|
| `python -m py_compile tools/doccheck.py` | rc=0 |
| `tools/doccheck.py --selftest` | `PASS: 45 项（28 项负向注入 / 17 项合规豁免）` rc=0 |
| `tools/doccheck.py`（生产跑） | `检查数字 956 处, 错误 0, 警告 0`；豁免 204；`[doccheck] PASS` |
| `tools/doccheck.py --selftest`（守卫加入前） | `PASS: 45 项` —— **数字未变**，说明本轮只加了"守卫"、未改任何既有用例 |
| `build/_hygiene.py` | 15 个文件, 0 处异常 |
| 全门禁 | `[release_check] PASS: 36 项检查全通过` |


## 2.50 门禁在 CI 上偶发 FAIL：`run_demo` 超时不回收子进程 -> `[WinError 32]`（2026-10-06）

### 2.50.1 缘起：一条"重跑就好"的 CI 失败

`1873d4c`（§2.49）推送后，CI run **37816072820** 在 `build-and-verify`
的 **`Checker mutation test`** 步**失败**，而**同一提交 `gh run rerun
--failed` 之后四 job 全绿**。此前 `37811713791`（同提交族）该步也是绿的。

日志（`gh run view 37816072820 --log-failed`）末尾逐字：

```
--- e2e ---   变异: 改 build/demo.exe 一个字节 (按布局取非掩码偏移)
              基线 rc=0 PASS / 变异后 rc=1 FAIL(正确抓到)
Traceback (most recent call last):
  File "...\tools\mutate_check.py", line 522, in main  restore()
  File "...\tools\mutate_check.py", line 91, in restore  shutil.copy2(tmp, path)
  File "...\shutil.py", line 460, in copy2  _winapi.CopyFile2(src_, dst_, flags)
PermissionError: [WinError 32] The process cannot access the file because
it is being used by another process
```

**关键读法**：`变异后 rc=1 FAIL(正确抓到)` —— **检测是成功的**。
失败发生在变异结束后的 **`restore()`**，即"把 `build/demo.exe` 覆盖
回原样"这一步。前 4 个检查器（modcheck / drills / doccheck / protchain）
全部 `✓ 健康`。**这不是检查器缺陷，是文件被占用。**

### 2.50.2 假设：进程泄漏

`tests/e2e.py` 有**两个**子进程等待点，纪律不一致：

| 等待点 | 超时行为 | 状态 |
|---|---|---|
| `pump_and_read()` | `except TimeoutExpired: _reap(proc)` + `return (None,'','')` | 2026-10-05 已修 |
| `run_demo()` | **无 except** —— 异常上抛给调用方 | 本次才修 |

`pump_and_read` 的 docstring（`tests/e2e.py:249-256`）逐字记着这条教训：

> 原实现在 `TimeoutExpired` 时只 `return (None, '', '')` —— 既不 kill
> 也不 wait，把**活进程 + PIPE 句柄**留给调用方。……实测全门禁因此挂死 1h45m

⇒ **同一个教训在 `run_demo` 上从未被应用**（它比 `pump_and_read` 更早，
且调用方 `except Exception as e: results.append((..., 'FAIL', repr(e)))`
会"看起来正确地"记录失败，**于是泄漏被静默**）。

### 2.50.3 证据一：泄漏真的存在（`build/_leak_probe.py`）

只读探针：`import e2e` 后调 `e2e.run_demo(args=['--wait-ms','6000'],
timeout=1.0)`，用 `tasklist` 数前后存活的 `demo.exe`。修复**前**实测：

```
build/demo.exe 存在? True
探针前 live demo pids: []
run_demo 抛出 subprocess.TimeoutExpired   —— 符合预期
探针后 live demo pids: ['38736']
*** 泄漏确认: run_demo 超时后仍有 1 个 demo 进程存活 ***
```

（`--wait-ms 6000` 是 `demo/main.c:533-536` 在 `prot_selfcrypt_init()`
之后的 `prot_plat_sleep_ms()`，足以撑过 `timeout=1.0`。）

### 2.50.4 证据二：活进程持有映像 ⇒ `copy2` 必然 WinError 32

`build/_winerr32_probe.py`：把 `build/demo.exe` 复制成替身
`build/_winerr32_victim.exe`（**绝不动真产物**），起替身 + 喂序列号，
再对替身做 `shutil.copy2`（与 `mutate_check.restore()` 同一动作）：

```
替身已建立: _winerr32_victim.exe (327680 B)
替身 pid=40412 存活? yes
--- 现在对它做 shutil.copy2 覆盖（mutate_check.restore() 的同一动作）---
copy2 抛 PermissionError —— **复现成功**
    [WinError 32] 另一个程序正在使用此文件，进程无法访问。
杀进程后重试 copy2:
  仍失败: [WinError 1224] 请求的操作无法在使用用户映射区域打开的文件上执行。
复现=True  杀进程后恢复=False
```

**因果链闭合**：
`run_demo` 超时 → 泄漏活进程 → `tools/mutate_check.py:91
shutil.copy2(tmp, path)` 覆盖 `build/demo.exe` → `PermissionError:
[WinError 32]`。

（`WinError 1224` 是"杀进程后**立即**重试"的残留映射，不是新问题；
真实场景里 `restore()` 与泄漏进程之间隔着整个 e2e 变异运行，
映射早已解除。）

### 2.50.5 为什么只在 CI 偶发、本机复现不出

泄漏的**前提是 e2e 里某个用例超时**。

* 本机：30 个用例全在各自 timeout 内跑完 ⇒ 不泄漏 ⇒ `mutate_check` 通过。
  （本轮 `--only protchain` / `--only e2e` 两次都 rc=0 / `PASS`。）
* CI runner（MSVC 14.51.36231 / Python 3.12.10，且 T11 要驻留 14 s）：
  **偶发超时** ⇒ 泄漏 ⇒ 下一项 `e2e` 变异恢复时撞上。

这正好解释"同提交重跑即绿"—— 重跑时那个用例没超时。

### 2.50.6 普查：这一处不是孤例（`build/_rsites.py`）

| 文件 | 位置 | 超时行为 | 本次处置 |
|---|---|---|---|
| `tests/e2e.py` | `:203` `run_demo` | **无 except**（缺陷源） | ✅ 修 |
| `tests/e2e.py` | `:259` `pump_and_read` | `_reap` | 2026-10-05 已修 |
| `tests/e2e.py` | `:737` T3 附加调试路径 | `_reap` | 已修 |
| `tests/e2e.py` | `:759` T3 `finally` | `_reap` | 已修 |
| `tests/_platform.py` | `:172` `run_demo_via_wsl` | **无 except** | ✅ 修 |
| `tests/attacks.py` | `:151` `run_demo`（win） | **无 except** | ✅ 修 |
| `tests/attacks.py` | `:215` `_run_demo_wsl` | **无 except** | ✅ 修 |
| `tests/protchain_check.py` | — | 0 处 | — |

**四处同型**（e2e 一处 + `_platform` 一处 + attacks 两处）。
`_platform.run_demo_via_wsl` 尤其要紧：它是 **e2e 与 attacks 共用的
单一来源**（S5 抽取），两处 Linux 路径都经它。

### 2.50.7 修法

四处统一为**同一形态**（与 `pump_and_read` 一致）：

```python
try:
    out, err = p.communicate(stdin, timeout=timeout)
except subprocess.TimeoutExpired:
    _reap(p)                    # 或 _plat.reap(p)
    return (None, '', '')       # attacks 侧是 (None, '')
```

要点：
* **返回 `(None, ...)` 而不是抛**（与 `pump_and_read` 同形）⇒
  调用方的 `except Exception` 不必改，且"没拿到退出码"这个语义
  由既有调用方正确解读（它们本来就比较 `_norm_exit(code)`）。
* `tests/_platform.py:113` **新增 `reap(proc, timeout=5)`**（该模块原先
  **没有**回收函数 —— 它是"公共层"，却漏了这一项）。`e2e._reap` 与
  `_platform.reap` 现在**内容等价**；**刻意没有让 e2e 改为委托**
  （e2e 的 T3 调用点已按 `_reap` 的名字与 docstring 写死，改名会
  扩大改动面，而收益只是少 12 行）。
* `reap` 两步**都有界**：`kill()` 可能抛（进程已退）⇒ 吞；
  `wait(timeout=...)` 超时后再补一次 kill 并**不再等**。理由同
  `e2e._reap` 的 docstring：无 timeout 的 `wait()` 曾让全门禁挂死 1h45m。

### 2.50.8 承重验证

**A. 六条用例全绿（`build/_leak_probe2.py`）**

| 用例 | 判据 | 结果 |
|---|---|---|
| A `e2e.run_demo` | 真实 demo（`--wait-ms 6000`, `timeout=1`）超时后 **0 个残留 pid**，且返回 `(None,'','')` | ok |
| B1 `attacks.run_demo`（win） | 替身进程被 `kill` + `wait`，返回 `(None,'')` | ok |
| B2 `attacks._run_demo_wsl` | 同上 | ok |
| C1 `_platform.run_demo_via_wsl` | 替身被 `kill` + `wait`，返回 `(None,'','')` | ok |
| C2 `_platform.reap` | `wait(timeout=7)` **带着 timeout** 传下去 | ok |
| C3 **负向** `reap` | `kill()` 抛 `OSError` 时**不冒泡** | ok |

（B1/B2/C1 用替身进程：它们的 timeout 是硬编码的 40 s / 60 s，
真等不现实；替身的 `communicate()` 立刻抛 `TimeoutExpired`，
直接验证新增的 except 分支。**C 组是真起进程**。）

**B. ⭐ HEAD vs 工作树的干净差分（`build/_lb_diff.py`）**

同一替身 harness，分别喂 `git show HEAD:<path>` 的函数体与工作树函数体：

| 位置 | HEAD（修复前） | 工作树（修复后） | 干净差分 |
|---|---|---|---|
| `tests/attacks.py::run_demo` | `raised TimeoutExpired('stub', 40)` / `kill=False wait=False` | `returned (None, '')` / `kill=True wait=True` | ✅ |
| `tests/_platform.py::run_demo_via_wsl` | `raised TimeoutExpired('stub', 1.0)` / `kill=False wait=False` | `returned (None, '', '')` / `kill=True wait=True` | ✅ |

⇒ 新增的 except 分支**确实承重**：修复前恰好泄漏（不 kill 不 wait
且异常上抛），修复后恰好回收。

### 2.50.9 我自己的探针踩的两个坑（同类第 13、14 次）

1. **`git show` 的文本仍带 U+FEFF**。`subprocess.run(..., encoding='utf-8')`
   解出的 `str` **保留了 BOM 字符** ⇒ `ast.parse` 报
   `SyntaxError: invalid non-printable character U+FEFF`。
   `encoding='utf-8-sig'` **只对 `open()` 生效**，对已解码的文本无效
   ⇒ 修法是 `r.stdout.lstrip('﻿')`。
2. **替身 harness 注入的命名空间漏了 `_plat`**。HEAD 版函数体用不到它，
   工作树版调用 `_plat.reap()` ⇒ 第一跑报
   `NameError("name '_plat' is not defined")`，**看起来像"修复后反而坏了"**。
   修法：两版都注入**全部**符号（对 HEAD 版无害）。
   ⇒ 与 §2.37.6 / §2.42 / §2.43.7 / §2.45.3 / §2.46.7 同型：
   **探针的错会伪装成被测对象的性质。**

### 2.50.10 诚实边界

1. **本机无法复现原始的 CI 失败**：需要 e2e 里某个用例真超时。
   本机复现靠的是**人造超时**（`timeout=1.0` + `--wait-ms 6000`），
   与 CI 的偶发超时**不是同一条路径**（但泄漏机制相同）。
   ⇒ 本节的证据链是"机制可复现"，不是"CI 那次失败的现场重放"。
2. **B1/B2/C1 用的是替身进程**，不是真实超时；真起进程的只有
   A（e2e 真实 demo）与 C2/C3（`reap` 单元）。
3. **`tests/attacks.py` 的 timeout 仍是硬编码**（40 s / 60 s）——
   本次**没有**把它参数化（改动面会扩大）；诚实记名。
4. **`WinError 1224` 那条没有被修**：它是"杀进程后立即重试"的
   残留映射，真实场景不触发（见 2.50.4 末）。
5. **没有为这一条加门禁判据**：要判"超时路径是否回收"需要有意识地
   制造超时（要起真进程 + 等），成本与收益不成比例；且 A 用例已经
   是**可复现的探针**。⇒ 与 §2.47.6 同类的"刻意不做"。
6. **§2.49 的提交 `1873d4c` 当时撞上了这个偶发失败**。时序：
   `1873d4c` 推送 → CI `37816072820` 失败（本节的机制）→
   `gh run rerun --failed` → 全绿。**§2.49 本身从未有过缺陷**，
   它的代码与判据与本节的改动无关。

### 2.50.11 修改文件与验证表

| 文件 | 改动 | 行数变化 |
|---|---|---|
| `tests/e2e.py` | `run_demo` 加 `except TimeoutExpired` + 29 行判据注释 | +22 |
| `tests/_platform.py` | 新增 `reap()`（+40 行）；`run_demo_via_wsl` 加 except | +46 |
| `tests/attacks.py` | `run_demo`（win）+ `_run_demo_wsl` 各加 except | +13 |

* `py_compile` 三个文件全部 rc=0（`tests/attacks.py` 与 `tests/e2e.py`
  是 BOM=True ⇒ 每处编辑后用 `tools/bom.py add` 补回，已复核
  `bom=True crlf=0`）。
* `build/_hygiene.py` ⇒ **15 个文件, 0 处异常**。
* `tests/_platform.py --selftest` ⇒ `PASS: 9 项（含 3 负向）`。
* 全门禁 ⇒ `[release_check] PASS: 36 项检查全通过`。
* CI ⇒ 见 2.50.12。

### 2.50.12 CI 实测：**没有拿到证据**（GitHub 帐单问题，非代码）

`49ad462` 推送后的 CI run **37823314673**（head
`49ad46283559fd829d6d39ab99f6320712191d7d`）状态是 `failure`，
但**四个 job 一个都没真的运行**。`gh run view 37823314673` 逐字：

```
JOBS
X build-and-verify in 2s (ID 113469631678)
X linux-portability  in 4s (ID 113469632119)
- reproducible       in 0s (ID 113469654102)
- sdk-package        in 0s (ID 113469654413)

ANNOTATIONS
X The job was not started because recent account payments have failed or
  your spending limit needs to be increased. Please check the
  'Billing & plans' section in your settings
```

⇒ **失败发生在调度层**（GitHub 帐号帐单/支出上限），与本次改动无关。
`gh run rerun 37823314673 --failed` 返回 rc=0，但重跑后
`gh run view` 的注解**仍然是同一条帐单信息**（job ID 变了：
`113471513797` / `113471513934`，结论仍是"未启动"）。

## 本条对 §2.50 的影响

**没有任何影响**，因为 §2.50 的证据链**不依赖 CI**：

* 2.50.3 / 2.50.4 是**本机可复现的机制证据**
  （`build/_leak_probe.py` 数残留 pid；`build/_winerr32_probe.py`
  用替身副本复现 `[WinError 32]`）。
* 2.50.8 的 **HEAD vs 工作树干净差分**是在本机跑出来的
  （`build/_lb_diff.py`），且是**逐函数的强弱对照**：
  修复前 `raised TimeoutExpired` / `kill=False wait=False`，
  修复后 `returned (None, ...)` / `kill=True wait=True`。
* 2.50.11 的**全门禁 PASS** 也是本机实跑（现值见该节的验证表）。

## 诚实边界（这条比"CI 绿"更重要）

1. **这条修复没有 CI 证据**。上次 CI 真跑成功的是 `1873d4c`
   （run 37816072820，重跑后全绿）与 `9987bdd`（37811713791）；
   `49ad462` 之后的 run 全部止步于调度层。
2. **CI 绿本来也不能证明"偶发已被消除"**：失败前提是 e2e 某用例
   超时，而超时本身是偶发的，绿只说明"这一次没触发"。
   真正的证据始终是 2.50.8 的**机制**差分 —— 超时路径现在会回收
   进程，因此"超时 → 泄漏 → WinError 32"这条链条**在机制上**断了。
3. 帐单问题属**外部基础设施状态**，不在本仓库的可修范围内；
   本记录只如实标注"该提交缺少 CI 验证这一环"。

---

## 2.51 门禁第 40 项：selfcrypt meta 布局「四方一致」—— 把一句人工承诺机械化（2026-10-08）

### 2.51.1 缘起：一句写在计划里的承诺，从来没有代码读它

`docs/N1_PHASE2_PLAN.md:36` 逐字写着：

> **注意**：meta 布局改动必须同步 `selfcrypt_proto.py`（写）与 `selfcrypt.c`（读）
> + `integrity.c build_selfcrypt_mask`（读 rva/len 偏移），三侧一致。

这是**人工承诺**：它规定了"谁必须和谁一致"，但仓库里**没有任何代码在读两侧并比较**。
本条把它机械化 —— 也就是本仓库第 10 例同型缺陷（「能用」不等于「在用」）。

### 2.51.2 勘查：实测是**四方**，不是「三侧」

按 `<IIQII` / `SC_ENTRY_SIZE` / `SC_ENTRY_GROUP_OFF` 三模式全库扫描，
真正使用该布局的地方是**四处**（承诺漏掉了 py 读侧与掩码侧的**裸字面量**）：

| 侧 | 位置 | 形态 |
|---|---|---|
| ① 写侧 | `tools/selfcrypt_proto.py:437` / `:443` / `:444` | `hdr = 4 + len(entries) * 24` / `e_off = blob_off + 4 + i * 24` / `struct.pack('<IIQII', rva, size, sd, crc, group)` — **裸字面量 24，无命名常量** |
| ② C 读侧 | `src/selfcrypt.c:80-81` | `#define SC_ENTRY_SIZE 24u` / `#define SC_ENTRY_GROUP_OFF 20u` |
| ② 附带 | `src/selfcrypt.c:141-144` | 四个字段的**逐字段 `memcpy` 偏移**：`e` / `e+4u` / `e+8u` / `e+16u` |
| ③ py 读侧 | `tests/protchain_check.py:70-71` | `SC_ENTRY_SIZE = 24` / `SC_ENTRY_GROUP_OFF = 20` |
| ④ 掩码侧 | `src/integrity.c:418-419` | `blob + 4u + i * 24u` 与 `... + 4u` — **第 4 处裸步长** |

四方**当前字面量一致**（24 / 24u / 24 / 24u），但一致性从未被验证过。

### 2.51.3 判据锐利度实测：三类漂移里**两类今天无人抓**

注入真实文件后跑现有检查（`build/_scmeta_probe2.py`，每例 `finally` 还原并断言逐字节一致）：

| 注入 | `tests/protchain_check.py` | `tests/e2e.py` |
|---|---|---|
| 基线（不注入） | rc=0（P1-P6 全 PASS） | — |
| A. py 读侧 `SC_ENTRY_SIZE 24 -> 20` | **rc=1**（`P1 ... fn 1 out of range`） | — |
| B. C 读侧 `src/selfcrypt.c:80` `24u -> 20u` | **rc=0 全绿** | **rc=0，30/30 PASS** |
| C. py 读侧 `SC_ENTRY_GROUP_OFF 20 -> 16` | **rc=0 全绿** | — |

⇒ 只有 A 有端到端兜底。**B、C 两类今天没有任何检查会红**，e2e 30 项也不兜底。

### 2.51.4 根因：group 字段被解出来又丢掉

`tests/protchain_check.py:149-170 selfcrypt_meta()` 确实解出了 group：

```python
grp = struct.unpack_from('<I', blob, off + SC_ENTRY_GROUP_OFF)[0]
out.append((rva, ln, grp))
```

但两个调用点都把它丢弃了 —— `:336` 写成 `for i, (rva, ln, _grp) in enumerate(...)`、
`:368` 写成 `meta = [(rva, ln) for rva, ln, _grp in ...]`。
⇒ **没有任何判据在用这个字段**，所以它的偏移漂移必然静默。
这正是"只数条数的检查看不见『条数对得上、语义对不上』的缺陷"。

### 2.51.5 ⭐ 自我更正：完整门禁**会**红，但**红错了项**且诊断**误导**

我原本预期"注入 C 偏移漂移后完整门禁会全绿"。实测**相反，但结论比预期更糟**。

在**最危险的那一类**（C：`tests/protchain_check.py` `SC_ENTRY_GROUP_OFF 20 -> 16`）
注入下跑完整门禁（`build/_gateload_meta.py`，`-SkipDirtyCheck`）：

```
[release_check] FAIL: 1/36 未通过
red = selfcrypt 驻留期密文态 (selfcrypt_residency)     # ← 门禁第 39 项
```

而第 39 项的打印**自相矛盾且诊断错误**：

```
  [ok] 组 0 条目数 > 0  (组 0 2 条 / 组 1 1 条)
  [ok] 组 0 在全部采样轮次均为磁盘密文  (全部 10 轮逐字节一致)
[selfcrypt-residency] FAIL: 2/4 条判据未通过      # ← 4 条全是 [ok]
```

机制：group 偏移读错 ⇒ 9 条条目被**重新分组**（实测 4+5 变成 2+1），
第 39 项按新的分组取组 0 ⇒ **把一个布局漂移误诊成"驻留期明文暴露"**，
并且它的 `FAIL: 2/4` 与逐条 `[ok]` 相互矛盾（计数用的是另一套口径，见 2.51.10）。

⇒ 正确表述是：**今天没有任何工具在检查「meta 布局是否四方一致」**。
第 39 项只是**碰巧**因重新分组而红，且给出的是**错误诊断**。
新门禁的价值因此不是"多一个红灯"，而是**诊断正确** —— 报错直接指向布局漂移。

（该轮同时实测确认：`e2e T1-T30` 在注入下仍 `[ok]`，与 2.51.3 一致。）

### 2.51.6 修法：`tools/selfcrypt_meta_check.py`（新建，门禁第 40 项）

**判据全部由写侧 `struct.pack` 的格式串推导，不抄字面量**：

1. 写侧格式串 ⇒ 步长与逐字段偏移（`<IIQII` ⇒ 24 / rva@0 len@4 key0@8 crc@16 group@20）；同时校验切片 `data[e_off:e_off+24]` == 推导步长
2. 写侧 `hdr` 与 `e_off` 的步长 == 推导值
3. `src/selfcrypt.c` 的 `SC_ENTRY_SIZE`/`SC_ENTRY_GROUP_OFF` **以及 `sc_do_range` 里四个字段的 `memcpy` 偏移** == 推导值
4. `tests/protchain_check.py` 两常量 == 推导值
5. `src/integrity.c build_selfcrypt_mask()` 内裸步长与 rva/len 偏移 == 推导值
6. **每一侧都必须被找到**：锚点消失即 FAIL —— 失锚**不得**读成"没有漂移"

退出码沿用仓库约定 `0=一致 / 1=漂移 / 2=SKIP`。
注册位置 = 第 39 项 `}` 之后、Linux 运行时**纯注释块之前**（纯注释块必须留在最末）。

**负向自检 9 条变异全部被抓**（`[selfcrypt-meta-selftest] 9/9 变异被抓`）：

| # | 变异 | # | 变异 |
|---|---|---|---|
| M1 | 写侧 `hdr` 步长 24→20 | M6 | py 读侧 `SC_ENTRY_SIZE` 24→20 |
| M2 | 写侧 `e_off` 步长 24→20 | M7 | py 读侧 `SC_ENTRY_GROUP_OFF` 20→16（**今天无人抓的那类**） |
| M3 | 写侧格式串 group 挪位（`<IIQII`→`<IQIII`） | M8 | 掩码侧步长 24u→20u |
| M4 | C 读侧 `SC_ENTRY_SIZE` 24u→20u | M9 | 掩码侧读 len 用 +4u→+8u |
| M5 | C 读侧 `SC_ENTRY_GROUP_OFF` 20u→16u | | |

**真实文件注入差分**（`build/_metaload.py`，每例还原后复核 `新判据 rc=0 | protchain rc=0`）：

| 注入 | 新判据 | protchain |
|---|---|---|
| B `src/selfcrypt.c` `SC_ENTRY_SIZE 24u→20u` | **rc=1** | rc=0 |
| C `tests/protchain_check.py` `GROUP_OFF 20→16` | **rc=1** | rc=0 |
| A py `SC_ENTRY_SIZE 24→20` | rc=1 | **rc=1**（兜底在场） |
| D `tools/selfcrypt_proto.py` `e_off` 步长 24→20 | **rc=1** | rc=0 |
| E `src/integrity.c` 掩码侧 `s_len +4u→+8u` | **rc=1** | rc=0 |

### 2.51.7 我自己的探针踩的坑（同类第 15、16 次）

1. **正则抓到文件里第一个 `struct.pack`**：`struct.pack('<I', len(entries))` 是 count 字段
   ⇒ 推导步长 4 ⇒ 基线恒红。修法 = 锚定到 entry 那一行
   （`data\[e_off:e_off\s*\+\s*(\d+)\]\s*=\s*struct\.pack\(...`）。
2. **只按实参变量名建偏移 dict** ⇒ `len`/`key0` 查不到（`None`）⇒ 那两条判据被**静默跳过**
   （基线绿、变异也绿）。修法 = 同时按**位置**把 `('rva','len','key0','crc','group')` 映射进去。
   这条与 2.51.4 的根因**同型**：判据悄悄不生效比判据报错危险得多。
3. **掩码侧 rva 的字段偏移是隐式 0**（写作 `blob + 4u + i * 24u`，后面没有 `+ 0u`）
   ⇒ 正则第二个 `+ Nu` 必须可选、缺省算 0，否则基线恒红。
4. **探针 `--quiet` 假象（同类第 16 次）**：`build/_metaload.py` 给 `tools/doccheck.py`
   传了 `--quiet`，而 doccheck **只认 `--list`/`--selftest`** ⇒
   `unrecognized arguments: --quiet` ⇒ rc=2。该列全为 rc=2 是**探针自身的假象，
   不代表 doccheck 有任何反应**。结论只以「新判据 vs protchain」两列为准。
   更早的 `build/_scmeta_probe.py` 给 `tests/protchain_check.py` 传 `--quiet`（该脚本只认
   `--exe/--blob/--map`）同型，rc=2 一度与"检查失败"同形 —— 差点误读。

### 2.51.8 计数口径 39/36 → 40/37

`tools/doccheck.py`：`GATE_TOTAL = 39 → 40` / `GATE_DEFAULT = 36 → 37`（容差注释同步），
并在沿革块续写一行 `2026-10-08: 39/36 -> 40/37`。
同步的**现时值**位置：`README.md:107`/`:132`/`:133` + 成员清单新增一项、
`CONTRIBUTING.md:67`、`ShardVase-展示文档.md:163`、`docs/BLUEPRINT.md:128`、
`docs/CONTINUATION_PLAN.md:441`/`:529`/`:622`/`:688`/`:716`、`docs/DEBUG_CONSOLE_PLAN.md:8`、
`docs/DECISION_REDUNDANCY_PLAN.md:257`、`publish/01-关于ShardVase.md:63`、
`publish/02-项目档案.md:116`/`:168`（**该串在此文件出现 2 次**，逐处断言唯一会失败）、
`.github/PULL_REQUEST_TEMPLATE.md:16`、`.github/workflows/ci.yml:111`/`:115`、
`docs/HANDOVER.md:18`。
`docs/HANDOVER.md` 里大量 36 项口径是**历史快照，一律不动**。

### 2.51.9 修改文件与验证表

| 文件 | 改动 |
|---|---|
| `tools/selfcrypt_meta_check.py` | 新建（约 17.5 KB，6 条判据 + 9 条负向变异） |
| `tools/release_check.ps1` | 注册门禁第 40 项 + 解释性注释块（+45 行） |
| `tools/doccheck.py` | `GATE_TOTAL`/`GATE_DEFAULT` 40/37 + 沿革续写 |
| `docs/N1_PHASE2_PLAN.md:36` | 就地补记「该承诺已机械化 + 实测是四方」 |
| 计数口径 13 个文件 | 39/36 → 40/37 同步 |

* `tools/selfcrypt_meta_check.py` ⇒ 基线 `PASS: 5 条判据全通过`（rc=0）；
  `--selftest` ⇒ `9/9 变异被抓`（rc=0）。`py_compile` rc=0。
* `build/_hygiene.py` ⇒ **15 个文件, 0 处异常**。
* `tools/doccheck.py` ⇒ `检查数字 979 处, 错误 0, 警告 0` / `[doccheck] PASS`
  （含 `[ok] README 门禁清单: 37 条成员与默认跑的 37 项双向唯一匹配`）。
* 全门禁（`-SkipDirtyCheck`）⇒ **`[release_check] PASS: 37 项检查全通过`**，
  含新增的 `[ok] selfcrypt meta 布局四方一致 (selfcrypt_meta)`。
* CI ⇒ 提交后另记。

### 2.51.10 诚实边界

1. 判据比对的是**源码文本**，不执行被测代码。若常量被挪到别的头文件，
   本项会报「找不到锚点」而不是**误绿** —— 这是刻意的取向。
2. 只覆盖**步长**与 rva/len/key0/crc/group **偏移**；不覆盖 Linux 侧
   （`src/selfcrypt.c` 与 `tools/selfcrypt_proto.py` 平台无关，两侧共用）。
3. **第 39 项的 `FAIL: 2/4` 与逐条 `[ok]` 自相矛盾**这件事，本条写下的当时
   只做了记录、没有修。**该缺陷已在 §2.52.5 修掉**（成因不是"计数口径不同"，
   而是 `--quiet` 把**失败诊断**一起抑制了，加上自检的合成基线没有表头 ——
   详见 §2.52.5 与 §2.52.7）。此处按时序保留原判断，不回头改写历史。
4. 本条**没有**为 2.51.3 的 A 类漂移增加新的端到端证据：A 类今天已经有兜底
   （protchain 会红），新门禁只是让它更早、更明确地报出来。

## 2.52 一份文档的 ``` 围栏总数是奇数 —— 代码块豁免整类静默反转（2026-10-08）

### 2.52.1 缘起：报错指着一个"明明在代码块里"的行

§2.51 落笔后立刻跑 `tools/doccheck.py`，得到：

```
[X] docs/HANDOVER.md:6671 门禁项数声称 36, 实际 40
```

而 `:6671` 的内容是 `[release_check] FAIL: 1/36 未通过`，它**就在一个 ``` 块里**
（围栏在 `:6670` 与 `:6673`）。用 `tools/doccheck.py` 自己的 `DocView(text, path)`
（**构造签名要两个参数**；类名是 `DocView` 不是 `View`）逐行查 `in_code`：

```
:6668 in_code=True   :6669 True   :6670 True
:6671 in_code=False  :6672 False  :6673 True     # ← 与肉眼理解正好相反
```

### 2.52.2 病因：单个布尔翻转 + 奇数围栏 ⇒ 语义整体反转

`tools/doccheck.py:281-304 DocView._walk()` 用**一个 `inside` 布尔**翻转围栏状态：

```python
if l.lstrip().startswith(FENCE):
    inside = not inside
```

⇒ **只要全文围栏总数是奇数**，那个未配对的围栏之后的**所有**行 `in_code` 语义
整体反转：真正的代码块被判成正文（于是它里面的数字变成"现值断言"），而正文被
判成代码块（于是**整类代码块豁免失效**）。这不是一处误报，是**一整个豁免机制
静默反转**。

### 2.52.3 引入提交：`da5f906` 多写了一行 ```

`build/_fence2.py` / `_fence3.py`：HEAD（`ab04716`）行 6608 / 围栏 **283（奇数）**；
工作树 6789 / 289（仍奇数）。前 283 个围栏**逐位相同** ⇒ 缺陷在 HEAD 里就存在，
我新加的 6 个围栏（3 个配对块）本身是配平的，只是**落进了被反转的区间**，
于是第一次把它暴露出来。

孤立围栏定位在 **`docs/HANDOVER.md:5839`**（`:5838` 空行 / `:5839` = ``` / `:5840`
空行），位于 `### 2.46.9 验证` 的表格之后、`### 2.46.10` 之前。用 `git log -L` +
`git log -S` 锁定来源 = 提交 **`da5f906`**（`docs: §2.46.10 —— CI 实测…`，
2026-10-08），其 diff hunk `@@ -5836,4 +5836,24 @@` 逐字为
`-*2026-10-06 v20*` → `+``` `（多写的这一行）+ `+### 2.46.10 CI 实测` + …

逐提交奇偶轨迹（`build/_fence9.py`，40 个 rev）：

| 提交 | 围栏数 | 带标记围栏错位数 |
|---|---|---|
| `590f2bf` 及之前 | 偶数 | 0 |
| **`da5f906`** | **253（奇）** | 0 |
| `b01cb8d` / `3858fe1` | 255 | 1 |
| `c3902bc` / `9987bdd` | 265 | 2 |
| `1873d4c` | 273 | 4 |
| `49ad462` | 281 | 5 |
| `ab04716` | 283 | 5 |

⇒ 从 `da5f906` 起，**每新增一个带 `python` 标记的围栏就多一条错位** ——
缺陷在累积，只是没有任何判据在看它。

### 2.52.4 修法 A：删掉孤立围栏 + 删掉 §2.50 里过期的数字

1. 删掉 `docs/HANDOVER.md:5839` 那一行 ```（用 `edit` 工具）。
   删后 doccheck 的报错从"`:6671`"变成"**`:6591`**"—— 病症从**受害者**移到了
   **真病因所在的 §2.50 区段**，这正是"先修结构、再看内容"该有的行为。
2. `:6591`（§2.50.11 的叙述性引用）`…的**全门禁 `PASS: 36 项`** 也是本机实跑。`
   → `…的**全门禁 PASS** 也是本机实跑（现值见该节的验证表）。`
   **刻意删数字而不是改成新数字** —— 该行是叙述，数字无信息量（§2.39 的取向）。

⇒ `tools/doccheck.py` 回到 `检查数字 1006 处, 错误 0, 警告 0` / `[doccheck] PASS`。
（§2.50 区段内另一条 `:6553` 的 `PASS: 36 项` 由 `hist=True` 正确豁免 —— 它的父
标题 `## 2.50 …（2026-10-06）` 带日期，属历史记录。）

### 2.52.5 修法 B：`check_fence_balance()` —— 让它不可能再静默

只修那 283 行是不够的：**下一次多写一行 ``` 仍然没人报**。故给
`tools/doccheck.py` 新增结构判据 `check_fence_balance(docs=None)`
（`docs=None` 读真实 `TARGETS`；传 `{rel: text}` 绕开文件系统供自检用）：

1. **围栏总数必须为偶数** —— 否则报"从某一处起 `in_code` 语义整体反转
   （代码块豁免整类失效）"。
2. **带 info string 的围栏必须落在偶数序号**（0-based）—— `.md` 里带语言标记的
   三反引号只可能是**开启**围栏，序号必为偶数。这条比 ① 更锐：总数偶数但配对
   错位时 ① 绿而 ② 红。

`main()` 新增 **0f** 步（紧跟 0e）；`selftest()` 新增**第六批 `fc_cases`（5 条）**：
配平 1 块 / 配平 3 块共 6 条 / 多一个孤立 ```（总数奇数）/ 总数偶数但带标记围栏
错位 / 空文档。四处必须同改（`total`、`neg`、`_BATCHES`、打印循环）—— 否则新批次
**暗处运行、看起来不存在**。

`_TOTAL_FLOOR` 由 45 提到 **50**（这条守卫的既有纪律：下限**紧贴当前值**，不留
余量 —— §2.49 实测过留 5 条余量会让守卫对自己要防的那件事失明）。

自检 **`PASS: 50 项（30 项负向注入 / 20 项合规豁免）`**；本体打印
`[ok] 围栏配平: 19 份文档的 ``` 总数为偶数且带标记的围栏均在偶数序号`。

### 2.52.6 承重验证：往真实文档注入，确认真的会红

`build/_fenceload.py`（还原放 `finally`，断言逐字节一致）：

| 用例 | rc | 报错条数 | 还原一致 |
|---|---|---|---|
| A 往 `README.md` 追加一个孤立 ``` | 1 | 1（含"奇数"，报 `15` 条） | True |
| B 往 `docs/HANDOVER.md` 追加一个孤立 ``` | 1 | 1（含"奇数"，报 `289` 条） | True |
| C 还原后对照 | 0 | 0 | — |

（B 用例实测报"`289` 条" —— 即"再写一个孤立围栏"这种错**今天已经会被立刻报出来**。）

### 2.52.7 ⭐ §2.51.5 的证据更正：39 项 → 40 项

§2.51.5 当时引用的是**只有 39 项**的那一轮日志（第 40 项还没写进
`tools/release_check.ps1`，日志里直接跳过了它）。现在用**含第 40 项**的脚本重跑
同一注入（`build/_gateload_meta.py`，`GROUP_OFF 20 -> 16`）：

```
[ok]  CRC 目标表一致性 (crc_targets)
[ok]  静态未定义名审计 (undef_check)
[ok]  Android 交叉编译 (android_compile_check)
[X]  selfcrypt 驻留期密文态 (selfcrypt_residency)      # 第 39 项
[X]  selfcrypt meta 布局四方一致 (selfcrypt_meta)      # 第 40 项  ← 新证据
[release_check] FAIL: 2/37 未通过
```

且第 40 项的诊断**准确指向**病因：

```
[selfcrypt-meta-selftest] 基线: 5 条判据, 1 条失败
  [XX] ④ tests/protchain_check.py 读侧常量  (tests/protchain_check.py: SC_ENTRY_GROUP_OFF 写作 16，字段 group 真偏移 20)
[selfcrypt-meta-selftest] 8/9 变异被抓
```

⚠️ 注意 `8/9` 里缺的那条是 **M7 自身**（"py 读侧 `SC_ENTRY_GROUP_OFF` 20 -> 16"）：
因为**真实文件已经被注入成 16**，自检找不到旧值。这**不是**自检失效，而是
"被测文件正处于变异态"。旧文案一律报"变异点未找到（**自检本身失效**）"，
属**误诊**。已在 `tools/selfcrypt_meta_check.py` 区分两种成因：

* 文件里已是**新值** ⇒ 报"**变异点已是新值**：…该文件当前处于变异/未还原状态
  （不是自检失效）"；
* 新旧值都没有 ⇒ 才报"自检本身失效（源码被改名/挪走了）"。

⇒ §2.51.5 那句"**今天没有任何工具在检查 meta 布局是否四方一致**"在**注入轮**
这个语境下依然成立（它是描述"修之前"的状态），但**第 40 项确实会因为这类漂移
而红，且诊断正确** —— 这是 §2.51.5 当时无法拿到的证据。

### 2.52.8 第 39 项诊断缺陷的修复（三处，都在 `tools/selfcrypt_residency_check.py`）

§2.51.10#3 记的"`FAIL: 2/4` 与 4 条 `[ok]` 自相矛盾"，本轮查明**成因不是"两套计数
口径"**，而是两条更朴素的原因：

1. **`judge()` 第 4 条判据的 detail 写错了。** 原实现
   `'; '.join(drifted[:3]) or ('全部 %d 轮逐字节一致' % len(samples))` —— 当 `g0`
   为空（9 条全被判成组 1）时 `drifted` **也是空**，于是**判 FAIL 的那一行却打印
   「全部 40 轮逐字节一致」**。
   修法：按 `g0` 空 / `samples` 空 / `missing` / `drifted` / 通过 五种情形分别给
   detail；`g0` 为空时明确报"组 0 为空（9 条全被判为组 1）-> 判据**空转**，
   没有任何条目被比对。先看①：这通常意味着 meta 的 group 字段被读错了"。
2. **`--quiet` 把失败诊断一起抑制了。** `:492 if not quiet:` 包住了逐条打印 ⇒
   门禁（它自己传 `--quiet`）写进日志的**只有** `FAIL: 2/4 条判据未通过` 一行，
   读日志的人看不到哪条红了、为什么。`--quiet` 的契约应是"**成功时不啰嗦**"，
   不是"失败时沉默"。修法：失败分支**无条件**打印每条红的判据。
3. **自检的合成基线没有表头。** 那 4 条 `[ok]` 是 `--selftest` 的**合成数据**
   （组 0 恰好 2 条 / 10 轮），紧挨在本体的 `FAIL` 之上，必然被读混。
   修法：加一行表头 `--- 以下是合成基线（自检用例数据, 非本体采样）---`。

复现证据（`build/_resquiet.py`，注入真实漂移后**分别**用两种参数跑）：

```
=== 无 --quiet  rc=1 ===
  条目 9 条（组 0: 0 条）        # ← group 全读错 ⇒ 组 0 空
  [XX] 组 0 条目数 > 0  (组 0 0 条 / 组 1 9 条)
  [ok] 采样轮数 >= 10  (40 轮)
  [ok] 组 0 每条目都有磁盘参考  (ok)
  [XX] 组 0 在全部采样轮次均为磁盘密文  (全部 40 轮逐字节一致)   # ← 修前的自相矛盾
  [selfcrypt-residency] FAIL: 2/4 条判据未通过
=== 带 --quiet（门禁实际用法）  rc=1 ===
  [selfcrypt-residency] FAIL: 2/4 条判据未通过      # ← 修前只剩这一行，没有归因
```

### 2.52.9 我自己的探针踩的坑（同类第 17、18、19 次）

1. **按 `utf-16-le` 解码门禁日志**（`build/_gateload_meta.py` 原第 39 行）——
   错。`gate_log.ps1` 落的门禁日志是**纯 UTF-8**（无 BOM），按 `utf-16-le` 解出
   乱码，于是 `[ok]` / `[X]` **全部数成 0**，`[ok]=0 [X]=0 [skip]=0` 看起来像
   "门禁一项都没跑"。同一份日志 `utf-8-sig` 解出 95 行 / 5 处 `release_check`。
   （"`*>` 落盘是 UTF-16LE"这条纪律只对 **PowerShell 重定向**成立，**不**对
   `gate_log.ps1` 自己写的文件成立 —— 我把前者套用到了后者。）
2. **`fc_cases` 第 4 条构造函数写错**：第一版造出 **5 条围栏（奇数）**，
   于是两条判据**同时开火报 2 条**，用例自己 FAIL（期望 1 条）。
   与 §2.37.6 同型：**探针的构造错会伪装成判据错**。修法：造 1 条裸 + 1 条带标记
   （落在奇数序号 #1）+ 4 条裸 = **6 条（偶数）**，只触发判据②。
3. ⭐ **我在写本节时把新判据自己触发了**（同类第 19 次，也是本轮最有说服力的一条
   生产证据）：本节 §2.52.5 正文里有一句 `.md 里带语言标记的`＋换行＋**行首三
   反引号** —— 那行被 `DocView` / `check_fence_balance()` 当成一个**裸围栏**，
   于是 `docs/HANDOVER.md` 的围栏总数从 300 变成 **301（奇数）**，doccheck 立刻报：

   ```
   [X] docs/HANDOVER.md 的 ``` 围栏总数 301 是**奇数** -> 从某一处起 `in_code`
       语义整体反转（代码块豁免整类失效）。最后一个围栏在 :6964
   ```

   修法：把那句改成"三反引号"（**行首不再出现裸 ```**）。
   ⇒ 这说明判据**在真实写作流程里就已经开始工作**，而不只是在我为它写的玩具
   用例上工作 —— 与 §2.52.6 的注入验证互相独立、互为旁证。

### 2.52.10 验证表

| 项 | 结果 |
|---|---|
| `tools/doccheck.py --selftest` | `PASS: 50 项（30 项负向注入 / 20 项合规豁免）` |
| `tools/doccheck.py` | `检查数字 1006 处, 错误 0, 警告 0` / `[doccheck] PASS` |
| 围栏配平判据本体 | `[ok] 围栏配平: 19 份文档的 ``` 总数为偶数且带标记的围栏均在偶数序号` |
| 承重验证 `build/_fenceload.py` | A/B/C 三用例全 OK，两次还原均逐字节一致 |
| `tools/selfcrypt_meta_check.py --selftest --quiet` | 干净树上 `9/9 变异被抓`，rc=0 |
| `tools/selfcrypt_residency_check.py --selftest --quiet` | `4/4 变异被抓`，rc=0 |
| `tools/selfcrypt_residency_check.py --quiet` | `PASS: 组 0 4 条 × 40 轮 全部逐字节等于磁盘密文`，rc=0 |
| 完整门禁（`-SkipDirtyCheck`） | **`[release_check] PASS: 37 项检查全通过`**，`ok=37 bad=0`，含两项 selfcrypt 项 |
| `build/_hygiene.py` | `文件卫生: 15 个文件, 0 处异常` |

### 2.52.11 诚实边界

1. 判据②（带标记围栏落在偶数序号）**只覆盖带 info string 的围栏**。若某文档
   错位后所有带标记围栏**恰好**都还在偶数序号（例如一次多写两行 ```），
   则①绿②也绿 —— 此时只能靠人工看。判据①（总数偶数）同样看不见"偶数个围栏
   但配对全错"的情形。
2. 只覆盖 `TARGETS` 内的 `.md`。仓库里的 `.md` 有相当一部分不在扫描面内
   （§2.40 已记名这条边界），它们围栏不配平**本判据看不见**。
3. 本轮**没有**从头扫全库所有 `.md` 的围栏奇偶；修的是 `docs/HANDOVER.md`
   这一个实测出问题的文件 + 加了面内判据。
4. §2.52.8 的三处修复**只改了报文与打印条件**，判据的 PASS/FAIL 结论与改前一致
   （干净树上都是 PASS）。即：本轮修的是"红了以后你看不懂为什么"，
   不是"该红没红"。
5. 第 40 项在**注入轮**里红、在**干净树**上绿；CI 侧**仍未取得证据**
   （提交 `3e09018` 的 run 仍因帐单问题未启动 job，见 §2.52.12）。

### 2.52.12 CI 实测：**仍然没有拿到证据**（帐单问题，非代码）

提交 `3e09018` 的 run **`37841965706`** 结论 `failure`，但它**不是代码问题**：

| job | conclusion | started | completed |
|---|---|---|---|
| `linux-portability` | failure | 20:46:36Z | 20:46:39Z（**3 s**） |
| `build-and-verify` | failure | 20:46:36Z | 20:46:41Z（**5 s**） |
| `reproducible` | skipped | 20:46:41Z | 20:46:41Z |
| `sdk-package` | skipped | 20:46:41Z | 20:46:41Z |

两个 job 各在 3 秒 / 5 秒内"完成"，注解逐字：

```
X The job was not started because recent account payments have failed or your
  spending limit needs to be increased. Please check the 'Billing & plans'
  section in your settings
```

⇒ **调度层失败**，一个 step 都没跑（若为代码问题，`build-and-verify` 至少要跑几分钟
的 Release 构建）。判定方法 = `gh run view <id> --json status,conclusion,jobs`，
逐 job 打印 `conclusion` 与 `startedAt/completedAt`：**秒级 + skipped 兄弟 job +
帐单注解** 三者同时出现即调度层失败。

本条对 §2.52 的影响 = **没有任何影响**：2.52.6 的承重验证、2.52.7 的第 40 项注入证据、
2.52.10 的完整门禁 `PASS: 37 项` 全部是**本机**实测。CI 绿本也不能替代它们
（§2.50.12 已记过同一件事：绿只说明"这一次没触发"）。

诚实边界（承接 §2.50.12 的三条）：帐单/支出上限属**外部基础设施状态**，
需去 GitHub `Billing & plans` 处理；在那之前**每一次提交都不会有 CI 证据**，
记录里只能如实标注"该提交缺少 CI 验证这一环"。

*2026-10-06 v30*

## 2.53 门禁第 41 项：6 个「登记了自检却没有任何执行者」的工具 —— 以及本项首跑就抓到我自己（2026-10-09）

### 2.53.1 缘起：§2.42 只补了 5 个，全量对账又查出 6 个

§2.42（`docs/HANDOVER.md:4778`）给 **5 个**「休眠自检」接了线，当时的做法是**人工列举**。
本轮改成**机器普查**，口径三条：

- **声明** = 用 `ast` 判定该文件是否真的 `add_argument('--selftest')`
  或 `add_parser('selftest')`。**不按文本判** —— 文本会把「定义了 `selftest()`
  函数」读成「登记了自检入口」。
- **执行者** = 在入口清单（`tools/release_check.ps1` / `tools/ci_sim.ps1` /
  `tools/ci_linux.ps1` / `build.ps1` / `.github/workflows/ci.yml` /
  `.github/workflows/ci-linux.yml`）里**以自检参数**调用它。
- **孤儿** = 有声明、无执行者。

结果：**29 个工具登记了自检，6 个是孤儿**：

| 工具 | 形态 | 用例数 | 此前为何没被发现 |
|---|---|---|---|
| `tools/genpaths.py` | `--selftest` | 17（含 3 负向） | 人工列举漏了 |
| `tools/hostgen.py` | `--selftest` | 19 | 同上 |
| `tools/identity.py` | `--selftest` | 12 | 同上 |
| `tools/migration_cost.py` | `--selftest` | 15 | 同上 |
| `tools/solve_profile.py` | `--selftest` | 13 | 同上 |
| `tools/observability.py` | **子命令** `observability.py selftest` | 10 | **形态不同，按 `--selftest` 搜必然漏** |

`docs/PROTOCOL_GOVERNANCE.md:174-175` 的强制纪律逐字是：

> **全部带 `--selftest` 的工具都能自证"会抓错"** —— 这是门禁失效事件（2026-09-23，
> 7/13 项曾静默通过）后确立的**强制纪律**。

**这条纪律说的是「能自证」，没有说「自证必须被执行」。** 这 6 个正是「能自证、
用例写得很足、但从未被任何自动化面跑过一次」—— 与 §2.36.8 / §2.38 / §2.40 /
§2.42 / §2.46 / §2.52 同一个家族：**事实可得，但没有任何判据在用它。**

### 2.53.2 修法：`tools/selftest_audit.py`（门禁第 41 项）

四条判据：

1. 登记了自检的工具数 > 0（**失锚守卫** —— 扫描面失效时必须报，不得读成"没有孤儿"）
2. 入口清单可达（**失锚守卫**，打印 `入口 N 个，可达文件 M 个`）
3. 无孤儿
4. **执行者传入的旗标必须已登记**（见 2.53.3，这是首跑之后才补的）

关键实现选择：

- `_strip_docstrings()` 用 `ast` 找 `ast.Expr(Constant(str))` 形态并**整行清空**，
  只清文档串、**不清普通字符串字面量** —— 因为 `os.path.join(REPO, 'tools',
  'vmc_linux.py')` 里的路径**就是代码**，清掉会让真实执行者消失。
- `_statements()` 按**逻辑行**切分（括号深度归零且不以反引号结尾才断句）。
  首版用「字符距离窗口 `REF_WINDOW = 400`」，自检用例 M3 立刻报
  `孤儿 0（期望 1）`：`& $py tools\a.py --quiet` 与 `& $py tools\b.py --selftest`
  是**相邻两行**（距离极近）但**不是同一条命令**。
  **判定必须按语句做，不能按字符距离。**
- `executors()` 做两轮：第一轮直达，第二轮从入口出发做**可达链 BFS**
  （支持「入口 -> A -> C」的传递调用）。

**成本实测**：6 个自检合计 **0.38 s**，连跑后 `git status --short` **完全干净**
（不写任何仓库文件）。

**自洽性检查**：审计工具自己也是「登记了自检」的一员。注册本项后，
孤儿名单里 `tools/selftest_audit.py` 与那 6 个**应当同时消失** —— 实测确实如此。

### 2.53.3 ⭐ 本项首跑就让完整门禁变红，而红的是我自己

第 41 项注册后跑完整门禁（后台作业 `pwsh-1163`）：

```
[release_check] FAIL: 1/38 未通过
```
诊断逐字（`build/logs/release_check_20261009_054204.log`）：

```
usage: identity.py [-h] [--project PROJECT] [--version VERSION] [--user USER]
                   [--purpose PURPOSE] [--master MASTER] [--selftest] [--info]
identity.py: error: unrecognized arguments: --quiet
[X]  休眠自检审计 (selftest_audit)
```

根因：我在门禁 body 里给 **6 个**孤儿**统一**加了 `--quiet`，而实测只有 **2 个**
登记了它。`build/_quietchk.py`（AST 判定）实测：

| 工具 | 有 `--quiet`? | 已登记的长旗标 |
|---|---|---|
| `genpaths.py` | **NO** | `--json --layout --platform --print-build-dir --print-gen --print-gen-rel --print-vm-json --selftest` |
| `hostgen.py` | YES | `--all --hook --out --quiet --selftest` |
| `identity.py` | **NO** | `--info --master --project --purpose --selftest --user --version` |
| `migration_cost.py` | **NO** | `--json --map-a --map-b --selftest` |
| `solve_profile.py` | YES | `--list --out --profile --quiet --selftest` |
| `observability.py` | **NO** | 子命令 `all/diff/entropy/selftest/static` |

⇒ 这个缺陷**恰好就是本项要防的那一类**：判据覆盖了「**有没有**执行者」，
没覆盖「**执行得对不对**」。补判据④：把执行者调用语句里的每个 `--` 长旗标
与该工具 `add_argument` 登记的名字比对，出现未登记即 FAIL。
**判不了 ⇒ 跳过**（源码不可解析 / 找不到），不得读成「没问题」，
也不得读成「有问题」。

### 2.53.4 ⭐ 判据④首版报 3 条假阳性，根因在 PowerShell 格式串

首版判据④（`tools/selftest_audit.py` 31330 B）实测报：

```
[XX] ④ 执行者传入的旗标都已登记
  tools/ci_sim.ps1 以 --all-compositions 调用 tools/android_compile_check.py
  tools/release_check.ps1 以 --all-compositions 调用 tools/android_compile_check.py
  tools/release_check.ps1 以 --install 调用 tools/android_compile_check.py
```

`build/_findflags.py` 全库定位证实：**`--all-compositions` 属 `tools/modcheck.py`
（`:978 ap.add_argument('--all-compositions', action='store_true'`），
`--install` 属 `wsl --install`** —— 三条**全是假阳性**。

根因（`build/_covdbg.py` 打印覆盖语句原文才看出来）：`_statements()` 按**括号深度**
断句，而 PowerShell 格式串 `Write-Host ("… {0}" -f $x)` 里的 **`{0}` 让深度永久抬高**
（`{` 未配对）⇒ 整个 `release_check.ps1` 被并成**一条巨型语句** ⇒ 判据在这条语句里
扫到别的工具的旗标，全算到 `android_compile_check.py` 头上。

修法 = `_invocation_segment(text, start)`：从工具名首次出现处截到**命令边界**
（`;` / `|` / 物理换行；行尾反引号表示续行**不算**断句），逐出现位置分别取段。
修后只报**真**缺陷 2 条（`identity.py` / `migration_cost.py` 收到 `--quiet`）。

### 2.53.5 自检 13/13（两族），含 5 条旗标面负向用例

孤儿面 8 条（M1 无人调用 / M2 只在注释里被提到 / M3 被调用但不带自检参数 /
M4 正常 / M5 传递可达 / M6 中间一跳不带参 / M7 子命令形态 / M8 **只在 docstring 里被提到**）
+ 旗标面 5 条：

| 用例 | 注入 | 期望 |
|---|---|---|
| F1 | 传入工具没登记的 `--quiet` | 必报 1 条 |
| F2 | 只传已登记的 `--selftest` | 不得报 |
| F3 | 工具**登记过** `--quiet` 后再传 | 不得报（防"一律报"） |
| F4 | 同一语句里**别的**工具的旗标 | 不得算到本工具头上（正是真实仓库的假阳性） |
| F5 | 工具源码不可解析 | 跳过、不得报（防"判不了读成有问题"） |

⇒ `[selftest-audit-selftest] 13/13 变异被抓`。

⚠️ **M8 用例的 fixture 踩过一次坑**：首版把 Python docstring 放进
`tools/release_check.ps1`（PowerShell）⇒ `ast.parse` 抛 `SyntaxError` ⇒
`_strip_docstrings()` 原样返回 ⇒ 根本没剥 ⇒ 用例报「孤儿 0（期望 1）」，
**看起来像判据没有判别力**，实际是 fixture 放错了语言。修法 = 放进可达的
**Python** 入口。这是「探针的错伪装成被测对象的性质」的第 21 次。

### 2.53.6 计数口径 40/37 → 41/38，以及第四种措辞

`tools/doccheck.py`：`GATE_TOTAL = 41` / `GATE_DEFAULT = 38`（`:208-209`），
`:198-207` 沿革续写一行。

同步的「现时值口径」位置：`README.md`（含**成员清单**新增一行）、
`.github/workflows/ci.yml:67`/`:111`/`:115`、`docs/CONTINUATION_PLAN.md:529`/`:622`/`:688`/`:716`、
`docs/DEBUG_CONSOLE_PLAN.md:8`、`docs/DECISION_REDUNDANCY_PLAN.md:257`、
`docs/HANDOVER.md:18`、`publish/01-关于ShardVase.md`、`publish/02-项目档案.md:116`/`:168`、
`ShardVase-展示文档.md:163`、`.github/PULL_REQUEST_TEMPLATE.md:16`。
**历史记录一律不动。**

⚠️ `publish/02-项目档案.md` 的同一串出现 **2 次** ⇒ 断言须写 `want=2`，
不能逐处断言唯一。

⭐ **顺带发现 `ci.yml:67` 是第四种措辞，从来无人判**：
原文 `release_check 覆盖 39 项 (默认 36)。` —— 第 40 项落地后它**早已过期**
（真值 40/37）却没有任何检查报。根因 = `tools/doccheck.py` 的 `_CI_FORMS`
只认三种措辞（`静态调用点` / `默认运行` / `要求N项全绿`），
**「覆盖 N 项 (默认 M)」不在其中** ⇒ **判据的措辞面比真值面窄，留下静默区**。
修法 = 增第四项形态（`kind == 'both'`，一句里**两个数各报一条** ——
拆成两条独立形态会让「缺一个数」退化成「少一条形态」）。
`ci_cases` 6 → 8 条；`_TOTAL_FLOOR` 50 → **52**（下限紧贴当前值，**不留余量**
—— §2.49 的教训：余量恰恰使它对自己要防的那件事失明）。
实测 ⇒ `PASS: 52 项（32 项负向注入 / 20 项合规豁免）`。

### 2.53.7 验证表

| 验证 | 命令 | 结果 |
|---|---|---|
| 新工具语法 | `python -m py_compile tools/selftest_audit.py` | rc=0 |
| 新工具自检 | `tools/selftest_audit.py --selftest` | `13/13 变异被抓` rc=0 |
| 新工具本体 | `tools/selftest_audit.py --quiet` | rc=0（四条判据全绿） |
| 门禁可解析 | `[Parser]::ParseFile tools/release_check.ps1` | `parse errors: 0` |
| 文件卫生 | `build/_hygiene.py` | 15 文件 / 0 异常 |
| doccheck 自检 | `tools/doccheck.py --selftest` | `PASS: 52 项` |
| doccheck 本体 | `tools/doccheck.py` | `错误 0, 警告 0` |
| docclaim | `tools/docclaim_check.py` | `PASS (8/8)`，`41 项` |
| 完整门禁 | `tools/release_check.ps1 -SkipDirtyCheck` | 见 2.53.8 |

### 2.53.8 诚实边界

- **判据④只比对 `--` 开头的长旗标**，且只认 `add_argument` / `add_parser`
  **字面量**登记的名字。位置参数、`-x` 短旗标、由父解析器继承的旗标
  **不在射程内**。
- **判据④判不了时跳过**（源码不可解析 / 找不到）—— 宁可沉默也不猜，
  与 `tools/drills.py` 的「无法判定的字段写 null, **不猜**」同一纪律。
  代价：若某工具源码被改成不可解析，它的旗标不再被检查。
- **入口清单是硬编码的 6 个文件**（`selftest_audit.py` 的 `HARNESS` 常量）。
  新增入口须同步；**失锚时判据①/②先 FAIL，不会静默**。
- 只判「**有没有**执行者」与「**旗标对不对**」，**不判自检本身是否充分**
  —— 一个只断言 `1 == 1` 的自检在本项眼里完全合格。
- 本项**不编译、只读源码**（纯 AST），故它证明的是「调用形态正确」，
  **不是**「自检在真产物上确实通过」；后者由被调用工具自己的退出码负责。

### 2.53.9 CI 实测：**又是调度层失败，没有拿到证据**

提交 `88b01f7` 推送后 CI run `37851588013`：

| job | conclusion | started | completed |
|---|---|---|---|
| `linux-portability` | failure | 22:08:48Z | 22:08:51Z（**3 s**） |
| `build-and-verify` | failure | 22:08:48Z | 22:08:51Z（**3 s**） |
| `reproducible` | skipped | 22:08:52Z | — |
| `sdk-package` | skipped | 22:08:52Z | — |

**3 秒 + skipped 兄弟 job** ⇒ 与 §2.50.12 逐字同一形态的**调度层失败**
（帐单/支出上限），一个 step 都没跑。若为代码问题，`build-and-verify`
至少要跑几分钟的 Release 构建。

⇒ **本节的证据链不依赖 CI**：2.53.2–2.53.5 是**本机**实测（13/13 变异、
判据④的真/假阳性对照），2.53.7 的完整门禁 `PASS: 38 项` 也是本机。
CI 绿本来也不能替代它们（绿只说明"这一次没触发"）。
在帐单问题处理前，**每一次提交都不会有 CI 证据**。

## 2.54 「恒为现时」文档里代码块内的门禁项数 —— 被"代码块"豁免整类吞掉（2026-10-09）

### 2.54.1 缘起

用户问「还有剩余计划未完成吗」（m26678）。照例先做全库 `- [ ]` 普查，
顺手对「剩余计划」里最不该出问题的一项做核对 —— 结果查出的不是待办，
而是**判据链自己的一个洞**。

`CONTRIBUTING.md:67` 逐字写着：

```
# 一键门禁（36 项，含模块契约与演练记录检查；发版前加 -With* 共 39 项）
```

而真值是 `Check` 调用点 **41** 个、默认跑 **38** 项（§2.51 落地第 40 项、
§2.53 落地第 41 项时都改过 `tools/doccheck.py` 的 `GATE_TOTAL`/`GATE_DEFAULT`，
也改过 README 正文的同一句话，**但这两处一个字都没动**）。

### 2.54.2 为什么没人发现：它在围栏里

`tools/doccheck.py` 的 `DocView.exempt()` 第一句是：

```python
if self.in_code[i]:
    return '代码块'
```

**无条件、一等公民、先于一切判断**。而 `CONTRIBUTING.md:67`/`:95` 与
`README.md:107` 恰好都是**命令示例 / PR 检查清单**，天然写在 ```` ``` ````
围栏内 —— 于是它们的项数声明**从未被对账过**，改成任意数字 doccheck 仍 `rc=0`。

实测（`build/_exemptx.py`，直接 import doccheck 调 `DocView` 与 `TARGETS`）：

| 文件 | 在扫描面内 | 声明位置 | 是否代码块 |
|---|---|---|---|
| `CONTRIBUTING.md` | **True** | `:67` / `:95` | **是** |
| `README.md` | **True** | `:107` | **是** |
| `ShardVase-展示文档.md` | True | `:163` | 否（正文，已被判据看住） |
| `docs/BLUEPRINT.md` | False | `:128`（`39 项，默认 36`） | 否 —— 压根不在面内 |

⇒ 同在扫描面内的正文声明（展示文档 `:163`）一直是**对的**（第 41 项落地时
已同步），偏偏**围栏内的两处漏了**。这不是"忘了改"，是**判据看不见那里**。

### 2.54.3 为什么不能简单地把这个豁免删掉

`exempt()` 的「代码块」豁免有**真实的、必须保留的**用途：程序输出转录、
命令示例、以及 —— 最要紧的 —— **历史记录**。全库量了一下，
扫描面（33 文件）内「代码块」里的门禁项数命中共 **60 处**，
其中绝大多数是 `docs/HANDOVER.md` 那类历史叙述里的转录。

搞一刀切删豁免 ⇒ 判据会要求**篡改历史记录**才变绿，
正是 §2.40 反向守卫在防的错误。

### 2.54.4 修法：按"这个文件通篇有没有历史语境"收窄，而不是按"是否在围栏里"

新增「恒为现时」集合 —— 这四个 glob 组的文件是读者**当下照着做**的说明，
通篇无历史小节、无程序输出转录：

```python
CURRENT_FACING = re.compile(
    r'^(?:[^/]+\.md'
    r'|\.github/[^/]+\.md'
    r'|publish/[^/]+\.md'
    r'|docs/marketing/[^/]+\.md)$')


def is_current_facing(rel):
    """该文档是否属于「恒为现时」集合(通篇无历史语境)。"""
    return bool(CURRENT_FACING.match((rel or '').replace('\\', '/')))
```

「代码块」分支改成**只对这两类命中、且只限这 25 个文件**才让路：

```python
if not (kind in ('nn', 'nge') and is_current_facing(self.path)):
    return '代码块'
```

刻意**不含** `docs/**` 里那些自声明 `> **最后核实**` 的文件
（`docs/HANDOVER.md` / `docs/CONTINUATION_PLAN.md` 等）：
它们自称"现时"，但正文里带日期的历史小节与转录极多，`docs/HANDOVER.md`
一处就有 60+ 处代码块内命中。把它们并进来就是 2.54.3 那个错误。

落到下方后，三条豁免（沿革 —— 带 `→`/`现为`/`旧值`；序号 —— `第 N 项`；
转述他文 —— `xxx.md:123`）**照旧生效** ——
所以「门禁 21/22 → 33 项」这类句子不会因为新判据变红。

**实测零误报**（`build/_nowfile.py`）：这 25 个文件里代码块内的项数命中
**仅 4 处，且全部是现值声明，0 处程序输出转录**。

### 2.54.5 判别力实测（两个方向，都在真实文件上）

**方向 A：收窄确实抓住了真缺陷。** 先只改代码、**不动**文档，
`tools/doccheck.py` 立刻报 4 条，一条不多一条不少：

```
[X] CONTRIBUTING.md:95 门禁项数声称 36, 实际 41
[X] CONTRIBUTING.md:67 门禁项数声称 36 项, 实际 41
[X] README.md:107 门禁项数声称 36 项, 实际 41
[X] README.md:107 门禁项数声称 39 项, 实际 41
```

豁免计数 `代码块 84 → 80`，恰好减 4 ⇒ **只动了这 4 处，无附带影响**。

**方向 B（反向守卫）：错误推广必须变红。** 用 `build/_cfmut.py` 把
`CURRENT_FACING` 的正则改成也匹配 `docs/.*\.md`（即错误地把历史文件
当成"恒为现时"），doccheck 报 **40 条**，其中 **18 条落在 `docs/**`
历史记录里**：

```
[X] docs/CONTINUATION_PLAN.md:516 门禁项数声称 33 项, 实际 41
[X] docs/HANDOVER.md:163 门禁项数声称 11, 实际 41
[X] docs/HANDOVER.md:6669 门禁项数声称 36, 实际 41
...
```

两个方向都在 `finally` 里**逐字节还原**（`逐字节一致 = True`），
还原后 `rc=0 报错 0 条`。

> ⚠️ 还原必须写在 `finally` 里 —— 这是 §2.46 已经吃过一次的亏：
> 断言中断会把被测文件停在注入态。

### 2.54.6 真值修正

`build/_fix254.py`（每处 `assert count==1`，按原风格回写，三文件均
`bom=False crlf=0`）：

| 文件:行 | 改前 | 改后 |
|---|---|---|
| `CONTRIBUTING.md:67` | `（36 项，…共 39 项）` | `（38 项，…共 41 项）` |
| `CONTRIBUTING.md:95` | `release_check 36/36 PASS` | `release_check 38/38 PASS` |
| `README.md:107` | `# 36 项门禁（默认；共 39 项）` | `# 38 项门禁（默认；共 41 项）` |

改后 `tools/doccheck.py` ⇒ `检查数字 1048 处, 错误 0, 警告 0` / `[doccheck] PASS`
（豁免 231：日期语境 133 / 代码块 80 / 自带日期 6 / 沿革 4 / 转述他文 3 /
规划交付物 3 / 计划验收 2）；`build/_hygiene.py` ⇒ 15 文件 0 异常。

### 2.54.7 自检第七批 `cf_cases`（7 条）

判据本体在 `exempt()` 里，所以用例必须走 `check_text` —— **生产同一条路径**。
七条覆盖：现时文件代码块内真值不报 / `41→36` 必报 / `36/36` 必报 /
**`docs/HANDOVER.md` 同样漂移不报（历史转录反例，本批最重要的一条）** /
带 `→` 沿革不报 / `第 N 项` 序号不报 / 转述他文不报。

自检 ⇒ **`PASS: 59 项（34 项负向注入 / 25 项合规豁免）`**（原 52 项）。

### 2.54.8 ⭐ 我写这批用例时踩的坑（同类第 26、27 次）

**坑一：fixture 的语序错了，看起来像"判据没有判别力"。**
第一版我写 `_mk_cf('README.md', '# 36 项门禁')` —— 数字在前。
而 `RE_GATE_N` 是 `(?:release_check|门禁)[^\n]{0,24}?(\d+)(?:\*\*)?\s*项`
⇒ **锚点在「门禁」上，数字必须跟在它后面**。于是「41→36 必须报」
实测 0 条错误，打印出来活像判据失效。改成 `'# 门禁 36 项'` 后立刻报。

**坑二：守卫写死了"必须是代码块豁免"，把另外三条合法豁免也判成失败。**
我第一版收尾写 `if _exc.get('代码块', 0) != 1: fails.append(...)`。
实测三条不报的用例分别记的是 `{'沿革': 2}`、`{}`、`{'转述他文': 1}` ——
**它们本来就该由沿革/转述他文豁免，或者根本没触发判据（真值 = 41 那条）**。
守卫把"不报"一律当成"必须是代码块豁免"，反而让三条**正确**的用例报红。

修法 = 守卫只**反向**锚定在它真正要防的那件事上（非现时文件**只能**靠
代码块豁免不报，因为若收窄蔓延到 `docs/**` 就出 2.54.5-B 那个错），
再补一条"判据至少跑过（`checked >= 1`）"防假绿。

> **教训：守卫也要有正确的锚点。** 我把"期望 0 条"与"必须是某一种豁免"
> 绑在一起，而豁免有六种 —— §2.47 的 `RE_XREF` 转述豁免、§2.54 的沿革豁免
> 都是**独立**路径。守卫只能断言它**真正**反对的那一种降级。

### 2.54.9 ⭐ 我刚写完这一节，围栏配平判据就抓到了我自己（同类第 28 次）

写完 2.54.4 后跑 `tools/doccheck.py`，它报了：

```text
[X] docs/HANDOVER.md 的 三连反引号 围栏总数 323 是**奇数** -> 从某一处起 `in_code`
    语义整体反转（代码块豁免整类失效）。最后一个围栏在 :7388；先找那个多出来的
    孤立围栏（§2.51 的成因是插新节时多写了一行）
```

根因（`build/_fence254.py` 定位）：我在 2.54.4 末段把三条豁免的名字写成了
**行首**的行内代码 —— 那一段的第二行以三连反引号开头，而围栏判定就是
`l.lstrip().startswith(三连反引号)`（`tools/doccheck.py` 的 `DocView._walk()`）：
它把**行内代码的收尾符**读成了**围栏开启**，于是从 `:7358` 起 `in_code`
整体反转，**后面所有代码块豁免全部失效**。

修法 = 不再用行首三连反引号写那三个名字，改用括号并列（见本版 2.54.4 末段）。

> **这条判据（§2.51 建的）第一次开火就是打在我身上，而且打对了。**
> 它报的正是"`in_code` 语义整体反转"，也就是 §2.52 记的那个"代码块豁免
> 整类静默反转"的机制 —— 我这次是**主动**触发它，而不是它被绕过。
> 换句话说：**这一节讲的是"豁免看不见东西"，而抓到我的是"豁免本身坏了"。**
> 两者同源：豁免是**按文本形态**给的，任何让形态判定失准的写法都会
> 静默改变判据射程。

### 2.54.10 诚实边界

1. **`docs/BLUEPRINT.md:128`（`39 项，默认 36`）仍未被任何检查看过** ——
   它不在扫描面内（未自声明 `> **最后核实**`，也不在 `publish/`/`docs/marketing/`）。
   同类还有 `docs/ATTACK_FRAMEWORK.md:29`（`18 项`）、
   `docs/blog_project_overview.md:45`/`:72`、`docs/部署档案-ShardVase.md:114`。
   **刻意不并入扫描面**：实测若并入，它们会要求篡改历史文档才变绿
   （`build/_cand.py` 预演过），而其中确有"当时真值"性质的旧记录。
   本节只解决了**围栏内**这一半，**面外**那一半是**人判断的残余**。
2. 判据只认 `RE_GATE_NN` / `RE_GATE_N` 两种形态（`N/N` 与 `N 项`），
   且都以 `release_check|门禁` 为前缀锚。写成「跑 38 个检查」之类
   **不在此列**（那是 §2.45 阈值判据、§2.46 ci.yml 判据各自的射程）。
3. 收窄**只**打在 `nn`/`nge` 两类命中上。`vague`（模糊表述）等其他
   kind 在「恒为现时」文件的代码块内**仍被无条件豁免** ——
   本节没有一并处理，因为量没量过。
4. 「恒为现时」集合是**按路径 glob 硬编码**的 25 个文件。
   若哪天新增一个根目录 `.md`（`^[^/]+\.md$` 自动覆盖），它会**默认**进入
   判据射程 —— 这是有意的：根目录文档天然是 front door。
   但若新增 `docs/` 下的现时说明文件，**不会**被覆盖，需要显式加进来。

### 2.54.11 验证表

| 项 | 命令 / 手段 | 结果 |
|---|---|---|
| 判据抓真缺陷 | `tools/doccheck.py`（只改码不改文档） | 4 条，精确命中 3 行 |
| 无附带影响 | 豁免 `代码块` 计数 | 84 → 80，恰好 −4 |
| 反向守卫 | `build/_cfmut.py` B（错误推广到 `docs/**`） | 40 条，18 条落在历史记录 |
| 逐字节还原 | 两个方向 `finally` | 均 `True`，复原后 rc=0 |
| 自检 | `tools/doccheck.py --selftest` | `PASS: 59 项（34 负向 / 25 豁免）` |
| 文档卫生 | `build/_hygiene.py` | 15 文件 0 异常 |
| 全门禁 | `tools/release_check.ps1 -SkipDirtyCheck` | `PASS: 38 项检查全通过` |

### 2.54.12 全门禁

`& powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\release_check.ps1 -SkipDirtyCheck`
⇒ 末四项 `[ok] selfcrypt 驻留期密文态 (selfcrypt_residency)` /
`[ok] selfcrypt meta 布局四方一致 (selfcrypt_meta)` /
`[ok] 休眠自检审计 (selftest_audit)` /
**`[release_check] PASS: 38 项检查全通过`**，
日志 `build/logs/release_check_20261009_075655.log`。

### 2.54.13 这条缺陷的一般形状

和 §2.36.8 / §2.38 / §2.40 / §2.42 / §2.46 / §2.53 是**同一个形状的第 7 次**：

> **判据存在、判据正确，但它看不见这一处 —— 而"看不见"和"没问题"
> 在输出上长得完全一样（都是 `[ok]` / `rc=0`）。**

差别只在于这次遮住它的是**豁免规则本身**：一条为"历史转录不该被改"
而设的豁免，顺手把"现值声明恰好也写在围栏里"这件事一起豁免掉了。
**豁免是按"文本长什么样"给的，而判断"该不该管"需要看"这个文件是什么"。**
v32 起的做法就是把这个区分显式写进代码，并给它配了一个反向守卫
（2.54.5-B）。

---

## 2.55 扫描面**外**「自称权威」文档里的门禁项数 —— 有人当现值在维护，却不在面内（2026-10-09）

### 2.55.1 缘起

§2.54 修的是**面内**代码块里的现值声明（`CONTRIBUTING.md:67` / `:95`、
`README.md:107`）。它留了一条诚实的尾巴（2.54.10 边界第 1 条）：

> 扫描面**外**的同类陈旧声明（`docs/BLUEPRINT.md:128` 等）本轮未处理 ——
> 它们不在面内，判据看不见，属**人判断的残余**。

本轮把这条尾巴查清并定性。普查口径（`build/_faceall.py`，只读）：

| 口径 | 数量 |
|---|---|
| 全库 `.md` | **126** |
| 扫描面内（`TARGETS`） | **33** |
| 扫描面外 | **93** |
| 面外含门禁项数声明者 | **10 文件 / 19 条** |

### 2.55.2 先把目标函数说清楚（这一步决定判据是帮忙还是添乱）

第一反应是「让面外文件也有判据」。**这个目标函数是错的**，理由是那 19 条的
构成 —— 逐条实测（`build/_faceall.py`）：

| 文件:行 | 声称 | 最后修改 |
|---|---|---|
| `docs/BLUEPRINT.md:128` | 39 项 | **2026-10-07** (`7062039`) |
| `docs/ATTACK_FRAMEWORK.md:29` | 18 项 | 2026-09-25 |
| `docs/LINUX_PORT_PLAN.md:28` | 21 项 | 2026-09-26 |
| `docs/OSS_TAIL_PLAN.md:21`/`:71`/`:103`/`:264` | 14 / 4 / 14 / 14 | 2026-09-2x |
| `docs/PILLAR2_OBSERVABILITY_PLAN.md:292` | 14 | 2026-09-2x |
| `docs/PLATFORM_EXPANSION_PLAN.md:363`/`:483` | 14 / 14 | 2026-09-2x |
| `docs/WINDOWS_COVERAGE.md:136`/`:212` | 14 / 14 | 2026-09-2x |
| `docs/WORKBENCH_ROADMAP.md:140` | 14 | 2026-09-2x |
| `docs/blog_project_overview.md:45`/`:72` | 11 / 11（`:45` 另含 28 项） | 2026-09-01 |
| `docs/部署档案-ShardVase.md:114`/`:166` | 11 / 11 | 2026-09-01 |
| `docs/BLUEPRINT.md:640` | 11 | 2026-09-21 |

其中 **18 条是历史计划文件里写死的旧值**。把它们并入扫描面，只会让判据要求
**篡改历史文档**才变绿 —— 那是 §2.40 反向守卫在防的**同一类错误**。

真正的问题只有一处：**`docs/BLUEPRINT.md:128` 是有人当现值在维护的**。
证据不是「它看着像」，而是**该行的最后一次修改**（`build/_blame55.py`，
`git log -1 -L 128,128:docs/BLUEPRINT.md`）：

```
提交 7062039  (门禁第 39 项落地那次)
@@ -128 +128 @@
-| 发布门禁（38 项，默认 35） | ✅ |
+| 发布门禁（39 项，默认 36） | ✅ |
```

即**第 39 项落地那次提交亲手改过它**。它不在面内 ⇒ 从那一刻起这个数字
**再也没有任何判据在看** ⇒ 到 §2.51（第 40 项）与 §2.53（第 41 项）之后
真值已是 **41/38**，而它仍写着 **39/36**。

对比 `docs/BLUEPRINT.md:640`：那行写的是 `release_check 11/11`，后面自注「实际 **13**（后为 14）」，
—— **它本身就是一条承认该值过期的漂移记录**，性质与 `:128` 相反。

> **所以判据的目标函数是：面外 交 自称权威 ⇒ 其门禁项数声明必须对账。**
> 不是「让面外都有判据」（要求篡改历史），也不是「什么都不做」（真会漂）。

### 2.55.3 措辞选型：为什么用「单一来源/单一事实源」而不是「总纲」

「自称权威」需要一个可判定的措辞。四个变体在**头部前 8 行**实测
（`build/_p55probe.py` / `_p55pick.py`）：

| 变体 | 面外命中 | 其中门禁类报错 |
|---|---|---|
| V1 只认加粗 `**总纲|单一来源|单一事实源**` | **1** | 2 |
| V2 加粗或不加粗、任意位置 | 4 | 2（另 3 个各 0） |
| V3 只认标题或引用行 | 4 | 2 |
| V4 标题/引用行 + 必须紧邻 | 1 | 2 |

选定 **P1 = 头部（跳过围栏）含 `单一来源|单一事实源`，加粗可选**：

* **`总纲` 是弱词**：`docs/ADVANCED.md:6` / `docs/ADVANCED2.md:6` /
  `docs/BUSINESS.md:1` 都用它，而且 `docs/ADVANCED.md:6` 那句是
  「关联：`docs/BUSINESS.md`（总纲）」—— 这是**引用别人**，不是自称；
  `docs/BUSINESS.md:1` 才是自称，但它**没有任何门禁项数声明**。
  用 `总纲` ⇒ 5 个命中（面外 4 + 面内 `docs/HANDOVER.md`），太宽。
* **`单一来源|单一事实源` 是自称权威的专有措辞**：全库任意位置仅 **9** 处，
  其中**头部仅 1 处**（`docs/BLUEPRINT.md:3`），其余 8 处都是正文里的架构
  讨论（`docs/ARCHITECTURE_OVERVIEW.md:274` / `docs/BLUEPRINT.md:1011` /
  `docs/HANDOVER.md:6450` / `docs/PLATFORM_ISOLATION_PLAN.md:326`/`:1526`/`:1685`/`:2257` /
  `docs/UWP_ASSESSMENT.md:150` / `prot_sdk/GUI_GUIDE.md:34`）
  ⇒ **限定头部即天然零附带影响**。

> ⚠️ 还试过一个「更精确」的变体 P2：P1 再排除头部含 `关联` 者。
> 实测命中 **0** —— 因为 `docs/BLUEPRINT.md:5` 正是关联行。
> **刻意不用它**：让判据精确到**永不触发**，和没有判据是同一种失效。
> 宁可覆盖面稍宽，也不能让它只在理论上有判别力。

### 2.55.4 修法

`tools/doccheck.py` 新增（紧接 `is_current_facing()` 之后）：

* 常量：`SELF_AUTHORITATIVE = re.compile(r'(?:\*\*\s*)?(单一来源|单一事实源)(?:\s*\*\*)?')`
  / `AUTH_HEAD_LINES = 8` / `AUTH_SKIP_DIRS = ('.git', '.vs', 'archive', 'node_modules', 'build', 'dist', '__pycache__')`
* `self_authoritative_head(text, lines=AUTH_HEAD_LINES)` —— 只扫头部前 8 行，
  **跳过代码块**（沿用 `DocView._walk()` 的围栏翻转写法），命中即 `True`。
* `self_authoritative_files()` —— `os.walk(REPO)` 排除 `AUTH_SKIP_DIRS`，
  并**跳过已在 `TARGETS` 内者**（面内已由主循环覆盖，不重复判），返回相对路径。
  `build/` 必须排除：它装着发布暂存与产物副本，里面有这些 `.md` 的拷贝。
* `check_self_authoritative_claims(docs=None, gate=None, rounds=None)` —— 两条判据：
  * **① 待判集合非空**（锚点守卫）：措辞被改 / 扫描器坏了 / 仓库根不对 ⇒
    返回**一条错误**，文案明写「**不得**读成"没有漂移"」；
  * **② 集合内每份文档的门禁项数声明必须落在 `GATE_OK` 内**，判定走
    `check_text()` —— 与生产**同一条**路径，故 `沿革`/`序号`/`转述他文`/
    `自带日期` 四条豁免照旧生效。
* `main()` 新增 **0g** 步（继 0/0b/0c/0d/0e/0f），成功时打印
  `[ok] 面外自称权威文档: 1 份（docs/BLUEPRINT.md）门禁项数与真值一致`。

> ⚠️ **刻意不把这几份文件并入 `TARGETS`**：它们会连带触发模糊表述与死链判据，
> 而那些是历史文档的既成事实（实测 `docs/BLUEPRINT.md` 另有 4 条模糊表述报错）。
> 本判据**只取**两条门禁项数判据的报错。

### 2.55.5 `DELTA_WORDS` 扩一个词：`后为`

`docs/BLUEPRINT.md:640` 那条漂移记录写的是「实际 **13**（**后为** 14）」。
`RE_DELTA`（`→`/`->`/`⇒`）不含它，`DELTA_WORDS`（`现为|曾|旧值?|已过期`）也不含。

全库影响半径实测（`build/_authprobe.py`）：

* 因新加 `后为` 而**新获「沿革」豁免**的**当前报错行 = 恰 1 条**
  （就是 `docs/BLUEPRINT.md:640`），**面内 = 0 条** ⇒ 无附带影响。
* 全库含 `后为` 的行共 5 条：`CHANGELOG.md:34` / `docs/BLUEPRINT.md:640` /
  `docs/HANDOVER.md:1326` / `docs/WORKBENCH_ROADMAP.md:979` / `:1751`
  —— 其余 4 条本来就是历史叙述，且已被别的豁免兜住。

### 2.55.6 真值修正

| 文件:行 | 改前 | 改后 |
|---|---|---|
| `docs/BLUEPRINT.md:128` | `| 发布门禁（39 项，默认 36） | ✅ |` | `| 发布门禁（41 项，默认 38） | ✅ |` |
| `docs/BLUEPRINT.md:640` | —— | **不改**（历史记录，靠新 `后为` 豁免） |

### 2.55.7 ⭐ 判别力实测（两个方向，真实文件，`finally` 里逐字节还原）

`build/_p55load.py`：

**方向 A —— 把真值改回漂移值（只改文档，不动代码）**

```
rc=1  报错 1 条
  [X] docs/BLUEPRINT.md:128 门禁项数声称 39 项, 实际 41
还原逐字节一致 = True   ->  还原后 rc=0 报错 0 条
```

**方向 B —— 反向守卫：把滤网放宽为「面外全部 `.md`」**

```
rc=1  报错 17 条
  [X] docs/ATTACK_FRAMEWORK.md:29 门禁项数声称 18 项, 实际 41
  [X] docs/LINUX_PORT_PLAN.md:28 门禁项数声称 21 项, 实际 41
  [X] docs/OSS_TAIL_PLAN.md:21 / :71 / :103 / :264     14 项 / 4 项 / 14 / 14
  [X] docs/PILLAR2_OBSERVABILITY_PLAN.md:292            14
  [X] docs/PLATFORM_EXPANSION_PLAN.md:363 / :483        14 / 14
  [X] docs/WINDOWS_COVERAGE.md:136 / :212               14 / 14
  [X] docs/WORKBENCH_ROADMAP.md:140                     14
  [X] docs/blog_project_overview.md:45 / :72            11 / 11（:45 另报 28 项）
  [X] docs/部署档案-ShardVase.md:114 / :166             11 / 11
还原逐字节一致 = True   ->  还原后 rc=0 报错 0 条
```

17 条**全部**是历史计划文件与旧发布快照里写死的旧值 ⇒ **「只认自称权威」
这条收窄是承重的**，不是装饰。

### 2.55.8 自检第八批 `sa_cases`（10 条）

三种 kind：`'c'` 判据本体（`docs=` 直接传入）/ `'p'` 滤网+判据组合 /
`'h'` 只测滤网。`tools/doccheck.py` 的 `selftest()` 新增，四处接线同改
（`total` / `neg` / `_BATCHES` / 两处打印循环 —— 否则「暗处运行、看起来不存在」），
`_TOTAL_FLOOR` **59 → 69**（紧贴当前值，不留余量）。

| 用例 | 断言 |
|---|---|
| sa1 | 面外自称权威 + 项数漂移 ⇒ 必报 |
| sa2 | 面外自称权威 + 项数 = 真值 ⇒ 不报 |
| sa3 | 两文件一漂移一正确 ⇒ **恰 1 条** |
| **sa4** | **滤网+判据：面外但未自称权威 ⇒ 不报（历史计划文件）** |
| sa5 | 带 `→` 的沿革 ⇒ 不报 |
| sa6 | 「后为」的漂移记录 ⇒ 不报 |
| sa7 | 待判集合为空 ⇒ 必报（失锚守卫） |
| sa8 | 滤网：不加粗的 `单一来源` ⇒ 认 |
| sa9 | 滤网：第 13 行才出现 ⇒ 不认 |
| sa10 | 滤网：「关联：另一份文档（总纲）」是引用，不是自称 ⇒ 不认 |

**sa4 是本批最重要的一条**：它断言的是「这个判据**不去管**它不该管的东西」。
一个只会报错的判据比没有更危险（§3.8），而 sa4 守的正是方向 B 那 17 条。

结果：`[doccheck-selftest] PASS: 69 项（39 项负向注入 / 30 项合规豁免）`。

### 2.55.9 诚实边界

1. **若哪天把 `docs/BLUEPRINT.md:128` 那行整个删掉，本判据不会报错** ——
   它守的是「**写了就必须对**」，**不是**「必须写」。
2. 滤网只看头部 `AUTH_HEAD_LINES = 8` 行；把自称挪到正文深处的写法会漏
   （但那样它也不再是「头部自称权威」的文档）。
3. 只判门禁**项数**，不判这几份文档的其它数字（版本号 / 轮次 / 日期）。
4. 面外其余 **9 个文件 / 18 条**陈旧声明**仍然没有任何判据** —— 这是**刻意的**：
   并入会要求篡改历史（§2.40 反向守卫同类）。它们属**人判断的残余**，
   本轮只是把「残余有多大」（19 条）量清楚了，没有消除它。
5. `AUTH_SKIP_DIRS` 是**人写的清单**：新增一个装 `.md` 拷贝的目录却没加进去，
   判据会在副本上重复开火（偏保守，不会漏报真缺陷）。

### 2.55.10 验证表

| 项 | 命令 | 结果 |
|---|---|---|
| 语法 | `py_compile tools/doccheck.py` | rc=0 |
| 自检 | `tools/doccheck.py --selftest` | `PASS: 69 项（39 负向 / 30 豁免）` |
| 本体 | `tools/doccheck.py` | `[ok] 面外自称权威文档: 1 份（docs/BLUEPRINT.md）门禁项数与真值一致` / `检查数字 1075 处, 错误 0, 警告 0` |
| 判别力 A | `build/_p55load.py` | 1 条错误 + 逐字节还原 |
| 判别力 B | `build/_p55load.py` | 17 条错误 + 逐字节还原 |
| 卫生 | `build/_hygiene.py` | 15 文件 0 异常 |

### 2.55.11 全门禁

`powershell -NoProfile -ExecutionPolicy Bypass -File tools\release_check.ps1 -SkipDirtyCheck`
⇒ `[release_check] PASS: 38 项检查全通过`。

### 2.55.12 这条缺陷的一般形状

和 §2.36.8 / §2.38 / §2.40 / §2.42 / §2.46 / §2.53 / §2.54 是**同一个形状的第 8 次**：

> **判据存在、判据正确，但它看不见这一处 —— 而"看不见"和"没问题"
> 在输出上长得完全一样（都是 `[ok]` / `rc=0`）。**

§2.54 里遮住它的是**豁免规则**（按文本长什么样给），这一次遮住它的是
**扫描面的边界**（按文件在不在面内给）。两者共用一个更深的原因：

> **判据的作用域是"配置出来的"，而配置不会因为它漏掉了什么而变红。**

所以这两节的做法是同一个：把「该不该管」这个判断从**隐含的配置**
变成**显式的、可被反向守卫检验的代码**（§2.54 的 `CURRENT_FACING`、
本节的 `SELF_AUTHORITATIVE`），并各配一条断言「它**不**管什么」的用例。

*2026-10-09 v33*

