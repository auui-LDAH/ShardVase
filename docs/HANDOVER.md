# 项目汇报与迁移交接 (HANDOVER)

> 生成日期：2026-08-21（v7：阶段 II 收尾 + 已知环境限制）· 基线提交：`9326122` 之后
> **最新增量：2026-09-20 迁移后状态见 §2.6（基线提交 `b8e8a38`）**
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
- **签发体系**：Ubuntu Server（issuer-host）离线签发 + GUI 签发台（本机
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
| 主机 | `DEV-MACHINE` / 用户 `devuser` / Win11 26200 x64 |
| 仓库路径 | `D:\specifically for development and work\Reverse Engineering`（含空格） |
| 工具链 | `D:\environment\VS2022BuildTools`（MSVC 14.44）+ `D:\environment\PYTHON`（3.13.13）——**均不在 PATH**，`build.ps1` 自动探测可命中 |
| 生产私钥 | ✅ 已随迁移带入 `build\keys\license_priv.json`（RSA-3072）——沿用同一把密钥 |
| machine_id | `12981648366597980211`（`demo\vm_build.json` 一致） |

### 已修复（提交 `b8d34e2` / `1105054`）

| # | 缺陷 | 要点 |
|---|------|------|
| 1 | **selfcrypt meta 步长 20B → 24B** | S1(`efded61`) 改了格式但解析侧未同步，**3 文件 8 处**：`protchain_check.py`(P1/P2 FAIL)、`attacks.py`、`attack_drill.py`（后者 5 处为**静默假绿**——错位 rva 恰不命中目标 → 报 PASS）。修法：建单一入口 `protchain_check.selfcrypt_meta()`，其余复用 |
| 2 | **SDK 骨架缺 3 项字符串** | `prot_sdk/skeleton/strings.txt` 11→14 项；`strgen.py:108` 严格 `raise` → 向导生成的新工程**构建即失败**。同步修 `strgen.FALLBACK_ORDER`（9→14） |
| 3 | **`build.ps1` 冒烟自检必然失败** | 两个独立成因：(a) `EAP=Stop` 下 stderr 重定向(`2>&1`/`2>$null` 均然)被包装成终止性异常；(b) PS 管道向原生 stdin 写 BOM。改用 `cmd /c`。**此前未暴露因所有门禁都带 `-SkipSmoke`** |
| 4 | **编码损坏（有损，不可逆）** | `efded61` 引入：UTF-8 字节被 CP936 有损解码（产生 U+E21B 等私用区）。已修**全部字符串字面量**（全库 62 个 `.c/.h` 扫描 = 0）+ BOM + 首行注释；**224 行纯注释乱码保留**（零功能影响） |

### 接手须知（踩坑纪律）

1. **不要试图「重建」乱码文件的注释**。已证伪：用干净祖先做骨架对齐重建后
   **能编译**，但 `e2e T1` 失败（`exit=1` 而 `license_ok=1`）——乱码吞换行，
   还原时丢 `*/` 终止符，注释边界与 `demo_mem` 相关宏行序被改变。
   **ASCII 骨架一致 ≠ 语义等价。**
2. **检测工具的准确性本身要验证**。初版乱码扫描用正则剥注释，无法处理
   「字符串内出现 `/*`」，漏检了 `app_main.c:740`；换带字符串状态机的剥离器才扫净。
   同理：仅查 `U+FFFD` **不足以**判定双重编码（产出的是合法字符，含 PUA）。
3. **`.ps1` 必须保留 UTF-8 BOM**（PS 5.1 无 BOM 时按 GBK 解析，破坏中文字符串，
   见 `35c0605`）。**编辑工具会静默去掉 BOM**——改完 `.ps1` 后务必复查首 3 字节
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
| 0 | SCDBG 调试日志改为 opt-in（Release 不再泄漏 RVA/密钥/CRC） | `f0aa393` |
| 1 | 模块注册表 `modules.json` + 校验器 `tools/modcheck.py` + 四档 `compositions/`，接入门禁 | `da6680e` |
| 2-构建层 | `tools/compose.py`（拼装图→源文件/宏/头文件）+ 宿主下限链接器实测 | `5eff7ae` |
| 2-宿主批1 | `vmdetect`/`dbiguard` 条件编译（实证：13→11 模块，产物省 3584B） | `f4ccf64` |

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
   `C:\Users\devuser\nssm\nssm-2.24\win64\`）。
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
| 攻防累计 | 三轮 45 项全结论（第一轮 23 + 第二轮 13 + 第三轮 9），0 破防点，已知边界 3 类（D2a 明文 dump/离线可 patch/内存 patch 非文件 CRC） | 完成 |
| 第四轮攻防演练 | **10 项 6 BLOCKED/0 BREACHED/4 PARTIAL/0 SKIP（2026-08-25 真机）**：verify 语义还原成功（设计已知）但单镜像不足以通过；Procdump 16.9MB 明文在场（D2a 边界）；精确挂线程崩溃防绕过；DR 不可用户态清；重放被 N5 拒 —— 见 docs/ATTACK_DRILL4.md | 完成 |
| 攻防累计 | **四轮 55 项全结论（23+13+9+10），0 破防点**；已知边界 4 类（D2a 明文 dump/离线可 patch/内存 patch 非文件 CRC（G2 已补）/单镜像可还原（多 VM+N5 阻断））；还原工具 vm_reduce.py + 取证转储 procdump_like.py 已建 | 完成 |
| D5/E5 补充 | **DLL 劫持（D5）BREACHED（环境下：同目录 winhttp.dll 影响运行——结论=安装目录 ACL 只读）**；VEH 覆盖（E5）PARTIAL（需注入前提，G1 已覆盖）—— 见 docs/ATTACK_DRILL5.md | 完成；**部署约束：安装目录 ACL 只读** |
| 平台延申 | **Android 原生 SO（A）+ 跨平台许可服务化（C）—— 完备计划见 docs/EXTENSION_PLAN.md**（C1/**A1/A2/A3 已完成源码，NDK 实编待环境） | 源码就绪 |
| 基础设施完善 | **I1-I6 全部完成（2026-08-26）**：ci_sim 本地 CI 模拟 / repro_check 统一 / release_check gate / build.ps1 --help+校验 / clean_build / changelog —— 见 docs/INFRA_PLAN.md | 完成 |
| **剩余待办（迁移）** | ① release_check 全量实跑（下次发版前 gate，当前 11/11 绿）② Android T1 攻防矩阵（需 NDK/真机）③ GitHub 真实 push 后 CI 实跑替换 ci_sim ④ EXTENSION A 的 NDK 实编 ⑤ Windows 侧 W2 长驻留实跑验证 + Release D2b 真机确认 | 见对应文档 |
| Windows 侧增强 | **W1-W4 已实施（2026-08-26）**：Release 默认 D2b（-NoD2b 回退）+ watchdog 周期回调（N3 冗余 + dbiguard 周期，FAKE 翻转 sum 修复）+ ACL 部署要求 + Release 错误收敛 —— 见 docs/WIN_ENHANCE.md | 完成（长驻留实跑验证待） |
| 清理 | `demo\license_vm.vasm` 为历史遗留（已被 4 小 VM 取代），保留作参考 | — |
| verify 增强 | **verify.ps1 已同步 protchain 保护链断言（2026-08-22）**：本地门禁=CI 门禁；附带修复 example 适配 BLOB_SIGN（容器移 selfcrypt.c + pack/revoke --sign）—— 见 docs/VERIFY_PLAN.md | 完成 |

### 4.4 阶段 II 实测记录（2026-08-21；2026-08-24 真机复验全能力）
- 真机（test-host，100.x.x.x，Win11 家庭版 24H2 26200，2026-08-24 复验）：
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
  授权伪造/篡改/试用期绕过——**全部拒绝**；发现的静态串暴露已加固（`d7c50bc`）。
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