# 项目汇报与迁移交接 (HANDOVER)

> 生成日期：2026-08-21（v7：阶段 II 收尾 + 已知环境限制）· 基线提交：`9326122` 之后
> 本文档对当前开发状态的唯一快照性说明。与本项目相关的正式规范/历史/路线图
> 见 `docs/BUSINESS.md`（总纲）/ `docs/RELEASE.md` / `docs/OPS.md` /
> `docs/COMPAT.md` / `docs/PHASE2.md` / `docs/PHASE3.md` / `docs/ADVANCED.md` /
> `docs/ADVANCED2.md` / `docs/CONTRACT.md` / `docs/PLAN.md` / `docs/ROADMAP.md` /
> `docs/THREATMODEL.md` / `docs/PRODUCTION.md` / `docs/N1_PLAN.md`（N1 一期计划）/
> `docs/N1_PHASE2_PLAN.md`（N1 二期增强计划）/ `docs/BLOB_SIGN_PLAN.md`（blob 签名+网络下发计划）/
> `docs/CI_PLAN.md`（CI 增强+兼容矩阵计划）。
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

### 4.2b 运维踩坑记录（2026-08-21）
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
| 阶段 II 剩余 | T3 真机调试、硬件绑定双机 —— **已知环境限制**（见 §4.5，非代码缺陷） | 待交互桌面会话 / 第二台机器 |
| CI 增强 | **CI 回归面补全 + 保护链断言 + 可复现 job —— 完备计划见 docs/CI_PLAN.md**（决策点 C1-C4 待拍板） | 规划完成，未开工 |
| 阶段 III | 服务端（可选）—— 详细计划见 **docs/PHASE3.md**；决策点 D2 已定离线优先（M3.1 已完成） | 未开工（按 D2 不启动 M3.2/M3.3） |
| 可选 | N1 真机复核（D2b 高频 SMC 杀软行为）—— 见 **docs/N1_PHASE2_PLAN.md** §8 | 需交互桌面会话（环境限制） |
| 清理 | `demo\license_vm.vasm` 为历史遗留（已被 4 小 VM 取代），保留作参考 | — |

### 4.4 阶段 II 实测记录（2026-08-21）
- 真机（oiahcoiah，Win11 24H2 26200）：e2e T1-T24 除 T3 全 PASS；attacks A1-A7；vm_unit；syscall_probe；
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