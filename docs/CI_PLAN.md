# CI 增强 + 兼容矩阵更新 — 完备实施计划 (CI_PLAN)

> 版本：2026-08-22 v2 · 状态：**✅ 全部完成（2026-08-22 落地）** · 关联：`docs/PHASE2.md`（B2 CI 待办）·
> `docs/HANDOVER.md`（环境限制/回归面）· `.github/workflows/ci.yml`（现状）·
> `docs/COMPAT.md` + `docs/compat-matrix.csv`（兼容矩阵）。
> 本文档规划：**GitHub Actions CI 回归面补全** + **兼容矩阵扩展**。
> v2 记录落地结果：protchain_check.py（P1-P6）、CI 双 job、矩阵三行。

---

## 1. 背景与目标

### 1.1 现状
CI（`.github/workflows/ci.yml`）当前覆盖：
- Build（Release, `-MachineId auto`）
- e2e（T1-T26——脚本已含，但 CI 未显式标注）
- attacks A1-A7
- vm_unit
- py_compile（5 个工具）
- artifact 上传（demo.exe/vm_unit.exe/manifest.json）

**缺口**（2026-08-14 后新增能力未被 CI 覆盖）：
| 能力 | CI 是否覆盖 | 风险 |
|------|------------|------|
| vmc 编译器单测（M2/M3 平坦化） | ❌ | 编译器回归无门禁 |
| example tool_demo 接入示例（E1-E7） | ❌ | SDK 接入面回归无门禁 |
| N1 selfcrypt（引擎加密/掩码/CRC） | ❌（build 隐含，无断言） | 掩码/加密静默失效 |
| N5 会话期望值（T25/T26） | ✅（e2e 内含） | — |
| BLOB_SIGN 签名 blob（T27/T28） | ✅（e2e 内含） | — |
| Release 可复现（verify -Reproducible） | ❌ | 种子机制回归无门禁 |
| N2/N3/N4（dbiguard/冗余/间接化） | ❌（e2e/attacks 隐含） | 无显式断言 |

### 1.2 目标
1. CI 回归面补全到与本地 `verify.ps1` 等价（build + e2e + attacks + vm_unit +
   vmc + example + 可复现 + 静态密文断言）；
2. 新增**保护链显式断言**（selfcrypt 密文/掩码、blob 签名、N4 间接化）——
   防止未来改动静默破坏保护能力；
3. 兼容矩阵扩展：记录 2026-08-14 后新能力（N1-N5/BLOB_SIGN/T25-T28）在
   各环境的验证状态。

---

## 2. CI 增强设计

### 2.1 Job 拆分（并行化 + 职责清晰）
```
job build-and-verify (现有, 扩展):
  steps:
    1. checkout
    2. Setup MSVC
    3. Build (Release, -MachineId auto -RecordSeeds)   # 产出 seeds.json
    4. e2e (T1-T28)
    5. attacks (A1-A7)
    6. vm_unit
    7. vmc_tests (新增)
    8. example tool_demo (新增: build_example.ps1 + test_example.py)
    9. py_compile (扩展: + indirect.py + selfcrypt_proto.py + mock_server.py
       + vmc.py + tests\vmc_tests.py)
    10. 保护链断言 (新增, 见 §2.2)
    11. artifact 上传 (扩展: + vm.blob + seeds.json)

job reproducible (新增, 可复现门禁):
    needs: build-and-verify
    steps:
      1. checkout
      2. Setup MSVC
      3. Build (Release, -SeedsFile build/seeds.json -SkipSign)
      4. 与首次构建 demo.exe SHA-256 比对 (upload artifact 下载或重建两次)
```

### 2.2 保护链断言（新脚本 `tests/protchain_check.py`）
用 Python 对 `build/demo.exe` + `build/vm.blob` 做**静态断言**（不运行进程，
无 WDAC 干扰）：
| 断言 | 检查 |
|------|------|
| P1 selfcrypt 密文 | `.text` 目标函数区（从 `.protcry` meta 读 rva/len）为密文（无 `40 55` 序言） |
| P2 selfcrypt 掩码 | hashpatch 掩码文件与 meta 一致；.text CRC 带掩码可复算 |
| P3 blob v1 签名 | `vm.blob` 头部 `PROTVMB1` + 签名区存在（256B） |
| P4 blob 签名可验 | 用 Python RSA 公钥（从 keygen blob 或内嵌公钥）验签通过 |
| P5 N4 间接化 | 反汇编扫描：`prot_vm_run` 等 4 函数无直接 `call rel32` 指向 |
| P6 会话期望值 | `expect_default.c` 生成值与 vm_build.json 一致 |

**价值**：CI 无 WDAC 干扰（GitHub runner 干净），静态断言稳定可复现；
本地 e2e 受 WDAC 间歇影响时，保护链断言仍能证明保护能力未被破坏。

### 2.3 可复现 job 细节
- 首次构建 `-RecordSeeds` → `build/seeds.json`；
- 复现构建 `-SeedsFile` 同种子 → 比对 demo.exe + vm.blob SHA-256；
- **注意**：签名（signtool）会引入差异——CI 用 `-SkipSign`（无 pfx）。

**本地门禁同步（缺陷 ⑥，2026-10-03）**：`tools/release_check.ps1` 的第 3/4 项
原先是两个各建各的 `Check`，一次门禁做 **3 次** Release 构建，且**第 3 项的
`demo.exe` 从未与任何东西比过**（实测 A=`3EBCDE6D…` ≠ B=C=`197550898…`）。
现改为：第 3 项是**唯一权威构建**（`-RecordSeeds -SkipSign`）并把产物快照到
`build\_gate_baseline`，第 4 项以 `repro_check.ps1 -BaselineDir build\_gate_baseline`
只重建**一次**、断言 `A' == Y` —— 即「`-RecordSeeds` 记下的种子表足以重建出
记下它的那个产物」，这正是本 job（§2.1 步骤 4）所依赖的前提。
净效果 3 次 → 2 次构建，**两次的产物都承重**。详见 `docs/HANDOVER.md` §2.18。

---

## 3. 兼容矩阵扩展（COMPAT.md + compat-matrix.csv）

### 3.1 现状
`compat-matrix.csv` 只有 1 行（2026-08-20 真机 oiahcoiah），覆盖到 e2e
T1-T19/attacks A1-A7。**缺**：
- 2026-08-14 后新能力（A2-A7、Phase 4、N1-N5、BLOB_SIGN）的验证记录；
- 托管 VM（WDAC）环境的基线记录；
- CI（GitHub Actions windows-latest）的验证记录。

### 3.2 设计（新列 + 新行）
新增列：
```
n1_selfcrypt, n2_dbiguard, n3_redundancy, n4_indirect, n5_session,
blob_sign, e2e_latest (T1-T28)
```
新增行：
- 2026-08-22 托管 VM（WDAC 环境）：e2e T1-T28（T3/T10 环境 SKIP）+
  保护链断言全过 + Release 可复现；
- 2026-08-22 CI（windows-latest）：build + e2e + attacks + vmc + example
  + 保护链断言（CI 跑通后填）；
- 真机行补 N1-N5/BLOB_SIGN 状态（待真机复核后填，标注"待验"）。

---

## 4. 决策点

| 编号 | 决策 | 选项 | 推荐 | 理由 |
|------|------|------|------|------|
| C1 | 保护链断言位置 | 新脚本 protchain_check.py / 并入 e2e | **新脚本** | 静态断言与动态 e2e 分离，CI 稳定性高 |
| C2 | 可复现验证方式 | 独立 job / 并入主 job | **独立 job** | 并行化，主 job 失败不影响判断 |
| C3 | 兼容矩阵维护 | 手动 CSV / 脚本生成 | **手动 CSV** | 量小，脚本过度设计 |
| C4 | CI 是否跑真机专属测试 | 跑（T3 尝试） / 跳过 | **跳过 T3** | GitHub runner 无交互桌面，T3 必 SKIP |

## 5. 实施步骤

| 步骤 | 内容 | 工作量 | 依赖 |
|------|------|--------|------|
| 1 | `tests/protchain_check.py`（P1-P6 静态断言） | 0.5-1 天 | 无 |
| 2 | CI：主 job 扩展（vmc/example/py_compile 全量 + 保护链断言 + artifact） | 0.5 天 | 步骤 1 |
| 3 | CI：reproducible job（同种子重建比对） | 0.5 天 | 步骤 2 |
| 4 | 兼容矩阵扩展（CSV 新列/新行 + COMPAT.md 更新） | 0.5 天 | 无 |
| 5 | 本地验证 protchain_check + 全量回归 | 0.5 天 | 步骤 1-4 |
| **合计** | | **2.5-3 天** | |

## 6. 验收标准

1. `python tests\protchain_check.py` 本地 PASS（P1-P6 全过）；
2. CI 主 job：build + e2e（T1-T28）+ attacks + vm_unit + vmc + example
   + py_compile + 保护链断言全绿；
3. CI reproducible job：同种子两次构建 SHA-256 一致；
4. 破坏性测试：人为改坏 selfcrypt（如去掉加密步骤）→ P1 断言 FAIL
   （证明断言有效）；
5. compat-matrix.csv 含 2026-08-22 托管 VM 行 + CI 行（标注状态）；
6. 本地全量回归不回归（e2e T1-T28 / attacks / vm_unit / vmc）。

## 7. 风险与回退

| 风险 | 等级 | 缓解 |
|------|------|------|
| GitHub runner 环境差异（无 vcvars/不同 MSVC） | 中 | ilammy/msvc-dev-cmd 已用；构建失败即暴露 |
| 保护链断言过严（误报） | 中 | P1-P6 用与构建相同的 meta/mask 数据源；本地先验证 |
| 可复现 job 与主 job 构建差异（seed 随机） | 低 | 同 seeds.json 注入，确定性 |
| CI 时长超限（25min） | 低 | job 并行化；vmc/example 快（秒级） |

**回退**：CI 改动纯增量（新 job/新 step），不影响本地构建；
protchain_check.py 独立脚本，删除即回退。

## 8. 待办清单

1. [x] 拍板 C1-C4（§4）——protchain 独立脚本 / reproducible 独立 job /
      矩阵手动 CSV / CI 跳过 T3。
2. [x] 步骤 1：protchain_check.py（P1-P6 全 PASS；破坏性测试 P1/P4 FAIL 验证有效）。
3. [x] 步骤 2：CI 主 job 扩展（vmc/example/py_compile 全量/保护链断言/artifact）。
4. [x] 步骤 3：CI reproducible job（同种子+同私钥重建比对 demo.exe+vm.blob）。
5. [x] 步骤 4：兼容矩阵扩展（CSV 3 行 + COMPAT.md §3 格式更新）。
6. [x] 步骤 5：本地验证（e2e T1-T28 / attacks / vm_unit / vmc / example /
      Release 可复现全绿）。
7. [x] **CI 远程运行**（2026-10-02 回填）：已推到私库
      `https://github.com/jurecoasertkrocket777/shardvase.git` 并实跑 9 轮。
      第 8 轮（`37055147715` / `e6917a2`）`build-and-verify` 22/22 与
      `linux-portability` 5/5 **全绿**。
      ⚠️ **`reproducible` 与 `sdk-package` 在第 8 轮才首次真正执行**
      （前 7 轮因 `needs: build-and-verify` 红而全部 `skipped`，
      里面的命令从未跑过），随即暴露缺陷 7（产物保留目录结构）与
      缺陷 8（SDK 包缺 `winproc.py` / `mapfile.py`）。
      **第 9 轮（`37061070912` / `90b98d4`）四个 job 全绿** ——
      `build-and-verify` 22/22、`reproducible` 6/6（含
      `Compare SHA-256 with first build`）、`sdk-package` 7/7（含
      `Verify SDK is standalone`）、`linux-portability` 5/5。
      唯一 `skipped` 是 `sdk-package` 的 `Publish GitHub Release`，
      其判据为 `if: startsWith(github.ref, 'refs/tags/v')` —— tag 门控，设计如此。
      ⇒ **Q6 的验收条件（两 job 至少绿一次）已达成。**
      详见 `docs/HANDOVER.md` §2.15 / §2.16。
