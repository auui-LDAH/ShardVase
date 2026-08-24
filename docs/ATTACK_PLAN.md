# 攻击模拟扩展 — 完备实施计划 (ATTACK_PLAN)

> 版本：2026-08-22 v2 · 状态：**✅ 已实现（A8-A12 代码落地；A10/A11 本地 PASS；A8/A9/A12 需无 WDAC 环境补跑进程类断言）** ·
> 关联：`docs/THREATMODEL.md`（威胁模型 §7 测试钉住）·
> `tests/attacks.py`（现有 A1-A7）· `tests/protchain_check.py`（静态断言 P1-P6，CI_PLAN）·
> `docs/N1_PHASE2_PLAN.md` / `docs/BLOB_SIGN_PLAN.md`（新保护层）。
> 本文档规划：把**攻击者视角**回归从 A1-A7 扩展到新保护层（N1-N5/BLOB_SIGN），
> 并用攻击模拟结果更新 THREATMODEL §7。v2 记录落地结果。

---

## 1. 背景与目标

### 1.1 现状
`tests/attacks.py` 覆盖 A1-A7（机器绑定/VM 密文/指纹/自检/授权伪造/异机/tier），
都是**授权链路**的攻击视角。2026-08-14 后新增的保护层**没有攻击视角测试**：

| 保护层 | 攻击者可能怎么做 | 现有测试 |
|--------|------------------|----------|
| N1 自变形（引擎加密） | dump 后静态还原引擎 | ❌ 无（protchain P1 是"密文存在"断言，非"攻击者还原"视角） |
| N4 间接化（函数表） | 静态追踪调用链到目标函数 | ❌ 无（P5 是"无直接 call"断言） |
| BLOB_SIGN（blob 签名） | 伪造/替换/回滚 blob | ✅ T14/T28（篡改拒绝），❌ 无"伪造合法签名"视角 |
| revoke 签名 | 伪造黑名单绕过吊销 | ❌ 无 |
| N5 会话期望值 | 固定本地期望值绕过 | ✅ T26（错误值拒绝），❌ 无"离线固定值对抗在线"视角 |

### 1.2 目标
1. 新增 A8-A12 攻击视角测试（黑盒，纯攻击者手段）；
2. 每个新测试**用攻击者的工具链**（修改字节/重新打包/静态扫描），
   验证保护层**确实提高攻击成本**；
3. THREATMODEL §7 测试钉住表补全新保护层。

---

## 2. 新增测试设计（A8-A12）

### A8 blob-forge（伪造签名 blob）
- **攻击者手段**：自己构造合法 v0 blob（重新 pack 不签名 / 篡改后重算 CRC）。
- **断言**：demo 装载 → 0xB10B（v0 被拒 / 签名无效）。
- **与 T14/T28 区别**：T14 是"改 1 位"（CRC 层），A8 是"重新打包 v0"
  （攻击者理解格式后的伪造）——验证 D1a 强制 v1。

### A9 revoke-forge（伪造黑名单绕过吊销）
- **攻击者手段**：构造 v0 黑名单（`PROTREVK`，自己算 CRC），或把 v1 黑名单
  改 serial 后重算 CRC。
- **断言**：`--revoke-file` 伪造版 → 不阻断（CORRUPT 语义）且**不能命中**
  （伪造黑名单不能拿来吊销别人）；真实 v1 黑名单仍命中。
- **价值**：验证 revoke 签名（D2：revoke 同 blob 签名）防"伪造吊销/绕过"。

### A10 static-trace（静态追踪 N4 间接链）
- **攻击者手段**：dumpbin/objdump 静态分析，尝试找 `prot_vm_run` 的直接
  call 或从间接表直接定位。
- **断言**：反汇编中 4 个目标函数**无直接 call**（与 protchain P5 同源，
  但用**攻击者工具**（dumpbin 文本解析）而非 Python 字节扫描）；
  间接表（.rdata 4 指针）存在但**顺序随机**（两次构建不同——用 build
  fingerprint 对比）。
- **价值**：证明 N4 确实把静态追踪成本抬高。

### A11 selfcrypt-dump（dump 视角验证 N1）
- **攻击者手段**：静态 dump 引擎函数 → 应为密文（不可直接反汇编）；
  运行期（D2a）可 dump 到明文——**记录在案**（诚实面）。
- **断言**：静态文件 dump 中目标函数**无 x64 序言特征**（与 P1 同源，
  但用攻击者的"特征扫描"方法——搜 `40 55`/`48 89` 模式）；
  **运行期 dump 验证**（可选，需子进程内存读取）——本环境做静态部分，
  运行期部分标注"待真机"。
- **价值**：证明 N1 静态面成立；动态面边界诚实记录。

### A12 offline-fix-expect（离线固定期望值对抗 N5）
- **攻击者手段**：patch demo_mem 的 vm_expect1/2 或期望值比较逻辑，
  使离线校验恒过（"一次还原永久有效"）。
- **断言**：**在线会话**下服务端下发不同期望值 → 本地固定值失效
  （T26 已证）；离线场景固定值有效（诚实记录——N5 是"在线增强"
  而非"在线强制"，离线仍可被 patch，这是设计语义）。
- **价值**：验证 N5 的边界符合设计（离线优先，不锁死）。

---

## 3. 实现要点

### 3.1 复用现有基础设施
- `run_demo()`（attacks.py 已有，subprocess + cwd=build）；
- `vmenc.py`（pack/revoke/sign——伪造场景复用其格式知识）；
- `protchain_check.py` 的 pe_sections（A8/A10/A11 解析 PE）。

### 3.2 A8/A9 的"伪造"工具
- 攻击者视角：**不使用 --sign**（无私钥）——纯格式构造：
  - A8：`vmenc.py pack`（无 --sign → v0）+ 手工重算 CRC；
  - A9：`vmenc.py revoke`（无 --sign → v0）+ 手工重算 CRC。
- 断言：demo 对 v0 blob/revoke 的处理（v0 拒绝 / CORRUPT 不阻断）。

### 3.3 A10/A11 的静态扫描
- 用 Python 解析 dumpbin 输出（`subprocess` 调 dumpbin /DISASM）或
  直接字节扫描（复用 protchain 的 scan_e8_calls / 序言特征）。

### 3.4 运行期 dump（A11 可选部分）
- 子进程启动 demo（--wait-ms 延迟），用 ReadProcessMemory 读目标函数
  内存——**需要调试权限**（本环境 WDAC/会话限制可能 SKIP）；
- 设计为"尽力而为"：失败 → SKIP 而非 FAIL（与 T3 同策略）。

---

## 4. 决策点

| 编号 | 决策 | 选项 | 推荐 | 理由 |
|------|------|------|------|------|
| D1 | A11 运行期 dump 是否做 | 做（ReadProcessMemory）/ 只做静态 | **只做静态 + 运行期标注待真机** | 本环境权限限制，静态已证 N1 价值 |
| D2 | A8-A12 与 protchain P1-P6 的关系 | 互补独立 / 合并 | **互补独立** | protchain 是"保护存在性"，A 系列是"攻击者成本" |
| D3 | 新测试放 attacks.py / 新文件 | 并入 attacks.py / 新文件 attacks2.py | **并入 attacks.py**（A8-A12 追加） | 保持单入口，verify 无需改 |
| D4 | THREATMODEL §7 更新 | 每次跑完手动更新 / 脚本 | **手动**（量小） | 与现有风格一致 |

## 5. 实施步骤

| 步骤 | 内容 | 工作量 | 依赖 |
|------|------|--------|------|
| 1 | A8 blob-forge + A9 revoke-forge（v0 伪造拒绝） | 0.5 天 | 无 |
| 2 | A10 static-trace（N4 无直接 call，dumpbin 视角） | 0.5 天 | 无 |
| 3 | A11 selfcrypt-dump（静态密文特征扫描） | 0.5 天 | 无 |
| 4 | A12 offline-fix-expect（N5 边界诚实记录） | 0.5 天 | 无 |
| 5 | THREATMODEL §7 更新 + 全量回归 | 0.5 天 | 1-4 |
| **合计** | | **2.5 天** | |

## 6. 验收标准

1. attacks.py 新增 A8-A12，全 PASS（A11 运行期部分可 SKIP）；
2. 每个新测试**破坏性验证**：人为去掉对应保护 → 测试 FAIL
   （证明测试真的在测保护，不是空转）；
3. 全量回归不回归（e2e T1-T28 / attacks A1-A12 / vm_unit / vmc / protchain）；
4. THREATMODEL §7 补全新保护层的测试钉住。

## 7. 风险与回退

| 风险 | 等级 | 缓解 |
|------|------|------|
| A8/A9 与构建时序耦合（v0 需重新 pack） | 低 | 从现有 vm.blob 剥离签名区构造 v0（不重打包） |
| A10 dumpbin 路径依赖 | 中 | 探测 vswhere/常见路径，缺失 → SKIP |
| A11 运行期 dump 权限 | 中 | 静态部分必测，运行期 SKIP（与 T3 同策略） |
| 新测试误报（攻击者手段过强） | 低 | 用与保护实现同源的数据（meta/格式），先本地验证 |

**回退**：A8-A12 纯增量（attacks.py 追加），删除即回退；不影响构建/CI。

## 8. 待办清单

1. [x] 拍板 D1-D4（§4）——A11 静态必测/运行期待真机；与 protchain 互补；
      并入 attacks.py；THREATMODEL 手动更新。
2. [x] 步骤 1：A8 blob-forge + A9 revoke-forge（v0 伪造拒绝，代码落地）。
3. [x] 步骤 2：A10 static-trace（N4 无直接 call，本地 PASS）。
4. [x] 步骤 3：A11 selfcrypt-dump（静态密文，本地 PASS）。
5. [x] 步骤 4：A12 offline-fix-expect（N5 边界，代码落地）。
6. [x] 步骤 5：THREATMODEL §7 更新。
7. [ ] **待补**：A8/A9/A12 进程类断言在无 WDAC 环境（真机/CI）补跑确认；
      本环境 WDAC 间歇拦截（HANDOVER §4.5 已知限制）。
