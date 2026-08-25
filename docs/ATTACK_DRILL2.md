# 第二轮攻防演练 — 完整计划 (ATTACK_DRILL2)

> 版本：2026-08-25 v1 · 状态：**规划完成，未开工** · 关联：`docs/ATTACK_DRILL.md`（第一轮 23 项，已实施）·
> `archive/attack-drill-real-20260825-final.json`（第一轮结果：15 BLOCKED/0 BREACHED/8 PARTIAL/0 SKIP）·
> `docs/THREATMODEL.md`（威胁模型）。
> 本文档规划第二轮演练：**深化第一轮 8 个 PARTIAL**（内存写实战/实策略/实战 PEB）+ **新增高级攻击面**，
> 目标是把 PARTIAL 转成确定结论、覆盖真实攻击者的进阶手法。

---

## 1. 背景与目标

### 1.1 第一轮回顾
- 23 项全结论：**15 BLOCKED / 0 BREACHED / 8 PARTIAL / 0 SKIP**；
- 静态/伪造/文件级补丁/在线对抗四类攻击面全拦截；
- **PARTIAL 分四类**（第二轮要深化）：

| 类别 | 项 | PARTIAL 原因 | 第二轮动作 |
|------|----|--------------|-----------|
| 内存写未实战 | P4/P5/E1 | 只验证了"能读"（read-ok），未真正写 demo_mem/PEB | **写实战** |
| D2b 重加密未验证 | D3 | demo 单次流程无调用后驻留窗口 | **长驻留场景** |
| 咨询项未测策略 | E2/E3 | 只报告 hook/VM 计数，未测 FAKE/EXIT 策略 | **策略测试** |
| 时序仅记录 | E4 | 只记录分布，未判断可利用性 | **利用判断** |

### 1.2 第二轮目标
1. **8 个 PARTIAL 全部转确定结论**（BLOCKED/BREACHED/明确边界）；
2. **新增 6 项高级攻击面**（攻击者进阶手法）；
3. 输出第二轮报告（对比第一轮，跟踪 PARTIAL 收敛率）。

---

## 2. 深化设计（第一轮 PARTIAL → 结论）

### P4-2 内存写 result 实战（N3 校验和识破）
- **手法**：定位 demo_mem 后**真实 WriteProcessMemory** 改 result 单副本；
- **定位方法**：demo 有 `--wait-after` 驻留 → 扫描进程内存找 `demo_mem` 特征
  （如 serial 明文在内存 + result=1 附近）→ 精准写 +52 字节；
- **预期**：写 1 副本 → N3 多数一致/校验和识破（0xBAD 或拒绝）；
- **结论判定**：改后运行判定异常 = BLOCKED（N3 生效）；正常运行 = BREACHED。

### P5-2 内存写 machine_id 实战（license 绑定）
- **手法**：定位 +56 machine_id，写异机值；
- **预期**：license 载荷含 machine_id → 写后验签失败（license:0）；
- **结论**：变更后拒绝 = BLOCKED（绑定生效）；接受 = BREACHED。

### E1-2 实战清 PEB（多因子检测）
- **手法**：真实写 PEB.BeingDebugged=0 + NtGlobalFlag=0（ScyllaHide 核心动作）；
- **预期**：demo 的 PEB 检测被绕过，但 **NtQueryInformationProcess/硬件
  断点/计时 等多因子仍工作** → 进程仍终止（0xDB）；
- **结论**：多因子仍杀 = BLOCKED；全绕过 = BREACHED。

### D3-2 D2b 长驻留重加密验证
- **手法**：用 tool_demo（`--serial` 单次）+ 造一个**循环校验 VM 的测试器**
  或给 demo 加测试钩子（`--loop-vm N`）；循环调用间隙 dump 验证 enter 解密/
  leave 重加密交替；
- **预期**：调用间隙（leave 后）函数密文；
- **结论**：间隙密文 = BLOCKED（D2b 生效）；明文 = BREACHED。

### E2-2/E3-2 策略测试（FAKE/EXIT）
- **手法**：`PROT_POLICY_FAKE` 构建下 hook/VM 检测 → FAKE 结果（垃圾/翻转）；
  `PROT_POLICY_EXIT` → 终止（0xDB）；
- **预期**：策略按配置生效；
- **结论**：策略生效 = BLOCKED（检测驱动行为正常）；无效 = BREACHED。

### E4-2 时序可利用判断
- **手法**：第一轮记录了 ~0.35s 稳定分布 → 判断是否可构造"时序条件竞争"
  （如 watchdog 周期 5s±40% 与 patch 时机重合）；
- **结论**：存在可重复利用窗口 = PARTIAL 保留（如实）；无实际可利用性
  = BLOCKED。

---

## 3. 新增高级攻击面（6 项）

| ID | 攻击手法 | 工具 | 预期防御 |
|----|----------|------|----------|
| G1 | **DLL 注入**（LoadLibrary 注入 + 钩子） | CreateRemoteThread + LoadLibrary | 完整性 CRC（注入 DLL 不改 .text 但可 hook API——看 dbiguard inline_hook 报告） |
| G2 | **IAT hook**（改写 .rdata 导入表跳转） | 内存写导入表 → 指向攻击函数 | .rdata CRC（A3 覆盖）+ 运行期检测 |
| G3 | **暂停进程绕过 watchdog**（挂起 → patch → 恢复） | NtSuspendProcess + patch + NtResumeProcess | 看门狗复查窗口 vs 暂停竞态 |
| G4 | **多阶段组合**（dump→patch→重打包） | 静态 dump → patch blob → 重签名（无钥失败） | blob 签名（F 类已验）+ 完整性 |
| G5 | **进程克隆/双开** | 复制 demo.exe 多开 | machine 绑定（同机多开 share mid → 都通过=设计允许？记录边界） |
| G6 | **超长 blob / 格式边界** | 畸形 COUNT/NAME/长度字段 | blob 解析边界（BLOB_CORRUPT 路径） |

---

## 4. 技术路线

### 4.1 内存定位（P4-2/P5-2 关键）
- **demo_mem 特征**：serial 明文（用户输入）会在内存出现——扫描进程内存
  找 serial 串，回溯 +52 result / +56 machine_id（demo_mem 布局已知）；
- 工具：`VirtualQueryEx` 枚举可读写区域 → 逐区 `ReadProcessMemory` 搜特征；
- 写：`WriteProcessMemory`（OpenProcess 已证可行）。

### 4.2 长驻留钩子（D3-2）
- demo 加 `--loop-vm N` 测试参数（构建期），循环 `vm_run_wrapped` N 次，
  间隔 Sleep——期间外部脚本 dump 验证密文/明文交替；
- 仅测试构建启用（不影响发布构建）。

### 4.3 组合攻击（G4）
- 复用第一轮 F2/F3 工具 + 完整 dump 链。

---

## 5. 决策点

| 编号 | 决策 | 选项 | 推荐 | 理由 |
|------|------|------|------|------|
| D1 | --loop-vm 钩子是否入正式代码 | 入（#ifdef 测试构建）/ 不入（外部造长驻留） | **#ifdef 测试钩子** | 可控、可测；发布构建无此代码 |
| D2 | G5 双开结论 | 记 BREACHED / 记设计边界 | **设计边界** | 同机多开 share mid 是授权语义（一台机器多实例），非防伪破点 |
| D3 | E4 时序无利用窗口 | 转 BLOCKED / 保留 PARTIAL | **转 BLOCKED + 记录** | 无实际可利用性视为防御成立 |
| D4 | G1 注入是否真注入 | 真 CreateRemoteThread / 仅检测 | **真注入**（真机） | 无 WDAC 环境可做；完整攻击链 |

## 6. 实施步骤

| 步骤 | 内容 | 工作量 | 依赖 |
|------|------|--------|------|
| 1 | 内存定位工具（搜 serial → demo_mem 偏移） | 1 天 | 无 |
| 2 | P4-2/P5-2/E1-2 内存写实战 | 1 天 | 步骤 1 |
| 3 | demo --loop-vm 钩子 + D3-2 | 0.5 天 | 无 |
| 4 | E2-2/E3-2 策略测试 + E4-2 时序判断 | 0.5 天 | 无 |
| 5 | G1-G6 高级攻击面 | 1-1.5 天 | 无 |
| 6 | 真机完整演练 + 报告对比归档 | 1 天 | 2-5 |
| **合计** | | **5-5.5 天** | |

## 7. 验收标准

1. 8 个 PARTIAL **全部转确定结论**（P4/P5/E1 写实战、D3 长驻留、E2/E3 策略、
   E4 时序判断）；
2. 新增 G1-G6 全执行（真机），无 SKIP（除 G1 注入明确环境依赖）；
3. 第二轮报告与第一轮对比：**PARTIAL 项收敛**（目标 8→0 或明确边界）；
4. 全量回归不回归。

## 8. 风险与回退

| 风险 | 等级 | 缓解 |
|------|------|------|
| 内存定位失败（serial 特征被加密/混淆） | 中 | serial 在输入时是明文进 demo_mem（fgets 后未加密）——可定位 |
| G3 暂停竞态不稳定 | 中 | 多轮尝试 + 记录实际窗口 |
| --loop-vm 钩子污染发布构建 | 低 | #ifdef 隔离（`PROT_DRILL_HOOK`） |
| 注入检测误杀 | 低 | 真机验证 + 记录 |

**回退**：第二轮全增量（攻击脚本 + 测试钩子 #ifdef），删除即回退。

## 9. 待办清单

1. [ ] 拍板 D1-D4（§5）。
2. [ ] 步骤 1：内存定位工具。
3. [ ] 步骤 2：P4/P5/E1 写实战。
4. [ ] 步骤 3：D3 长驻留（--loop-vm）。
5. [ ] 步骤 4：E2/E3 策略 + E4 时序。
6. [ ] 步骤 5：G1-G6。
7. [ ] 步骤 6：真机演练 + 对比报告。