# 批量攻防演练 — 完整计划 (ATTACK_DRILL)

> 版本：2026-08-25 v1 · 状态：**规划完成，未开工** · 关联：`docs/THREATMODEL.md`（威胁模型）·
> `tests/attacks.py`（A1-A12 单项攻击）· `tests/protchain_check.py`（P1-P6 静态断言）·
> `docs/ATTACK_PLAN.md`（攻击模拟扩展）· `docs/HANDOVER.md`（环境限制）。
> 本文档规划：**模拟真实攻击者的完整攻击链**，批量尝试多类攻击手法，
> 验证防御拦截率，统计**破防点**（诚实面）并输出演练报告。

---

## 1. 背景与目标

### 1.1 现状
现有测试是"单项"的：
- `attacks.py` A1-A12：单项攻击视角（伪造/篡改/追踪）；
- `protchain_check.py` P1-P6：保护链静态断言。

**缺**：真实攻击者会**串联多手法**（静态定位→补丁→伪造→绕过→dump），
且我们从未**批量统计过"拦截率"**——哪类攻击被拦、哪类能得手、得手后的
影响有多大。

### 1.2 目标
1. 建立**攻击矩阵**（6 类 20+ 项攻击），每项有明确手法/工具/预期结果；
2. `tests/attack_drill.py` 批量执行，输出**拦截率报告**
   （JSON + 控制台矩阵）；
3. 诚实记录**破防点**（D2a 运行期 dump 明文、离线可 patch 等已知边界），
   评估影响并与 THREATMODEL 对齐；
4. 演练结果归档，供商业发布前的风险评估引用。

---

## 2. 攻击矩阵设计（6 类）

### S — 静态分析类（攻击者第一步：找目标）
| ID | 攻击手法 | 工具 | 预期防御 | 验收 |
|----|----------|------|----------|------|
| S1 | 搜明文特征串（"校验通过"/"license:"/serial） | 字节扫描 demo.exe | 字符串加密（strcrypt） | 0 命中 |
| S2 | 搜常量（expect1/2、machine_id、序列号） | 字节扫描 | 常量不落明文 | 0 命中 |
| S3 | 反汇编找关键函数直接 call（vm_run/license） | E8 扫描（复用 protchain） | N4 间接化 | 0 直接 call |
| S4 | 找引擎函数序言特征码（40 55 等） | 特征扫描 | N1 密文 | 0 命中 |

### P — 补丁攻击类（改关键判定）
| ID | 攻击手法 | 工具 | 预期防御 | 验收 |
|----|----------|------|----------|------|
| P1 | .text 补丁 result 判定指令 | 字节 patch 副本 | 完整性 CRC（L4a） | 0xBAD |
| P2 | .text 补丁 license 校验调用点 | 字节 patch 副本 | 完整性 CRC | 0xBAD |
| P3 | .text 补丁 hostid 读取 | 字节 patch 副本 | 完整性 CRC | 0xBAD |
| P4 | 运行期写 result 三副本（单点） | ctypes WriteProcessMemory | N3 校验和 | 拒绝/退出码异常 |
| P5 | 运行期写 machine_id | ctypes 写进程内存 | license 绑定 | license:0 |

### F — 伪造攻击类（造合法凭证）
| ID | 攻击手法 | 工具 | 预期防御 | 验收 |
|----|----------|------|----------|------|
| F1 | 伪造 license（无私钥自签） | 自构 RSA 签名 | 验签失败 | license:0 |
| F2 | 伪造 blob v0 | 自算 CRC 打包 | D1a 强制 v1 | 0xB10B |
| F3 | 伪造 blob v1 换镜像 | 剥离签名重签（无 key 只能坏签） | 签名失败 | 0xB10B |
| F4 | 伪造 revoke v0 | 自算 CRC | revoke 签名 | 不阻断 |
| F5 | 回滚旧构建 blob | 旧版 v1 blob | 签名不匹配（新 key） | 0xB10B |

### D — dump/还原类（抓引擎）
| ID | 攻击手法 | 工具 | 预期防御 | 验收 |
|----|----------|------|----------|------|
| D1 | 静态 dump 引擎函数 | 文件读 .text | N1 密文 | 无序言 |
| D2 | D2a 运行期 dump 引擎 | ctypes ReadProcessMemory | **已知破防点**（明文驻留） | 如实记录 |
| D3 | D2b 构建非调用时刻 dump | 同上（-D2b 构建） | 重加密 | 密文 |

### E — 环境对抗类（绕过检测）
| ID | 攻击手法 | 工具 | 预期防御 | 验收 |
|----|----------|------|----------|------|
| E1 | 模拟清 PEB 标志（外部写进程 PEB） | ctypes 写 PEB | 多因子检测仍工作 | 检测非全依赖 PEB |
| E2 | Inline hook 咨询项验证 | dbiguard selftest | N2 报告 | 记录 hook 计数 |
| E3 | 虚拟机环境咨询项 | vmdetect selftest | M1 报告 | 记录 VM 计数 |
| E4 | 多轮运行时序指纹 | 10 次运行计时 | 无稳定可攻击时序 | 分布记录 |

### O — 在线对抗类（网络侧）
| ID | 攻击手法 | 工具 | 预期防御 | 验收 |
|----|----------|------|----------|------|
| O1 | 离线固定期望值对抗在线会话 | mock 下发不同值 | N5 会话值 | 拒绝 |
| O2 | 中间人替换 blob | mock 返回篡改 blob | 签名 | 0xB10B |

---

## 3. 演练闭环与输出

### 3.1 演练流程
```
build（当前构建产物）→ attack_drill.py
  ├─ S 类：静态扫描（无进程）
  ├─ F 类：构造伪造凭证 → 运行验证
  ├─ P 类：副本 patch / 运行期内存写
  ├─ D 类：dump 分析（D2/D3 需子进程）
  ├─ E 类：环境对抗
  └─ O 类：mock 服务对抗
→ 汇总矩阵 + 拦截率 → attack-drill-report.json
```

### 3.2 判定规则
| 结果 | 含义 |
|------|------|
| **BLOCKED** | 防御成功拦截（攻击未得手） |
| **BREACHED** | 攻击得手（需评估影响——诚实面） |
| **PARTIAL** | 部分得手（如只拿到非关键信息） |
| **SKIP** | 环境无法执行（如内存权限） |

### 3.3 拦截率报告
```json
{
  "tool": "attack_drill.py",
  "timestamp": "...",
  "summary": {"total": 22, "blocked": 18, "breached": 2, "partial": 1, "skip": 1,
              "block_rate": "81.8%"},
  "breach_points": [{"id": "D2", "impact": "D2a 运行期明文可 dump", "severity": "known-boundary"}],
  "matrix": [{"id": "S1", "result": "BLOCKED", "detail": "0 明文命中"}]
}
```

---

## 4. 技术路线

### 4.1 复用现有设施
- `run_demo()`（attacks.py 模式）——进程运行验证；
- `pe_sections`/`scan_e8_calls`（protchain_check.py）——静态分析；
- `vmenc.py` 格式知识——伪造凭证构造；
- `mock_server.py`——O 类对抗。

### 4.2 新增能力（attack_drill.py）
1. **字符串/常量扫描**：对 demo.exe 全文搜 UTF-8/ASCII 特征；
2. **运行期内存读写**：ctypes OpenProcess/ReadProcessMemory/
   WriteProcessMemory（P4/P5/D2/D3/E1；需权限，受限则 SKIP）；
3. **-D2b 构建联动**：D3 需先 `build.ps1 -D2b`（演练脚本自动切换或要求预构建）；
4. **攻击副本管理**：P1-P3 用副本 patch（不破坏原产物），
   临时目录 `build/drill/`。

### 4.3 环境适配
- **本机（WDAC）**：S/F/O 类可跑（无进程限制）；P/D/E 的内存读写类
  可能受限（WDAC 拦新副本 exe）→ SKIP 并提示真机补；
- **真机（无 WDAC）**：全类可跑——**完整演练在真机跑**（与本机
  attack_drill 同脚本，环境差异自动 SKIP/执行）。

---

## 5. 决策点

| 编号 | 决策 | 选项 | 推荐 | 理由 |
|------|------|------|------|------|
| D1 | 破防点（D2 明文 dump）如何呈现 | 计入 BREACHED / 标记 known-boundary | **标记 known-boundary** | 与 THREATMODEL 一致：已知边界诚实记录，不掩盖 |
| D2 | P 类 .text patch 用副本还是原文件 | 副本 / 原文件 | **副本** | 不破坏构建产物；patch 副本无需 hashpatch |
| D3 | D3（D2b dump）是否自动切换构建 | 自动 -D2b 构建 / 要求预构建 | **要求预构建** | 演练脚本保持简单；文档写明 D3 需 -D2b 产物 |
| D4 | 内存写类失败策略 | FAIL / SKIP | **SKIP** | 权限限制非防御问题（与 T3 同策略） |
| D5 | 演练报告是否入 git | 入 git（报告） / 不入 | **不入 git**（build/drill/ 产物） | 报告含攻击细节，属敏感 |

---

## 6. 实施步骤

| 步骤 | 内容 | 工作量 | 依赖 |
|------|------|--------|------|
| 1 | attack_drill.py 框架 + 汇总/报告输出 | 0.5 天 | 无 |
| 2 | S 类（4 项静态分析） | 0.5 天 | 步骤 1 |
| 3 | F 类（5 项伪造） | 0.5 天 | 步骤 1 |
| 4 | P 类（5 项补丁，含内存读写） | 1 天 | 步骤 1 |
| 5 | D 类（3 项 dump）+ E 类（4 项环境）+ O 类（2 项在线） | 1 天 | 步骤 1 |
| 6 | 本机演练 + 真机完整演练 + 报告归档 | 1 天 | 2-5 |
| **合计** | | **4.5 天** | |

## 7. 验收标准

1. `python tests/attack_drill.py` 本地运行，输出 22 项矩阵 + 拦截率；
2. S/F 类 9 项**全部 BLOCKED**（静态/伪造 100% 拦截）；
3. P 类补丁（文件级）全 BLOCKED（0xBAD）；内存写类按环境执行；
4. 破防点清单与 THREATMODEL 已知边界一致（D2a dump、离线 patch）；
5. 真机完整演练（无 WDAC）跑通，报告归档 `archive/attack-drill-*.json`；
6. 全量回归不回归（e2e/attacks/protchain 仍绿）。

## 8. 风险与回退

| 风险 | 等级 | 缓解 |
|------|------|------|
| 内存读写权限（本机/SSH 会话） | 中 | SKIP 策略 + 真机补跑 |
| P 类副本被 WDAC 拦 | 中 | 副本打 patch 前先测可运行性；受限 SKIP |
| D2 破防点被误读为"防御失败" | 中 | 报告明确 severity=known-boundary + 影响评估 |
| 演练脚本破坏构建产物 | 低 | 副本策略（build/drill/ 隔离） |
| 报告敏感 | 低 | build/drill/ + archive/ gitignore |

**回退**：attack_drill.py 纯增量（新文件 + 报告目录），删除即回退；
不影响现有 tests/attacks/protchain。

## 9. 待办清单

1. [ ] 拍板 D1-D5（§5）。
2. [ ] 步骤 1：框架 + 报告输出。
3. [ ] 步骤 2-5：六类攻击实现。
4. [ ] 步骤 6：本机 + 真机演练 + 归档。
5. [ ] 更新 THREATMODEL/COMPAT 引用演练结果。
