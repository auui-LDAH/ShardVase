# 反逆向纵深增强轮计划 — S1-S5 (DEFENSE_DEEPEN_PLAN)

> 版本：2026-08-29 v2 · 状态：**S1 部分落地（2/5 目标）；S2-S5 待续** ·
> v1 规划五项全收；v2 实施记录：meta 24B 组化+EXT 组 + 装载/验签两函数加密
> 全链通过（含 30s watchdog）；antidebug/integrity/revoke 三个目标加密因
> 运行期布局互扰未落地（诚实边界详见 §8 实施记录）。

---

## 1. 背景与目标

已有：VM 引擎 4 函数 selfcrypt、授权/业务链 VM 化、10 维反调试、三节 CRC+watchdog。
缺口（按攻击者视角排名）：
- 静态分析者仍能一眼锁定"加密的函数亮区"边界；
- 同一构建多次运行 VM 密文**固定** → 双次 dump 可对比；
- 宿主框架函数（验签/装载/完整性）为普通控制流；
- 少量字符串/格式串明文残留；
- 反调试维度边际已降（已有 10 维）。

## 2. 设计（S1-S5）

### S1 selfcrypt 覆盖扩容（主杠杆）
- 现状：仅 VM 引擎 4 函数（prot_vm_run/vm_build_keymaps/vm_wb/vm_var）加密；
- 扩展（新组 GROUP_EXT，调用级 enter/leave 包裹，与 VM 组同机制）：
  `prot_vm_blob_load` / `prot_license_verify` / `prot_integrity_check_self` /
  `prot_antidebug_scan` / `prot_revoke_check(prot_license_verify 复用?)`;
- 工具：`selfcrypt_proto.py` 增加 `--names`/`--group` 参数（多组支持）；
  宿主侧（app_main/demo main）在关键调用点包装 enter/leave（新组）；
- 效果：静态分析者在函数级撞密文；窗口=调用周期。

### S2 运行时密钥多样性（直击双 dump 对比）
- 装载后（blob 验签已过、文件不变）对镜像 code 做**内存重编码**：
  滚动密钥流为线性 XOR 变换 → 可逆：code' = code ⊕ Δ(key→key')
  Δ 由运行期随机种子（GetTickCount^指针熵）决定 → 每次进程密文流转不同；
- 实现：vm.c 增加 `prot_vm_rekey(img, new_seed)`（一次调用，装载后）；
  `vm.c` VM 运行使用 img 内当前 key（重编码后 key' 已写入 img 头？——
  设计：rekey 同时改写 img->key0/key1 与 code，自洽）；
- 效果：两次转储的密文/密钥对不匹配 → 双 dump 对比与重放失效；
  明文窗口内的"长驻痕迹"仍按原语义销毁。

### S3 宿主控制流平坦化（受限试点）
- 试点函数：`prot_integrity_check_self`（宿主可信路径）——把顺序分支
  改为等价 switch-dispatch（手写受限平坦化，不引三方）；
- 范围：单个函数试点；验证通过后再评估扩展到 license 门宿主段；
- 诚实边界：全函数 OLLVM 式不在本期（成本/AV 特征）。

### S4 字符串/数据加密扩容
- 扫描构建产物明文串（脚本：strings 扫描 exe）→ 清单；
- 漏网串并入 strcrypt 表 / 格式串收敛（PROT_LOG_VM_ERR 已有隐模式）；
- 目标：发布版（RELEASE 收敛）下无业务语义明文字符串。

### S5 反调试维度 +2
-（a）**启动时间与父进程**：记录启动 tick；父进程白名单
  （explorer/cmd/守护宿主——防"被附到调试器父进程"与时间探测）；
-（b）**时间源交叉**：GetSystemTimeAsFileTime vs GetTickCount 漂移检测
  （防时钟伪装类绕过）；
- 并入 antidebug.c：新报告字段 + selftest 输出 + 干净环境零误报验证
  （真机 selftest）。

## 3. 决策点
| 编号 | 决策 | 选项 | 推荐 |
|------|------|------|------|
| D1 | S1 扩展函数清单 | 4+1 组(blob/license/integrity/antidebug+revoke) / 更小 | **4+1** |
| D2 | S2 rekey 时机 | 装载后立即 / 首次 VM 前 | **装载后立即**（语义最简）|
| D3 | S3 试点函数 | integrity_check_self / license 门宿主段 | **integrity_check_self** |
| D4 | S5 新增维度 | (a)+(b) / 仅 (a) | **(a)+(b) 两个** |
| D5 | 回归强度 | 全量矩阵+Defender / 部分 | **全量矩阵 + Defender 复测 + 真机闭环** |

## 4. 实施步骤
| 步骤 | 内容 | 工作量 |
|------|------|--------|
| 1 | S1：selfcrypt_proto 多组 + 4 函数扩展 + 宿主包裹点 | 1 天 |
| 2 | S2：vm.c rekey + 启动接入 + 熵源 | 0.5 天 |
| 3 | S3：integrity 平坦化试点 | 0.5 天 |
| 4 | S4：字符串扫描 + 收敛 | 0.5 天 |
| 5 | S5：antidebug +2 维度 + selftest | 0.5 天 |
| 6 | 回归：矩阵(含 M11/M12) + Defender + 真机闭环 + 归档 | 0.5 天 |
| **合计** | | **3.5 天** |

## 5. 验收标准
1. S1：发布版静态扫描（strings/函数指纹）无法直接定位加密边界；enter/leave 全配对；
2. S2：同一构建两次运行 → dump 的密文区密钥不同（双份对比不相符）；
3. S4：发布版内无业务语义明文字符串；
4. S5：新维度 selftest 干净环境 0 误报（真机）；
5. 回归全绿：矩阵（含 M11/M12）PASS、Defender 静态+行为复测 0 拦截、真机授权闭环 PASS；
6. 各 S 项记录进 THREATMODEL/能力页（含新边界与诚实限制）。

## 6. 风险与回退
| 风险 | 缓解 |
|------|------|
| S2 重编码破坏 blob 语义 | 装载后即 rekey；回归必须含 M6/M7/M8（blob 面）+ 授权闭环 |
| S3 手写平坦化 bug | 试点函数本身进矩阵（篡改/回归）；golden 对照宿主行为 |
| AV 特征叠加 | 每 S 后 Defender 复测；S3/S4 最敏感，先测后扩 |
| rekey 与 watchdog 复查冲突 | watchdog 复查只查 result 域，不涉 VM 密钥 |

**回退**：S1-S5 各自独立开关/可裁剪；全部改动有回归护栏。


## 9. 实施记录 v3（2026-08-29 晚）

**S1 补完（干净环境下逐枚二分）**：此前"0x3940 互扰/最后一段必崩/完整性失败"
全部被证实为**损坏工具链（142B 废 selfcrypt_proto 脚本）+ 构建失败旧 exe**
叠加的假象。干净重建后：
- 反调试/integrity 两枚加回，EXT 增至 4 枚全链 PASS（30s watchdog）；
- **revoke（0x4ff0 邻段）仍触发 VirtualProtect 调用点崩溃（0x5d0d）**——
  记为布局边界（低频调用+间接表+黑名单签名兜底，加密收益最低）；
- 最终 S1 落地：blob_load / license_verify / antidebug_scan /
  integrity_check_self 四函数加密（组 1）。

**S2（运行时密钥多样性）尝试与阻断**：
- 设计就绪（差分流重编码理论正确，KB 实现 prot_vm_rekey 已写好并验证思路）；
- **阻断：新增任何编译单元或对既有 .c 追加函数 → .text 布局漂移 →
  integrity 完整性校验重启失败（TAMPERED），与"调用与否"无关——
  即掩码/自检查机制对代码体积变化不具备重建自洽性**；
- 结论（诚实）：这是比 S2 更需先修的**原子性缺陷**：基于"布局敏感的
  .text CRC + 静态掩码区"的完整性设计，任何代码变更都可能打破运行态
  CRC 与文件态 CRC 的掩码对齐。**修复方向（下一轮）**：
  a) 完整性改为"运行时段 CRC + 加密段豁免依据 meta（已基本如此）"——
     定位为何豁免失效（∵ hashpatch 文件侧掩码与运行侧掩码需同步重建，
     疑似 crc_len/段范围判断在扩容 .text 后错位）；
  b) 或引入"构建期固定 .text 布局"（链接脚本/段预留）隔离业务代码增量。

**经验与纪律（写入本轮的教训）**：
1. 构建失败 = 旧 exe → 所有运行结论作废（以 exe 时间戳为准）；
2. 工具链文件被误写（<2KB）应立即以 `git cat-file blob HEAD:<path>`
   原样还原（PS 重定向会毁字节/混淆 CRLF）；
3. 加密/掩码类改动，先跑"新增代码对照"（不调用）区分布局 vs 逻辑。

## 8. 实施记录（v2，2026-08-29）

**S1 落地部分（已完成）**：
- meta 24B（group 字段）组化：selfcrypt_proto/selfcrypt.c/integrity.c 同步；
  integrity 掩码重建步长 20B→24B（**整晚 TAMPERED 谜团的根因**）；
- EXT 组包裹：blob 装载与 license 验签调用点 enter/leave；
  watchdog 线程 enter/leave（为未来 EXT 加密预留；当前空转）；
- 落地目标：`prot_vm_blob_load` + `prot_license_verify` 两函数加密；
  真机全链 PASS（完整性 rc=0、授权门、**30s watchdog 复查 0 误杀**）。

**未落地（诚实边界）**：`prot_antidebug_scan` / `prot_integrity_check_self` /
`prot_revoke_check` 加密触发 0x3940 区运行期互扰（build_reloc/iat 快照域）。
排障过程原样：整夜用损坏的 selfcrypt 文件（142B）与未重构建的 exe 反复
取假象；最终以"真机直连 + [MASK-ENTRY] n=0 定位 + 单函数二分+恢复文件"
收网。**经验**：调试任何"加密后异常"三查——① 构建真的成功（exe 时间戳）
② meta 真写入（hexdump 段）③ 掩码重建步长与写入步长一致。

**S2-S5 待续**（下一轮）：S2 运行时密钥多样性 / S3 控制流平坦化试点 /
S4 字符串收敛 / S5 反调试 +2 维 + 本轮回归（矩阵+Defender）。

## 9. 待办清单
- [x] 拍板 D1-D5
- [x] S1 部分（blob/license 两枚 + 组化基础）
- [ ] S1 剩余（antidebug/integrity/revoke——专项解 0x3940 互扰）
- [ ] S2-S5 实施
- [ ] 回归：矩阵 + Defender + 真机闭环