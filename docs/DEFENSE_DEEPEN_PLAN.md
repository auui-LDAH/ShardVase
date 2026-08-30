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






## 12.5 实施记录 v7（2026-08-30 · S1 4/5 落地 + S3 扩展）

**S1 突破（4/5 落地）**：
- antidebug/integrity 加密最终落地：辅助函数（antidebug 的 ad_*/vh_int3、
  integrity 的 build_reloc/iat_snapshot 等）全移 `.protxec` 独立页；
- **根因最终闭环**：`prot_revoke_check` 与 `main` 同页（0x5000）——
  VP 切 RW 禁执行 main 自伤，**不可解**（revoke 排除，间接表+签名兜底）；
- **页冲突安全网**：selfcrypt_proto 检测加密段与 main 同页 → 警告跳过
  （防未来把 main 同页函数加回加密集合）；
- 最终 S1 = blob_load/license_verify/integrity_check_self/antidebug_scan
  四枚加密，稳定性门槛 3/3 PASS。

**S3 扩展**：平坦化推广到 `prot_antidebug_apply_policy`（策略分发
switch-dispatch 状态机），门槛 3/3 PASS。

## 12. 实施记录 v6（2026-08-29 深夜 · S4/S5 完成）

- **S5 落地**：反调试 +2 维（父进程调试器黑名单=关键项 / 墙钟-tick 漂移=咨询项）；
  真机 selftest 0 误报（ppid_blacklist=0, clock_drift_sec=0）。
- **S4 落地**：字符串明文收敛（HWID 格式 / revoke 提示 / 在线 URL 模板入
  strcrypt 表）；exe 扫描验证 `0x%016` 与 URL 模板已消失；revoke 默认路径
  常量保留（运营参数）。
- **S1 最终态**：2 枚加密（blob_load + license_verify）+ pdata 边界防御 +
  .protxec 分节；其余 3 枚记录为 VP 崩溃技术债（机制部分厘清：同页执行
  禁权；integrity 段仍崩待专攻）。
- **稳定性回归器** `mask_stability_test.ps1`：S2/S4/S5 各改动后均 3/3 PASS。

## 13. 下一轮待办
- S1 剩余 3 枚（VP 崩溃技术债专项：解密器/辅助完全独立页 + integrity 段
  重新定位）
- S3 控制流平坦化试点（最小示范：switch-dispatch 等价变换单函数）
- 全量回归（attack_sdk_matrix 含 M11/M12 + Defender 复测）后统一提交基线

## 11. 实施记录 v5（2026-08-29 深夜 · S1 定稿与基建）

**S1 定稿（诚实）**：落地 = blob_load + license_verify **两枚**（稳定基线，
回归器多次 3/3 PASS）。antidebug/integrity/revoke 三枚在 5 枚组合下仍触发
"VirtualProtect 调用点崩溃"（integrity 段 0x3bxx 与 revoke 段 0x5120 等），
机制部分厘清：**加密段与"解密/校验辅助代码同页"时，VP 切换页权限会禁执行
自伤**——已通过 `.protxec` 独立节（解密器 + crc32）分页解决 revoke 段；
integrity 段仍崩（待专攻：可能其段与 libc/堆相关执行同页或另有栈因素）。

**新增基建（已提交前两版演进）**：
- `pdata 边界防御`：selfcrypt_proto 对每个加密函数校验 rva+size 不越 .text
  段尾（防写坏邻节 → 间歇 TAMPERED/崩的一类真凶）；
- `.protxec` 独立可执行节：解密器（sc_xor_range/sc_do_range 等）与
  crc32（prot_crc32 族）移入，避免与加密段同页。

**S2 已落地（另见 v4）**；稳定性回归器（mask_stability_test.ps1）成为
标准门槛。下一步（S3-S5）在 2 枚稳定基线上推进。

## 10. 实施记录 v4（2026-08-29 深夜，决定性）

**"布局漂移/掩码残留"假象结案**：以"删旧 mask + 完整构建(全管线到 DONE) + UTF-8 判定"
的三连建实验（`mask_stability_test.ps1`）证实：同一源码树**连续 12 轮全 PASS**
（含带 S2 与探针组态）——**间歇性 TAMPERED 的全部来源 = 旧 exe/半成品 exe 投喂**
（构建中途失败但 demo.exe 时间戳更新的阶段），**无真实运行时缺陷**。

**S1 状态修正（诚实重述）**：真实落地 = blob_load + license_verify **两枚**
（与 efded61 提交一致——此前"4 枚"为误记；antidebug/integrity/revoke 加密仍
有待在稳定构建流程下逐枚复验；revoke 0x4ff0 邻段崩同样待复验是否亦为幻影）。

**S2 落地（完成）**：
- `src/vm_rekey.c`（独立编译单元）+ `vm.h` 声明 + demo main 装载后钩 + 双构建
  脚本编译项；
- 差分重编码实现（线性密钥域），仅内存操作（blob 文件/签名不变）；
- 实证：**两次运行 [S2KEY] 密钥域不同**（A=0x...a24899 / B=0x...c3c07683），
  全链（含完整性/授权门/30s watchdog）连续多轮 PASS。

**经验追加**：构建产物时间戳≠构建成功；判定输出一律 UTF-8 读档；
"X 代码导致 TAMPERED"类结论必须先验证完整构建（smoke 用 -SkipSmoke 绕过
WDAC 后手动运行）。

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