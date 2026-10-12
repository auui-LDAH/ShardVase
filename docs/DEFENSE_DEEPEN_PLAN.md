# 反逆向纵深增强轮计划 — S1-S5 (DEFENSE_DEEPEN_PLAN)

> 版本：2026-08-29 v2 · **2026-10-06 复核 v9** · 状态：**S1 全数落地（5/5 目标）**；
> **S2-S5 亦全部落地**（S2 `src/vm_rekey.c` / S3 `prot_antidebug_detected` 平坦化 /
> S4 33 条串明文 0 / S5 `ppid_blacklist`+`clock_drift_sec`）—— 逐条证据见 §14；
> ⚠️ **S3 试点函数偏离 D3 决策**（实为 antidebug 而非 integrity），见 §14.1；
> **仍未做**：真机面验收（S2 双运行密钥取证 / S5 真机 0 误报 / 回归矩阵 + Defender）；
> v1 规划五项全收；v2 实施记录：meta 24B 组化+EXT 组 + 装载/验签两函数加密
> 全链通过（含 30s watchdog）；antidebug/integrity 随后落地（§7）；
> **revoke 的"永久排除"结论已于 2026-10-05 证伪并落地 —— 见 §15**。
> ⚠️ **节号自 2026-10-12 起按文件位置递增，与版本号无关**：原方案「节号 = 版本号 + 6」
> 在 v7 时已失效（13 被"下一轮待办"占用，只能降级写成 12.5）。新增实施记录**追加在文末**
> 并接续下一号，不要回头改旧节号。

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






## 7. 实施记录 v7（2026-08-30 · S1 4/5 落地 + S3 扩展）

**S1 突破（4/5 落地）**：
- antidebug/integrity 加密最终落地：辅助函数（antidebug 的 ad_*/vh_int3、
  integrity 的 build_reloc/iat_snapshot 等）全移 `.protxec` 独立页；
- **根因（当时）**：`prot_revoke_check` 与 `main` 同页（0x5000）——
  VP 切 RW 禁执行 main 自伤。当时判为**不可解**（revoke 排除）。
  ⚠️ **该结论已于 2026-10-05 证伪**：`.protpad` 填充节（§7 下一条的
  "页冲突安全网"同批引入）把 `.protxec` 推后一页，revoke 现落独立页 ——
  详见 §15；本条保留为当时记录，勿再作为现状引用；
- **页冲突安全网**：selfcrypt_proto 检测加密段与 main 同页 → 警告跳过
  （防未来把 main 同页函数加回加密集合）；
- 最终 S1 = blob_load/license_verify/integrity_check_self/antidebug_scan
  四枚加密，稳定性门槛 3/3 PASS。

**S3 扩展**：平坦化推广到 `prot_antidebug_apply_policy`（策略分发
switch-dispatch 状态机），门槛 3/3 PASS。

## 8. 实施记录 v6（2026-08-29 深夜 · S4/S5 完成）

- **S5 落地**：反调试 +2 维（父进程调试器黑名单=关键项 / 墙钟-tick 漂移=咨询项）；
  真机 selftest 0 误报（ppid_blacklist=0, clock_drift_sec=0）。
- **S4 落地**：字符串明文收敛（HWID 格式 / revoke 提示 / 在线 URL 模板入
  strcrypt 表）；exe 扫描验证 `0x%016` 与 URL 模板已消失；revoke 默认路径
  常量保留（运营参数）。
- **S1 最终态**：2 枚加密（blob_load + license_verify）+ pdata 边界防御 +
  .protxec 分节；其余 3 枚记录为 VP 崩溃技术债（机制部分厘清：同页执行
  禁权；integrity 段仍崩待专攻）。
- **稳定性回归器** `mask_stability_test.ps1`：S2/S4/S5 各改动后均 3/3 PASS。

## 9. 下一轮待办
- S1 剩余 3 枚（VP 崩溃技术债专项：解密器/辅助完全独立页 + integrity 段
  重新定位）
- S3 控制流平坦化试点（最小示范：switch-dispatch 等价变换单函数）
- 全量回归（attack_sdk_matrix 含 M11/M12 + Defender 复测）后统一提交基线

## 10. 实施记录 v5（2026-08-29 深夜 · S1 定稿与基建）

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

## 11. 实施记录 v4（2026-08-29 深夜，决定性）

**"布局漂移/掩码残留"假象结案**：以"删旧 mask + 完整构建(全管线到 DONE) + UTF-8 判定"
的三连建实验（`mask_stability_test.ps1`）证实：同一源码树**连续 12 轮全 PASS**
（含带 S2 与探针组态）——**间歇性 TAMPERED 的全部来源 = 旧 exe/半成品 exe 投喂**
（构建中途失败但 demo.exe 时间戳更新的阶段），**无真实运行时缺陷**。

**S1 状态修正（诚实重述）**：真实落地 = blob_load + license_verify **两枚**
（与 efded61 提交一致——此前"4 枚"为误记；antidebug/integrity/revoke 加密仍
有待在稳定构建流程下逐枚复验；revoke 0x4ff0 邻段崩同样待复验是否亦为幻影）。
> ⚠️ **本条为 2026-08-29 当时状态**：上述"逐枚复验"已完成 —— antidebug /
> integrity 于 §7 落地，**revoke 于 2026-10-05 落地且 0x5d0d 崩确为幻影**
> （见 §15）。当前 S1 = **5/5**。

**S2 落地（完成）**：
- `src/vm_rekey.c`（独立编译单元）+ `vm.h` 声明 + demo main 装载后钩 + 双构建
  脚本编译项；
- 差分重编码实现（线性密钥域），仅内存操作（blob 文件/签名不变）；
- 实证：**两次运行 [S2KEY] 密钥域不同**（A=0x...a24899 / B=0x...c3c07683），
  全链（含完整性/授权门/30s watchdog）连续多轮 PASS。

**经验追加**：构建产物时间戳≠构建成功；判定输出一律 UTF-8 读档；
"X 代码导致 TAMPERED"类结论必须先验证完整构建（smoke 用 -SkipSmoke 绕过
WDAC 后手动运行）。

## 12. 实施记录 v3（2026-08-29 晚）

**S1 补完（干净环境下逐枚二分）**：此前"0x3940 互扰/最后一段必崩/完整性失败"
全部被证实为**损坏工具链（142B 废 selfcrypt_proto 脚本）+ 构建失败旧 exe**
叠加的假象。干净重建后：
- 反调试/integrity 两枚加回，EXT 增至 4 枚全链 PASS（30s watchdog）；
- **revoke（0x4ff0 邻段）仍触发 VirtualProtect 调用点崩溃（0x5d0d）**——
  记为布局边界（低频调用+间接表+黑名单签名兜底，加密收益最低）；
  > ⚠️ **该结论已于 2026-10-05 证伪**：崩溃是"损坏工具链 + 旧 exe"假象的一部分
  > （与本节开头所记同源）。`.protpad` 填充节使 revoke 落独立页后,
  > 实测构建 rc=0、无 0x5d0d、无 TAMPERED（见 §15）。本条保留为当时记录。
- 最终 S1 落地：blob_load / license_verify / antidebug_scan /
  integrity_check_self 四函数加密（组 1）。

**S2（运行时密钥多样性）尝试与阻断**：
> ⚠️ **该"阻断"已被后来的 S2 落地推翻** —— 见 §13「S2 落地（完成）」
> （`src/vm_rekey.c` 独立编译单元 + 双构建脚本编译项，实证两次运行密钥域不同）。
> 本节保留为 2026-08-29 当时的受阻记录；其"原子性缺陷"担忧最终以
> **构建期同步布局**的方式绕过（新增编译单元纳入同一构建管线）。
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

## 13. 实施记录（v2，2026-08-29）

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

## 14. 待办清单
- [x] 拍板 D1-D5
- [x] S1 部分（blob/license 两枚 + 组化基础）
- [x] S1 剩余（antidebug/integrity 于 §7 落地；**revoke 于 2026-10-05 落地**，
      原"0x3940 互扰 / 与 main 同页"阻断经复验为**已解**——见 §15）
- [x] S2-S5 实施 —— **2026-10-06 复核：S2/S3/S4/S5 均已落地**（逐条见下），
      但 **S3 的试点函数与 D3 决策不符**（详见 **§14.1** 的偏离记录）
- [ ] 回归：矩阵 + Defender + 真机闭环

> **2026-10-06 复核（S2-S5 逐条证据）**：
>
> | 项 | 状态 | 证据 |
> |----|------|------|
> | **S2** 运行时密钥多样性 | ✅ | `src/vm_rekey.c:18 prot_status prot_vm_rekey(prot_vm_image* img, uint64_t new_key)`；调用点 `demo/main.c:731 prot_vm_rekey(&g_vm_imgs[vi], (ent ^ (uint64_t)vi) \| 1u)`，熵源 `:726 prot_plat_monotonic_ns()/1000000 ^ (uintptr_t)bp` ⇒ **每运行密钥域不同**；注册于 `modules.json:604-605`（`"source": "src/vm_rekey.c"`，独立编译单元）|
> | **S3** 控制流平坦化 | ⚠️ **已落地但偏离 D3** | 实际试点 = `src/antidebug.c:509-548 prot_antidebug_detected`（7 位聚合改 `switch`-dispatch 状态机）+ `:553-575 prot_antidebug_apply_policy`（策略分发）；**不是** D3 推荐的 `prot_integrity_check_self` —— `src/integrity.c` 内**无任何平坦化**（其 `switch (g_wd_policy)` 是原有策略分发，非状态机变换）|
> | **S4** 字符串收敛 | ✅ | `demo/strings.txt` 33 条语义串全部经 `tools/strgen.py` 加密进 `demo/gen/{win,linux}/strings.c`（243 行）；**本轮实测 `build/demo.exe`（327680 B）对 33 条串的 UTF-8 与 UTF-16LE 两种编码扫描 ⇒ 明文命中 0** |
> | **S5** 反调试 +2 维 | ✅ | `include/protect/antidebug.h:35 ppid_blacklist`（关键项）/ `:36 clock_drift_sec`（咨询项）；置位处 `src/antidebug.c:302` / `:342`（Linux 侧 `:493`）；已进判定位 `:534 mask[6]`，且 `demo/strings.txt` 有对应 `SELFTEST_PPID` / `SELFTEST_CLOCK` 输出行 |
>
> **S2 的原"阻断"已解**：§12 记录的"新增任何编译单元 → `.text` 漂移 → TAMPERED"
> 最终以**构建期同步布局**绕过（新编译单元纳入同一构建管线，见 §13 的 S2 落地记录）；
> 本条与 §15 的 revoke 收口属同一类"当时的不可解结论已被后续机制推翻"。
>
> ⚠️ **仍未做的部分（保留未勾）**：S5 验收标准第 4 条要求"新维度 selftest
> **干净环境 0 误报（真机）**"，S2 验收要求"同构建两次运行 dump 密钥不同"的
> **真机取证**，以及下方 `回归：矩阵 + Defender + 真机闭环` —— 这些需真机，
> 与 `docs/PHASE2.md` 同属硬件面。

### 14.1 S3 试点函数的偏离（2026-10-06 补记，供后来者核对）

D3 决策（§3）推荐 **`prot_integrity_check_self`**，实施步骤（§4 步骤 3）
也写"integrity 平坦化试点"。**实际落地在 `prot_antidebug_detected`**
（提交 `f72f134`，2026-08-30：`feat(s3-pilot): control-flow flattening pilot on
prot_antidebug_detected - equivalent switch-dispatch state machine (7 key signals
incl. S5 ppid_blacklist)`，1 file changed / 26 insertions / 7 deletions），
随后扩展到 `prot_antidebug_apply_policy`。

**该偏离此前未在任何地方记录** —— §7 只写"S3 扩展：平坦化推广到
`prot_antidebug_apply_policy`"，未指出它与 D3 / §4 步骤 3 不一致。
本轮如实补记，**不修改 D3 的原始文字**（那是当时的决策记录）。

**推测的偏离理由（未取证，故标为推测）**：`prot_antidebug_detected` 是
7 个独立位的纯聚合函数，语义等价性易于证明（改 `switch`-dispatch 后
仍逐位 `acc |= mask[i]`，见 `src/antidebug.c:535-547`）；
而 `prot_integrity_check_self` 含 IAT 快照 / 段 CRC / 掩码重建等副作用，
等价变换的验证成本高得多。**若确为此因，应当在 §7 当时写明** ——
这正是本阶段反复出现的"结论在、依据不在"的又一例。

---

## 15. 复验与收口（2026-10-05 · v8）— S1 5/5

### 15.1 缘起

§14 待办长期挂着「S1 剩余（antidebug/integrity/revoke）」，而 §7 已记
antidebug/integrity 落地 —— **待办清单与实施记录自相矛盾**。逐项核对后，
真正未覆盖的目标只有 **revoke 一枚**，其唯一阻力是 §7 的
「与 main 同页（0x5000）· 不可解」判断。

该判断写于 2026-08-30，此后仓库经历了**节名随机化**（阶段 1，第二支柱）、
**`.protpad` 填充节**、**`.protxec` 第 4 段 CRC**（DRILL9）、
**`merge_baseline` 基线提升**等多项布局相关改动。故「revoke 必崩」
是**可证伪的陈旧结论**，不能直接作为现状引用。

### 15.2 证伪实验（最小改动，利用既有逃生舱）

`build.ps1:36` 早已提供 `-ExtraSelfCrypt <逗号分隔函数名>`，`tools/selfcrypt_proto.py:344-346`
的 `--extra` 会以 `setdefault(en, 1)` 并入 EXT 组 —— **无需改任何代码**即可复验：

```
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Config Release `
    -ExtraSelfCrypt prot_revoke_check
```

实测：

| 观测项 | 结果 |
|--------|------|
| 构建 | `rc=0`；`selfcrypt_proto: prot_revoke_check rva=0x2ba0 size=154 seed=0x4e31504245474d21 crc=0x1a617e16 group=1 (in-place)` |
| 目标数 | `patched build\demo.exe (9 fns in-place, meta@0x34a00 hdr=220)`（原 8 → **9**） |
| 页冲突安全网 | **未触发** —— revoke 落页 `0x2`，与 `main` **不同页**（原判断的前提已不成立） |
| smoke | `build: smoke test PASS (correct serial accepted)` |
| `demo.exe --selftest` | `rc=1`（正常"序列号无效"路径）—— **无 0x5d0d 崩溃、无 0xBAD TAMPERED** |
| e2e | `[e2e] 平台=win  总计 28: PASS 28 / FAIL 0 / SKIP 0 / NA 0` |
| attacks | `[attacks] 平台=win  总计 12: PASS 12 / FAIL 0 / NA 0`，含 `A11 selfcrypt-dump PASS   (plaintext-fns=none (static ciphertext))` |
| window_check | `作用域 24 文件 / 308 函数; 加密目标 9 个` ⇒ `PASS: 全部加密目标调用点都在配对 enter/leave 窗口内` |

### 15.3 阻断已解的真因

`src/selfcrypt.c:39-41` 的注释即修复本身：

```
/* S1 专项 (2026-08-30): .protpad 填充节 — 把 .protxec 推后一页,
 * 使其与 .text 尾部加密段 (revoke) 分页, 消除
 * 页粒度 VP 禁执行自伤。 */
```

即 §7 记录那次"页冲突安全网"的同批改动**顺带解掉了 revoke 的同页问题**，
只是当时的实施记录没有回头销掉 revoke 的排除结论 ——
**修了、也记了，但记在了另一条下面，旧结论无人回收**。

### 15.4 落地

`tools/selfcrypt_proto.py` 的 `EXT_TARGETS` 增加 `'prot_revoke_check': 1`
（含复验数据注释）。`tools/window_check.py:107-129` 的 `load_targets()`
**从该文件动态读清单、不硬编码**，故新增目标自动进入调用点窗口校验。

`demo/main.c:829-837` 的调用点**本就已在 `sc_ext_enter()/sc_ext_leave()` 窗口内**
（§13 已为"未来 EXT 加密预留"），无需改动宿主代码。

`examples/tool_demo/main.c:327` 是直接调用且**无**窗口，但该目录**不在
`tools/window_check.py:86 SCOPE_DIRS` 内** —— 其 `build_example.ps1`
**不调** `selfcrypt_proto`（`tools/window_check.py:61` 明载），
故其 `prot_revoke_check` 是明文函数，无窗口需求。

### 15.5 诚实边界

- revoke 是**低频 + 间接表 + 签名兜底**的模块（§7 自评"加密收益最低"）；
  本次纳入是**消除一处"已修未销"的陈旧阻断记录**，安全增益有限。
- D2b 下窗口 = 调用周期；窗口外 revoke 仍是密文，符合设计意图。
- 未做：revoke 加密对**真机 Defender 复测**（§14 待办末条）仍挂账。
