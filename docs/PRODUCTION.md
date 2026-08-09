# 生产实施计划 (PRODUCTION)

> 面向"把当前演示级保护推向可用/商业级"的分期实施清单。
> 与 `docs/ROADMAP.md`（阶段目标）、`docs/THREATMODEL.md`（每层弱点评级与
> 技术债）、`docs/CONTRACT.md`（实现契约）配套。
> 本文只列**不依赖真机/远程**、现在即可动手的项（A 区）；需要真机或远程
> 交互的验收统一放 B 区延后，等真机就绪后补做。

## A. 可立即实施（无需真机）

按 THREATMODEL §6 技术债 + ROADMAP 分派排序，逐项给目标/方案/涉及文件/验收。

### A1｜RSA 离线签发（Phase 4 主线）— 最高优先级
- **目标**：把"期望值可计算"升级为"私钥签名、公钥验签"，使 THREATMODEL §4 指出的
  "防分析可破、防伪造不可破"真正落地；即破解者还原全部 VM 也造不出合法 key。
- **方案**：
  1. `tools/vmenc.py` 增加 `sign` 子命令：`(serial, machine_id, product_tag)` 拼接 →
     SHA-256 → RSA-2048 签名（Padding 用 PKCS1 v1.5），输出 `license.txt`（base64）。
  2. VM 新增指令或宿主扩展：把"校验 expect"改成"公钥验签"或在校验 VM 前由宿主
     `prot_license_verify(sig, serial, mid, pubkey)` 预检（关键判定位仍进 VM 执行，
     避免只依赖宿主侧可 patch 的调用点）。
  3. 公钥常量嵌入 `demo/main.c`/镜像；私钥留本地离线，**不入库**（`.gitignore`
     增加 `*.key` `*_priv.pem`）。
  4. `build.ps1` 增加"签发模式"开关：下发时读 `license.txt`，不改变 build 主链。
- **涉及文件**：tools/vmenc.py、demo/main.c、include/protect 新头、license 证书文件、
  docs/CONTRACT（§5/§9）、docs/THREATMODEL（§4 标记为已立项）、tests（A 区新用例）。
- **验收**：新 `vmenc sign`→`verify` 往返 OK；篡改 1 位签名/篡改 serial → T 系列
  FAIL；`verify.ps1` 加 A5 license-sign 用例全绿；私钥文件不进入 git 提交树。

### A2. 引擎语义随构建变异（THREATMODEL 技术债 #2）
- **目标**：让"窗口/取指/混联"等引擎语义也随构建随机，阻断 A3 的"通用还原器
  一次通吃所有构建"。
- **方案**：在 vmenc 的随机流里再派生 2~3 个**语义微变开关**（如访存仍是直序，
  但 `vm_wfetch` 的字节序可按构建选 LE/BE-SWAP；`vm_kr_fold` 的折叠写法多选），
  `vm.c` 用构建期烧录的 `img->var` 位枚举这些微变；每变体语义保持逐位一致
  （约束与 CONTRACT §4.2 等价性相同）。
- **验收**：A3 build-fingerprint 断言在"只重启建"时指纹就变化（现有已提供基线）；
  新增 `tests/unit_vm.vasm` 覆盖所有新开关路径；连续 3 轮重建 e2e 全绿。

### A3. integrity 扩展到 `.rdata`/`.pdata`（L4a 增强）
- **目标**：补广为"改文件就死"，覆盖只校验 `.text` 的缺口。
- **方案**：`integrity.c` `check_self` 遍历节表，除 `.text` 外对 `.rdata`/`.pdata`
  各自做 CRC 并与构建期烧录的一组值比对（`g_prot_baked_crc` 扩为小数组，或加
  第二个 magic 段；需与 `hashpatch.py` 保持同一 `min(VirtualSize,SizeOfRawData)` 约定）。
- **验收**：`tests/e2e.py` T4 扩到"翻 .rdata 一个字节也退 0xBAD"；verify.ps1 全绿。

### A4. 指令集扩充（ROADMAP Phase 1d 余量）
- **目标**：按 THREATMODEL §6 B2 的"接口面增长"+ ROADMAP 预登记，补 `brk`、`move`、
  寄存器索引寻址。
- **方案**：扩展 `vmenc.py INSTRUCTIONS` 与 `vm.c g_routes` 同步 opcode 域
  （0x00..0x2A → 追加 2~3 条）；`PROT_VM_OP_COUNT`/`OPCODE_SLOTS` 两侧同步；
  每个新指令在 `tests/unit_vm.vasm` + `tests/vm_unit.c` 单测覆盖。
- **验收**：构建通过、vm_unit 新用例 PASS、连续 3 轮重建 e2e 全绿。

### A5. 反附加定时器（Phase 3 剩余）
- **目标**：把"只在启动测一次"升级为"周期复查"：看门狗级后台线程每随机
  间隔（派生自 TSC/计时抖动）重新 `prot_antidebug_scan`，命中关键项推既有
  EXIT/FAKE/CONTINUE 策略 —— 提升"驻留期"检测密度，降低 ScyllaHide 一次性绕过。
- **方案**：在原看门狗线程逻辑加"复查间隔抖动"（基数 ±40%），周期调用
  `prot_antidebug_scan`，命中关键项推既有 EXIT/FAKE/CONTINUE 策略（复用
  `antidebug.c` 既有权责，不改坏 `g_wd_*` 状态机）。
- **验收**：干净环境 60s 运行零误报（T7 仍全 0）；连续 N 次运行无 FAKE/退出误伤；
  真机(B1)补验。

### A6. direct syscall 反 hook（Phase 3 剩余，低优先）
- **目标**：`NtQueryInformationProcess`/`NtQuerySystemInformation` 等关键信息类
  改走 `syscall` 直调，规避 ntdll hook（反钩子）增持。
- **收益评估**：仅在"攻击者已 hook ntdll"场景有增量；排 A5 后做。
- **验收**：T7 selftest-clean 不退化；真机(B1)补验后按结论归档。

## B. 需要真机/远程后延（当前不动）

| # | 项 | 锁因 | 开门条件 |
|---|----|------|----------|
| B1 | T3 真机调试验证 | 需真实 attach 调试器会话 | 提供可远程登录的 Windows（RDP）→ 跑 `python tests\e2e.py` 将 SKIP 转 PASS/FAIL 并补用例 |
| B2 | CI 推 GitHub 跑通 | 需远程仓库/runner | push 远端后 `ci.yml` 自动跑 MSVC build + verify；产物 manifest 可审计 |
| B3 | 发包全量回归（含 T3 三角验证） | 依赖 B1/B2 | 两者完成后 `verify.ps1 -Rounds 3` 作为发版 gate |
| B4 | 真实硬件/部署验证 | 需物理机（换机、UEFI 等） | Phase 4 授权签发完成后用真机验证绑定 |

## 开发节奏建议

1. 先做 **A1（RSA）** — 它一次性把"防分析梯队"升级成"防伪造"，价值最大。
2. 之后 **A2 + A3** 小步进（都是改一行契约 + 生成器），可一起验。
3. **A4/A5** 按需增量，注意不改契约破坏 T1/T2 既有行为。
4. **A6** 视时间放在最后，只在有 hook 场景的有效性明显再无回报时犹豫。

> 更新日志：2026-08-09 v1 初稿（由 THREATMODEL v1 分化出"可立即实施"与"延后需真机"两份清单）。