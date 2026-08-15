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

### A2. 引擎语义随构建变异（THREATMODEL 技术债 #2）— ✅ 2026-08-14 落地
- **目标**：让"窗口/取指/混联"等引擎语义也随构建随机，阻断 A3 的"通用还原器
  一次通吃所有构建"。
- **方案**：在 vmenc 的随机流里再派生 2~3 个**语义微变开关**（如访存仍是直序，
  但 `vm_wfetch` 的字节序可按构建选 LE/BE-SWAP；`vm_kr_fold` 的折叠写法多选），
  `vm.c` 用构建期烧录的 `img->var` 位枚举这些微变；每变体语义保持逐位一致
  （约束与 CONTRACT §4.2 等价性相同）。
- **落地细节**：`sem=[sem0,sem1]` 由 `key[1]` 随机流在 slot 派生后、var 派生前
  两侧同位置复算（vmenc.py `make_opcode_keymaps` ↔ vm.c `vm_build_keymaps`）。
  `sem0`=操作数字节序（LE/BE-SWAP，生成侧 `assemble_source` 反转写出，执行侧
  `vm_wfetch32/64` 反转读回）；`sem1`=折叠公式 0..3（vm.c `vm_fold`，仅影响
  等价路径选择）。4 个 demo VM + 2 个单测 VM 全部随机覆盖。
- **验收**：✅ 连续 8 轮重建 e2e 全绿（BE/LE 与全部折叠公式均被实际覆盖）；
  A3 build-fingerprint 断言每轮指纹变化。

### A3. integrity 扩展到 `.rdata`/`.pdata`（L4a 增强）— ✅ 2026-08-14 落地
- **目标**：补广为"改文件就死"，覆盖只校验 `.text` 的缺口。
- **方案**：`integrity.c` `check_self` 遍历节表，除 `.text` 外对 `.rdata`/`.pdata`
  各自做 CRC 并与构建期烧录的一组值比对（`g_prot_baked_crc` 扩为小数组，或加
  第二个 magic 段；需与 `hashpatch.py` 保持同一 `min(VirtualSize,SizeOfRawData)` 约定）。
- **落地细节**：烧录表迁到专用只读段 `.protcrc`（3 组 16B marker，避免自引用）；
  **ASLR 掩码**是落地关键——`.rdata` 的 IAT（目录项 12）与基址重定位字段
  （type 10/3）会被 loader 改写，文件侧与运行侧用同一掩码归零后再算 CRC，
  两侧一致（hashpatch.py ↔ integrity.c `build_reloc_mask`）。
- **验收**：✅ T9 翻 .rdata（+0x1000 避开 IAT）→ 0xBAD；T10 翻 .pdata → 0xBAD；
  干净环境零误报（T1/T6/T7 仍全绿）。

### A4. 指令集扩充（ROADMAP Phase 1d 余量）— ✅ 2026-08-14 落地
- **目标**：按 THREATMODEL §6 B2 的"接口面增长"+ ROADMAP 预登记，补 `brk`、`move`、
  寄存器索引寻址。
- **方案**：扩展 `vmenc.py INSTRUCTIONS` 与 `vm.c g_routes` 同步 opcode 域
  （0x00..0x2A → 追加 4 条到 0x2E）；`PROT_VM_OP_COUNT`/`OPCODE_SLOTS` 两侧同步
  为 0x2F(47)；每个新指令在 `tests/unit_vm.vasm` + `tests/vm_unit.c` 单测覆盖。
- **落地细节**：`brk`=CON!=0 断言陷阱（新增 `PROT_ERR_VM_BREAKPOINT` 状态码，
  可做 VM 内门控/反 patch 标记）；`move imm32`=R←imm32；`loadr32`/`storr32`=
  mem[BR+R+off] 寄存器索引寻址；`tests/unit_vm_brk.vasm` 覆盖 brk 陷阱路径
  （必须返回 BREAKPOINT 且陷阱后指令不执行）。
- **验收**：✅ 构建通过、vm_unit 新用例 PASS、连续 8 轮重建 e2e 全绿。

### A5. 反附加定时器（Phase 3 剩余）— ✅ 2026-08-14 落地
- **目标**：把"只在启动测一次"升级为"周期复查"：看门狗级后台线程每随机
  间隔（派生自 TSC/计时抖动）重新 `prot_antidebug_scan`，命中关键项推既有
  EXIT/FAKE/CONTINUE 策略 —— 提升"驻留期"检测密度，降低 ScyllaHide 一次性绕过。
- **方案**：在原看门狗线程逻辑加"复查间隔抖动"（基数 ±40%，xorshift 种子派生
  自 QPC），周期调用 `prot_antidebug_scan`，命中关键项推既有 EXIT/FAKE/CONTINUE
  策略（复用 `antidebug.c` 既有权责，不改坏 `g_wd_*` 状态机）。
- **验收**：✅ 干净环境零误报（T7 仍全 0）；多次运行无 FAKE/退出误伤；
  真机(B1)补验。

### A6. direct syscall 反 hook（Phase 3 剩余）— ✅ 2026-08-14 落地
- **目标**：`NtQueryInformationProcess`/`NtQuerySystemInformation` 等关键信息类
  改走 `syscall` 直调，规避 ntdll hook（反钩子）增持。
- **收益评估**：仅在"攻击者已 hook ntdll"场景有增量；排 A5 后做。
- **落地细节**：运行时从 ntdll 原始 stub 提取 SSN（扫 `0F 05` 前最近的
  `B8 imm32`，不硬编码）+ 可执行内存生成 12B stub（`mov r10,rcx; mov eax,SSN;
  syscall; ret`，无 MASM、二进制无固定 syscall 代码）；失败回退 GetProcAddress
  路径，不新增误报面（src/syscall.c + antidebug.c 四项优先直调）。
- **验收**：✅ `syscall_probe.exe`（build.ps1 内）断言 available=1 且直调 ==
  API 路径；T7 selftest-clean 不退化；真机(B1)补验后按结论归档。

## B. 需要真机/远程后延（当前不动）

| # | 项 | 锁因 | 开门条件 |
|---|----|------|----------|
| B1 | T3 真机调试验证 | 需真实 attach 调试器会话 | 提供可远程登录的 Windows（RDP）→ 跑 `python tests\e2e.py` 将 SKIP 转 PASS/FAIL 并补用例 |
| B2 | CI 推 GitHub 跑通 | 需远程仓库/runner | push 远端后 `ci.yml` 自动跑 MSVC build + verify；产物 manifest 可审计 |
| B3 | 发包全量回归（含 T3 三角验证） | 依赖 B1/B2 | 两者完成后 `verify.ps1 -Rounds 3` 作为发版 gate |
| B4 | 真实硬件/部署验证 | 需物理机（换机、UEFI 等） | Phase 4 授权签发完成后用真机验证绑定 |

## 开发节奏建议

1. ✅ **A1（RSA）** 已完成（2026-08-10）— 一次性把"防分析梯队"升级成"防伪造"。
2. ✅ **A2 + A3** 已完成（2026-08-14）— 引擎语义变异 + 完整性扩三节。
3. ✅ **A4/A5** 已完成（2026-08-14）— 指令集扩充 4 条 + 反附加定时器。
4. ✅ **A6** 已完成（2026-08-14）— direct syscall 反 hook（syscall_probe 单测）。
   **A 区全部结清**；B 区（真机/远程）见下。

> 更新日志：2026-08-14 v4 — 技术债 #3（DBI launcher）结清：vm.blob 外部
> 装载，exe 无 VM 逻辑；T13/T14 全绿。THREATMODEL §6 三个技术债全部结清。