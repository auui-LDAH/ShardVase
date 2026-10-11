# Studio 协议 v1 — NDJSON over stdio

> 版本：2026-10-10 v1 · 状态：**ST0 / ST4 / ST2 / ST1 已实施**
> （`tools/studio_core.py` + `tools/studio_cli.py`）
> 逐阶段追加（每行自成一句）：
> · ST4 追加 `vm.images` / `vm.disasm`（VM 级调试入口；单步与断点尚在
>   `tools/vm_debug.py` 的库/CLI 层，未提升为协议命令 —— 见 §9.4）。
> · ST2 追加 `test.gate.results`（门禁结果的**历史查询**；文本出口不变，新增 NDJSON 出口）。
> · ST1 追加 `plan.graph`（依赖/冲突图）与**流式命令** `build.run`
>   （一个请求产出多行响应 —— 这是协议第一次出现非请求/响应形态，见 §5.1）。
> 本文是**契约**：面板、测试、脚本、未来的编辑器扩展都按它对接后端。

## 1. 为什么需要一份协议文档

`docs/STUDIO_PLAN.md` §2 定了三条架构边界，其中**边界 2 = 契约统一**：
Studio 后端对外只有**一套**契约，不允许「面板调一套、门禁调另一套」。

理由不是洁癖，是**已有教训**：本项目此前的结构化输出能力散落在少数工具里
（`prot_dbg.py` 有 `--json`、迁移类工具有 `json.dump`），
其余工具**只有人类可读文本** ⇒ 任何面板想画图，都得**再写一份解析器**，
于是同一份事实有了两个消费者、两套理解、两条漂移路径。
`docs/DEBUG_CONSOLE_PLAN.md:32` 已经把这条盘点记下来了：`格式不统一`。

⇒ 结论：**先有协议，再有面板。** 面板不做解析，只做渲染。

## 2. 传输：一行 = 一条消息

**NDJSON**（Newline Delimited JSON）：每行一个 JSON 对象，
行尾 `\n` 是**消息边界**，不是格式的一部分。

为什么是 NDJSON 而不是「一个 JSON 文档」：**调试天生是流式的**。
断点命中、单步、日志、退出各自是一个**时刻**；一次性 JSON 表达不了
「停在断点、等下一个命令」，除非把协议改成请求/响应双工 ——
而 NDJSON over stdio 本身就是双工的，且**任何语言都能实现客户端**
（面板、测试、shell 管道、未来的编辑器扩展）。

**编码**：UTF-8，**不转义非 ASCII**（`ensure_ascii=False`）⇒ 中文原样可读。
消费方必须按 UTF-8 解码；Windows 控制台默认 GBK 会让中文乱码，
故读写两端都显式指定 UTF-8（见 `tools/studio_cli.py` 的 `_in_stream` / `_out_stream`）。

## 3. 请求

```json
{"id": 1, "cmd": "plan.solve", "args": {"profile": "balanced"}}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `id` | 否 | 客户端自选，**原样回传**。用于配对；缺省为 `null`。 |
| `cmd` | **是** | 命令名，必须在 §5 的清单内。 |
| `args` | 否 | 命令参数对象；缺省 `{}`。**必须是对象**，不是数组/标量。 |

## 4. 响应

**成功**
```json
{"id": 1, "ok": true, "data": {"selected": ["dbiguard", "license"]}}
```

**失败**
```json
{"id": 1, "ok": false, "error": {"code": "E_NOT_FOUND", "message": "策略不存在: x", "detail": {"available": ["balanced"]}}}
```

| 字段 | 说明 |
|---|---|
| `ok` | 成败布尔量。**消费方必须先看它**，不要靠字段是否存在来猜。 |
| `data` | 成功时的载荷。形状由命令定义（§5）。 |
| `error.code` | **稳定机读标识**（见 §6），面板据此决定怎么提示，**不解析 message**。 |
| `error.detail` | 可选的结构化补充（候选列表、实际类型、原始输入片段）。 |

**两条纪律**

1. **失败不终止会话。** 流式会话里一条命令出错，只让那一行 `ok=false`，
   后续请求照常处理。终止会话是客户端的决定，不是后端的。
2. **失败不抛给调用方。** `envelope()` 把异常收成响应包；
   只有**协议层**的错误才可能没有响应（见 §7）。

## 5. 命令清单（协议 v1）

命令名是**点分命名空间**（`域.动作`）：`ping` / `capabilities` / `plan.*` /
`modules.*` / `gate.*` / `vm.*` / `test.*` / `debug.*`。
新增命令**只能追加**，不得改变已有命令的语义。

`debug.*` 里**只读**的一组（`doctor` / `sym` / `mask` / `exit`）**不碰目标进程**；
`read` / `patch` 会附着进程，因此**额外要求 `confirm: true`**（见 §6 的
`E_CONFIRM_REQUIRED`）。

| `cmd` | `args` | `data`（要点） |
|---|---|---|
| `ping` | — | `protocol_version` / `studio_version` / `repo` / `platform` |
| `capabilities` | — | `capabilities{}`（**以能力名为键的对象**，不是数组），每项 `{status, backend, evidence, note?, step?}`；`status ∈ ready/partial/planned` |
| `plan.list` | — | `profiles[]` `{name, description, threats, strength, performance_budget}` + `count` |
| `plan.solve` | `profile` | `solve_profile.solve()` 的完整结果（`selected`/`excluded`/`auto_added`/`reasons`/`conflicts`/`order`/…）**外加** `_profile_file` 与 `_text` |
| `modules.list` | — | `modules[]` `{name, maturity, caps, deps, conflicts_with, cost, header, source, known_limits, evidence, ordering, phases, consumes, produces, modifies_text, verifies_text, needs_writable_dir, page_align, host_hooks, abi_version}` + `primitives` + `maturity_scale`（分级**依据**，不是形容词） |
| `gate.items` | — | `items[]` `{name, line, gated}` + `total`/`gated`/`default`/`source` |
| `src.show` | `path`, `line?`, `context?` | 读仓库内**文本文件**的一段行：`lines[]` `{n, text, hit}` + `start`/`end`/`total`/`truncated`/`binary`/`backend`；`context` 缺省 12，窗口上限 400。**二进制不报错**（如实 `binary: true` 且无 `lines`）；`line` 越界报 `E_NOT_FOUND` 而**不夹到末尾**；仓库外路径报 `E_BAD_ARGS` |
| `vm.images` | `blob?` | `images[]` `{name, code_len, key0, key1, crc, offset}` + `count`；`blob` 缺省 `build/vm.blob` |
| `vm.disasm` | `source`, `name`\|`asm`, `blob?` | `insns[]` `{off, mnem, operand, size, target?, line}` + `code_len`/`count`/`sem0`/`has_lines` |
| `vm.source` | `asm` | 逐行视图：`rows[]` `{line, text, kind, tokens[][2], off?, asm_mnem?, breakable}` + `mnemonics[]`(47) / `symbols[]` / `executable_lines[]` / `assemble_error` / `breakpoint_key` / `rel`（相对仓库根的路径） |
| `vm.open` | `source`, `name`\|`asm`, `blob?` | 建**调试会话**，返回 `session` + 会话状态（见 §5.4） |
| `vm.state` | `session` | 会话当前状态（同 `vm.open` 的载荷） |
| `vm.continue` | `session`, `max_steps?` | 跑到断点/停机；停机原因见 `stop_reason` |
| `vm.step` | `session` | 执行**恰好一条**指令（断点**不**拦截单步） |
| `vm.stepOver` | `session` | 跨过一条 `call`/`callind`；**被调函数内部的断点仍会命中** |
| `vm.restart` | `session` | 回到初态；**保留断点**（重启不该悄悄清掉用户下的断点） |
| `vm.breakpoints` | `session`, `lines[]` \| `add[]`/`remove[]` | `lines` = 整体替换（空数组 = 全清）；与 `add`/`remove` **不可同时给**（顺序有歧义） |
| `vm.close` | `session` | 关闭会话；**对未知 id 也成功**（幂等），返回值里 `existed` 说明它是否真的存在过 |
| `plan.graph` | `profile`\|`modules` | `nodes[]` / `edges[]`（每条带 `relation`）/ **`order_edges[]`** / `topo` / `cycle` / `conflicts[]` / `relations` / `topo_dep_violations[]`；**`modules` 优先于 `profile`** |
| `test.gate.results` | `query?`, `run?`, `a?`, `b?`, `dir?` | `query` 取 `latest`（缺省）/`list`/`verify`/`diff`/`trend`；`latest` 返回 `items[]` 逐项 `{seq, name, status, seconds, why, src, src_line}` + `jump_unresolved[]` + `counts_json`/`pass_n` |
| `debug.doctor` | `exe?`, `map?` | 体检：`summary{ok, syms, mask_regions, n_errors, n_warns}`；**不开进程**（`opened_process: false`） |
| `debug.sym` | `symbols[]`, `exe?`, `map?` | `symbols[]`（表）+ `missing[]`（查不到的符号名）；**`symbols` 为空 ⇒ `E_BAD_ARGS`**，不是空结果 |
| `debug.mask` | `symbols[]` \| `rva,len`, `exe?`, `map?` | `payload_key ∈ 'mask' / 'sym'` —— 如实透出「给了符号名时底层转成符号查询」，不替调用方抹平 |
| `debug.exit` | `codes[]` | 退出码 → 语义；`unknown[]` 是**查不到的码**（不猜、不映射成最近的一个） |
| `debug.read` | `symbols[]`, `length?`, `pid?`, **`confirm`** | 读目标进程内存；`length` 缺省 16；`opened_process: true` |
| `debug.patch` | `symbols[]`, `bytes` \| `nop` \| `restore`, `pid?`, **`confirm`** | 改写目标进程内存；`opened_process: true` |

`debug.read` / `debug.patch` 的参数键是 **`symbols`（数组或字符串）**，与
`debug.sym` / `debug.mask` 一致 —— 面板上「选中的符号」是一个**集合**，
让这三条命令用同一个键名，前端就不必为每条命令记一套形状。

⚠️ **错误码的先后顺序也是契约**：活体命令的检查顺序是
**「先说清对象」→「再要授权」**。即 `symbols` 缺失/为空时报 `E_BAD_ARGS`
（**不知道该读什么**），只有在对象明确之后才判 `confirm`
（`E_CONFIRM_REQUIRED`）。反过来会在"什么都没指定"时就弹一个
"要附着进程吗"的确认框 —— 用户点了确认，然后拿到一个参数错误。


### 5.4 VM 调试会话：`session` 是什么，以及它**不是**什么

`vm.disasm` 是**一次性**的：把一段字节译成助记符，看一眼就结束。
`vm.open` 建的是一个**跨多次调用活着的解释器**（`tools/vm_debug.py:class Session`）——
「继续 / 单步 / 步过」这些动作要的是同一个解释器的下一次推进，而不是重放一遍。

**会话状态字段**（`vm.open` / `vm.state` / `vm.continue` / … 都返回同一形状）：

| 字段 | 含义 |
|---|---|
| `session` | 会话 id，形如 `vm-7`；**单调递增，不复用** —— 复用一个已关闭的 id 会让面板手里那个过期的 id 突然指向一个新会话 |
| `line_at_ip` | 当前 IP 对应的**源行号**；没有行号表时为 `null`（**不编造 0**） |
| `ip` / `steps` / `stack_depth` / `stack_top` / `br` / `r` / `con` / `mem_written` | 解释器快照（`stack_depth` 是**数据栈**深度） |
| `call_depth` / `call_stack` | **调用栈**（影子记录），与 `stack_depth` **不是一回事**（见下） |
| `stop_reason` / `stop_detail` | 停机原因；`terminated` 为真时面板应把「继续/单步」置灰 |
| `breakpoints` / `breakpoints_supported` | 断点表与**是否支持按行号下断点** |
| `hit_breakpoint` | 本次停止命中的断点行号；没命中为 `null` |

⭐ **`call_stack` 为什么要单独记，而不是从 `stk` 里读**：
`src/vm.c` 把 `call` 的返回地址压进**与数据同一个栈**（`stk`）。
因此「`stk` 是纯数据栈」和「能从 `stk` 读出调用栈」这两件事**不可能同时成立**。
Studio 的做法是**旁路记录**调用帧（`_note_call` / `_note_ret`），并且当 `ret` 弹出的值与
最近一次 `call` 压入的不一致时，**如实把 `call_stack.reliable` 置为 `false`** 并给出
`dirty_reason` —— 显示一张错的调用栈比不显示更糟，因为它会被当成证据。

**会话的诚实边界**：会话活在 **Studio 服务进程内**。`tools/studio_cli.py --cmd` 每次
是一个新进程，因此**拿不到上一次的会话**；服务重启或换进程后旧 id 失效，
此时报 `E_NOT_FOUND` 并在 `detail.why` 里说明原因 —— **不静默重建**
（静默重建会让面板以为还在调原来那个程序）。

### 5.1 流式命令（`build.run` / `debug.watch`）—— 一个请求，多行响应

`build.run` 与 `debug.watch` **都不在** `dispatch()` 的命令表里：一个请求产出
**多行响应**。它们必须走 `stream_events()` / `respond_stream()`，而
`dispatch('build.run', …)` 会返回 **`E_STREAM_CMD`**。

**为什么错误码不沿用 `E_UNKNOWN_CMD`**：报「未知命令」并附 `available` 列表，
会让面板把「这个命令要用流式调用」读成「名字拼错了」，于是去翻候选清单
而不是改成流式调用 —— 错误码必须指向**正确的下一步动作**。

事件序列与两处刻意的默认值：

| 事件 | 字段 | 说明 |
|---|---|---|
| `plan` | `argv`, `confirm_required` | **总是先出计划**，让人看见将执行的命令行；`config` 三档见 §5.3 |
| `start` | `argv` | **只有 `confirm: true` 才出现** |
| `line` | `text`, `tag` | `tag='build'` 表示 `build.ps1` 自己的进度行 |
| `exit` | `rc`, `lines`, `first_diag` | `first_diag` 是**第一个像诊断的行** |
| `done` | `started`, `ok`, `rc`, `first_diag`, `note?` | 未启动时 `started:false` |

- **不带 `confirm: true` 只返回计划、不启动构建。** 一次完整构建是**分钟级
  副作用操作**（会改写 `build/` 产物）；默认不执行与项目「先计划后执行」的
  纪律一致。面板要有明确的「执行」按钮，而不是把构建绑在一次查询上。
- **`first_diag` 找不到就如实说找不到，不编造。** 里层是 `stderr=STDOUT` 合并
  （实测 PowerShell 原生命令的错误走 stderr 而 `build.ps1` 的进度走 stdout，
  分开读会让事件顺序错乱）。
- **同一条流的每个响应行共用同一个 `id`** —— 这是调用方把多行归并为
  「一次调用」的依据。

`debug.watch`（ST3.3）用同一套机制，事件序列不同：

| 事件 | 字段 | 说明 |
|---|---|---|
| `plan` | `argv`, `sym`, `len`, `interval`, `seconds`, `prepatch`, `confirm_required` | **采样间隔与观测窗口在事件里结构化可见**（ST3.3 的验收点） |
| `start` | `timeout_s` | **只有 `confirm: true` 才出现** |
| `line` | `text`, `tag` | `tag='sample'` 表示这一行是采样输出 |
| `result` | `watch`, `antidebug_interference`, `raw_ok` | 结构化结果**来自被调工具自己的 `--json`** |
| `done` | `started`, `ok`, `rc?`, `note?` | 未启动时 `started:false` |

- **不重新解析采样文本。** 事件里的变化计数直接取自 `tools/prot_dbg.py --json`
  的 `changes` / `n_changes` / `first` / `last`。重新解析会制造**第二套口径**，
  而它漂移时不会报错 —— 只会安静地少报几次变化。
- **超时预算 = 观测窗口 + 120 秒固定余量**（附着与清理的开销与窗口无关，
  按窗口比例给预算会在短窗口上给得太少）。

### 5.2 `plan.graph`：`deps` 与 `ordering` 是两种关系，不可混画

`tools/compose.py:topo_order` 的注释逐字：

> **`deps` 不参与链接顺序图**（2026-09-23 实测修正）。初版把 `deps` 当作
> 「被依赖者先」的边 -> 产生**假环**：`integrity.deps` 含 `selfcrypt`
> （运行时**能力**依赖），而 `selfcrypt.ordering.after` 含 `integrity`
> （**链接顺序**）。**结论**：`deps` = 能力依赖，`ordering` = 链接顺序。

因此 `plan.graph` **分两套边**：

- `edges[]` —— 含 `relation: 'dep' | 'conflict'`。**dep 边不能画进顺序图**，
  否则画出来是**自相矛盾的图**（实测每个组合都有两处方向相反：
  `selfcrypt->integrity`、`syscall->antidebug`）。
- `order_edges[]` —— 拓扑序**真正遵循**的关系，面板的顺序图按它画。
  已按 `(from, to)` 去重（同一约束常被两侧各说一遍：
  `vm.before=[blob]` 与 `blob.ordering.after=[vm]`）。
- `topo_dep_violations[]` —— 如实列出「按 topo 排列时方向相反的 dep 边」。
  这是**语义差异的机读证据，不是错误**；`relations.why_not_mixed` 给出理由，
  否则面板会把它读成「工具算错了」。

**策略求解出 0 个模块是合法结果，不是参数错误。** `profiles/minimal-cost.json`
实测就是：威胁 `piracy` 推导所需能力 `respond`，而 13 个模块**没有一个**提供
`respond`（`license` / `revoke` / `hostid` / `blob` 都是 `verify`）。
此时返回**合法空图** + `notes` 说明原因；只有调用方**显式**给
`modules: []` 才是 `E_BAD_ARGS`。报成参数错误会让面板说「你传错了参数」，
而真相是「这个策略什么都不选」—— 后者才是用户需要看见的信息。

**`vm.disasm` 的两种 `source`**（这是理解 ST4 的关键，不是两个别名）：

- `source:"blob"` — 读**真实产物**（`build/vm.blob` 的某个镜像）。
  镜像里的字节码是**置换过**的，必须用该镜像的 `key1` 逆置换才能解出助记符；
  这条路径验证的是「调试器能打开**将要发布的东西**」。
- `source:"asm"` — 就地汇编一个 `.vasm`（规范 opcode，**不需要种子也不需要
  `vm_build.json`**）。这条路径**带源行号**（`line` 非 `null`），
  因为行号来自本次汇编本身。

⚠️ 两种路径的解码分支**必须一致**（同一个 `inv`/`sem0` 决策）。
若把规范字节当成构建产物去逆置换，会得到一串**看似合理**的垃圾
（错位但合法的助记符序列）—— 那比报错更坏，因为它不会失败。
此条由 `tools/vm_debug.py --selftest` 的「四个真实镜像反汇编与 `.vasm`
源码**逐条**一致」用例守住。

**`line` 的诚实语义**：没有行号表时如实返回 `null`，**不编造 `0`**。
`0` 是合法偏移，用它表示「不知道」会让面板把第一批指令全标在高亮第 0 行。

**`capabilities` 为什么值得是第一条命令**：面板启动时先问它，
就能**按现状渲染**（把 `planned` 的东西灰掉、把 `partial` 的边界标出来），
而不是画出几个点了报错的按钮。三态的含义是硬的：

- `ready` — 今天就能用，`backend` 指向**真实存在**的实现。
- `partial` — 能用但有**已知边界**，`note` 必须说明是什么边界。
- `planned` — **还没有**。标注它属于哪个阶段（`step`）。

**`gate.items` 的诚实边界**：它列的是 `tools/release_check.ps1` 里的
**静态 `Check` 调用点**（声明），**不是运行结果**。响应里带
`kind: "static-declaration"` 就是让消费方无法把它误读成「这一项通过了」。
运行结果由 **`test.gate.results`** 提供（ST2 已落地）。

**门禁的两个出口必须逐项一致**（ST2.1 的硬约束）：

- **文本**（人读，**格式不变**）：`[ok]` / `[X]` / `[skip] …… 前置不满足` / `[info] ……未运行`，以及结尾那句 `PASS: N 项检查全通过`。
  ⚠️ 这句话被 `tools/docclaim_check.py` 的 T7 不变量拿去与 `[ok]` 行数对账，**逐字不得改**。
- **NDJSON**（机读）：`build/logs/release_check_<ts>.ndjson`，每行一项，五态 `pass` / `fail` / `error` / `skip` / `not-run`。

`not-run` 与 `skip` **不是一回事**：`skip` = 前置不满足（判据本可执行但环境缺东西），`not-run` = 加了 `-With*` 开关才跑的项这一轮没启用（或 `-Only` 过滤掉了）。
两者都**不计入** `PASS: N`——否则"N 项全通过"会谎报。

`query=verify` 是**独立对账**：它读**实际日志行**逐项比对，不信任门禁自己的计数器（同轮门禁也自对照，两处独立）。
历史轮次（ST2.1 之前）只有 `.log` 没有 `.ndjson`，`verify` 对它们会**如实报"无 .ndjson"而不是判通过**。

### 5.3 `Debug` 构建配置：为什么必须产物隔离

`build.ps1 -Config` 有三个取值：`Dev`（缺省）/ `Release` / `Debug`（ST3.2 新增）。
`Debug` 加 `/Zi`（编译器 PDB，用 `/Fd` 钉进变体目录）与 `/DEBUG:FULL`（链接器 PDB）。

**三档必须从 Studio 全部可触达**。`build.run` 接受 `config`（见 §5.1 的 `plan`
事件），取值集合由 `studio_core.BUILD_CONFIGS` **单点定义**，面板的配置下拉框
（`#cfg`）必须与它一致。这条不是洁癖：起初 `build_argv()` 只认 `Dev`/`Release`
（ST1 时点的取值），ST3.2 加 `Debug` 后**后端仍拒收**，而面板连下拉框都没有 ——
于是 `Debug` 构建从 Studio 里**根本调不到，且不报任何错**（面板只是少一个选项）。
现在两处都由判据看住：`studio_server` 自检比对 `<select id="cfg">` 的选项与
`BUILD_CONFIGS`，e2e 再断言 `build_argv()` 接受全部三档。

**产物落 `build/debug/`，不是 `build/`。** 这不是洁癖，有两条实证理由：

1. 同名覆盖会**丢掉发布产物** —— 调试版 `demo.exe` 与发布版同名。
2. **`section_baseline.json` 只增不减**（`tools/merge_baseline.py` 的语义是
   「基线只允许变大」）。调试构建的节尺寸与发布不同，若共用一份基线，
   调试构建会**抬高**发布构建的基线 → 改变发布填充尺寸 → **破可复现性（I3）**。

隔离由 `tools/genpaths.py` 的**构建变体**承担（`--variant debug`，
或环境变量 `PROT_BUILD_VARIANT`）：`build_dir` 与它派生的一切（`b()`、
`out_rel()`）自动带上变体段。`variant` 为空时**所有路径与引入变体之前逐字符相同** ——
这是「发布构建字节逐字节不变」的前提。

⚠️ **隔离必须查「工具自己的默认值」，不能只看命令行里写了什么路径。**
实测：`tools/selfcrypt_proto.py` 的 `--mask-out` 有硬编码默认
`build/selfcrypt_mask.txt`，第一次改造时该文件被调试构建**悄悄覆盖**，
而本变体侧的文件根本不存在（于是 Hashpatch 少带掩码、且发布侧掩码被污染）。
修法是 `build.ps1` **显式传** `--mask-out`。

⚠️ **`/OPT:NOREF /OPT:NOICF` 与运行期完整性校验不兼容。** 初版给 `Debug` 加了这两个
开关，结果 `demo.exe` 一律报「完整性校验失败」（rc `2989` / `0xBAD`）。根因是
`src/integrity.c` 的段 CRC 缓冲是**栈上的 `uint8_t mask[0x40000]`**（256 KB），
而它把「缓冲区装不下」**与「被篡改」报成同一个错误**：

```c
if (len > sizeof(mask)) return PROT_ERR_INTEGRITY;   /* 实为容量不足 */
```

实测 `/Od` 无优化代码体积约为 `/O2` 的 3.3 倍，`.text` 达 458688 B > 262144 B ⇒
必然触发。此上限历史上已被撞到过一次（`docs/BLOB_SIGN_PLAN.md` 记 128 KB→256 KB 扩容）。
**因此 `Debug` 与 `Release` 采用同一套优化开关**（`/OPT:REF /OPT:ICF`），
只加调试信息：调试版 `demo.exe` 与发布版**同尺寸**、行为逐字一致。
代价是断点可能落在被 ICF 合并的等价函数上 —— 而 `PROT_NOISE` / `REPLICAS`
本就在刻意制造等价函数，这与保护机制的方向一致，不是缺陷。

## 6. 错误码

| `code` | 含义 | 谁的问题 |
|---|---|---|
| `E_UNKNOWN_CMD` | 命令不在清单内；`detail.available` 给出候选 | 调用方 |
| `E_BAD_ARGS` | 参数缺失/类型不对；`detail` 给出实际类型 | 调用方 |
| `E_NOT_FOUND` | 路径或对象不存在；`detail` 常带候选清单 | 调用方 |
| `E_PARSE` | 文件存在但不是合法 JSON | 仓库状态 |
| `E_BAD_LINE` | **请求行**不是合法 JSON 对象（协议层） | 调用方 |
| `E_STREAM_CMD` | 该命令**必须**用流式调用（多行响应），不能走 `dispatch`；`detail.stream_commands` 给出清单 | 调用方 |
| `E_CONFIRM_REQUIRED` | 参数都合法，**只缺 `confirm: true`**（活体操作：跑构建、附着进程）；`detail.how` 说明该做什么 | 调用方（缺授权） |
| `E_TIMEOUT` | 子进程超时；`detail` 带上限秒数 | 环境（不是被测对象的结论） |
| `E_INTERNAL` | 兜底。**出现它就说明有未预料的路径**，应当被修掉 | 后端缺陷 |

**`E_BAD_ARGS` 与 `E_INTERNAL` 必须分清**：若把「用户传了个数组」
错报成 `E_INTERNAL`，面板显示的就是「Studio 内部故障」而不是
「你的参数写错了」—— 这句话决定了用户接下来去看文档还是去看日志。
`studio_core.load_profile()` 因此做了**独立的类型守卫**（不是靠 `if not name`，
那会漏掉非空非字符串的值）。此条由 `--selftest` 的负向用例守住。

**`E_CONFIRM_REQUIRED` 不许降级成 `E_BAD_ARGS`。** 参数没有错，少的是**授权**。
报成「参数写错了」，面板会显示成「你传错了参数」，而正确动作是**弹一个确认框** ——
错误码必须指向正确的下一步动作（与 §5.1 里 `E_STREAM_CMD` 不许降级成
`E_UNKNOWN_CMD` 是同一条理由）。

**`E_TIMEOUT` 不许降级成「失败」。** 超时说的是**我们没等到结论**，
不是「结论是不通过」。报成失败会把一次环境抖动记成一次防御失效。

**`E_NOT_FOUND` 也不许静默回退**：读文件失败时**返回错误**，
不返回 `None`、不用默认值。否则面板会显示一个空列表，
与「文件真的空」**无法区分** —— 这正是本项目反复出现的
「失锚不静默」纪律（见 `docs/HANDOVER.md` §2.36 起诸节）。

## 7. 进程契约（`tools/studio_cli.py`）

**会话模式**（默认，供面板/编辑器长驻使用）

```
python tools/studio_cli.py           # 从 stdin 逐行读请求, 向 stdout 逐行写响应
```

**单发模式**（供脚本/CI，不用管道）

```
python tools/studio_cli.py --cmd ping
python tools/studio_cli.py --cmd plan.solve --args '{"profile":"balanced"}'
```

**退出码 —— 三态，与门禁一致**

| 码 | 含义 | 门禁侧应读成 |
|---|---|---|
| `0` | 成功（会话模式：正常 EOF 结束） | PASS |
| `1` | **命令失败**（有结果，但 `ok=false`） | FAIL |
| `2` | **用法/输入错误**（协议层用不了：`--args` 不是合法 JSON 等） | **SKIP** |

**为什么 2 必须与 1 分开**：门禁里 `2 = SKIP` 表示「这一项没跑」，
`未验证 != 通过`。若把用法错误也报成 `1`，一次参数写错就会显示成
「防御失效」；若反过来把命令失败报成 `2`，真的失败会被当成跳过 ——
两种混淆都会让面板给出**方向相反**的建议。

**stdout 只放协议**：人类可读的会话小结（`[studio_cli] 会话结束: 请求 N / 失败 M`）
走 **stderr**。这样 `stdout` 可以安全地被管道与 JSON 解析器消费。

## 8. 版本与兼容

`PROTOCOL_VERSION = 1`（`tools/studio_core.py`）。
`ping` 回传它，客户端应在握手时比对。

**兼容规则**

- 新增**命令** ⇒ 不需要升版本（旧客户端不调用它即可）。
- 新增**响应字段** ⇒ 不需要升版本（消费方必须忽略未知字段）。
- 删除/改名命令、改变已有字段语义、改变错误码含义 ⇒ **必须升版本**。

## 9. 未决与已知边界

1. **没有超时与心跳。** 会话模式靠 EOF/断开结束。等 ST5 需要长连接时再加。
2. **不支持跨行 JSON 请求。** 行就是消息边界；跨行会被判 `E_BAD_LINE`
   （这是刻意的，因为「一行一消息」正是 NDJSON 的全部价值）。
3. ~~`gate.items` 只有声明，没有结果~~ ⇒ ✅ **ST2 已补**：`test.gate.results` 提供运行结果（含历史与对账）。
4. **主机级调试（`debug.*`）已落地（ST3），但只到「附着式读写观测」。**
   命令名是 `debug.doctor` / `debug.sym` / `debug.mask` / `debug.exit`
   （只读）与 `debug.read` / `debug.patch`（活体，需 `confirm`），
   外加流式的 `debug.watch`。
   **原生断点与单步本阶段不做** —— 那是**服务端主动推送**的形态：
   `stopped` / `output` / `exited` 会在**没被问的时候**说话（`id` 为 `null`）。
   这需要把协议 v1 的「请求/响应严格配对」放宽为「响应可主动推送」，
   属于**向后兼容的扩展**（老客户端只需忽略 `id=null` 的行），故不升版本。
   ⚠️ 还有一条**被测对象反过来干扰观测者**的边界：`tools/prot_dbg.py`
   自己 `OpenProcess` 会触发目标的反调试扫描（实测退出码 `219`）。
   这不是防御失效，而是**观测行为本身留下的痕迹**；因此每条活体响应
   都带机读字段 `antidebug_interference`（`possible` / `exit_code_if_detected` /
   `cannot_be_used_as` / `how_to_judge`），面板必须据此提示，
   而不是把 `219` 当成一次防御胜利或一次防御失败。
   ✅ **VM 级（ST4）已落地**：`vm.images` / `vm.disasm` 是**请求/响应**形态，
   没有主动推送 —— 单步与断点在 `tools/vm_debug.py` 的 CLI/库层完成，
   尚未提升为协议命令。下一步是把 `vm.run` / `vm.break` 加进来，
   那时才真正需要上面那条推送扩展。
   ✅ **流式已先落地在 ST1**：`build.run`（§5.1）已经是一个请求产出多行响应，
   但它**不是**服务端主动推送 —— 每行仍是对**同一个请求**的响应，
   `id` 贯穿整条流。区别在于「谁先说话」：`build.run` 是调用方发一次、
   服务端连答多行；`debug.host.*` 则是服务端**在没被问的时候**说话
   （`id=null`）。后者仍待 ST3。
5. **本文档不写 `> **最后核实**` 元数据** ⇒ 它不在 `tools/doccheck.py`
   的扫描面内。理由：它是**协议的规范说明**，不是「读者当下照着做」的
   现值声明；进面会要求它跟着门禁项数等数字一起漂移，
   而协议版本自己已经承担了「这份契约是第几版」的表达。

## 11. Studio 外壳（`tools/studio_server.py`）

协议本身与传输无关（§2 只定义「一行 = 一条消息」）。ST5 交付的**参考实现**是
`tools/studio_server.py`：一个把 `studio_core.envelope()` / `stream_events()`
的结果写进 HTTP 响应的**薄层**。它**不含任何业务判据** —— 判据在 `studio_core`
与它下游的工具里。

| 决定 | 取值 | 理由 |
|------|------|------|
| 绑定地址 | **只绑 `127.0.0.1`**，**不提供 `--host` 参数** | 一个能被写成 `0.0.0.0` 的开关，迟早会被写成 `0.0.0.0` |
| 端口 | 缺省 **0**（内核分配） | 固定端口撞车表现为「服务起不来」，容易被误读成程序坏了 |
| 鉴权 | 一次性 `secrets.token_urlsafe(24)`；`/api/**` 要求 **`X-Studio-Token` 头** | 头不进 URL、不进日志 |
| 令牌交付 | 经 URL 的 **fragment**（`/index.html#t=...`） | fragment **不进 `Referer`**、不进服务端日志 |
| 页面与静态资源 | **不要求令牌** | 它们不含数据；要求令牌只会让 UI 无法启动 |
| `/api` 的方法 | 仅 **POST**；GET ⇒ **405** | 能被 GET 触发的副作用命令会被预取/历史恢复悄悄执行 |
| `/favicon.ico` | **204**（不是 404） | 404 会刷控制台错误，把真错误淹掉 |
| 令牌失败 | **401 `E_FORBIDDEN`**，`detail.query_token_accepted: false` | 明说「query 里的令牌**不**被接受」，省掉一轮排查 |
| 浏览器 | **不自动打开** | 本项目要求命令静默执行（硬约束） |
| 外部请求 | **零**（不引 CDN / 字体 / 前端库） | 离线可用；也避免把本地端口暴露给第三方 |

**流式的 HTTP 映射**：`POST /api/stream` ⇒ `Content-Type: application/x-ndjson`，
**不设 `Content-Length`**，结束由连接关闭界定；每个事件一行 `{"id":N,"ok":true,"event":{...}}`，
**收尾补发一行 `{"id":N,"ok":true,"end":true}`** —— 让客户端不必为「最后一行没有换行符」
写特例。

**静态资源的路径安全**：`safe_join()` 四步 —— 统一解码 → 统一分隔符 → `normpath`
→ `realpath` **前缀比对**。注释里写明它**不能**简化为 `'..' in rel`。

**自检的判别力**：`tools/studio_server.py --selftest` = **21 项（含 9 项负向）**。
其中 20 项跑在 `tempfile` 造的**合成 UI** 上；**第 21 项跑在真实 `studio/` 资产上**
（断言三个资产存在、**无外部 URL 引用**、且资产里确实出现 `X-Studio-Token` 与 `/api`）。
⚠️ 两者必须在**同一条命令**里跑完：若只测合成 UI，资产被删掉时门禁会**全绿** ——
那是「检查器只在自己造的输入上成立」的经典失效。门禁第 43 项正是这条命令。

**真浏览器判据**（门禁第 **45** 项 `Studio 真浏览器 (studio_ui)`，
`tools/studio_ui_check.py`）：上面的自检全是**静态**的（读文本 / 读协议 / 读 id 接线）。
静态判据看不见一类缺陷：**前端读的键，后端从来没发过**。

实测（§2.68）：`studio/static/app.js` 的 `loadCaps()` 原先写 `d.items.forEach(...)`，
而 `capabilities` 命令发的是 **`capabilities{}`**（§5 表格）—— 于是「关于」页
**从 ST5 起一直是空的**，唯一的表现是一个 **unhandled rejection**。

这条判据起一个真的 headless Edge，用 **CDP**（零依赖：纯 node 内置 `http`
+ 全局 `WebSocket`）把六个活动栏按钮逐个点一遍，断言外壳启动、视图切换、
每个视图渲染出了东西、以及 `window.__err` 为空。

⚠️ **三态**：本机没有 Edge ⇒ `rc=2`（**SKIP**，不是通过）。CI runner 上没有 Edge
⇒ 这一项在 CI 上恒为 SKIP；`PASS: N 项` 只数 `[ok]`。

**契约对账**（门禁第 **46** 项 `Studio 协议 (studio_proto)`，
`tools/studio_proto_check.py`）：**本文档是契约** —— 前端照着 §5 写。
在此之前，**契约与实现之间一条判据都没有**：如实测（§2.69.2），把
`plan.list` 从 §5 表格里整行删掉，`doccheck` / `studio_core` 自检 /
`studio_server` 自检 / `docclaim` **四个判据全是 rc=0**。

判据三条：

1. **命令集合双向一致** —— `studio_core.COMMANDS`（25 条）+ `STREAM_COMMANDS`
   （2 条）与 §5 表格（含 §5.1 标题里的两条流式命令）必须相等。
   代码有文档没有 ⇒ 文档漏项；文档有代码没有 ⇒ 文档陈旧。
2. **声明的 `x[]` / `x{}` 键必须真的存在于 `dispatch()` 的载荷**。
   这一条防的正是 `loadCaps`：文档声明了一个后端从来不发的键，
   而消费方会读到 `undefined`。
3. **失锚必须失败** —— 解析不出行 / 命令表为空 / 一条载荷都没对账上，
   都不算通过。

⚠️ 判据只认 `[]` / `{}` 这一种**无歧义**形态。`data` 列里另有**枚举值**与
**函数名**（`latest`、`E_BAD_ARGS`、`solve_profile.solve()` …），
按裸标识符对账会要求**篡改正确的文档**才能变绿。

**请求侧（`args` 列）对账**（同属第 46 项，2026-10-11 追加）：上面的三条
只查**响应键**；`args` 列的**参数名**当时没有任何判据在看。实测
（§2.70.2）：把第 111 行 `debug.sym` 的参数名改成 `symbolz[]`，
`studio_proto_check` / `studio_core` 自检 / `studio_server` 自检 /
`doccheck` / `docclaim` **五个判据全是 rc=0**。

两条臂互补，**缺一条就会漏掉一个方向**：

1. **词法臂** —— `args` 列声明的键名必须作为字符串字面量出现在
   `tools/studio_core.py` 里。抓「**文档写错名字**」。
2. **行为臂** —— 按**文档声明的键**造参数喂 `dispatch()`；若报错说
   「`<某键>` 为空」而那个键**正是我刚按文档给的**，说明代码读的是另一个
   名字。抓「**代码改了它读的键名**」。

为什么必须两条：把代码里的 `args.get('codes')` 改成 `args.get('codez')` 时，
`codes` 作为字面量在别处（自检里）仍然存在 ⇒ **词法臂不红**；反过来，代码把
键改名后**静默取缺省值**、报错不点名时，**行为臂也命中不了**。实测两个方向
各有一臂独占命中（§2.70.3）。

⚠️ **行为臂绝不给 `confirm`**：`debug.read` / `debug.patch` 的文档就声明了
`confirm`，而 `_need_confirm()` 只看真假值 —— 给一个真值等于让判据在门禁里
**真的去附着目标进程**。不给 ⇒ 那两条停在 `E_CONFIRM_REQUIRED`
（报错不点名键名 ⇒ 天然不会被误判成漂移）。

⚠️ **诚实边界**：只判**键名**，不判参数**类型**、不判「必填/可选」、
不判二选一关系（`bytes` \| `nop` \| `restore`）；行为臂只对**跑得动**的
命令生效（跑不动的落进 skip，**不判**不等于**判过**）。

**响应子键（花括号写法）对账**（同属第 46 项，2026-10-11 追加）：上面两条
查的是「顶层键在不在」与「参数名对不对」，这一条查花括号里写出的**子键**。

| 写法 | 语义 | 落点 |
|---|---|---|
| `` `items[]` `` | 顶层数组 | 直接查 |
| `` `capabilities{}` `` | 顶层对象 | 直接查 |
| `` `summary{a, b}` `` | 父键内联子键 | 在 `summary` **自身**上查 |
| `` `items[]` `{a, b}` `` | 数组元素键 | 在 `items` 的**每个元素**上查 |

**为什么单独一条**：判据原先只认「反引号紧跟 `[]`/`{}`」这一种形态，
于是上表后两种写法**结构上匹配不到** —— 实测把 `debug.doctor` 的 5 个
`summary` 子键、`modules.list` 的 20 个元素键全改成垃圾名字，
判据报错**都是 0 条**（§2.72.3）。子键本身当时**是对的**，所以这不是
「文档写错了」，而是「判据读不到它」；两者的区别在**下一次改动**上。

**可选子键**：带 `?` 的（`note?` / `off?` / `target?`）不在元素里**不算错**。
**空数组**（`items` 是 `[]`）无从核对，如实记进 `shape_skipped`，
**不静默当通过**。

⚠️ **诚实边界**：只判子键**在不在**，不判类型、不判嵌套深度
（`tokens[][2]` 只判 `tokens` 键存在）；元素形状不一致时**逐元素判**，
任一元素缺该键就报；花括号里写散文说明（`{见下文}`）时判据**沉默**
（收窄换来的 —— 宽化会产生 §2.70 记过的 9 条假阳性）。

## 10. 参考

- `docs/STUDIO_PLAN.md` — 阶段规划（ST0-ST6）与决策 D1-D8
- `tools/studio_core.py` — 纯逻辑层（可无头 import，无 I/O 副作用）
- `tools/studio_cli.py` — 进程边界（NDJSON over stdio）
- `tools/vm_debug.py` — VM 级调试器（ST4：反汇编 / 单步 / 断点 / 视图）
- `tools/studio_server.py` — Studio 外壳（HTTP/NDJSON 参考实现）
- `studio/index.html` / `studio/static/app.js` / `studio/static/style.css` — 零依赖前端
- `tools/prot_dbg.py` — 主机级调试后端（ST3：`doctor`/`sym`/`mask`/`exit`/`read`/`patch`/`watch`，**唯一实现**；`debug.*` 是它的结构化包装）
- `tools/vmenc.py` — `.vasm` 汇编器；`--map-out` 产出行号表 sidecar
- `tools/release_check.ps1` — `gate.items` 的数据来源（静态 `Check` 调用点）
- `tools/studio_proto_check.py` — 本文档与 `studio_core` 的**契约对账**（门禁第 46 项）
- `tools/compose.py` / `tools/compat.py` / `tools/solve_profile.py` —
  `plan.graph` 与 `plan.solve` 的数据来源（拓扑序、冲突检查、策略求解，**唯一实现**）
- `tools/gate_results.py` — `test.gate.results` 的数据来源（门禁 NDJSON 的解析与对账，**唯一实现**）
- `docs/DEBUG_CONSOLE_PLAN.md` — 既有调试控制台的边界与设计纪律
