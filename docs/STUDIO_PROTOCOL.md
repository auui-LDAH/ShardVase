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
`modules.*` / `gate.*`。新增命令**只能追加**，不得改变已有命令的语义。

| `cmd` | `args` | `data`（要点） |
|---|---|---|
| `ping` | — | `protocol_version` / `studio_version` / `repo` / `platform` |
| `capabilities` | — | `items[]`，每项 `{name, status, backend, evidence, note?, step?}`；`status ∈ ready/partial/planned` |
| `plan.list` | — | `profiles[]` `{name, description, threats, strength, performance_budget}` + `count` |
| `plan.solve` | `profile` | `solve_profile.solve()` 的完整结果（`selected`/`excluded`/`auto_added`/`reasons`/`conflicts`/`order`/…）**外加** `_profile_file` 与 `_text` |
| `modules.list` | — | `modules[]` `{name, maturity, caps, deps, conflicts_with, cost, header, source, known_limits, evidence, ordering, phases, consumes, produces, modifies_text, verifies_text, needs_writable_dir, page_align, host_hooks, abi_version}` + `primitives` + `maturity_scale`（分级**依据**，不是形容词） |
| `gate.items` | — | `items[]` `{name, line, gated}` + `total`/`gated`/`default`/`source` |
| `vm.images` | `blob?` | `images[]` `{name, code_len, key0, key1, crc, offset}` + `count`；`blob` 缺省 `build/vm.blob` |
| `vm.disasm` | `source`, `name`\|`asm`, `blob?` | `insns[]` `{off, mnem, operand, size, target?, line}` + `code_len`/`count`/`sem0`/`has_lines` |
| `plan.graph` | `profile`\|`modules` | `nodes[]` / `edges[]`（每条带 `relation`）/ **`order_edges[]`** / `topo` / `cycle` / `conflicts[]` / `relations` / `topo_dep_violations[]`；**`modules` 优先于 `profile`** |
| `test.gate.results` | `query?`, `run?`, `a?`, `b?`, `dir?` | `query` 取 `latest`（缺省）/`list`/`verify`/`diff`/`trend`；`latest` 返回逐项 `{seq, name, status, seconds, why}` + `counts_json`/`pass_n` |

### 5.1 流式命令（`build.run`）—— 协议至今唯一的例外

`build.run` **不在** `dispatch()` 的命令表里：一个请求产出**多行响应**。
它必须走 `stream_events()` / `respond_stream()`，而 `dispatch('build.run', …)`
会返回 **`E_STREAM_CMD`**。

**为什么错误码不沿用 `E_UNKNOWN_CMD`**：报「未知命令」并附 `available` 列表，
会让面板把「这个命令要用流式调用」读成「名字拼错了」，于是去翻候选清单
而不是改成流式调用 —— 错误码必须指向**正确的下一步动作**。

事件序列与两处刻意的默认值：

| 事件 | 字段 | 说明 |
|---|---|---|
| `plan` | `argv`, `confirm_required` | **总是先出计划**，让人看见将执行的命令行 |
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

## 6. 错误码

| `code` | 含义 | 谁的问题 |
|---|---|---|
| `E_UNKNOWN_CMD` | 命令不在清单内；`detail.available` 给出候选 | 调用方 |
| `E_BAD_ARGS` | 参数缺失/类型不对；`detail` 给出实际类型 | 调用方 |
| `E_NOT_FOUND` | 路径或对象不存在；`detail` 常带候选清单 | 调用方 |
| `E_PARSE` | 文件存在但不是合法 JSON | 仓库状态 |
| `E_BAD_LINE` | **请求行**不是合法 JSON 对象（协议层） | 调用方 |
| `E_STREAM_CMD` | 该命令**必须**用流式调用（多行响应），不能走 `dispatch`；`detail.stream_commands` 给出清单 | 调用方 |
| `E_INTERNAL` | 兜底。**出现它就说明有未预料的路径**，应当被修掉 | 后端缺陷 |

**`E_BAD_ARGS` 与 `E_INTERNAL` 必须分清**：若把「用户传了个数组」
错报成 `E_INTERNAL`，面板显示的就是「Studio 内部故障」而不是
「你的参数写错了」—— 这句话决定了用户接下来去看文档还是去看日志。
`studio_core.load_profile()` 因此做了**独立的类型守卫**（不是靠 `if not name`，
那会漏掉非空非字符串的值）。此条由 `--selftest` 的负向用例守住。

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
4. **主机级调试（`debug.host.*`）尚未进入协议。** ST3 会新增它（断点、单步、
   栈、内存），采用**同一套 NDJSON 信封**；调试天生的流式事件
   （`stopped` / `output` / `exited`）将作为**服务端主动推送**的响应行出现
   （`id` 为 `null`）—— 这需要协议 v1 的「请求/响应严格配对」规则放宽为
   「响应可主动推送」，属于**向后兼容的扩展**（老客户端只需忽略 `id=null`
   的行），故不升版本。
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

## 10. 参考

- `docs/STUDIO_PLAN.md` — 阶段规划（ST0-ST6）与决策 D1-D8
- `tools/studio_core.py` — 纯逻辑层（可无头 import，无 I/O 副作用）
- `tools/studio_cli.py` — 进程边界（NDJSON over stdio）
- `tools/vm_debug.py` — VM 级调试器（ST4：反汇编 / 单步 / 断点 / 视图）
- `tools/vmenc.py` — `.vasm` 汇编器；`--map-out` 产出行号表 sidecar
- `tools/release_check.ps1` — `gate.items` 的数据来源（静态 `Check` 调用点）
- `tools/compose.py` / `tools/compat.py` / `tools/solve_profile.py` —
  `plan.graph` 与 `plan.solve` 的数据来源（拓扑序、冲突检查、策略求解，**唯一实现**）
- `tools/gate_results.py` — `test.gate.results` 的数据来源（门禁 NDJSON 的解析与对账，**唯一实现**）
- `docs/DEBUG_CONSOLE_PLAN.md` — 既有调试控制台的边界与设计纪律
