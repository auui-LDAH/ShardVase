# Studio 协议 v1 — NDJSON over stdio

> 版本：2026-10-09 v1 · 状态：**ST0 已实施**（`tools/studio_core.py` + `tools/studio_cli.py`）
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
| `modules.list` | — | `modules[]` `{name, maturity, caps, deps, conflicts_with, cost, header, source}` + `primitives` |
| `gate.items` | — | `items[]` `{name, line, gated}` + `total`/`gated`/`default`/`source` |

**`capabilities` 为什么值得是第一条命令**：面板启动时先问它，
就能**按现状渲染**（把 `planned` 的东西灰掉、把 `partial` 的边界标出来），
而不是画出几个点了报错的按钮。三态的含义是硬的：

- `ready` — 今天就能用，`backend` 指向**真实存在**的实现。
- `partial` — 能用但有**已知边界**，`note` 必须说明是什么边界。
- `planned` — **还没有**。标注它属于哪个阶段（`step`）。

**`gate.items` 的诚实边界**：它列的是 `tools/release_check.ps1` 里的
**静态 `Check` 调用点**（声明），**不是运行结果**。响应里带
`kind: "static-declaration"` 就是让消费方无法把它误读成「这一项通过了」。
运行结果属于 ST2（`test.gate.results`，当前 `planned`）。

## 6. 错误码

| `code` | 含义 | 谁的问题 |
|---|---|---|
| `E_UNKNOWN_CMD` | 命令不在清单内；`detail.available` 给出候选 | 调用方 |
| `E_BAD_ARGS` | 参数缺失/类型不对；`detail` 给出实际类型 | 调用方 |
| `E_NOT_FOUND` | 路径或对象不存在；`detail` 常带候选清单 | 调用方 |
| `E_PARSE` | 文件存在但不是合法 JSON | 仓库状态 |
| `E_BAD_LINE` | **请求行**不是合法 JSON 对象（协议层） | 调用方 |
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
3. **`gate.items` 只有声明，没有结果**（ST2 补）。
4. **`debug.*` 尚未进入协议。** ST3/ST4 会新增 `debug.host.*` / `debug.vm.*`
   命令（断点、单步、栈、内存），采用**同一套 NDJSON 信封**；
   调试天生的流式事件（`stopped` / `output` / `exited`）将作为
   **服务端主动推送**的响应行出现（`id` 为 `null`）—— 这需要协议 v1 的
   「请求/响应严格配对」规则放宽为「响应可主动推送」，属于**向后兼容的扩展**
   （老客户端只需忽略 `id=null` 的行），故不升版本。
5. **本文档不写 `> **最后核实**` 元数据** ⇒ 它不在 `tools/doccheck.py`
   的扫描面内。理由：它是**协议的规范说明**，不是「读者当下照着做」的
   现值声明；进面会要求它跟着门禁项数等数字一起漂移，
   而协议版本自己已经承担了「这份契约是第几版」的表达。

## 10. 参考

- `docs/STUDIO_PLAN.md` — 阶段规划（ST0-ST6）与决策 D1-D8
- `tools/studio_core.py` — 纯逻辑层（可无头 import，无 I/O 副作用）
- `tools/studio_cli.py` — 进程边界（NDJSON over stdio）
- `tools/release_check.ps1` — `gate.items` 的数据来源（静态 `Check` 调用点）
- `docs/DEBUG_CONSOLE_PLAN.md` — 既有调试控制台的边界与设计纪律
