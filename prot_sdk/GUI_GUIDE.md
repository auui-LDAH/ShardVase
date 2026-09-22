# GUI 骨架接入指南

> **目标**：在 Windows **窗口程序**（无控制台）中接入 ShardVase 保护。
> **状态**：✅ 已验证可用（2026-09-21 端到端实测）。
> **关联**：`QUICKSTART.md`（首次接入）、`TUTORIAL.md`（计时与流程）、
> `docs/WINDOWS_COVERAGE.md`（各应用形态覆盖情况）。

---

## 1. 为什么需要单独的 GUI 指南

保护壳（`app_main.c`）用的是标准 `main()`，而 Windows GUI 程序的常规入口是
`WinMain`。这两者**不是**换个函数名那么简单：

```
若只把 /SUBSYSTEM:CONSOLE 改成 WINDOWS 而不指定入口:
    LIBCMT.lib(exe_winmain.obj) : error LNK2019:
    无法解析的外部符号 WinMain    <- 实测
```

**本 SDK 的解法**（实测验证）：

```
/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup
```

即：**告诉链接器用 `main` 作为 CRT 启动入口**，同时产出 GUI 子系统程序。

### 这样做的关键好处：**保护壳零改动**

| 做法 | 后果 |
|------|------|
| ❌ 另写一份 `app_main_gui.c` | 990 行的保护链要维护**两份**，必然漂移 |
| ✅ 复用同一份壳 + 改链接参数 | 保护逻辑**单一来源**，GUI/CONSOLE 共享 |

这正是本次设计的选择：**壳与业务形态彻底解耦**。

---

## 2. 快速开始

### 2.1 构建 GUI 程序

```powershell
# 用 -Gui 开关（其余参数与普通构建相同）
powershell -File build_skeleton.ps1 -Project <你的工程目录> -Gui
```

向导生成的工程同样适用（在向导中选择 GUI 形态，或手工加 `-Gui`）。

### 2.2 替换业务层

`-Gui` 模式下，业务层用 `business_stub_gui.c`（本目录已提供）替换
`business_stub.c`。它已给出**可运行的最小窗口**：

```
business_stub_gui.c
  ├─ business_calc()          纯函数示例（可迁移进 VM）
  ├─ gui_wndproc()            窗口过程（WM_CREATE/WM_COMMAND/WM_DESTROY）
  ├─ gui_create_main_window() 建窗（RegisterClassExW + CreateWindowExW）
  └─ prot_business_main()     业务入口：建窗 + ShowWindow + 消息循环
```

**你要改的地方**：`gui_create_main_window` 的窗口尺寸/样式，以及
`gui_wndproc` 里的消息处理。其余（授权上下文、退出码）保持契约不变。

---

## 3. ✅ 序列号获取：四条路径（限制已解决）

> **2026-09-21 更新**：本节原为"重要限制：序列号仍从 stdin 读取"。
> 该限制**已修复** —— 现在按以下优先级获取序列号。

### 3.1 获取顺序（优先级从高到低）

| # | 来源 | 用途 | 触发条件 |
|---|------|------|----------|
| **1** | 环境变量 `PROT_SERIAL` | CI / 构建期 smoke | 设置了该变量 |
| **2** | **exe 同目录 `serial.txt`** | **产品部署：双击即用** | 文件存在且首行非空 |
| **3** | **弹窗收集** | 用户首次运行、无授权文件 | **无控制台窗口**（真双击）|
| **4** | 回退 stdin | 命令行 / 自动化 | 有控制台窗口 |

**设计意图**：商业软件通常在授权文件里**已含序列号**，弹窗只是"没带授权
文件时"的补救路径。故把显式来源放在前面，弹窗作为最后手段。

### 3.2 实测验证结果（四条路径全部通过）

| 路径 | 实测 |
|------|------|
| 1 环境变量 | ✓ smoke PASS（构建输出含 `license: 1`）|
| 2 `serial.txt` | ✓ `序列号来自 serial.txt` → `license: 1` |
| 3 无控制台 → 弹窗 | ✓ 进程阻塞等待输入（说明窗口确实弹出）|
| 4 有控制台 → stdin | ✓ 控制台形态构建 smoke PASS |

### 3.3 产品部署怎么做（推荐）

```
把你的应用目录布置成:
    yourapp.exe
    vm.blob
    <你的授权文件>        # 含序列号/签名, 由签发方生成
    serial.txt            # ★ 内容 = 序列号 (一行, 无多余字符)
```

这样**双击即用**，用户无需输入。

> **注意**：`serial.txt` 是**序列号明文**。若你的威胁模型要求序列号不能
> 落地为明文，请改用授权文件路径（把序列号写进签名载荷），或让业务层
> 自行实现 `prot_shell_serial_provider()` 从加密配置读取。

### 3.4 想改行为？

在 `business_stub_gui.c` 里改 `prot_shell_serial_provider()` 的顺序即可 ——
它是一个普通函数，契约见 `prot_shell.h`：

```c
/* 返回 0 = 已写入序列号; 非 0 = 未取得(壳回退 stdin) */
int prot_shell_serial_provider(char* buf, unsigned cap);
```

### 3.5 向后兼容（重要）

**控制台工程完全不受影响**。壳用 MSVC 的 `/alternatename` 弱符号解析：

```
业务层未定义 provider -> 链接到壳内默认实现 -> 返回非 0 -> 回退 stdin
业务层已定义 provider -> 用业务实现（本 GUI 骨架即是）
```

已实测双向验证：控制台工程（未定义）与 GUI 工程（已定义）**均构建通过、
授权门 PASS**。这就是选择弱符号而非编译期开关的原因。

## 4. 构建产物验证

```powershell
# 1. 子系统应为 WINDOWS(2)，不是 CONSOLE(3)
python -c "import struct;d=open('out\app.exe','rb').read();e=struct.unpack_from('<I',d,0x3C)[0];print(struct.unpack_from('<H',d,e+24+68)[0])"

# 2. 构建脚本的 smoke 会检查授权门（判据 = 输出含 'license: 1'）
```

**实测结果**（本指南验证时）：

| 项 | 值 |
|----|----|
| 构建 | rc=0 |
| 产物大小 | 247256 字节 |
| 子系统 | **WINDOWS(GUI)** ✓ |
| 授权门 | PASS（smoke 输出含 `license: 1`）|
| 业务执行 | ✓（输出 `business: gui mode ...`）|

---

## 5. 常见问题

### Q1: GUI 程序没有控制台，保护壳的 `printf` 会怎样？

**不影响。** 实测：GUI 子系统程序在 **stdout 被重定向时 `printf` 正常**
（subprocess 捕获与文件重定向均验证通过）。故：

- 构建期 smoke 判据（`license: 1`）**无需为 GUI 特殊处理**
- 排障时可用 `app.exe > log.txt 2>&1` 拿到完整诊断输出
- 双击运行则看不到输出（这是预期的 —— GUI 程序本就没有控制台）

### Q2: 想要"有控制台便于排障"的构建？

用普通（`CONSOLE`）构建即可 —— 除子系统外**保护链完全相同**。

### Q3: 需要哪些链接库？

`-Gui` 模式额外链接 `user32.lib`（窗口 API）与 `comctl32.lib`（常用控件）。
其余（`bcrypt`/`winhttp`/`advapi32`）与普通构建一致。

### Q4: 能用 C++ 写 GUI 业务层吗？

可以。头文件已内建 `extern "C"` 保护（2026-09-21 起），C++ 项目可直接
`#include`。但**深层兼容**（C++ 异常/RAII 与保护链共存、大型 C++ 工程的
`.text` 布局对 selfcrypt 页冲突的影响）**尚未验证** —— 见
`docs/WINDOWS_COVERAGE.md` §5。

---

## 6. 与其它文档的关系

| 文档 | 内容 |
|------|------|
| `QUICKSTART.md` | 首次接入（控制台）|
| `TUTORIAL.md` | 完整接入计时与流程 |
| **本文件** | **GUI（窗口程序）特有事项** |
| `docs/WINDOWS_COVERAGE.md` | 各应用形态（GUI/DLL/C++/服务）覆盖率实测 |
| `docs/CONTRACT.md` | 保护链的实现契约 |

---

*2026-09-21 · 基于端到端实测（构建 rc=0 / 子系统 WINDOWS / 授权门 PASS）*
