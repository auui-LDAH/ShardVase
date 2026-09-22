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

## 3. ⚠️ 重要限制：序列号仍从 stdin 读取

**这是当前实现的真实限制，务必了解。**

保护壳在授权判定前会：

```c
printf("请输入序列号:");                 /* app_main.c 附近 */
fgets(mem.serial, sizeof(mem.serial), stdin);
```

也就是说**序列号来自标准输入**。而 GUI 程序双击运行时**没有 stdin**：

**实测结果**（GUI 产物 + `--license-file` + 无 stdin）：

```
rc=1
| 请输入序列号:license: 0 (tier=1 expires=0)
| 序列号无效。
```

→ **授权失败**。序列号为空字符串，验签不通过。

### 3.1 当前可行的绕法

| 场景 | 做法 |
|------|------|
| 开发/测试 | 从**命令行**启动（此时有 stdin）：<br>`gui_demo.exe --license-file license.txt --vm-blob vm.blob` 并从控制台输序列号 |
| 自动化/CI | 重定向 stdin：`echo <serial> \| gui_demo.exe --license-file ...` |
| **产品交付（双击运行）** | ⚠️ **当前不可行** —— 需按下节改造 |

### 3.2 建议的改造方向（供你按需实施）

GUI 产品的常规做法是**用对话框收集序列号**，而不是 stdin。改造点在业务层，
**不需要动保护壳**：

```c
/* 在 business_stub_gui.c 中: 建窗前先弹出输入对话框 */
static int gui_ask_serial(char* out, size_t cap)
{
    /* 用 DialogBox / 自绘窗口收集序列号;
     * 然后写到你自己的授权文件, 或在启动时传给 --license-file */
    return 0;
}
```

或者更彻底：把序列号**编译进授权文件**（签发时已绑定机器），
运行时只读文件、不再询问 —— 这需要改壳里的 stdin 分支
（`app_main.c` 的 `fgets` 段），属**受支持的定制点**，但请知悉：
壳的改动会偏离"零改动"约定，升级 SDK 时需重新合并。

> **诚实说明**：本 SDK **尚未**提供"无 stdin 的 GUI 授权流程"开箱方案。
> 上表是绕过方式与改造方向，不是已实现的功能。

---

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
