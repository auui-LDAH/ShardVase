# WinPE-SymPatcher — PE 符号解析 + 内存补丁工具

> 攻防演练用（仅自有产物）。目标：运行时定位受保护程序的关键函数/变量并改写，
> 验证"盾"的失效路径。实证记录见 `docs/ATTACK_DRILL7.md`。

## 组成

| 文件 | 说明 |
|------|------|
| `symparse.h/.c` | 符号解析：MAP 文件 + PE 导出表(.edata) + COFF 符号表三通道 |
| `mempatch.h/.c` | 附加进程（OpenProcess）+ 内存读写（WriteProcessMemory）+ ASLR 换算 |
| `main.c` | 命令行入口 |
| `test_target.c` | 带符号测试目标（模拟"盾"：反调试判定 + 可补丁布尔） |
| `build.ps1` | 一键构建（自动探测 VS/vcvars，自动短路径） |

## 构建

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
# 输出: winpe_sympatcher.exe
```

## 用法

```powershell
# 1) 离线解析符号 (MAP / PE 导出表)
winpe_sympatcher.exe --map <file.map> --sym prot_antidebug_detected
winpe_sympatcher.exe --file <pe> --sym MessageBoxW     # 导出表

# 2) 附加进程写内存 (含 ASLR 换算: 编译时 VA + --pref 首选基址)
winpe_sympatcher.exe --pid <pid> --mod <mod.exe> --pref 0x140000000 \
    --addr 0x1400073f0 --byte 31 --byte C0 --byte C3

# 3) 列出 COFF 符号
winpe_sympatcher.exe --list <pe>
```

## 测试目标重建（可选）

```powershell
# 生成带 MAP 的测试目标 (需 VS x64 环境)
cl /nologo /O2 /std:c11 /utf-8 /Z7 test_target.c /link /SUBSYSTEM:CONSOLE ^
   /MAP:test_target.map /OUT:test_target.exe
```

## 已知边界

| 边界 | 说明 |
|------|------|
| RELEASE 构建无 COFF 符号 | `/DEBUG:NONE /OPT:REF,ICF` 剥离符号；需 MAP/PDB 才能定位（真实破解者同样受限） |
| 函数头 patch 可被完整性检测捕获 | 本项目 demo 的 CRC/watchdog 会拦 `.text` patch（DRILL3 已证） |
| ASLR | 编译时 VA ≠ 运行时地址；用 `--pref` 传入首选基址自动换算 |

## 实证结论（ATTACK_DRILL7）

- 符号解析（MAP）定位 ✅；写判定布尔无效（周期重算覆盖）；
- **patch 判定函数头（`xor eax,eax; ret`）→ "盾"永久失效**。
