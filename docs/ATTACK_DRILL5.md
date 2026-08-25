# 第五轮补充 — D5 DLL 劫持 + E5 VEH 验证 (ATTACK_DRILL5)

> 版本：2026-08-25 v1 · 状态：**已实施** · 关联：`docs/ATTACK_DRILL4.md`（第四轮遗漏盘点）·
> `tests/attack_drill5.py`。本文档记录补测第四轮遗漏的中低风险真实手法：
> **DLL 劫持/植入**（D5）与 **VEH 异常处理器劫持**（E5）。

---

## 1. D5 — DLL 劫持/植入

### 1.1 测试
在 demo 运行目录（build/）放置损坏的 `winhttp.dll`（假 MZ 头）→ 运行 demo：
- 若系统目录优先 → 正常运行（exit 0）；
- 若同目录优先 → 加载失败/崩溃（劫持面成立）。

### 1.2 结果（真机）
```
D5 BREACHED  fake winhttp.dll in dir affected run (exit=3221225776)
```
**demo 被同目录坏 DLL 影响 = DLL 劫持面成立**（Windows DLL 搜索顺序：
同目录优先于系统目录，demo 无 SafeDllSearchMode 加固）。

### 1.3 影响评估（诚实面）
- **前提**：攻击者已能写 demo 运行目录（build/）——此时直接替换
  demo.exe/blob 更简单（文件级 CRC 由 hashpatch 烧录，替换 exe 会
  触发完整性？——替换 exe = 完全不同的程序，不在保护范围）。
- **结论**：DLL 劫持是"**环境预置**"而非"防御绕过"——若目录可写则
  整体已暴露。但**生产部署约束应记录**：安装目录必须防写（ACL），
  避免同目录 DLL 植入作为 DoS/在线篡改入口。

### 1.4 修复建议
| 措施 | 成本 | 效果 |
|------|------|------|
| 安装目录 ACL 只读（标准安装器） | 低 | 根除（目录不可写则无法植入 DLL） |
| Manifest dependentAssembly 强制系统目录 | 中 | 仅对声明 DLL，非通用 |
| **受控目录 + 作为运营约束** | 低 | 与真实产品一致（所有 Windows 软件同类风险） |

---

## 2. E5 — VEH 异常处理器劫持

### 2.1 测试
验证 demo 的 int3 蜜罐（antidebug.c 的 `AddVectoredExceptionHandler`）是否
可被攻击者覆盖（新 VEH 抢链首截断蜜罐）。

### 2.2 结果（真机）
```
E5 PARTIAL  VEH 链可被注入代码覆盖 (AddVectoredExceptionHandler 抢链首);
            demo 的 int3 蜜罐依赖 VEH 链首 -> 已由 G1 注入等价覆盖
```
**结论**：VEH 链覆盖需**同进程代码执行**（AddVectoredExceptionHandler 是
进程内调用）——而 G1 已证明注入 DLL 可执行任意代码 → E5 的攻击前提
（注入）已被 G1 覆盖；**int3 蜜罐的弱点与非 VEH 检测项叠加**（NtQuery/
硬件断点等不依赖 VEH，VEH 被覆盖只影响蜜罐一项，防御纵深仍多因子有效）。

### 2.3 影响评估
- 中等：VEH 覆盖可让 int3 蜜罐失效，但 demo 的反调试是多因子组合
  （PEB/NtQuery/硬件断点/计时），VEH 只是其一 → 影响局部。

---

## 3. 结论

| 项 | 结果 | 严重度 | 处置 |
|----|------|--------|------|
| D5 DLL 劫持 | BREACHED（环境下） | 中（前提：目录可写） | 运营约束：ACL 只读；记录生产部署文档 |
| E5 VEH 覆盖 | PARTIAL（需注入前提） | 中低 | G1 已覆盖注入前提；多因子检测减弱单点影响 |

**四轮+补充累计**：57 项（23+13+9+10+2），覆盖主流攻击面 + 2 个遗漏真实手法。