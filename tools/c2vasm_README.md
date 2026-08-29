# c2vasm — C 子集 → vasm 自动翻译器（A2 原型）

> 状态：**原型完成（2026-08-28）** · golden 6/6 全 PASS · **A2 二阶段接入
> prot_sdk 完成（同日真机验收）** · 计划 `docs/A2_PLAN.md`

业务函数体自动 VM 化的第一步：把 **C 子集单函数**翻译成 vasm（VM 汇编），
经现有工具链（vmenc assemble）编造成加密 VM 镜像。从此不需要手写 vasm。

## 用法

```bash
# 翻译
python tools/c2vasm.py tests/c2vasm_cases/fnv1a64.c --out build/fnv.vasm
# 汇编（现有链条）
python tools/vmenc.py assemble build/fnv.vasm demo/vm_build.json \
    out.c out.h --name g_fn_image --bin-out fn.bin --bin-name fn
```

## 支持子集（语法参考样例 tests/c2vasm_cases/*.c）

| 类别 | 支持 | 不含 |
|------|------|------|
| 类型 | `uint64_t` / `uint32_t`（均按 64 位语义）| 浮点/指针/结构体/数组 |
| 字面量 | 十进制 / 0x 十六进制，`ull/ul` 后缀 | 字符串/字符 |
| 运算 | `+ - * / % & \| ^ << >>`，比较 `< <= > >= == !=` | 三元 `?:` |
| 赋值 | `=`、复合 `op=`（含算术/位/移位）、`x++/x--` | 位段/链式赋值 |
| 控制流 | `if/else`、`while`、`for`（init/cond/incr 三形态）| goto/switch/break/continue |
| 函数 | 单个无调用无 IO 整数函数 | 调用/递归/指针/外部引用 |

调用方（宿主）负责：参数写偏移 0..、读返回槽（默认 0x1000）。

## 验证（golden，可复跑）

```bash
python tests/c2vasm_golden.py
```

- 6 个样例（FNV-1a / 累加 / 位混合 / 多项式 / 条件聚合 / 除法取模），
  每组输入：宿主参考结果 vs VM 执行结果**逐一相等**；
- 篡改演示：对生成 vasm 的某个立即数异或随机值 → 输出改变
  （5/6 样例命中；证明计算真实发生在 VM 内，不是宿主演戏）；
- 样例同时用 cl /c 编译做**语法 sanity**（样例必须是合法 C）。

## 已知限制（诚实）

1. `for` 头部 `init` 目前只支持 "字节" 形式（`i = 0;` 或 `uint64_t i=0;`），
   不支持逗号多表达式；
2. 整数运算一律 64 位语义（uint32 不截断到 32 位）——写函数时注意；
3. 比较结果按 C 语义 0/1；`==` 对常量短路未做优化；
4. 循环需要宿主保证 mem 尺寸与步数上限（mini-vm 20M 步）；
5. 无符号仅——有符号除法/右移不保证语义一致。

## A2 二阶段（prot_sdk 集成，已完成）

业务源中标注 `// @vmcalc` 的纯计算函数会被自动 VM 化：

```c
// @vmcalc
uint64_t biz_seed(uint64_t a, uint64_t b) { ... }
```

构建时 `tools/vmcalc_build.py` 自动完成：
1. 扫描标注 → c2vasm 翻译 → vmenc assemble（bin 名 `b_<fn>`）；
2. 源中定义改名 `<fn>_native`（调用点不变 → 链接到桩）；
3. 生成 `gen/vmcalc_stubs.c`（blob 装载器 + 同名 VM 桩）与
   `gen/vmcalc_interface.h`（业务源自动注入 include）；
4. 业务镜像并入同一 `vm.blob`（与授权镜像同链签名）；
5. 壳在授权门通过后 `prot_vmcalc_load`，缺失业务镜像 → 拒绝进入业务。

真机验收（hashcalc）：
- `业务VM演示种子` 输出 = 参考值（`0x249b8c28655d869c`）逐位一致；
- 负面：移除业务镜像的 blob → 拒绝进入业务（保护链完整性兜底）；
- 排障记录：桩参数 memcpy 未按槽偏移（`frame+8*i` 修复）、源 `_native`
  残留与 gen 清空的**不一致状态自动修复**（unrename+重建）。

## 目录

- `tools/c2vasm.py` — lexer/parser/代码生成/mini-vm（无三方依赖）
- `tests/c2vasm_golden.py` — golden 验证（宿主参考 + mini-vm + 篡改演示）
- `tests/c2vasm_cases/*.c` — 6 个样例（合法 C，双重用途）