# c2vasm — C 子集 → vasm 自动翻译器（A2 原型）

> 状态：**原型完成（2026-08-28）** · golden 6/6 全 PASS · 计划 `docs/A2_PLAN.md`

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

## A2 二阶段（接入 prot_sdk，设计）

把本工具接入骨架工程：
1. `business_*.c` 中标注 `// @vmcalc` 的纯函数 → 构建前自动翻译 +
   生成对应 vasm 镜像 + 宿主函数替换为"VM 装载→执行→取回"桩；
2. blob 打包纳入现有 pack（与授权镜像同链签名）；
3. 桩与 VM 结果的"结果一致性"由 golden 机制全量保障；
4. 签名/篡改语义完全复用现有 VOID 链（无需新防御面）。

## 目录

- `tools/c2vasm.py` — lexer/parser/代码生成/mini-vm（无三方依赖）
- `tests/c2vasm_golden.py` — golden 验证（宿主参考 + mini-vm + 篡改演示）
- `tests/c2vasm_cases/*.c` — 6 个样例（合法 C，双重用途）