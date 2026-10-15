#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
#
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
# 商业授权见 LICENSE.md。
#
# =============================================================================
# build.sh — ShardVase 的 **Linux 构建脚本**（B4，2026-09-25）
#
# ## 为什么需要（而不是复用 build.ps1）
#   `build.ps1`（812 行）深度依赖 **MSVC**（cl.exe / vcvars64 / .lib / signtool）
#   —— PowerShell + Windows 工具链在 Linux 上不可用。
#
#   但**绝大多数构建步骤是 Python 工具**（12 个）——
#   它们**本身是纯逻辑的**，Linux 上可直接跑。
#
#   => 本脚本的结构: **保留 Python 工具步骤 + 把 MSVC 部分换成 gcc**。
#
# ## 与 build.ps1 的**对应关系**（逐步对照）
#   | build.ps1 步骤 | 本脚本 | 差异 |
#   |---------------|--------|------|
#   | 1. vm_build.json 默认值 | ✅ 保留 | — |
#   | 2. vmenc.py genserial | ✅ 保留 | — |
#   | 2.2 expect_default.c | ✅ 保留 | 用 jq/python 替代 ConvertFrom-Json |
#   | 2.5 RSA 密钥导出 | ✅ 保留 | — |
#   | 3. 汇编 + 加密 VM 镜像 | ✅ 保留 | — |
#   | 4. 字符串加密（strgen）| ✅ 保留 | — |
#   | 5. **编译 + 链接** | ⚠️ **改用 gcc** | **MSVC -> gcc** |
#   | 6. selfcrypt 原位加密 | ⚠️ **ELF 支持待补**（B2/B3）| PE -> ELF |
#   | 6.1 hashpatch CRC 烧录 | ⚠️ **ELF 支持待补**（B2）| PE -> ELF |
#   | 6.2 数字签名 | ❌ **跳过** | Windows 用 signtool 自签证书；Linux 无对应 |
#   | 6.5 清理 .obj | ✅ 保留（gcc 的 .o）| — |
#   | 7. VM 单测 | ✅ 保留 | — |
#   | 7.2 冒烟自检 | ✅ 保留 | — |
#
# ## 诚实边界（**必读**）
#   · **本脚本产出的是"可运行的 ELF"**，**不是**与 Windows 等强度的加固产物
#     —— ELF 侧的完整性烧录（B2）与节名随机化（B3）**尚未接线**
#   · **数字签名不适用**（Linux 无 signtool 等价物；ELF 签名机制不同）
#   · 依赖: gcc / python3 / libcrypto（OpenSSL）
# =============================================================================

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

# ---- 参数 ----
COMPOSITION="${COMPOSITION:-full}"
PY="${PY:-python3}"
CONFIG="${CONFIG:-Release}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

# ---- 输出 ----
say()  { printf '\033[36m[build]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

say "ShardVase Linux 构建 (composition=$COMPOSITION, config=$CONFIG)"
mkdir -p build

# 与 Windows 侧一致的编译选项（**语义对应**）
#
# | MSVC | gcc | 说明 |
# |------|-----|------|
# | /W4 /WX | -Wall -Wextra -Werror | 警告即错误 |
# | /std:c11 | -std=c11 | C 标准 |
# | /O2 | -O2 | 优化 |
# | /utf-8 | -finput-charset=UTF-8 | 源文件编码 |
# | /DPROT_USE_GENERATED_SECTIONS=1 | 同 | 用随机节名 |
# =============================================================================
# 生成物路径（A-b，2026-09-25）—— **单一来源**: tools/genpaths.py
#
# ## 为什么用变量而非把 `demo/gen` 直接换成 `demo/gen/linux`
#   直接替换是**一次性**的: 将来再改布局还得再改 33 处。
#   用变量 -> **路径只在一处决定**，且布局切换零改动。
#
# ## 布局回退（迁移期安全网）
#   `PROT_GEN_LAYOUT=flat` -> genpaths 返回旧的 `demo/gen`
#   -> 本脚本**无需改动即可回退**。
# =============================================================================
GEN="$("$PY" tools/genpaths.py --platform linux --print-gen 2>/dev/null)"
# ## 平台专属 build 目录（A-d，2026-09-25）
#   实测: `build/vm.blob` / `build/license.txt` / `build/selfcrypt_mask.txt`
#   被**两平台都写** -> 跑完 Linux 后 Windows 的 e2e 读到 Linux 产物 -> 失败。
#   => 这些**状态文件**也按平台分（Linux: `build/linux/`）。
BDIR="$("$PY" tools/genpaths.py --platform linux --print-build-dir 2>/dev/null)"
VM_JSON="$("$PY" tools/genpaths.py --platform linux --print-vm-json 2>/dev/null)"
if [ -z "$GEN" ] || [ -z "$VM_JSON" ]; then
  echo "build: FAIL 无法取得生成物路径（tools/genpaths.py 异常）" >&2
  exit 1
fi
mkdir -p "$GEN" "$BDIR" "$(dirname "$VM_JSON")"
# heredoc（<<'PYEOF'，quoted）内无法展开 shell 变量 -> 用环境变量传递
export VM_JSON_PATH="$VM_JSON"
export GEN_PATH="$GEN"

# ## ⚠️ CFLAGS 用**数组**（A-b 实测修正）
#   本仓库路径含空格（`Reverse Engineering`）——
#   字符串拼接的 `CFLAGS="$CFLAGS -I $GEN"` 在展开时会被**词分割**
#   -> `-I /mnt/d/specifically` + `for` + `development` ... 全被当独立参数。
#   **数组**让每个参数独立元素，展开时天然保形（`"${CFLAGS[@]}"`）。
#   （与本脚本既有的 `PLATFORM_SRCS=()` / `GEN_SRCS=()` 风格一致。）
CFLAGS=(-c -O2 -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE)
CFLAGS+=(-I include -I "$GEN" -DPROT_USE_GENERATED_SECTIONS=1)
LDFLAGS=(-lcrypto -lpthread)

# =============================================================================
# 步骤 1: 组合（源文件清单）—— **注册表驱动**（不硬编码）
# =============================================================================
say "步骤 1: 组合 '$COMPOSITION' -> 源文件清单"
command -v "$PY" >/dev/null 2>&1 || die "找不到 $PY"

# ## 顺序随机化: **默认关**（2026-09-25 实测教训）
#   实测: 开启后**多数布局让程序崩溃**（`--version` 成功但完整启动崩
#   0xC0000005，发生在 license 校验之后 —— selfcrypt 解密路径）。
#   根因: selfcrypt 的**页分离保证（S1）是布局相关的** ——
#   源文件顺序变化会移动 `.text` 内各贡献的相对位置，可能让启动路径
#   与加密段同页 -> VirtualProtect(RW) 禁执行 -> 崩溃。
#   => 默认关闭；需要时 `PROT_SHUFFLE_SEED=0x... bash build.sh`。
# ## 2026-09-25: **默认开启**（selfcrypt 页自伤已修复，见 build.ps1 注释）
#   `PROT_SHUFFLE_SEED=0` 可关闭（回归诊断）。
SHUFFLE_ARGS=()
if [ "${PROT_SHUFFLE_SEED:-x}" != "0" ]; then
  SHUFFLE_ARGS=(--shuffle-seed "${PROT_SHUFFLE_SEED:-$RANDOM}")
fi

# 尾部文件并入统一清单（与原 build.ps1 的 cl 尾部**完全一致**）
EXTRA_ARGS=()
for ex in demo/main.c "$GEN/strings.c" \
          "$GEN/license_pubkey.c" "$GEN/indirect_table.c" \
          "$GEN/expect_default.c"; do
  EXTRA_ARGS+=(--extra "$ex")
done

"$PY" tools/compose.py "$COMPOSITION" \
      --header-out "$GEN/prot_modconfig.h" \
      --sources-out "$BDIR/_composition_srcs.txt" \
      "${SHUFFLE_ARGS[@]}" "${EXTRA_ARGS[@]}" \
  || die "compose.py 失败"

# 读清单（**过滤空行**）
mapfile -t COMP_SRCS < <(grep -v '^[[:space:]]*$' "$BDIR/_composition_srcs.txt")
[ "${#COMP_SRCS[@]}" -gt 0 ] || die "组合 '$COMPOSITION' 无源文件"
say "  组合含 ${#COMP_SRCS[@]} 个源文件"

# =============================================================================
# 步骤 1.5: **构建期生成链**（B 阶段，2026-09-25）
#
# ## 为什么需要
#   初版 build.sh **未调用生成器** —— 直接用 Windows 侧遗留的 demo/gen/*，
#   故节名固定（实测两次构建均为 `.derxeo4`）-> **B3 未真正生效**。
#
# ## 顺序（**关键**）
#   gen_sections **最先**（其头文件被其它生成物与 C 侧引用）；
#   keygen 在 license 相关之前。
# =============================================================================
say "步骤 1.5: 构建期生成链"

# ① 随机节名（**B3 的落点**：头文件宏 -> C 侧 PROT_ALLOCATE 应用）
SECT_SEED="0x$(od -An -N8 -tx8 /dev/urandom 2>/dev/null | tr -d ' \n')"
"$PY" tools/gen_sections.py --out-dir "$GEN" \
      --extra-crc 0 \
      --json-out "$GEN/prot_sections.json" --seed "$SECT_SEED" \
  || die "gen_sections.py 失败"
say "  ① 随机节名 seed=$SECT_SEED"

# ② RSA 密钥（含 **DER** —— Linux 侧密码学层用它；BCRYPT blob 供 Windows）
# ⚠️ 私钥路径必须与下方 sign/pack **一致**（build.ps1 用 license_priv.json）
"$PY" tools/vmenc.py keygen \
      --key-out build/keys/license_priv.json \
      --blob-out "$GEN/license_pubkey.c" \
      --blob-out-der "$GEN/prot_pubkey_der.c" \
  || die "vmenc keygen 失败"
say "  ② RSA 密钥 + DER 公钥"

# ③ 期望值（genserial -> vm_build.json -> expect_default.c）
if [ ! -f "$VM_JSON" ]; then
  printf '{"serial":"DEMO-2026-ABCDEFGH","machine_id":0}' > "$VM_JSON"
fi
# ## ⚠️ 先重置 machine_id = 0（触发 auto 重算）
#
# **根因（实测）**: `vm_build.json` 是**版本库里的文件**，其中的
#   `machine_id` 是**某台 Windows 机器**的值（非 0）。
#   `vmenc.py` 对**非 0 的 machine_id** 视为"**显式覆盖**"、**不重算**
#   -> Linux 侧期望值仍按那台 Windows 机器算 -> **序列号永远无效**。
#
#   => 构建前把它置 0（`0` = auto），让 genserial 按**本机**重算。
#      （这与"全新克隆后首次构建"的行为一致 ——
#        build.ps1 在 json 不存在时正是写 machine_id=0。）
"$PY" - <<'PYEOF'
import json
import os

vm_json = os.environ['VM_JSON_PATH']
d = json.load(open(vm_json, encoding='ascii'))
d['machine_id'] = 0            # 0 = auto（本机）
json.dump(d, open(vm_json, 'w', encoding='ascii'), indent=2)
print('  (machine_id 重置为 0 = auto)')
PYEOF

"$PY" tools/vmenc.py genserial --json "$VM_JSON" --machine-id auto \
  || die "vmenc genserial 失败"
say "  ③ 期望值（genserial）"

# ③b. 从 vm_build.json 生成 **构建期默认期望值** C 文件
#
# ## 为什么必需（实测，build.sh 曾缺此步）
#   缺此步 -> `demo/gen/expect_default.c` 是**别处遗留**的旧值
#   -> 与本次构建的 vm_build.json **不一致**
#   -> VM#3 校验失败 -> demo 报"序列号无效"
#   （实测: 旧 expect2=0x2d27... vs 新 0x2e9f...）
#
# ## 对应 build.ps1 L305-318（N5: VM#3 离线兜底值）
#   **必须在编译前**生成 —— 它是被编译进产物的 **C 源**。
"$PY" - <<'PYEOF'
import json
import os
import sys

gen_dir = os.environ['GEN_PATH']
vm_json = os.environ['VM_JSON_PATH']

d = json.load(open(vm_json, encoding='ascii'))
e1 = d.get('expect1') or ''
e2 = d.get('expect2') or ''
if not e1 or not e2:
    sys.stderr.write('expect_default: vm_build.json 缺 expect1/expect2\n')
    sys.exit(1)

e1 = e1[2:] if e1.startswith('0x') else e1
e2 = e2[2:] if e2.startswith('0x') else e2

txt = (
    '/* generated by build.sh from vm_build.json - do not edit */\n'
    '#include <stdint.h>\n'
    '#include "protect/protdef.h"\n'
    '\n'
    '/* N5: VM#3 build-time default expects '
    '(overridden by server session values) */\n'
    'const uint64_t g_prot_expect_default[2] = '
    '{ 0x%sULL, 0x%sULL };\n' % (e1, e2)
)
out = os.path.join(gen_dir, 'expect_default.c')
open(out, 'w', encoding='ascii', newline='\n').write(txt)
print('  3b expect_default.c 已生成 (expect1=0x%s...)' % e1[:12])
PYEOF
[ -f "$GEN/expect_default.c" ] || die "expect_default.c 生成失败"

# ④ 字符串加密
"$PY" tools/strgen.py demo/strings.txt "$GEN/strings.c" \
      --seed "$SECT_SEED" \
  || warn "  ④ strgen 失败（沿用既有 demo/gen 下的 strings.c）"

# ⑤ 间接化表
"$PY" tools/indirect.py --out "$GEN/indirect_table.c" --seed "$SECT_SEED" \
  || warn "  ⑤ indirect 失败（沿用既有 demo/gen 下的 indirect_table.c）"

# ⑥ RSA 签发授权（A1）—— 对该 json 的 serial/machine_id 签发
"$PY" tools/vmenc.py sign --key build/keys/license_priv.json \
      --json "$VM_JSON" --out "$BDIR/license.txt" \
  || warn "  ⑥ sign 失败（无 license.txt）"

# ⑦ VM 镜像汇编 + 加密（**4 个独立小 VM**）
#
# ## 为什么必需（实测）
#   缺 `vm.blob` -> demo 报"VM 镜像装载失败 (code=10)" ->
#   **VM 校验链完全未执行**（保护套件最核心的一环）。
#
# ## 参数与 build.ps1 **逐字对齐**（权威）
#   `--bin-out` 产出 pack 的输入（`.bin`）；
#   `--name` 是 C 侧符号名（须与 main.c 引用一致）。
for _vm in hash mix verify gate; do
  "$PY" tools/vmenc.py assemble "demo/license_${_vm}.vasm" "$VM_JSON" \
        "$GEN/vm_${_vm}_blob.c" "$GEN/vm_${_vm}_blob.h" \
        --name "g_vm_${_vm}_image" \
        --bin-out "$GEN/vm_${_vm}_blob.bin" --bin-name "${_vm}" \
    || die "vmenc assemble 失败（${_vm}）"
done
say "  ⑦ VM 镜像 ×4 已汇编加密"

# ⑧ 打包 vm.blob（**签名版**，防伪造）
"$PY" tools/vmenc.py pack --sign build/keys/license_priv.json \
      --out "$BDIR/vm.blob" \
      "$GEN/vm_hash_blob.bin" "$GEN/vm_mix_blob.bin" \
      "$GEN/vm_verify_blob.bin" "$GEN/vm_gate_blob.bin" \
  || die "vmenc pack 失败（**VM 校验链不会运行**）"
say "  ⑧ $BDIR/vm.blob 已生成"

# =============================================================================
# 步骤 2: 平台层源文件（**按平台选择**）
#
# ## 为什么不能用 compose.py 的清单
#   compose.py 给的是**模块**清单（`src/*.c`）；
#   平台层（`src/platform/`）是**按平台选**的 ——
#   Windows 用 `prot_platform_win.c` + `prot_crypto_win.c`；
#   Linux 用对应的 `_linux.c`。
# =============================================================================
PLATFORM_SRCS=(
  src/platform/prot_platform_linux.c
  src/platform/prot_crypto_linux.c
)
for f in "${PLATFORM_SRCS[@]}"; do
  [ -f "$f" ] || die "平台层源文件缺失: $f"
done
say "步骤 2: 平台层 ${#PLATFORM_SRCS[@]} 个源文件"

# =============================================================================
# 步骤 3: 生成的 C 文件（**构建期产物**）
#
# ## 诚实边界
#   本阶段**直接使用已有的 demo/gen/**（由 Windows 侧构建生成）。
#   **完整实现**应由本脚本自己调用 12 个 Python 工具重新生成 ——
#   那是 B2/B3 的接线工作。
# =============================================================================
# ## ⚠️ `prot_padding.c` **不在**此列表（A-b 实测修正）
#   它由**步骤 4.2**（measure -> merge -> gen_padding）生成，
#   而步骤 3 在**它之前** —— 若在此要求存在就构成**顺序矛盾**。
#   实测证据: 切到 `demo/gen/linux/`（全新空目录）时立刻报
#   "生成文件缺失: .../prot_padding.c"。
#   （旧 flat 布局下它是 **Windows 侧遗留文件**，检查恰好通过 ->
#     平台隔离让这个隐式依赖浮出水面。）
GEN_SRCS=(
  "$GEN/strings.c"
  "$GEN/prot_pubkey_der.c"
  "$GEN/indirect_table.c"
  "$GEN/expect_default.c"
)
for f in "${GEN_SRCS[@]}"; do
  [ -f "$f" ] || die "生成文件缺失: $f （生成链未跑通 -> 见步骤 1.5）"
done
say "步骤 3: 生成文件 ${#GEN_SRCS[@]} 个"

# =============================================================================
# 步骤 4: 编译 + 链接（**gcc**）
# =============================================================================
OUT="build/demo_linux"
say "步骤 4: 编译 (gcc, -j$JOBS)"

# 两段式: 先 -c 编译（可并行），再链接
# **为什么不用一次性**（gcc src*.c -o out）:
#   一次性调用**无法并行**，且失败时**错误定位**不如分文件清晰。
OBJDIR="build/obj_linux"
rm -rf "$OBJDIR"; mkdir -p "$OBJDIR"

# ## 源文件清单（2026-09-25 修正：**去重**）
#
# ⚠️ **踩过的坑**: `COMP_SRCS`（compose 输出）**已含** `--extra` 传入的
#   `demo/main.c` / `license_pubkey.c` / `indirect_table.c` /
#   `expect_default.c`（并入是为了支持顺序打乱）。
#   初版又在此**追加**它们 -> 同一文件编译多次 ->
#   **`multiple definition`** 链接失败。
#   （接入 extras 之前追加是必需的；接入后变成重复 —— 端到端链接才暴露。）
#
# => 只追加**平台层**（按平台选，不在 compose 清单内），并**整体去重**。
# ## Linux 专用源: **DER 公钥**（2026-09-25）
#
# `license.c` 按平台选公钥（`PROT_LICENSE_PUB`）:
#   Windows -> BCRYPT blob（`license_pubkey.c`，已在 extras 中）
#   **Linux -> DER**（`prot_pubkey_der.c`）—— 必须加入链接，
#     否则 `undefined reference to g_prot_pubkey_der`。
# => **按平台区分**，而非全局增删。
LINUX_ONLY_SRCS=()
[ -f "$GEN/prot_pubkey_der.c" ] && \
  LINUX_ONLY_SRCS+=("$GEN/prot_pubkey_der.c")

ALL_SRCS=()
declare -A _seen=()
for _s in "${COMP_SRCS[@]}" "${PLATFORM_SRCS[@]}" "${LINUX_ONLY_SRCS[@]}"; do
  if [ -z "${_seen[$_s]:-}" ]; then
    _seen[$_s]=1
    ALL_SRCS+=("$_s")
  fi
done
unset _seen
say "  总源文件: ${#ALL_SRCS[@]}（已去重）"

# 并行编译（每个文件一个 .o，文件名用路径转义）
# ## ⚠️ 并行编译的参数传递（A-b 实测修正）
#   `export CFLAGS OBJDIR` 之后 `bash -c 'compile_one ...'` 在**子 shell** 执行 ——
#   但 **bash 数组无法通过 export 传递**（子 shell 里 ${CFLAGS[@]} 拿不到）。
#   而用未加引号的字符串 `$CFLAGS` 又会因**路径含空格**被词分割。
#   => **在函数内部直接写字面参数**（重复一次定义，但绝对安全）；
#      只需 export 两个**标量**（GEN / OBJDIR）。
compile_one() {
  local src="$1"
  local obj="$OBJDIR/$(echo "$src" | tr '/' '_').o"
  if ! gcc -c -O2 -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE \
        -I include -I "$GEN" -DPROT_USE_GENERATED_SECTIONS=1 \
        "$src" -o "$obj" 2>"$obj.log"; then
    printf '\033[31m[FAIL]\033[0m %s\n' "$src"
    cat "$obj.log" >&2
    return 1
  fi
  # 警告也视为需展示（-Werror 下不会有警告，但保留以防）
  return 0
}
export -f compile_one
export GEN OBJDIR

FAILED=0
# 用 xargs 并行（**注意**: 需要 -I{} 传参）
printf '%s\n' "${ALL_SRCS[@]}" | \
  xargs -P "$JOBS" -I{} bash -c 'compile_one "$@"' _ {} || FAILED=1

if [ "$FAILED" -ne 0 ]; then
  die "编译失败（详见上方错误）"
fi
N_OBJ=$(ls -1 "$OBJDIR"/*.o 2>/dev/null | wc -l)
say "  编译完成: $N_OBJ 个目标文件"

say "  链接 -> $OUT"
# ## 链接顺序 = ALL_SRCS 顺序（**必须保持输入顺序**，2026-09-25）
#
#   `gcc "$OBJDIR"/*.o` 的**通配符展开是字母序** ——
#   会**丢掉** compose 的 --shuffle-seed 打乱（顺序随机化失效）。
#   改为按 ALL_SRCS（含打乱后的清单顺序）拼对象列表 -> **打乱生效**。
OBJ_LIST=()
for _src in "${ALL_SRCS[@]}"; do
  OBJ_LIST+=("$OBJDIR/$(echo "$_src" | tr '/' '_').o")
done
gcc "${OBJ_LIST[@]}" -o "$OUT" "${LDFLAGS[@]}" 2>&1 | head -40
[ -f "$OUT" ] || die "链接失败"

# =============================================================================
# 步骤 4.2-4.4: 节尺寸归一化（**需要第二轮编译**）
#
# ## 为什么需要（第二支柱）
#   `gen_padding.py` 的填充把各节尺寸**归一化到统一基线**，
#   消除"攻击者据节大小判断开了哪些防护"的信号。
#
# ## 依赖链（**必须两轮编译**）
#   ① 第一轮编译（上方步骤 4）—— **测量用**
#   ② measure_sections  -> 实际节尺寸 JSON
#   ③ merge_baseline    -> 合并为基线（只增不减）
#   ④ gen_padding       -> 产出 `demo/gen/prot_padding.c`（**C 源文件**）
#   ⑤ **第二轮编译**     -> 让填充真正进入产物
#
# ## 诚实边界
#   · 基线文件 `build/section_baseline.json` 是**只增不减**的本地状态 ->
#     多次构建后基线会偏高（**这与地址抖动的取舍见 §15/§16**）
#   · 本步骤在 Linux 侧**首次接线** —— 行为与 Windows 侧对齐
# =============================================================================
say "步骤 4.2: 节尺寸归一化（measure -> merge -> padding -> 重编）"

BASE_JSON="$BDIR/section_baseline.json"
ACT_JSON="$BDIR/section_actual.json"
[ -f "$BASE_JSON" ] || echo '{"file":0,"sections":{}}' > "$BASE_JSON"

"$PY" tools/measure_sections.py "$OUT" --out-json "$ACT_JSON" \
  --sections-json "$GEN/prot_sections.json" \
  || warn "  measure_sections 失败（跳过归一化）"
"$PY" tools/merge_baseline.py --baseline "$BASE_JSON" --actual "$ACT_JSON" \
  || warn "  merge_baseline 失败"
"$PY" tools/gen_padding.py --baseline "$BASE_JSON" --actual "$ACT_JSON" \
      --sections-json "$GEN/prot_sections.json" \
      --out "$GEN/prot_padding.c" \
      --seed "$SECT_SEED" --spread-ratio 0.35 --min-spread 512 \
  || die "gen_padding 失败（填充是第二支柱的一部分，不可跳过）"
[ -f "$GEN/prot_padding.c" ] || die "gen_padding 未产出 $GEN/prot_padding.c"
say "  ② measure / ③ merge / ④ gen_padding 完成"

# ⑤ 第二轮编译（让填充进入产物）
#
# ## 注意: 必须**重新编译全部**（填充改变节的聚合布局，
#   且 selfcrypt 的加密区间依赖最终地址）。
say "  ⑤ 第二轮编译（含填充）"
rm -rf "$OBJDIR"; mkdir -p "$OBJDIR"
FAILED=0
printf '%s\n' "${ALL_SRCS[@]}" | \
  xargs -P "$JOBS" -I{} bash -c 'compile_one "$@"' _ {} || FAILED=1
[ "$FAILED" -eq 0 ] || die "第二轮编译失败"
OBJ_LIST=()
for _src in "${ALL_SRCS[@]}"; do
  OBJ_LIST+=("$OBJDIR/$(echo "$_src" | tr '/' '_').o")
done
gcc "${OBJ_LIST[@]}" -o "$OUT" "${LDFLAGS[@]}" \
    -Wl,-Map=build/demo_linux.map 2>&1 | head -30
[ -f "$OUT" ] || die "第二轮链接失败"
say "  第二轮完成: $(stat -c%s "$OUT") 字节"

# =============================================================================
# 步骤 4.4: **运行期自变形加密**（selfcrypt）
#
# ## 做什么
#   `selfcrypt_proto.py` 把指定函数的 `.text` 内容**原位 XOR 加密**，
#   并输出 `build/selfcrypt_mask.txt`（被加密的 RVA 区间）。
#   运行期 `prot_selfcrypt_enter` 解密后执行。
#
# ## 为什么必须在 hashpatch **之前**
#   加密改变了 `.text` 的字节 -> CRC 必须在**加密后**计算
#   （且加密段在 CRC 中被**掩码**，两侧一致）。
# =============================================================================
say "步骤 4.4: selfcrypt 原位加密"
"$PY" tools/selfcrypt_proto.py "$OUT" build/demo_linux.map \
      --mask-out "$BDIR/selfcrypt_mask.txt" \
      --sections-json "$GEN/prot_sections.json" \
  || warn "  selfcrypt_proto 失败（**.text 未加密** —— 无自变形）"

# =============================================================================
# 步骤 4.5: 烧录 CRC 到**烧录表**（B2，2026-09-25）
#
# ## 为什么需要（与 build.ps1 步骤 6.1 对应）
#   `integrity` 模块运行时校验 `.text`/`.rodata`/`.eh_frame` 的 CRC32，
#   期望值**由本步骤烧录**（构建期写进专用节）。
#
# ## 与 Windows 的差异（**如实标注**）
#   · 目标节名: PE `.text/.rdata/.pdata`；ELF **`.text/.rodata/.eh_frame`**
#   · 掩码: PE 用 `.reloc` 块 + IAT；ELF 用 **`.rela.dyn` + `.got`**
#   · 烧录表节名**两平台一致**（都从 prot_sections.json 读随机名）
#
# ## selfcrypt 掩码
#   加密段在 CRC 中**被掩码**（明文/密文两侧一致）——
#   掩码区间由 `selfcrypt_proto.py` 产出。**若该步骤未跑则无掩码** ->
#   CRC 与运行期不一致 -> 运行时会报完整性失败。
# =============================================================================
MASK_FILE="$BDIR/selfcrypt_mask.txt"
MASK_ARGS=()
if [ -s "$MASK_FILE" ]; then
  while IFS= read -r _ln; do
    [ -n "$_ln" ] && MASK_ARGS+=(--mask "$_ln")
  done < "$MASK_FILE"
  say "步骤 4.5: 烧录 CRC（含 ${#MASK_ARGS[@]} 个 selfcrypt 掩码区间... 实为 $(( ${#MASK_ARGS[@]} / 2 )) 个）"
else
  warn "  未找到 $MASK_FILE —— **不带 selfcrypt 掩码**烧录"
  warn "  （若组合含 selfcrypt，运行期完整性校验会失败；见 build.ps1 步骤 6）"
fi

"$PY" tools/hashpatch.py "$OUT" "${MASK_ARGS[@]}" \
      --sections-json "$GEN/prot_sections.json" \
  || die "hashpatch 失败（ELF 烧录）"

# =============================================================================
# 步骤 4.6: 文件尾精确填充（**统一文件大小**，W1 差异扩散收尾）
#
# ## 工具性质（已核实）
#   `normalize_tail.py` 纯做**文件尾追加**（70 行、无平台代码）——
#   **ELF 加载器同样忽略尾部多余字节** -> 无需 ELF 分支、格式无关。
#
# ## 为什么需要（build.ps1 的同类注释）
#   节填充只能花在**节**上，且链接器按 0x200 对齐 ->
#   各组合最终文件大小仍差 512~1024 字节 ->
#   **攻击者可据文件大小推断组合**。尾部填充使其**完全一致**。
#
# ## 插入顺序（关键）
#   节填充 -> selfcrypt -> hashpatch -> **本步骤** -> (签名)
#   · 必须在 hashpatch **之后**（否则 CRC 与最终字节不符）
#   · 必须在签名**之前** —— Linux 无签名，故为最后一步
#
# ## target 策略
#   `PROT_TAIL_TARGET` 显式指定 > 基线文件（只增不减，首次记录当前大小）
#   => 同一项目多次构建**大小统一**。
# =============================================================================
TAIL_BASE="build/tail_target.txt"
CUR_SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
if [ -n "${PROT_TAIL_TARGET:-}" ]; then
  TAIL_TARGET="$PROT_TAIL_TARGET"
elif [ -s "$TAIL_BASE" ]; then
  TAIL_TARGET=$(cat "$TAIL_BASE")
  # 只增不减: 当前更大则提升目标
  if [ "$CUR_SIZE" -gt "$TAIL_TARGET" ]; then
    TAIL_TARGET="$CUR_SIZE"
    echo "$TAIL_TARGET" > "$TAIL_BASE"
  fi
else
  TAIL_TARGET="$CUR_SIZE"
  echo "$TAIL_TARGET" > "$TAIL_BASE"
fi

say "步骤 4.6: 文件尾填充（目标 $TAIL_TARGET 字节，当前 $CUR_SIZE）"
"$PY" tools/normalize_tail.py "$OUT" --target "$TAIL_TARGET" \
      --seed "$SECT_SEED" --quiet \
  || warn "  normalize_tail 失败（大小可能不统一）"
FINAL_SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
say "  最终大小: $FINAL_SIZE 字节"

# =============================================================================
# 步骤 5: 冒烟
# =============================================================================
say "步骤 5: 冒烟自检"
if "$OUT" --version 2>&1 | head -3; then
  say "  --version OK"
else
  warn "  --version 失败（不中止 —— 授权链可能需要 license/blob）"
fi

SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
say "产物: $OUT ($SIZE 字节)"

# 校验是 ELF
if file "$OUT" 2>/dev/null | grep -q ELF; then
  say "  格式: ELF ✅"
else
  warn "  格式校验: file 命令不可用或非 ELF"
fi

printf '\n\033[32mDONE\033[0m\n'
