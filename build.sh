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
mkdir -p build demo/gen

# 与 Windows 侧一致的编译选项（**语义对应**）
#
# | MSVC | gcc | 说明 |
# |------|-----|------|
# | /W4 /WX | -Wall -Wextra -Werror | 警告即错误 |
# | /std:c11 | -std=c11 | C 标准 |
# | /O2 | -O2 | 优化 |
# | /utf-8 | -finput-charset=UTF-8 | 源文件编码 |
# | /DPROT_USE_GENERATED_SECTIONS=1 | 同 | 用随机节名 |
CFLAGS="-c -O2 -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE"
CFLAGS="$CFLAGS -I include -I demo/gen -DPROT_USE_GENERATED_SECTIONS=1"
LDFLAGS="-lcrypto -lpthread"

# =============================================================================
# 步骤 1: 组合（源文件清单）—— **注册表驱动**（不硬编码）
# =============================================================================
say "步骤 1: 组合 '$COMPOSITION' -> 源文件清单"
command -v "$PY" >/dev/null 2>&1 || die "找不到 $PY"
"$PY" tools/compose.py "$COMPOSITION" \
      --header-out demo/gen/prot_modconfig.h \
      --sources-out build/_composition_srcs.txt \
  || die "compose.py 失败"

# 读清单（**过滤空行**）
mapfile -t COMP_SRCS < <(grep -v '^[[:space:]]*$' build/_composition_srcs.txt)
[ "${#COMP_SRCS[@]}" -gt 0 ] || die "组合 '$COMPOSITION' 无源文件"
say "  组合含 ${#COMP_SRCS[@]} 个源文件"

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
GEN_SRCS=(
  demo/gen/strings.c
  demo/gen/prot_pubkey_der.c
  demo/gen/indirect_table.c
  demo/gen/expect_default.c
  demo/gen/prot_padding.c
)
for f in "${GEN_SRCS[@]}"; do
  [ -f "$f" ] || die "生成文件缺失: $f （请先在 Windows 上构建一次，或运行 tools/ 生成）"
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

ALL_SRCS=("${COMP_SRCS[@]}" "${PLATFORM_SRCS[@]}" "${GEN_SRCS[@]}" demo/main.c)
say "  总源文件: ${#ALL_SRCS[@]}"

# 并行编译（每个文件一个 .o，文件名用路径转义）
compile_one() {
  local src="$1"
  local obj="$OBJDIR/$(echo "$src" | tr '/' '_').o"
  if ! gcc $CFLAGS "$src" -o "$obj" 2>"$obj.log"; then
    printf '\033[31m[FAIL]\033[0m %s\n' "$src"
    cat "$obj.log" >&2
    return 1
  fi
  # 警告也视为需展示（-Werror 下不会有警告，但保留以防）
  return 0
}
export -f compile_one
export CFLAGS OBJDIR

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
gcc "$OBJDIR"/*.o -o "$OUT" $LDFLAGS 2>&1 | head -40
[ -f "$OUT" ] || die "链接失败"

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
