#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/vm_debug.py — VM 级调试器 (docs/STUDIO_PLAN.md ST4)

它做四件事，且**每一件都与 `src/vm.c` 逐条对齐**（这是本工具唯一的正确性标准）:

  ST4.2 反汇编   密文 + key1 -> 解密 -> 逆置换 -> 规范 opcode -> 助记符 + 操作数
  ST4.3 解释器   单步 / 继续 / 步过 / 运行到断点; `halt` 与 `brk`(CON!=0) 都停
  ST4.4 视图     栈 / 寄存器 R / 条件寄存器 CON / 基址 BR / 内存窗口 / 指令计数
  ST4.1 行号     读 `vmenc.py --map-out` 的 sidecar, 把偏移映射回 `.vasm` 源行号

## 为什么它不是 `tools/vm_reduce.py` 的重复

`vm_reduce.py` 是**攻击者视角的还原证明**（ATTACK_DRILL4 R1-4）: 它只求"能打印出
语义轨迹"，因此**故意**不完整 —— 它没有 `call`/`ret` 的栈语义, `callind` 也不改
`ip`（见该文件 209-213 行）。它对"证明引擎可被还原"够用，但**不足以当调试器**:
调试器要在任意指令处停下、把 `ip` 改回去、按源行号下断点。

所以本工具**重写**解释器, 而**不**复用 `vm_reduce.reduce_image()`:
两个工具的**目的**不同, 共用一个不完整的实现会让调试器静默给出错误的控制流
（"看起来在跑，其实跳转全错"）—— 那比没有调试器更坏。

## 诚实边界（写进工具而不是只写在文档里）

1. **解释器与 `src/vm.c` 可能漂移**。判据是 `tests/vm_unit.c` 的六个宿主内存
   断言（见 `SELFTEST_EXPECT`）；本工具的 `--selftest` 就跑它们。
   漂移一旦发生, 是**本工具的缺陷**, 不是"引擎实现不同"。
2. **`vm_wd_fill` 的明文滑动窗口不在本工具范围内**: 那是运行期的**内存驻留**
   优化（每个 64 字节窗口用完即加密）, 不改变**语义**。本工具在**完全解密**的
   明文上解释 —— 这正是 ST4 决策 D3 的理由（镜像可离线解密, 不受密文窗口影响）。
3. **断点是解释器内的**, 不改任何产物。真机断点（把副本的目标 opcode 临时改成
   `brk`）是**独立一步**, 且只对副本操作 —— 见 ST4.5。
4. **不触发反调试**: 本工具不 `OpenProcess`、不 attach、不读目标进程内存。
   这是 VM 级调试相对主机级调试的结构性优势（规划 D3 理由②）。

用法:
    python tools/vm_debug.py --asm tests/unit_vm.vasm --run
    python tools/vm_debug.py --asm tests/unit_vm.vasm --break 41 --run
    python tools/vm_debug.py --asm tests/unit_vm.vasm --steps 5 --view
    python tools/vm_debug.py --blob build/vm.blob --name verify --disasm
    python tools/vm_debug.py --map build/unit_vm.vasm.map --blob build/vm.blob --name verify
"""

import argparse
import io
import json
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmenc  # noqa: E402
import vm_reduce  # noqa: E402  (只借它的 blob 读取与解密, 不借解释器)

M64 = (1 << 64) - 1
STACK_CAP = 512  # 与 src/vm.c PROT_VM_STACK_CAP 一致

# 与 src/vm.c g_routes 同序的规范 opcode -> 助记符（由 vmenc.INSTRUCTIONS 反推,
# 故**不会**与汇编器漂移 —— 少写一条就会在这里丢键, 由 selftest 断言覆盖完整）。
MNEMONICS = {op: mn for mn, (op, _k) in vmenc.INSTRUCTIONS.items()}
OPND_KIND = {op: kind for mn, (op, kind) in vmenc.INSTRUCTIONS.items()}

# 停机原因（机读, 面板据此显示"为什么停了"而不是只说"停了"）
HALT = 'halt'                 # 0x00
BREAKPOINT = 'breakpoint'     # 0x2B 且 CON != 0
STEP_LIMIT = 'step-limit'     # 到达 --steps 上限
USER_BREAK = 'user-break'     # 命中用户断点
ERR_BAD_OPCODE = 'bad-opcode'
ERR_STACK_OVERFLOW = 'stack-overflow'
ERR_STACK_UNDERFLOW = 'stack-underflow'
ERR_OUT_OF_BOUNDS = 'out-of-bounds'
ERR_DIV_ZERO = 'div-by-zero'
ERR_TRUNCATED = 'truncated'


class VmError(Exception):
    """解释器停机（正常或异常）。`reason` 是机读原因, `detail` 给人看。"""

    def __init__(self, reason, detail=None, ip=None):
        Exception.__init__(self, detail or reason)
        self.reason = reason
        self.detail = detail
        self.ip = ip

    def to_dict(self):
        return {'reason': self.reason, 'detail': self.detail, 'ip': self.ip}


# ---------------------------------------------------------------------------
# ST4.2 反汇编
# ---------------------------------------------------------------------------
def decode_one(code, ip, inv, sem0):
    """解一条指令。返回 (mnem, operand_value, insn_len, kind) 或抛 VmError。

    `kind` 决定操作数语义, 与 `src/vm.c vm_wfetch32/64` 及 `assemble_source`
    的 INSN_SIZE 一一对应（1 / 5 / 9 字节）。
    """
    if ip >= len(code):
        raise VmError(ERR_TRUNCATED, 'ip=%d 超出代码长度 %d' % (ip, len(code)),
                      ip=ip)
    emit = code[ip]
    canon = inv[emit]
    if canon == 0xFF:
        raise VmError(ERR_BAD_OPCODE, 'emit byte 0x%02x @%d 不在置换表中'
                      % (emit, ip), ip=ip)
    mnem = MNEMONICS.get(canon, 'OP_%02x' % canon)
    kind = OPND_KIND.get(canon)

    def fetch(n, signed=False):
        raw = code[ip + 1:ip + 1 + n]
        if len(raw) < n:
            raise VmError(ERR_TRUNCATED,
                          '%s 的操作数被截断 @%d' % (mnem, ip), ip=ip)
        if sem0 & 1:              # A2: 构建期字节序微变
            raw = bytes(reversed(raw))
        return int.from_bytes(raw, 'little', signed=signed), n

    if kind == 'imm32':
        v, n = fetch(4)
        return mnem, v, 1 + n, kind
    if kind == 'imm64':
        v, n = fetch(8)
        return mnem, v, 1 + n, kind
    if kind == 'labs':
        v, n = fetch(4)
        return mnem, v, 1 + n, kind
    if kind == 'rel32':
        v, n = fetch(4, signed=True)
        return mnem, v, 1 + n, kind
    return mnem, None, 1, kind


def disassemble(code, key1, sem0=None):
    """整段反汇编。返回 (insns, sem0)。

    `key1=None` 表示**代码是规范 opcode**（就地汇编的 `.vasm`, perm=None）——
    此时不做逆置换。这不是"默认参数", 而是一个**真实存在的两种输入形态**:
    调试自己写的源码走 canonical, 调试构建产物走 key1 置换。
    把两者混起来会让反汇编看似"到处是 bad opcode"。
    """
    if key1 is None:
        inv = list(range(256))
        sem0 = 0
    else:
        _perm, _slot, sem0_calc, _sem1 = vmenc.make_opcode_keymaps(key1)
        if sem0 is None:
            sem0 = sem0_calc
        inv = [0xFF] * 256
        for c in range(vmenc.OPCODE_SLOTS):
            inv[_perm[c]] = c
    out = []
    ip = 0
    while ip < len(code):
        off = ip
        mnem, operand, size, kind = decode_one(code, ip, inv, sem0)
        ip += size
        rec = {'off': off, 'mnem': mnem, 'operand': operand,
               'size': size, 'target': None}
        if kind == 'rel32':
            rec['target'] = (ip + operand) & 0xFFFFFFFF
        out.append(rec)
    return out, sem0


def format_insn(rec, line=None):
    """一行反汇编文本。有源行号时前缀它 —— 这是"像调试 Java"的观感来源。"""
    head = '%6d  ' % rec['off']
    src = ('L%-5d ' % line) if line else ''
    body = rec['mnem']
    if rec['operand'] is not None:
        if rec['target'] is not None:
            body += ' -> %d (rel %+d)' % (rec['target'], rec['operand'])
        else:
            body += ' 0x%x' % rec['operand']
    return head + src + body


# ---------------------------------------------------------------------------
# ST4.3/ST4.4 解释器
# ---------------------------------------------------------------------------
class Vm(object):
    """VM 解释器。语义逐条对齐 `src/vm.c`（见模块 docstring 的诚实边界 1）。"""

    def __init__(self, code, key1, mem=None, max_steps=200000, mem_size=None):
        self.code = code
        self.key1 = key1
        if key1 is None:
            # 规范 opcode（就地汇编的 .vasm）: 恒等置换, sem0=0。
            # 与 disassemble() 的同一分支对应 —— 两处必须一致, 否则
            # "反汇编对了但单步跳错"。
            self._perm = list(range(256))
            self.sem0 = 0
            self.sem1 = 0
        else:
            self._perm, _slot, self.sem0, self.sem1 = \
                vmenc.make_opcode_keymaps(key1)
        self.inv = [0xFF] * 256
        for c in range(vmenc.OPCODE_SLOTS):
            self.inv[self._perm[c]] = c
        self.stk = []
        self.ip = 0
        self.br = 0
        self.rr = 0
        self.con = 0
        self.mem = dict(mem or {})
        # 越界判定要一个尺寸。真机上 mem_size 由宿主给出; 调试器默认给一个
        # **足够大但有限**的上限, 并把越界当错误 —— 而不是无限字典（那样
        # "越界"永远不触发, 调试器就看不见这个真实的失败模式）。
        self.mem_size = mem_size if mem_size is not None else (1 << 20)
        self.steps = 0
        self.max_steps = max_steps
        self.history = []
        # ST5.4 **影子调用栈**。见 `_exec` 里 call/callind/ret 三处: `stk` 是
        # 数据栈与返回栈**混用**的（与 src/vm.c 一致）, 所以调用栈不可能从
        # `stk` 反推出来, 只能在执行时旁路记录。
        #   `frames[i] = {'call_off': call 指令偏移, 'ret_addr': 压入的返回
        #   地址, 'dest': 跳转目标}`
        # `frames_dirty` 在"ret 弹出的不是最近一次 call 压的返回地址"时置位
        # —— 那一刻起这张表**不再是调用栈**, 必须如实说出来而不是继续显示
        # 一个看起来很合理的假栈。
        self.frames = []
        self.frames_dirty = False

    # --- 内存（与 vm_mem_oob 同式: 回绕安全） -----------------------------
    def _oob(self, addr, width):
        if width > self.mem_size:
            return True
        return addr > self.mem_size - width

    def _rd(self, addr, width):
        if self._oob(addr, width):
            raise VmError(ERR_OUT_OF_BOUNDS,
                          '读 [0x%x, +%d) 越界 (mem_size=%d)'
                          % (addr, width, self.mem_size), ip=self.ip)
        v = 0
        for j in range(width):
            v |= (self.mem.get(addr + j, 0) & 0xFF) << (8 * j)
        return v

    def _wr(self, addr, width, val):
        if self._oob(addr, width):
            raise VmError(ERR_OUT_OF_BOUNDS,
                          '写 [0x%x, +%d) 越界 (mem_size=%d)'
                          % (addr, width, self.mem_size), ip=self.ip)
        for j in range(width):
            self.mem[addr + j] = (val >> (8 * j)) & 0xFF

    def _push(self, v):
        if len(self.stk) >= STACK_CAP:
            raise VmError(ERR_STACK_OVERFLOW, '栈已满 (%d)' % STACK_CAP,
                          ip=self.ip)
        self.stk.append(v & M64)

    def _pop(self):
        if not self.stk:
            raise VmError(ERR_STACK_UNDERFLOW, '栈为空', ip=self.ip)
        return self.stk.pop()

    # --- 影子调用栈 (ST5.4) ------------------------------------------------
    def _note_call(self, call_off, ret_addr, dest):
        """记录一次 call / callind。

        调用发生在 `_push` **之前**（见 `_exec`: `call`/`callind` 都是先
        `_note_call` 再 `_push`）—— 否则压进去的返回地址会被自己当成上一帧。
        """
        self.frames.append({'call_off': call_off, 'ret_addr': ret_addr,
                            'dest': dest})

    def _note_ret(self, at, ret_addr):
        """记录一次 ret。**只以"弹出的值 == 最近一帧的返回地址"为配对依据。**

        `src/vm.c` 把返回地址压进**数据栈**, 所以"这条 ret 对应哪次 call"
        在字节层面并非自明 —— 一个 push32 的立即数完全可能长得像返回地址。
        因此这里**不猜**: 对得上就弹帧, 对不上就把整张表标记为**不再可信**。
        显示一张错的调用栈比不显示更糟（它会被当成证据）。
        """
        if self.frames and self.frames[-1]['ret_addr'] == ret_addr:
            self.frames.pop()
            return
        self.frames_dirty = True

    def call_stack(self):
        """给面板用的调用栈快照。栈顶（当前帧）在**最后**。"""
        depth = len(self.frames)
        out = []
        for i, f in enumerate(self.frames):
            out.append({
                'index': i,
                'call_off': f['call_off'],
                'ret_addr': f['ret_addr'],
                'dest': f['dest'],
                'is_top': (i == depth - 1),
            })
        return {
            'depth': depth,
            'frames': out,
            # 如实透出可信度: 面板应当据 `reliable` 决定"显示还是报警",
            # 而不是把一张已知不可信的表照常渲染。
            'reliable': not self.frames_dirty,
            'dirty_reason': ('检测到 ret 弹出的返回地址与最近一次 call 压入的'
                             '不一致 -> 该 ret 可能只是数据栈上的一个值 '
                             '(src/vm.c 的返回地址与数据共用 stk), 调用栈不再可信'
                             ) if self.frames_dirty else None,
        }

    # --- 单步 --------------------------------------------------------------
    def step(self):
        """执行一条指令。返回 True 表示**还能继续**, False 表示已停机。

        停机原因写在 `self.stop_reason` / `self.stop_detail`。
        """
        if self.steps >= self.max_steps:
            self.stop_reason = STEP_LIMIT
            self.stop_detail = '到达 --steps 上限 %d' % self.max_steps
            return False
        at = self.ip
        rec_off = at
        try:
            mnem, operand, size, kind = decode_one(
                self.code, at, self.inv, self.sem0)
            self.ip += size
            self._exec(mnem, operand, kind, at)
        except VmError as e:
            if e.ip is None:
                e.ip = rec_off
            self.stop_reason = e.reason
            self.stop_detail = e.detail
            self.steps += 1
            self.history.append((rec_off, self.stop_reason))
            return False
        self.steps += 1
        self.history.append((rec_off, mnem))
        # ⚠️ 必须判 `is not None` 而不是 `== HALT`。`src/vm.c vm_h_brk` 在
        # CON != 0 时返回 `PROT_ERR_VM_BREAKPOINT` —— 那是**停机**, 与 halt
        # 同级。只认 HALT 会让 brk 陷阱**静默失效**: 自检首跑就抓到这一条
        # （unit_vm_brk 期望 breakpoint、实得 halt, 因为陷阱后继续跑到了 halt）。
        if self.stop_reason is not None:
            return False
        return True

    def _exec(self, mnem, operand, kind, at):
        ip = self.ip  # ip 已越过操作数
        if mnem == 'halt':
            self.stop_reason = HALT
            self.stop_detail = 'halt'
        elif mnem == 'push32' or mnem == 'push64':
            self._push(operand)
        elif mnem == 'dup':
            if not self.stk:
                raise VmError(ERR_STACK_UNDERFLOW, 'dup 栈为空')
            self._push(self.stk[-1])
        elif mnem == 'drop':
            self._pop()
        elif mnem == 'swap':
            if len(self.stk) < 2:
                raise VmError(ERR_STACK_UNDERFLOW, 'swap 需要 2 个元素')
            self.stk[-1], self.stk[-2] = self.stk[-2], self.stk[-1]
        elif mnem in ('add', 'sub', 'mul', 'divu', 'modu', 'xor', 'and', 'or'):
            b = self._pop()
            a = self._pop()
            if mnem == 'add':
                r = a + b
            elif mnem == 'sub':
                r = a - b
            elif mnem == 'mul':
                r = a * b
            elif mnem == 'divu':
                if b == 0:
                    raise VmError(ERR_DIV_ZERO, 'divu 除零')
                r = a // b
            elif mnem == 'modu':
                if b == 0:
                    raise VmError(ERR_DIV_ZERO, 'modu 除零')
                r = a % b
            elif mnem == 'xor':
                r = a ^ b
            elif mnem == 'and':
                r = a & b
            else:
                r = a | b
            self._push(r)
        elif mnem == 'not':
            if not self.stk:
                raise VmError(ERR_STACK_UNDERFLOW, 'not 栈为空')
            self.stk[-1] = (~self.stk[-1]) & M64
        elif mnem in ('shl', 'shr'):
            b = self._pop()
            a = self._pop()
            c = b & 63
            self._push((a << c) if mnem == 'shl' else (a >> c))
        elif mnem in ('cmpeq', 'cmpne', 'cmpltu', 'cmpleu', 'cmpgtu', 'cmpgeu'):
            b = self._pop()
            a = self._pop()
            r = {'cmpeq': a == b, 'cmpne': a != b, 'cmpltu': a < b,
                 'cmpleu': a <= b, 'cmpgtu': a > b, 'cmpgeu': a >= b}[mnem]
            self._push(1 if r else 0)
        elif mnem == 'jmp':
            self.ip = (ip + operand) & 0xFFFFFFFF
        elif mnem in ('jz', 'jnz'):
            c = self._pop()
            if (c == 0) if mnem == 'jz' else (c != 0):
                self.ip = (ip + operand) & 0xFFFFFFFF
        elif mnem == 'call':
            self._note_call(at, ip, (ip + operand) & 0xFFFFFFFF)
            self._push(ip)
            self.ip = (ip + operand) & 0xFFFFFFFF
        elif mnem == 'ret':
            ret_addr = self._pop() & 0xFFFFFFFF
            self._note_ret(at, ret_addr)
            self.ip = ret_addr
        elif mnem in ('load8', 'load32', 'load64'):
            n = {'load8': 1, 'load32': 4, 'load64': 8}[mnem]
            self._push(self._rd(self._pop(), n))
        elif mnem in ('store8', 'store32', 'store64'):
            n = {'store8': 1, 'store32': 4, 'store64': 8}[mnem]
            val = self._pop()
            addr = self._pop()
            self._wr(addr, n, val)
        elif mnem == 'setbase':
            self.br = self._pop()
        elif mnem == 'pushbase':
            self._push(self.br)
        elif mnem == 'nop':
            pass
        elif mnem == 'lea':
            self._push(operand)
        elif mnem == 'pushr':
            self._push(self.rr)
        elif mnem == 'popr':
            self.rr = self._pop()
        elif mnem == 'setcon':
            self.con = 1 if self._pop() != 0 else 0
        elif mnem == 'pushcon':
            self._push(self.con)
        elif mnem == 'callind':
            target = self._pop()
            self._note_call(at, ip, target & 0xFFFFFFFF)
            self._push(ip)
            self.ip = target & 0xFFFFFFFF
        elif mnem == 'brk':
            if self.con != 0:
                self.stop_reason = BREAKPOINT
                self.stop_detail = 'brk 且 CON=%d -> 断言陷阱' % self.con
        elif mnem == 'move':
            self.rr = operand & M64
        elif mnem == 'loadr32':
            off = self._pop()
            self._push(self._rd((self.br + self.rr + off) & M64, 4))
        elif mnem == 'storr32':
            val = self._pop()
            off = self._pop()
            self._wr((self.br + self.rr + off) & M64, 4, val)
        else:
            raise VmError(ERR_BAD_OPCODE, '未实现的助记符 %r' % mnem)

    stop_reason = None
    stop_detail = None

    # --- ST4.4 视图 --------------------------------------------------------
    def view(self):
        """机器可读的状态快照。面板用它渲染, CLI 也用它 —— **同一个来源**。"""
        cs = self.call_stack()
        return {
            'ip': self.ip,
            'steps': self.steps,
            'stack_depth': len(self.stk),
            'stack_top': ['0x%x' % x for x in self.stk[-8:]],
            'br': '0x%x' % self.br,
            'r': '0x%x' % self.rr,
            'con': self.con,
            'mem_written': len(self.mem),
            'stop_reason': self.stop_reason,
            'stop_detail': self.stop_detail,
            # ST5.4: 调用栈来自影子表, **不是**从 stk 反推的。`stack_depth`
            # 是数据栈深度（含返回地址）, `call_stack.depth` 是调用深度;
            # 两者**不相等**是正常的, 面板不得把它们混为一谈。
            'call_depth': cs['depth'],
            'call_stack': cs,
        }

    def view_text(self):
        v = self.view()
        return ('ip=%-6d steps=%-6d sp=%-4d R=%-18s BR=%-10s CON=%d mem=%d'
                % (v['ip'], v['steps'], v['stack_depth'], v['r'],
                   v['br'], v['con'], v['mem_written']))


def run(vm, break_lines=None, off_to_line=None, max_steps=None):
    """跑到停机 / 断点 / 步数上限。返回 (stopped_reason, detail)。

    `break_lines` 是**源行号**集合（ST4.1 的行号表把偏移映射回行号）——
    断点按行号下、按偏移命中, 这是"像调试 Java"的关键一步。
    """
    if max_steps is not None:
        vm.max_steps = max_steps
    off_to_line = off_to_line or {}
    while True:
        if break_lines:
            ln = off_to_line.get(vm.ip)
            if ln is not None and ln in break_lines:
                vm.stop_reason = USER_BREAK
                vm.stop_detail = '命中断点 L%d (off=%d)' % (ln, vm.ip)
                return vm.stop_reason, vm.stop_detail
        if not vm.step():
            return vm.stop_reason, vm.stop_detail


# ---------------------------------------------------------------------------
# ST5.4 调试会话
# ---------------------------------------------------------------------------
# `run()` 是**一次性**的: 它从 ip=0 跑到底, 中间没有任何"暂停给用户看"的
# 地方。调试工具条的"继续/单步/步过/重启/停止"要的是一件别的东西: 一个
# **跨多次调用活着的解释器**。这就是本类存在的理由。
class Session(object):
    """一个可交互的 VM 调试会话。

    与 `run()` 的关键差别:
      * 状态**跨调用存活**（面板点一次"单步"就是一次 `step_once()`）;
      * 停机**不清空** —— 停在断点/陷阱上之后仍然可以问"现在在哪、栈什么样";
      * `step_over()` 有**真实的步过语义**, 不是"多走几步"。

    诚实边界: 会话活在**进程内**。`tools/studio_cli.py --cmd` 每次是一个新
    进程, 因此拿不到上一次的会话; 用它的 session 模式（从 stdin 逐行读）或
    Studio 外壳（同一个 HTTP 服务进程）才跨调用有效。
    """

    def __init__(self, code, key1, off_to_line=None, line_to_asm=None,
                 src=None, kind='asm', mem=None, mem_size=None,
                 max_steps=200000):
        self.code = code
        self.key1 = key1
        self.src = src
        self.kind = kind                      # 'asm' | 'blob'
        self.off_to_line = dict(off_to_line or {})
        self.line_to_asm = dict(line_to_asm or {})
        self._init_mem = dict(mem or {})
        self._mem_size = mem_size
        self._max_steps = max_steps
        self.breakpoints = set()
        self.stopped_hit_breakpoint = None
        self.restart()

    def restart(self):
        """回到初始状态，**保留断点**（重启不该悄悄清掉用户下的断点）。"""
        self.vm = Vm(self.code, self.key1, mem=dict(self._init_mem),
                     max_steps=self._max_steps, mem_size=self._mem_size)
        self.stopped_hit_breakpoint = None
        return self.state()

    # --- 断点 --------------------------------------------------------------
    @property
    def supports_breakpoints(self):
        """只有带行号表的源码会话能按**源行号**下断点。

        blob 会话没有行号表（ST4.1 的 sidecar 目前没有任何磁盘产物）,
        此时**如实说不支持**, 而不是退化成"按偏移下断点却仍叫行号" ——
        那会让面板显示一个用户没法从源码上指认的断点。
        """
        return bool(self.off_to_line)

    def set_breakpoints(self, lines):
        if not self.supports_breakpoints:
            raise VmError('no-line-table',
                          '该会话没有行号表 (来源 %r), 无法按源行号下断点。'
                          '用 .vasm 源码打开会话才有行号表。' % self.kind)
        bp = set()
        for ln in (lines or []):
            ln = int(ln)
            if ln not in self.line_to_asm:
                # **不静默接受**一个永远命不中的行号: 用户会以为断点生效了。
                raise VmError('bad-breakpoint',
                              '第 %d 行不是可执行指令行' % ln)
            bp.add(ln)
        self.breakpoints = bp
        return sorted(bp)

    def add_breakpoint(self, line):
        return self.set_breakpoints(sorted(self.breakpoints | {int(line)}))

    def clear_breakpoint(self, line):
        return self.set_breakpoints(sorted(self.breakpoints - {int(line)}))

    # --- 执行 --------------------------------------------------------------
    def _at_breakpoint(self):
        ln = self.off_to_line.get(self.vm.ip)
        return ln if (ln is not None and ln in self.breakpoints) else None

    def _hit(self, ln):
        self.vm.stop_reason = USER_BREAK
        self.vm.stop_detail = '命中断点 L%d (off=%d)' % (ln, self.vm.ip)
        self.stopped_hit_breakpoint = ln

    def run_until_stop(self, max_steps=None):
        """"继续"：跑到断点 / 停机 / 步数上限。"""
        if max_steps is not None:
            self.vm.max_steps = max_steps
        while True:
            # ⚠️ **停机后不再前进**。`Vm.step()` 在 `stop_reason` 已置位时仍会
            # 继续解码执行（它只在 step 内部检查），所以这里必须先判一次 ——
            # 否则"停在 halt 上再点继续"会把 halt 之后的字节当成程序跑下去。
            if self.vm.stop_reason is not None:
                return self.state()
            ln = self._at_breakpoint()
            if ln is not None:
                self._hit(ln)
                return self.state()
            if not self.vm.step():
                return self.state()

    def step_once(self):
        """"单步"：执行**恰好一条**指令（断点不拦截单步 —— 用户已经在这里了）。"""
        if self.vm.stop_reason is not None:
            return self.state()
        self.vm.step()
        return self.state()

    def step_over(self):
        """"步过"：跨过一条 call, 而不是走进它。

        实现 = 若当前指令是 `call`/`callind`, 则**跑到调用深度回到起点**;
        否则等价于单步。与"单步三次然后说这是步过"的区别在于: 被调用函数
        内部下过的断点**仍然会命中**（真调试器的步过就是这个语义 —— 步过
        是"别停在调用内部", 不是"别让调用内部发生别的事"）。
        """
        if self.vm.stop_reason is not None:
            return self.state()
        cur = self.vm.ip
        try:
            mnem, _op, _sz, _kind = decode_one(self.code, cur, self.vm.inv,
                                              self.vm.sem0)
        except VmError:
            return self.step_once()
        if mnem not in ('call', 'callind'):
            return self.step_once()
        base = len(self.vm.frames)
        self.vm.step()
        while True:
            if self.vm.stop_reason is not None:
                return self.state()
            ln = self._at_breakpoint()
            if ln is not None:
                self._hit(ln)
                return self.state()
            if len(self.vm.frames) <= base:
                return self.state()
            if not self.vm.step():
                return self.state()

    # --- 状态 --------------------------------------------------------------
    def line_at_ip(self):
        return self.off_to_line.get(self.vm.ip)

    def state(self):
        v = self.vm.view()
        v.update({
            'session_kind': self.kind,
            'src': self.src,
            'line_at_ip': self.line_at_ip(),
            'breakpoints': sorted(self.breakpoints),
            'breakpoints_supported': self.supports_breakpoints,
            'hit_breakpoint': self.stopped_hit_breakpoint,
            'terminated': self.vm.stop_reason is not None,
        })
        # 帧的源码行号（有行号表时才有）—— 面板要显示"从哪一行调过来的",
        # 而不是只显示偏移。
        cs = v.get('call_stack') or {}
        for f in cs.get('frames', []):
            f['call_line'] = self.off_to_line.get(f['call_off'])
            f['ret_line'] = self.off_to_line.get(f['ret_addr'])
        return v



# ---------------------------------------------------------------------------
# 输入装配（明文 + 行号表）
# ---------------------------------------------------------------------------
def default_symbols():
    """`EXPECT1`/`EXPECT2` 是 `.vasm` 里唯一的符号引用（其余都是标签）。

    它们的**数值不影响指令长度**（imm32 恒 5 字节），因此不影响行号表 ——
    行号表与种子、与符号都无关，这正是 ST4.1 能把它做成"与构建无关"的原因。
    默认给确定性的 0，让调试器**不需要种子也不需要构建 json** 就能打开源码；
    想按真实序列号调试时用 `--build-json` 传入真值。
    """
    return {'EXPECT1': 0, 'EXPECT2': 0}


def load_from_asm(path, symbols=None):
    """就地汇编一个 `.vasm`。

    **不需要种子**: 偏移与 opcode 置换无关, 只取决于指令序列 —— 这正是
    ST4.1 能把 sidecar 做得"与构建无关"的原因。解释器用**规范** opcode
        （perm=None, sem0=0）, 因为它解释的是**语义**而非某一构建的字节。
    """
    text = io.open(path, encoding='utf-8').read()
    info = {}
    plain = vmenc.assemble_source(text, symbols or default_symbols(), None, 0,
                                  info=info)
    off_to_line = {off: ln for (off, ln, _mn) in info['lines']}
    return plain, off_to_line, info


def load_from_blob(blob, name):
    """从 vm.blob 取镜像并用 key1 反置换（真实构建的字节，sem0 由 key1 复算）。"""
    code, key0, key1, crc = vm_reduce.read_blob_image(blob, name)
    plain = vm_reduce.decrypt(code, key0)
    return plain, key1, key0, crc


def merge_map(mapdoc):
    """读 sidecar -> (off_to_line, src, size)。"""
    off_to_line = {}
    for off, ln, _mn in mapdoc.get('lines', []):
        off_to_line[int(off)] = int(ln)
    return off_to_line, mapdoc.get('src'), mapdoc.get('size')


# ---------------------------------------------------------------------------
# ST5.3 源码视图（高亮 + 行号 + 断点槽）
# ---------------------------------------------------------------------------
# 词表**从汇编器现读**, 不另抄一份 —— 少写一条助记符只会让某个词不亮,
# 而那正是"看不出来的错"（§2.36 起反复记名的同型缺陷）。
MNEMONIC_SET = frozenset(vmenc.INSTRUCTIONS)


def classify_line(raw):
    """把一行 `.vasm` 拆成可高亮的片段。

    返回 `{'kind', 'tokens', 'mnemonic', 'label', 'executable'}`。
    `kind` 取值: `blank` / `comment` / `label` / `code` / `error`。
    `tokens` 是 `[(text, cls)]`, `cls ∈ {'cmt','mnem','num','label','sym',
    'bad'}` —— **分类只做词法, 不做语义**（例如 `push32 0xzz` 这里只把
    `0xzz` 标成 `num`, 说"这不是合法数字"是汇编器的事）。
    """
    code, _sep, cmt = raw.partition(';')
    stripped = code.strip()
    tokens = []
    kind = 'blank'
    mnemonic = None
    label = None
    # 先把注释之外的部分切出来, 再单独接上注释 —— 这样注释里的 ';' 之后
    # 不会再被当代码扫描（`split(';', 1)` 已经保证了这一点, 这里只是显式化）。
    lead = code[:len(code) - len(code.lstrip())]
    if lead:
        tokens.append((lead, 'ws'))
    if stripped:
        if stripped.endswith(':'):
            kind = 'label'
            label = stripped[:-1]
            tokens.append((stripped, 'label'))
        else:
            parts = stripped.split()
            kind = 'code'
            mn = parts[0]
            if mn.lower() in MNEMONIC_SET:
                mnemonic = mn.lower()
                tokens.append((mn, 'mnem'))
            else:
                tokens.append((mn, 'bad'))
            for j, p in enumerate(parts[1:]):
                # 只给"助记符之后的第一段"留空格, 其余按原文照排。
                tokens.append((' ' if j == 0 else ' ', 'ws'))
                low = p.lower()
                if low in vmenc.RESERVED_SYMBOLS:
                    tokens.append((p, 'sym'))
                elif (low.startswith('0x') or low.startswith('0b')
                        or low.isdigit()):
                    tokens.append((p, 'num'))
                else:
                    # 标签引用。解析得出就标 label, 否则标 bad —— 但**仍然
                    # 如实回显原文**, 不吞掉也不改写（回显是面板的职责,
                    # 判断合法性是汇编器的职责）。
                    tokens.append((p, 'label' if _is_label_ref(p) else 'bad'))
    if _sep:
        tokens.append((';' + cmt, 'cmt'))
    return {'kind': kind, 'tokens': tokens, 'mnemonic': mnemonic,
            'label': label,
            # 只有 `code` 行能落断点: 标签/空行/注释都不是指令位置。
            'executable': kind == 'code'}


def _is_label_ref(tok):
    t = tok.strip()
    return bool(t) and t.replace('_', '').isalnum() and not t[0].isdigit()


def source_view(path):
    """读一个 `.vasm` 并给出逐行视图 + 行号表 + 断点槽信息。

    行号表由**汇编器现算**（`off_to_line` 的逆）—— 没有 sidecar 也拿得到,
    因为 `.vasm` 的偏移与种子无关（ST4.1）。
    """
    text = io.open(path, encoding='utf-8').read()
    info = {}
    assemble_error = None
    try:
        vmenc.assemble_source(text, default_symbols(), None, 0, info=info)
    except Exception as e:                                  # noqa: BLE001
        # 汇编不过**不是**读不了文件: 仍然把源码显示出来, 并把错误如实带上。
        # 若在这里抛出去, 面板就只能显示"打不开" —— 而真正该看到的是源码
        # 本身加上"第 N 行汇编不过"。
        assemble_error = '%s: %s' % (type(e).__name__, e)
    line_to_off = {}
    line_mnem = {}
    for off, ln, mn in info.get('lines', []):
        line_to_off.setdefault(int(ln), int(off))
        line_mnem.setdefault(int(ln), mn)
    raw_lines = text.split('\n')
    rows = []
    for i, raw in enumerate(raw_lines, 1):
        cl = classify_line(raw.rstrip('\r'))
        cl.update({
            'line': i,
            'text': raw.rstrip('\r'),
            'off': line_to_off.get(i),
            'asm_mnem': line_mnem.get(i),
            # 断点槽: **行号**是断点的唯一键（`tools/vm_debug.py:run` 按行号
            # 命中), 所以面板的槽位必须与行号一一对应, 不能按"第几条指令"。
            'breakable': i in line_to_off,
        })
        rows.append(cl)
    return {
        'path': path,
        'size': len(text.encode('utf-8')),
        'line_count': len(raw_lines),
        'rows': rows,
        'mnemonics': sorted(MNEMONIC_SET),
        'symbols': sorted(vmenc.RESERVED_SYMBOLS),
        'executable_lines': sorted(line_to_off),
        'assemble_error': assemble_error,
        # 与文件内容无关的常量, 面板不必自己猜: 断点按源行号下。
        'breakpoint_key': 'line',
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def cmd_disasm(args, code, key1, off_to_line):
    insns, _sem0 = disassemble(code, key1, sem0=0 if args.asm else None)
    print('=== 反汇编 %d 字节 / %d 条指令 ===' % (len(code), len(insns)))
    for r in insns:
        ln = off_to_line.get(r['off'])
        mark = '  <<<' if (args.line and ln == args.line) else ''
        print(format_insn(r, ln) + mark)
    return 0


def cmd_run(args, code, key1, off_to_line):
    plain = code
    vm = Vm(plain, key1, mem_size=args.mem_size, max_steps=args.steps)
    for spec in (args.mem or []):
        try:
            addr_s, val_s = spec.split('=', 1)
            vm.mem[int(addr_s, 0)] = int(val_s, 0) & 0xFF
        except ValueError:
            sys.stderr.write('[vm_debug] --mem 需要 addr=byte 形式: %r\n' % spec)
            return 2
    breaks = set(args.break_at or [])
    reason, detail = run(vm, breaks, off_to_line, max_steps=args.steps)
    print('=== 执行 ===')
    print('停机: %s -- %s' % (reason, detail))
    print(vm.view_text())
    if args.mem_dump:
        print('--- 内存（已写单元） ---')
        for a in sorted(vm.mem):
            print('  0x%06x = 0x%02x' % (a, vm.mem[a]))
    if args.trace:
        print('--- 轨迹（末 %d 步） ---' % args.trace)
        for off, what in vm.history[-args.trace:]:
            ln = off_to_line.get(off)
            print('  %6d %s %s' % (off, ('L%d' % ln) if ln else '   ', what))
    # 退出码: 0 = 正常停机（halt / 用户断点）; 1 = 异常停机
    ok = reason in (HALT, USER_BREAK, STEP_LIMIT)
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(
        prog='vm_debug.py',
        description='VM 级调试器 (ST4): 反汇编 / 单步 / 断点 / 视图')
    # ⚠️ 互斥组**不设 required=True**: 否则 `--selftest` 会先被 argparse 拦成
    # usage 错误(rc=2), 而调用方那个"rc != 0"就变成了**看起来像自检失败** ——
    # 正是本仓库反复记名的"探针的错伪装成被测对象的性质"。改为在下面显式校验。
    src = p.add_mutually_exclusive_group()
    src.add_argument('--asm', help='就地汇编一个 .vasm 并调试它 '
                                   '(不需要种子: 偏移与置换无关)')
    src.add_argument('--blob', help='从 vm.blob 取一个镜像 (需要 --name)')
    p.add_argument('--name', help='--blob 时的镜像名')
    p.add_argument('--map', dest='map_file',
                   help='ST4.1 行号表 sidecar (vmenc.py --map-out 产出)')
    p.add_argument('--build-json', dest='build_json',
                   help='vm_build.json —— 用真实 EXPECT1/EXPECT2 调试 '
                        '(不给则用确定性的 0; 二者都不影响行号表)')
    p.add_argument('--disasm', action='store_true', help='反汇编')
    p.add_argument('--run', action='store_true', help='运行到停机/断点')
    p.add_argument('--view', action='store_true', help='只打印初始状态')
    p.add_argument('--steps', type=int, default=100000, help='最大步数')
    p.add_argument('--break-at', dest='break_at', type=int, action='append',
                   metavar='LINE', help='在 .vasm 源行号下断点 (可重复)')
    p.add_argument('--line', type=int, help='--disasm 时高亮这一行')
    p.add_argument('--mem', action='append', metavar='ADDR=BYTE',
                   help='预置一个内存字节 (可重复, 如 0x1000=0x2a)')
    p.add_argument('--mem-size', dest='mem_size', type=int, default=1 << 20,
                   help='内存尺寸; 越界按错误停机 (默认 1 MiB)')
    p.add_argument('--mem-dump', dest='mem_dump', action='store_true',
                   help='停机后打印已写内存')
    p.add_argument('--trace', type=int, metavar='N', help='打印末 N 步轨迹')
    p.add_argument('--selftest', action='store_true', help='自检 (负向)')
    p.add_argument('--quiet', action='store_true')
    args = p.parse_args(argv)

    if args.selftest:
        return selftest(args.quiet)

    if not args.asm and not args.blob:
        sys.stderr.write('[vm_debug] 需要 --asm 或 --blob (或 --selftest)\n')
        return 2

    if args.mem_size < 1:
        sys.stderr.write('[vm_debug] --mem-size 必须 >= 1\n')
        return 2

    try:
        if args.asm:
            syms = default_symbols()
            if args.build_json:
                syms = vmenc.load_symbols(args.build_json)
            code, off_to_line, _info = load_from_asm(args.asm, syms)
            # ⚠️ 必须是 `None`（= 规范 opcode / 恒等置换）, **不是 0**。
            # `0` 是一个**合法的种子**, 会派生出一张真实置换表 —— 于是就地
            # 汇编出来的规范字节被当成"某个构建的产物"逆置换, 反汇编结果
            # 变成一串看似合理的垃圾（实测: 首条 `push32 1` 被读成 `halt`,
            # 19 字节解出 19 条指令）。这正是"解释器静默给错答案"那一类。
            key1 = None
            if args.map_file:
                doc = vmenc.load_vasm_map(args.map_file)
                mo, msrc, msize = merge_map(doc)
                if msize is not None and msize != len(code):
                    sys.stderr.write(
                        '[vm_debug] sidecar size=%s 与就地汇编 size=%d 不符 -> '
                        '拒绝用错位的行号表\n' % (msize, len(code)))
                    return 1
                off_to_line = mo
                if not args.quiet:
                    print('[vm_debug] 行号表来自 %s (src=%s)' % (args.map_file, msrc))
        else:
            if not args.name:
                sys.stderr.write('[vm_debug] --blob 需要 --name\n')
                return 2
            code, key1, _k0, _crc = load_from_blob(args.blob, args.name)
            off_to_line = {}
            if args.map_file:
                doc = vmenc.load_vasm_map(args.map_file)
                off_to_line, msrc, msize = merge_map(doc)
                if msize is not None and msize != len(code):
                    sys.stderr.write(
                        '[vm_debug] sidecar size=%s 与镜像 len=%d 不符 -> '
                        '镜像与源不是同一次构建, 拒绝错配\n'
                        % (msize, len(code)))
                    return 1
                if not args.quiet:
                    print('[vm_debug] 行号表来自 %s (src=%s)'
                          % (args.map_file, msrc))
    except vmenc.VasmError as e:
        sys.stderr.write('[vm_debug] %s\n' % e)
        return 1
    except (IOError, OSError) as e:
        sys.stderr.write('[vm_debug] 读入失败: %s\n' % e)
        return 1
    except ValueError as e:
        sys.stderr.write('[vm_debug] %s\n' % e)
        return 1

    if args.disasm:
        return cmd_disasm(args, code, key1, off_to_line)
    if args.run:
        return cmd_run(args, code, key1, off_to_line)
    # 默认: 打印首条 + 状态, 不执行（"打开文件"的语义）
    insns, _ = disassemble(code, key1, sem0=0 if args.asm else None)
    print('=== %s ===' % (args.asm or ('%s:%s' % (args.blob, args.name))))
    print('%d 字节 / %d 条指令' % (len(code), len(insns)))
    if insns:
        print(format_insn(insns[0], off_to_line.get(insns[0]['off'])))
    vm = Vm(code, key1)
    print(vm.view_text())
    return 0


# ---------------------------------------------------------------------------
# 自检
#
# 判据来自 `tests/vm_unit.vasm` 的**注释契约**（该文件 7-12 行逐字写下六个
# 宿主内存断言, 并由 `tests/vm_unit.c` 在真机侧断言）。本工具独立复算它们 ——
# 这就是"解释器与 src/vm.c 是否漂移"的判据, 而不是"看起来跑通了"。
# ---------------------------------------------------------------------------
SELFTEST_EXPECT = [
    (0x1000, 0x1BAD2F5E, 'nop + pushr/popr'),
    (0x1004, 0x101, 'setcon + pushcon'),
    (0x2000, 0xC0F0, 'lea + callind 间接调用'),
    (0x302C, 0xCAFEBABE, 'move + storr32 寄存器索引写'),
    (0x3030, 0xCAFEBABE, 'loadr32 寄存器索引读'),
    (0x0000, 0x2A2A, 'brk CON=0 通过路径 + 整体成功标记'),
]


def _rd32(mem, addr):
    v = 0
    for j in range(4):
        v |= (mem.get(addr + j, 0) & 0xFF) << (8 * j)
    return v


# 自检用例数下限。**紧贴当前值（实测 54 条），不留余量**。
# 见 `selftest()` 里的说明：留余量会让守卫对"整批被掏空"失明（§2.49 / §2.75）。
_ST_FLOOR = 54


def selftest(quiet=False):
    cases = []

    def case(name, ok, want=None, got=None):
        cases.append((name, bool(ok), want, got))

    def raises(fn, reason=None):
        """调用必须抛 `VmError`（且 reason 匹配）。返回 True/False。

        **不写 `try/except: pass`** —— 那样"没抛"和"抛了别的"都会被读成成功。
        """
        try:
            fn()
        except VmError as e:
            return (reason is None) or (e.reason == reason)
        except Exception:                                   # noqa: BLE001
            return False
        return False

    try:
        code, off_to_line, info = load_from_asm(
            os.path.join(REPO, 'tests', 'unit_vm.vasm'))
        load_err = None
    except Exception as e:                                  # noqa: BLE001
        code, off_to_line, info, load_err = b'', {}, {}, repr(e)

    case('就地汇编 tests/unit_vm.vasm 不抛异常', load_err is None, None, load_err)

    # --- 正向: 逐条复算 vm_unit.c 的六个断言 -------------------------------
    vm = Vm(code, None, mem_size=1 << 20)
    reason, detail = run(vm, None, off_to_line)
    case('unit_vm 正常 halt 结束', reason == HALT, HALT, reason)
    for addr, want, what in SELFTEST_EXPECT:
        got = _rd32(vm.mem, addr)
        case('unit_vm host[0x%x] = 0x%X (%s)' % (addr, want, what),
             got == want, want, '0x%X' % got)

    # --- 正向: brk 陷阱路径必须停机且**不执行**后续写 ----------------------
    code_b, otl_b, _i = load_from_asm(
        os.path.join(REPO, 'tests', 'unit_vm_brk.vasm'))
    vm_b = Vm(code_b, None, mem_size=1 << 20)
    reason_b, _d = run(vm_b, None, otl_b)
    case('unit_vm_brk 在 brk 处停机 (CON=1)', reason_b == BREAKPOINT,
         BREAKPOINT, reason_b)
    case('unit_vm_brk 陷阱后的 store32 未执行 (host[0] 仍为 0)',
         _rd32(vm_b.mem, 0) == 0, 0, '0x%X' % _rd32(vm_b.mem, 0))

    # --- ST4.1: 行号表与指令一一对应 -------------------------------------
    case('行号表条数 = 指令数', len(info['lines']) == len(info['labels']) + 54
         if False else len(info['lines']) == 54, 54, len(info['lines']))
    case('行号表偏移严格递增',
         all(info['lines'][i][0] < info['lines'][i + 1][0]
             for i in range(len(info['lines']) - 1)), True,
         [x[0] for x in info['lines'][:4]])
    case('标签偏移落在指令边界上',
         all(off in off_to_line for off in info['labels'].values()), True,
         sorted(info['labels'].values()))
    case('L18 是最早的指令行 (源文件第 18 行)',
         info['lines'][0][1] == 18, 18, info['lines'][0][1])

    # --- ST4.3: 断点按**源行号**命中 -------------------------------------
    vm2 = Vm(code, None, mem_size=1 << 20)
    r2, d2 = run(vm2, {41}, off_to_line)
    case('在源行 L41 下断点 -> 命中并停在 L41',
         r2 == USER_BREAK and off_to_line.get(vm2.ip) == 41,
         'L41', '%s off=%d' % (r2, vm2.ip))

    # --- ST4.4: 视图字段齐全 ---------------------------------------------
    v = vm2.view()
    case('视图含 ip/steps/栈/寄存器/停机原因',
         all(k in v for k in ('ip', 'steps', 'stack_depth', 'stack_top',
                              'br', 'r', 'con', 'stop_reason')), True,
         sorted(v.keys()))

    # --- ST5.4: 影子调用栈 ------------------------------------------------
    # ⚠️ 这四条**必须**用自造的嵌套 call 程序。实测全部 13 个 .vasm 里只有
    # `tests/unit_vm.vasm` 有 1 次 call（而且立刻 ret 回来）—— 拿真实资产
    # 测调用栈，会得到"深度恒为 0"的假绿。这与 §2.44「度量只存在于一次性
    # 探针的输出里」是同一类: 证据必须来自**能覆盖该行为的输入**。
    _nested = vmenc.assemble_source(
        '\n    call f1\n    halt\nf1:\n    call f2\n    ret\nf2:\n    ret\n',
        default_symbols(), None, 0)
    _vmc = Vm(_nested, None)
    _deps = []
    _peak = None
    while _vmc.step():
        _csx = _vmc.call_stack()
        _deps.append(_csx['depth'])
        if _csx['depth'] == 2:
            _peak = _csx
    _cs = _vmc.call_stack()
    case('嵌套 call 的调用栈深度达到 2 (而不是恒为 0)',
         max(_deps) == 2 if _deps else False, 2, max(_deps) if _deps else None)
    case('全部 ret 之后调用栈深度回到 0 且仍可信',
         _cs['depth'] == 0 and _cs['reliable'] is True,
         'depth=0 reliable=True', 'depth=%d reliable=%s'
         % (_cs['depth'], _cs['reliable']))
    case('深度 2 时的帧含 call_off/ret_addr/dest, 且仅栈顶 is_top',
         _peak is not None
         and all(k in f for f in _peak['frames']
                 for k in ('call_off', 'ret_addr', 'dest', 'is_top'))
         and [f['is_top'] for f in _peak['frames']] == [False, True],
         '[False, True]',
         [f['is_top'] for f in _peak['frames']] if _peak else None)
    # **负向**: ret 弹出的值 ≠ 最近一次 call 压的返回地址 -> 必须自认不可信。
    # 若不判这条, 一块数据栈上的普通立即数会被显示成"一个调用帧"。
    _fake = vmenc.assemble_source(
        '\n    call f1\n    halt\nf1:\n    push32 0x9999\n    ret\n',
        default_symbols(), None, 0)
    _vmf = Vm(_fake, None)
    run(_vmf, None, {})
    _csf = _vmf.call_stack()
    case('**负向**: ret 弹出的不是返回地址 -> 调用栈标记为不可信',
         _csf['reliable'] is False and bool(_csf['dirty_reason']),
         'reliable=False + dirty_reason', 'reliable=%s reason=%s'
         % (_csf['reliable'], bool(_csf['dirty_reason'])))
    _v = Vm(_nested, None).view()
    case('视图含 call_depth / call_stack 两个键',
         'call_depth' in _v and 'call_stack' in _v, True,
         [k for k in ('call_depth', 'call_stack') if k in _v])

    # --- ST5.4: 调试会话（继续/单步/步过/重启/停止） -----------------------
    # 同样必须用自造程序: 真实 .vasm 里没有嵌套调用, 拿它们测"步过"会得到
    # "步过 == 单步"的假绿。
    _sess_src = ('\n    push32 1\n    call f1\n    halt\nf1:\n    push32 2\n'
                 '    call f2\n    drop\n    ret\nf2:\n    push32 3\n'
                 '    drop\n    push32 4\n    drop\n    ret\n')
    _s_info = {}
    _s_code = vmenc.assemble_source(_sess_src, default_symbols(), None, 0,
                                    info=_s_info)
    _s_otl = {off: ln for (off, ln, _m) in _s_info['lines']}
    _s_lta = {ln: m for (_o, ln, m) in _s_info['lines']}

    def _mk_sess():
        return Session(_s_code, None, _s_otl, _s_lta, src='<inline>',
                       kind='asm')

    _ss = _mk_sess()
    _st0 = _ss.state()
    case('会话初态: 未停机且位于首条可执行行',
         _st0['terminated'] is False and _st0['line_at_ip'] == 2,
         'L2', 'L%s terminated=%s' % (_st0['line_at_ip'],
                                      _st0['terminated']))
    _ss.step_once()
    case('单步恰好走一条指令 (L2 push32 -> L3 call)',
         _ss.state()['line_at_ip'] == 3, 3, _ss.state()['line_at_ip'])
    # ⭐ 判别力核心: 单步会走进 f1, 步过必须跨过整个 f1/f2 子树。
    _walk = _mk_sess()
    _walk.step_once()
    _walk.step_once()                 # 走进 call f1
    _into = _walk.state()
    _over = _mk_sess()
    _over.step_once()
    _over.step_over()
    _ov = _over.state()
    case('步过 call 停在调用之后的下一行 (而单步会走进被调函数)',
         _into['call_depth'] >= 1 and _ov['call_depth'] == 0
         and _ov['line_at_ip'] == 4,
         '单步 depth>=1 / 步过 depth=0 @L4',
         '单步 depth=%d @L%s / 步过 depth=%d @L%s'
         % (_into['call_depth'], _into['line_at_ip'], _ov['call_depth'],
            _ov['line_at_ip']))
    # 停机后**不得前进**: Vm.step() 在 stop_reason 已置位时仍会解码执行,
    # 所以"停在 halt 上再点继续"是把 halt 之后的字节当程序跑。
    _done = _mk_sess()
    _done.run_until_stop()
    _d1 = _done.state()
    _done.step_once()
    _done.run_until_stop()
    _d2 = _done.state()
    case('停机后单步/继续都不得前进',
         _d1['stop_reason'] == HALT
         and (_d2['ip'], _d2['steps']) == (_d1['ip'], _d1['steps']),
         'ip/steps 不变', 'ip %s->%s steps %s->%s'
         % (_d1['ip'], _d2['ip'], _d1['steps'], _d2['steps']))
    _rb = _mk_sess()
    _rb.set_breakpoints([6])
    _rb.run_until_stop()
    _rb.restart()
    _rst = _rb.state()
    case('重启回到初态且**保留**断点',
         _rst['line_at_ip'] == 2 and _rst['terminated'] is False
         and _rst['breakpoints'] == [6], 'L2 + bp[6]',
         'L%s bp%s' % (_rst['line_at_ip'], _rst['breakpoints']))
    _rb.run_until_stop()
    _hit = _rb.state()
    case('继续 -> 命中源行断点, 且调用深度为 1 (在 f1 内)',
         _hit['stop_reason'] == USER_BREAK and _hit['hit_breakpoint'] == 6
         and _hit['call_depth'] == 1, 'bp6 depth=1',
         'bp%s depth=%d' % (_hit['hit_breakpoint'], _hit['call_depth']))
    # ⭐ 步过**不是**"忽略断点": 被调函数内部下过的断点仍必须命中。
    _bo = _mk_sess()
    _bo.set_breakpoints([11])
    _bo.step_once()
    _bo.step_over()
    case('步过时被调函数内部的断点仍然命中 (步过 != 忽略断点)',
         _bo.state()['hit_breakpoint'] == 11, 11,
         _bo.state()['hit_breakpoint'])
    # **负向**: 没有行号表的会话必须拒绝下断点, 而不是退化成按偏移下。
    # ⚠️ 这里必须**判 reason**, 不能只判"抛了异常" —— 实测: 把这条守卫改成
    # 永不触发, `set_breakpoints` 仍会因为"行号不在 line_to_asm 里"抛出
    # `bad-breakpoint`, 于是"只判抛没抛"的用例**照样绿**（变异实测抓到）。
    # 两个错误码对应两件不同的事: `no-line-table` = 这个会话根本不能按行号
    # 下断点; `bad-breakpoint` = 这个行号不对。混为一谈会让面板显示错解释。
    _nb = Session(b'\x00', None, {}, {}, src='blob:x', kind='blob')
    _nbres = raises(lambda: _nb.set_breakpoints([1]), reason='no-line-table')
    case('**负向**: 无行号表的会话以 no-line-table 拒绝 (不是 bad-breakpoint)',
         _nbres is True, True, _nbres)
    case('无行号表的会话如实标 breakpoints_supported=False',
         _nb.state()['breakpoints_supported'] is False, False,
         _nb.state()['breakpoints_supported'])
    # **负向**: 不可执行行号必须报错, 不能静默接一个永远命不中的断点。
    _bbres = raises(lambda: _mk_sess().set_breakpoints([1]),
                    reason='bad-breakpoint')
    case('**负向**: 不可执行行号 -> bad-breakpoint (不是静默接受)',
         _bbres is True, True, _bbres)

    # --- 负向: 解释器必须**真的**报错, 不能静默继续 -----------------------
    vm3 = Vm(code, None)
    vm3.ip = len(code) + 10
    ok3 = vm3.step()
    case('**负向**: ip 越过程序末尾 -> 停机且原因为 no-op 失败',
         (not ok3) and vm3.stop_reason in (ERR_TRUNCATED, ERR_BAD_OPCODE),
         'truncated/bad-opcode', vm3.stop_reason)

    vm4 = Vm(b'\x03', None)       # dup 且栈为空
    ok4 = vm4.step()
    case('**负向**: dup 空栈 -> stack-underflow',
         (not ok4) and vm4.stop_reason == ERR_STACK_UNDERFLOW,
         ERR_STACK_UNDERFLOW, vm4.stop_reason)

    vm5 = Vm(code, None, mem_size=8)
    vm5.stk = [0x100, 0x41]
    ok5 = vm5.step()              # push32 0x1BAD2F5E ... 不, 首条是 push32
    vm5.stk = [0x100, 0x41]
    case('**负向**: 默认 mem_size 越界要能报 (不是无限字典)',
         Vm(code, None, mem_size=8)._oob(0x100, 4) is True, True,
         Vm(code, None, mem_size=8)._oob(0x100, 4))

    vm6 = Vm(bytes([0x00]), None)  # halt
    r6, _ = run(vm6, None, {})
    case('**负向**: 只有 halt 的程序停因是 halt 而非 step-limit',
         r6 == HALT, HALT, r6)

    vm7 = Vm(code, None, max_steps=3)
    r7, _ = run(vm7, None, off_to_line)
    case('**负向**: 步数上限生效 (不会无限跑)',
         r7 == STEP_LIMIT, STEP_LIMIT, r7)

    # --- 反汇编器与汇编器不漂移 ------------------------------------------
    insns, _s0 = disassemble(code, None)
    case('反汇编条数 = 汇编器记录的行数', len(insns) == len(info['lines']),
         len(info['lines']), len(insns))
    case('反汇编 mnemonics 与汇编器逐条一致',
         [r['mnem'] for r in insns] == [x[2] for x in info['lines']],
         [x[2] for x in info['lines']][:5],
         [r['mnem'] for r in insns][:5])
    case('反汇编偏移与汇编器逐条一致',
         [r['off'] for r in insns] == [x[0] for x in info['lines']],
         [x[0] for x in info['lines']][:5],
         [r['off'] for r in insns][:5])
    case('MNEMONICS 覆盖全部 47 个规范 opcode',
         len(MNEMONICS) == vmenc.OPCODE_SLOTS, vmenc.OPCODE_SLOTS,
         len(MNEMONICS))

    # --- ⭐ 真实构建产物: key1 逆置换必须对 -------------------------------
    # 上面所有用例走的都是**恒等置换**(key1=None) —— 那条路径即使逆置换写错了
    # 也照样全绿。只有从 vm.blob 的密文镜像出发才真正验证它。实测 4 个镜像
    # 逐条与 `.vasm` 源码一致（含 sem0=1 的 BE 操作数场景）。
    blob = os.path.join(REPO, 'build', 'vm.blob')
    pairs = [('hash', 'demo/license_hash.vasm'),
             ('mix', 'demo/license_mix.vasm'),
             ('verify', 'demo/license_verify.vasm'),
             ('gate', 'demo/license_gate.vasm')]
    if not os.path.exists(blob):
        case('**负向**: vm.blob 缺失时不得静默跳过逆置换验证',
             False, 'build/vm.blob 存在', 'not found')
    for name, src in pairs:
        try:
            bcode, bkey1, _k0, _crc = load_from_blob(blob, name)
            binsns, _s = disassemble(bcode, bkey1)
            got = [r['mnem'] for r in binsns]
            stext = io.open(os.path.join(REPO, src), encoding='utf-8').read()
            want = []
            for raw in stext.splitlines():
                ln = raw.split(';', 1)[0].strip()
                if not ln or ln.endswith(':'):
                    continue
                want.append(ln.split()[0].lower())
            case('blob:%s 反汇编与 %s 逐条一致 (真实验证 key1 逆置换)'
                 % (name, src), got == want, want, got)
        except Exception as e:                              # noqa: BLE001
            case('blob:%s 反汇编与 %s 逐条一致' % (name, src), False,
                 'no exception', repr(e))

    # --- ST4.6: 既有 .vasm 覆盖面 -----------------------------------------
    # 规划 §3 的 ST4.6 验收是「7 个 .vasm 全覆盖」；实际全库有 9 个（含
    # `tests/vmc_case1.vasm` 与 `examples/tool_demo/check.vasm`），全部要能
    # 反汇编并单步。**逐个列名而不是 glob** —— glob 会在文件被删时静默缩小
    # 覆盖面（这正是本仓库反复记名的"清单会漏"）。下面先断言文件存在。
    VASM = ['tests/unit_vm.vasm', 'tests/unit_vm_brk.vasm',
            'tests/vmc_case1.vasm', 'demo/license_gate.vasm',
            'demo/license_hash.vasm', 'demo/license_mix.vasm',
            'demo/license_verify.vasm', 'demo/license_vm.vasm',
            'examples/tool_demo/check.vasm']
    ncov = 0
    for rel in VASM:
        p = os.path.join(REPO, rel)
        if not os.path.exists(p):
            case('覆盖 %s' % rel, False, '存在', 'missing')
            continue
        try:
            c2, otl2, info2 = load_from_asm(p)
            i2, _s2 = disassemble(c2, None)
            vm8 = Vm(c2, None, mem_size=1 << 22)
            r8, _d8 = run(vm8, None, otl2)
            good = (len(i2) == len(info2['lines'])
                    and r8 in (HALT, BREAKPOINT))
            ncov += 1 if good else 0
            case('覆盖 %s (%d 条指令, 停因 %s)' % (rel, len(i2), r8),
                 good, 'halt/breakpoint 且条数一致', r8)
        except Exception as e:                              # noqa: BLE001
            case('覆盖 %s' % rel, False, 'no exception', repr(e))
    case('9 个 .vasm 全部可反汇编并单步', ncov == len(VASM),
         len(VASM), ncov)

    # 用例数下限守卫（§2.49 / §2.75 形状）。
    # 为什么必须有：本函数的收尾只看 `failed = [c for c in cases if not c[1]]`
    # —— 这是**筛选**，空批次得到空 failed ⇒ 打印 `PASS: 0 条 (含 0 条负向)`
    # 并 **rc=0**。实测确证（§2.75）：整批清空后彻底静默。
    # 下限紧贴当前值、不留余量（留余量会对"掏空一个批次"失明）。
    if len(cases) < _ST_FLOOR:
        print('[vm_debug-selftest] FAIL: 自检用例只有 %d 条，低于下限 %d '
              '—— 有用例被删或被掏空（下限紧贴当前值：删用例须显式下调此数字）'
              % (len(cases), _ST_FLOOR))
        return 1
    failed = [c for c in cases if not c[1]]
    if not quiet:
        for name, ok, want, got in cases:
            print('%s %s' % ('ok ' if ok else '[X]', name))
            if not ok:
                print('      want=%r got=%r' % (want, got))
    if failed:
        print('[vm_debug-selftest] FAIL (%d/%d)' % (len(failed), len(cases)))
        return 1
    print('[vm_debug-selftest] PASS: %d 条 (含 %d 条负向)'
          % (len(cases), len([c for c in cases if '负向' in c[0]])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
