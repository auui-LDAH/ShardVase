#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/vmc.py — 类 C 迷你编译器 -> VM 字节码 (M2, ADVANCED.md §4)

把"受限 C 子集"的校验函数编译成 VASM (tools/vmenc.py 的指令集),
替代手写 .vasm。支持:

  语法:
    uint64 name = expr;     局部变量 (uint64, 自动分配宿主内存槽)
    name = expr;            赋值
    if (cond) { } else { }  条件 (cond 为 uint64, 0=假)
    while (cond) { }        循环
    return expr;            返回 (写 host.result@52, 见下)
    uint64 x = 5;           声明+初始化

  表达式: 字面量(dec/0x/0b) / 变量 / 二元 + - * / % ^ & | << >>
          比较 == != < <= > >= / 逻辑 && || ! / 括号
  内置函数 (访问宿主内存):
    mem8(addr) mem32(addr) mem64(addr)  读宿主内存
    store8(addr,val) store32(addr,val) store64(addr,val)  写宿主内存

  return 语义: 把值写 host[52] (与现有 VM result 约定一致)。
  宿主内存布局: 变量自动分配从偏移 0x40 起; 与宿主约定由输出布局表 JSON
  给出 (vmc.py 输出 .vasm + .layout.json)。

CLI:
    python tools/vmc.py <in.vmc> <out.vasm> <out.layout.json>
"""

import json
import re
import sys

# ---------------------------------------------------------------------------
# 词法
# ---------------------------------------------------------------------------
KEYWORDS = {'uint64', 'if', 'else', 'while', 'return'}
PUNCT = {'{', '}', '(', ')', ';', '=', '+', '-', '*', '/', '%', '^', '&',
         '|', '<', '>', '!', '<<', '>>', '==', '!=', '<=', '>=', '&&', '||'}


class VmcError(Exception):
    pass


def tokenize(src):
    toks = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        if src.startswith('//', i):
            j = src.find('\n', i)
            i = n if j < 0 else j + 1
            continue
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            if j < 0:
                raise VmcError('unterminated comment')
            i = j + 2
            continue
        if c.isdigit():
            j = i
            while j < n and (src[j].isalnum() or src[j] in 'xXbB'):
                j += 1
            toks.append(('num', src[i:j]))
            i = j
            continue
        if c.isalpha() or c == '_':
            j = i
            while j < n and (src[j].isalnum() or src[j] == '_'):
                j += 1
            toks.append(('id', src[i:j]))
            i = j
            continue
        matched = None
        for op in ('<<', '>>', '==', '!=', '<=', '>=', '&&', '||'):
            if src.startswith(op, i):
                matched = op
                break
        if matched is None and c in PUNCT:
            matched = c
        if matched is None:
            raise VmcError('unexpected char %r at %d' % (c, i))
        toks.append(('op', matched))
        i += len(matched)
    toks.append(('eof', ''))
    return toks


def parse_u64(tok):
    t = tok.strip()
    try:
        if t.lower().startswith('0x'):
            return int(t, 16)
        if t.lower().startswith('0b'):
            return int(t, 2)
        return int(t, 10)
    except ValueError:
        raise VmcError('bad number %r' % tok)


# ---------------------------------------------------------------------------
# 语法 (递归下降) -> AST 列表
# ---------------------------------------------------------------------------
class Parser:
    def __init__(self, toks):
        self.t = toks
        self.p = 0

    def peek(self):
        return self.t[self.p]

    def next(self):
        tok = self.t[self.p]
        self.p += 1
        return tok

    def expect(self, kind, val=None):
        tok = self.next()
        if tok[0] != kind or (val is not None and tok[1] != val):
            raise VmcError('expected %r got %r' % (val or kind, tok))
        return tok

    def accept(self, val):
        if self.peek()[0] == 'op' and self.peek()[1] == val:
            self.p += 1
            return True
        return False

    def parse_program(self):
        stmts = []
        while self.peek()[0] != 'eof':
            stmts.append(self.parse_stmt())
        return stmts

    def parse_stmt(self):
        tok = self.peek()
        if tok[0] == 'id' and tok[1] == 'uint64':
            self.next()
            name = self.expect('id')[1]
            init = None
            if self.accept('='):
                init = self.parse_expr()
            self.expect('op', ';')
            return ('decl', name, init)
        if tok[0] == 'id' and tok[1] == 'if':
            self.next()
            self.expect('op', '(')
            cond = self.parse_expr()
            self.expect('op', ')')
            then_s = self.parse_stmt()
            else_s = None
            if self.peek()[0] == 'id' and self.peek()[1] == 'else':
                self.next()
                else_s = self.parse_stmt()
            return ('if', cond, then_s, else_s)
        if tok[0] == 'id' and tok[1] == 'while':
            self.next()
            self.expect('op', '(')
            cond = self.parse_expr()
            self.expect('op', ')')
            body = self.parse_stmt()
            return ('while', cond, body)
        if tok[0] == 'id' and tok[1] == 'return':
            self.next()
            v = self.parse_expr()
            self.expect('op', ';')
            return ('return', v)
        if tok[0] == 'op' and tok[1] == '{':
            self.next()
            body = []
            while not self.accept('}'):
                if self.peek()[0] == 'eof':
                    raise VmcError('unterminated block')
                body.append(self.parse_stmt())
            return ('block', body)
        # 赋值
        name = self.expect('id')[1]
        self.expect('op', '=')
        v = self.parse_expr()
        self.expect('op', ';')
        return ('assign', name, v)

    # 表达式: 最低优先级逻辑或
    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()
        while self.accept('||'):
            left = ('binop', '||', left, self.parse_and())
        return left

    def parse_and(self):
        left = self.parse_eq()
        while self.accept('&&'):
            left = ('binop', '&&', left, self.parse_eq())
        return left

    def parse_eq(self):
        left = self.parse_rel()
        while self.peek()[0] == 'op' and self.peek()[1] in ('==', '!='):
            op = self.next()[1]
            left = ('binop', op, left, self.parse_rel())
        return left

    def parse_rel(self):
        left = self.parse_shift()
        while self.peek()[0] == 'op' and self.peek()[1] in ('<', '>', '<=', '>='):
            op = self.next()[1]
            left = ('binop', op, left, self.parse_shift())
        return left

    def parse_shift(self):
        left = self.parse_add()
        while self.peek()[0] == 'op' and self.peek()[1] in ('<<', '>>'):
            op = self.next()[1]
            left = ('binop', op, left, self.parse_add())
        return left

    def parse_add(self):
        left = self.parse_mul()
        while self.peek()[0] == 'op' and self.peek()[1] in ('+', '-', '^', '|'):
            op = self.next()[1]
            left = ('binop', op, left, self.parse_mul())
        return left

    def parse_mul(self):
        left = self.parse_unary()
        while self.peek()[0] == 'op' and self.peek()[1] in ('*', '/', '%', '&'):
            op = self.next()[1]
            left = ('binop', op, left, self.parse_unary())
        return left

    def parse_unary(self):
        if self.accept('!'):
            return ('not', self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        tok = self.peek()
        if tok[0] == 'num':
            self.next()
            return ('num', parse_u64(tok[1]))
        if tok[0] == 'id':
            self.next()
            if self.peek()[0] == 'op' and self.peek()[1] == '(':
                # 函数调用 (内置)
                self.next()
                args = []
                if not self.accept(')'):
                    while True:
                        args.append(self.parse_expr())
                        if self.accept(')'):
                            break
                        self.expect('op', ',')
                return ('call', tok[1], args)
            if tok[1] in ('EXPECT1', 'EXPECT2'):
                # 符号: vmenc assemble 期解析 (vm_build.json expect1/expect2)
                return ('symbol', tok[1])
            return ('var', tok[1])
        if tok[0] == 'op' and tok[1] == '(':
            self.next()
            e = self.parse_expr()
            self.expect('op', ')')
            return e
        raise VmcError('unexpected token %r' % (tok,))


# ---------------------------------------------------------------------------
# 语义 + 布局分配
# ---------------------------------------------------------------------------
# 语义 + 布局分配
# ---------------------------------------------------------------------------
class Analyzer:
    def __init__(self, seed=0):
        self.vars = {}          # name -> offset
        self.seed = seed & 0xFFFFFFFF
        self._slots = None      # 打乱后的槽位序列 (seed!=0 时)
        self._slot_idx = 0
        self.builtins = {'mem8', 'mem32', 'mem64',
                         'store8', 'store32', 'store64'}

    def _rand(self):
        """xorshift32 (确定性, 同 seed 同序列)."""
        x = self.seed
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        self.seed = x & 0xFFFFFFFF
        return x

    def _make_slots(self):
        """M3a: 0x40..0xF8 的 24 个槽位, Fisher-Yates 打乱 (确定性)."""
        slots = [0x40 + i * 8 for i in range(24)]
        for i in range(len(slots) - 1, 0, -1):
            j = self._rand() % (i + 1)
            slots[i], slots[j] = slots[j], slots[i]
        return slots

    def alloc(self, name):
        if name in self.vars:
            raise VmcError('duplicate variable %r' % name)
        if self.seed == 0:
            off = 0x40 + len(self.vars) * 8
        else:
            if self._slots is None:
                self._slots = self._make_slots()
            off = self._slots[self._slot_idx]
            self._slot_idx += 1
        self.vars[name] = off
        return off

    def analyze(self, stmts):
        for st in stmts:
            self.visit_stmt(st)

    def visit_stmt(self, st):
        k = st[0]
        if k == 'decl':
            self.alloc(st[1])
            if st[2] is not None:
                self.visit_expr(st[2])
        elif k == 'assign':
            if st[1] not in self.vars:
                raise VmcError('undefined variable %r' % st[1])
            self.visit_expr(st[2])
        elif k == 'if':
            self.visit_expr(st[1])
            self.visit_stmt(st[2])
            if st[3] is not None:
                self.visit_stmt(st[3])
        elif k == 'while':
            self.visit_expr(st[1])
            self.visit_stmt(st[2])
        elif k == 'block':
            for s in st[1]:
                self.visit_stmt(s)
        elif k == 'return':
            self.visit_expr(st[1])

    def visit_expr(self, e):
        k = e[0]
        if k == 'binop':
            self.visit_expr(e[1])
            self.visit_expr(e[2])
        elif k == 'not':
            self.visit_expr(e[1])
        elif k == 'var':
            if e[1] not in self.vars:
                raise VmcError('undefined variable %r' % e[1])
        elif k == 'call':
            if e[1] not in self.builtins:
                raise VmcError('unknown function %r' % e[1])
            for a in e[2]:
                self.visit_expr(a)


# ---------------------------------------------------------------------------
# 代码生成 -> VASM 指令列表
# ---------------------------------------------------------------------------
class CodeGen:
    """生成 (mnemonic, operand) 列表; operand None 或字符串。"""

    BINOP = {
        '+': 'add', '-': 'sub', '*': 'mul', '/': 'divu', '%': 'modu',
        '^': 'xor', '&': 'and', '|': 'or',
        '<<': 'shl', '>>': 'shr',
        '==': 'cmpeq', '!=': 'cmpne', '<': 'cmpltu', '<=': 'cmpleu',
        '>': 'cmpgtu', '>=': 'cmpgeu',
    }
    # 逻辑 && || 需要跳转 (短路), 单独处理

    def __init__(self, analyzer, layout_off=52):
        self.an = analyzer
        self.ins = []
        self.label_id = 0

    def new_label(self):
        self.label_id += 1
        return 'L%d' % self.label_id

    def emit(self, mnem, operand=None):
        self.ins.append((mnem, operand))

    def emit_label(self, name):
        self.ins.append(('label', name))

    def gen(self, stmts):
        for st in stmts:
            self.gen_stmt(st)

    def gen_stmt(self, st):
        k = st[0]
        if k == 'decl':
            off = self.an.vars[st[1]]
            if st[2] is not None:
                self.gen_expr(st[2])
                self.store_off(off, 64)
        elif k == 'assign':
            off = self.an.vars[st[1]]
            self.gen_expr(st[2])
            self.store_off(off, 64)
        elif k == 'if':
            else_l = self.new_label()
            end_l = self.new_label()
            self.gen_expr(st[1])
            self.emit('jz', else_l)
            self.gen_stmt(st[2])
            self.emit('jmp', end_l)
            self.emit_label(else_l)
            if st[3] is not None:
                self.gen_stmt(st[3])
            self.emit_label(end_l)
        elif k == 'while':
            cond_l = self.new_label()
            end_l = self.new_label()
            self.emit_label(cond_l)
            self.gen_expr(st[1])
            self.emit('jz', end_l)
            self.gen_stmt(st[2])
            self.emit('jmp', cond_l)
            self.emit_label(end_l)
        elif k == 'block':
            for s in st[1]:
                self.gen_stmt(s)
        elif k == 'return':
            self.gen_expr(st[1])
            self.store_off(52, 32)  # host.result@52
            self.emit('halt')

    def gen_expr(self, e):
        k = e[0]
        if k == 'num':
            v = e[1]
            if v <= 0xFFFFFFFF:
                self.emit('push32', '0x%x' % v)
            else:
                self.emit('push64', '0x%x' % v)
        elif k == 'symbol':
            self.emit('push64', e[1])  # EXPECT1/EXPECT2: vmenc 期解析
        elif k == 'var':
            off = self.an.vars[e[1]]
            self.load_off(off, 64)
        elif k == 'not':
            self.gen_expr(e[1])
            self.emit('push32', '0')
            self.emit('cmpeq')
        elif k == 'binop':
            op = e[1]
            if op in ('&&', '||'):
                self.gen_logic(op, e[2], e[3])
                return
            self.gen_expr(e[2])
            self.gen_expr(e[3])
            self.emit(self.BINOP[op])
        elif k == 'call':
            name = e[1]
            args = e[2]
            if name in ('mem8', 'mem32', 'mem64'):
                self.gen_expr(args[0])
                self.emit('load32' if name == 'mem32' else
                          ('load8' if name == 'mem8' else 'load64'))
            elif name in ('store8', 'store32', 'store64'):
                self.gen_expr(args[1])  # val
                self.gen_expr(args[0])  # addr
                self.emit('swap')
                self.emit('store32' if name == 'store32' else
                          ('store8' if name == 'store8' else 'store64'))

    def gen_logic(self, op, a, b):
        """短路 && / ||: 生成比较后合并。简化: 非短路 (先算两侧再逻辑合并)。
        语义: && = (a!=0) & (b!=0); || = (a!=0) | (b!=0)。"""
        self.gen_expr(a)
        self.emit('push32', '0')
        self.emit('cmpne')
        self.gen_expr(b)
        self.emit('push32', '0')
        self.emit('cmpne')
        self.emit('and' if op == '&&' else 'or')

    def load_off(self, off, bits):
        """把 host[off] 压栈 (64 位读取)."""
        self.emit('push32', '0x%x' % off)
        self.emit('load64' if bits == 64 else 'load32')

    def store_off(self, off, bits):
        """栈顶 -> host[off] (val 在栈顶, addr 在次顶)."""
        self.emit('push32', '0x%x' % off)
        self.emit('swap')
        self.emit('store64' if bits == 64 else 'store32')


# ---------------------------------------------------------------------------
# M3b: 控制流平坦化后处理
# 把 (mnemonic, operand) 列表改造成"dispatch 循环 + state 表"模式:
#   entry:  初始化 state=0, 跳 dispatch
#   dispatch: 读 state, 比较链 -> 各基本块
#   block_i: 原块指令, 末尾写 next_state + 跳 dispatch
# state 存宿主内存固定偏移 0x200 (超出 vmc 变量区)。
# ---------------------------------------------------------------------------
FLAT_STATE_OFF = 0x200


def flatten(insns, seed=0):
    """控制流平坦化: 按 label/halt 切基本块, 块经 dispatch 循环进入,
    块间跳转经 state 槽间接化。空标签 (L1: L2: 相邻) 合并到后继块。"""
    # 1. 切块; 空标签映射到下一个非空块
    labels = {}
    blocks = []       # list of [insns]
    pending = []      # 待定标签 -> 指向"下一个块" (收尾时确定)
    cur = []
    insn_list = list(insns)
    for idx, (mnem, op) in enumerate(insn_list):
        if mnem == 'label':
            if cur:
                blocks.append(cur)
                for lb in pending:
                    labels[lb] = len(blocks) - 1   # 指向刚 append 的块
                pending = []
                cur = []
            pending.append(op)
        elif mnem == 'halt':
            if cur:
                blocks.append(cur)
                for lb in pending:
                    labels[lb] = len(blocks) - 1   # 指向 halt 前的块
                pending = []
                cur = []
            blocks.append([('halt', None)])
        elif mnem in ('jz', 'jnz') and idx + 1 < len(insn_list) and \
                insn_list[idx + 1][0] not in ('label', 'halt'):
            # 条件跳转后还有直线代码: 条件与 jz 留在本块 (栈语义),
            # 之后的指令开新块 (jz 的非跳转路指向它)。
            cur.append((mnem, op))
            if cur:
                blocks.append(cur)
                cur = []
            for lb in pending:
                labels[lb] = len(blocks) - 1
            pending = []
        else:
            cur.append((mnem, op))
    if cur:
        blocks.append(cur)
        for lb in pending:
            labels[lb] = len(blocks) - 1
    elif pending:
        for lb in pending:
            labels[lb] = len(blocks) - 1

    n = len(blocks)
    if n == 0:
        return [('halt', None)]

    # 2. 块顺序打乱 (seed) —— entry 块 (原 0) 必须固定在 state 0
    order = list(range(n))
    if seed != 0:
        rest = list(range(1, n))
        x = seed & 0xFFFFFFFF
        for i in range(len(rest) - 1, 0, -1):
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= x >> 17
            x ^= (x << 5) & 0xFFFFFFFF
            j = x % (i + 1)
            rest[i], rest[j] = rest[j], rest[i]
        order = [0] + rest
    pos_of = {orig: new for new, orig in enumerate(order)}

    def jump_to(state_id):
        return [('push32', '0x%x' % state_id),
                ('push32', '0x%x' % FLAT_STATE_OFF),
                ('swap', None),
                ('store32', None),
                ('jmp', '__dispatch')]

    out = []
    out += jump_to(0)
    out.append(('label', '__dispatch'))
    for new_idx in range(n):
        out.append(('push32', '0x%x' % FLAT_STATE_OFF))
        out.append(('load32', None))
        out.append(('dup', None))            # [state, state]
        out.append(('push32', '0x%x' % new_idx))
        out.append(('cmpeq', None))          # [state, eq]
        out.append(('jz', '__d%d' % (new_idx + 1)))
        out.append(('drop', None))           # 清残留 state
        out.append(('jmp', '__b%d' % new_idx))
        out.append(('label', '__d%d' % (new_idx + 1)))
        out.append(('drop', None))           # 清残留 state
    out.append(('jmp', '__halt'))

    # 3. 块体
    stub_id = 0
    for new_idx, orig in enumerate(order):
        body = blocks[orig]
        out.append(('label', '__b%d' % new_idx))
        if body == [('halt', None)]:
            out.append(('jmp', '__halt'))
            continue
        nxt = orig + 1 if orig + 1 < n else None
        n_state = pos_of[nxt] if nxt is not None else 0
        for mnem, op in body:
            if mnem == 'jmp':
                tgt = labels.get(op)
                t_state = pos_of[tgt] if tgt is not None else 0
                out += jump_to(t_state)
            elif mnem in ('jz', 'jnz'):
                tgt = labels.get(op)
                t_state = pos_of[tgt] if tgt is not None else 0
                stub_id += 1
                sname = '__s%d' % stub_id
                out.append((mnem, sname))   # jz/jnz -> 本块 stub
                out += jump_to(n_state)     # 非目标路 -> 顺序后继
                out.append(('label', sname))
                out += jump_to(t_state)     # 目标路 -> 目标块
            else:
                out.append((mnem, op))
        out += jump_to(n_state)             # 块尾顺序后继

    out.append(('label', '__halt'))
    out.append(('halt', None))
    return out


# ---------------------------------------------------------------------------
def compile_vmc(src, seed=0, flatten_cf=False):
    toks = tokenize(src)
    ast = Parser(toks).parse_program()
    an = Analyzer(seed)
    an.analyze(ast)
    cg = CodeGen(an)
    cg.gen(ast)
    cg.emit('halt')
    ins = cg.ins
    if flatten_cf:
        ins = flatten(ins, seed)
    return ins, an.vars


def insns_to_vasm(insns):
    lines = []
    for mnem, op in insns:
        if mnem == 'label':
            lines.append('%s:' % op)
        elif op is None:
            lines.append('    %s' % mnem)
        else:
            lines.append('    %s %s' % (mnem, op))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog='vmc.py', description='restricted-C -> VM bytecode (M2)')
    parser.add_argument('in_vmc', help='input .vmc source')
    parser.add_argument('out_vasm', help='output .vasm (for vmenc assemble)')
    parser.add_argument('out_layout', help='output layout JSON (var->offset)')
    parser.add_argument('--seed', dest='seed', type=lambda s: int(s, 0),
                        default=0,
                        help='stack-slot randomization seed (M3a; 0=sequential)')
    parser.add_argument('--flatten', action='store_true',
                        help='control-flow flattening (M3b; dispatch-loop + '
                             'state table)')
    args = parser.parse_args(argv)

    try:
        with open(args.in_vmc, 'r', encoding='utf-8') as f:
            src = f.read()
        insns, var_map = compile_vmc(src, args.seed, args.flatten)
        with open(args.out_vasm, 'w', encoding='utf-8', newline='\n') as f:
            f.write(insns_to_vasm(insns))
        with open(args.out_layout, 'w', encoding='utf-8', newline='\n') as f:
            json.dump({'result_off': 52, 'seed': args.seed, 'vars': var_map},
                      f, indent=2)
            f.write('\n')
        print('vmc: compiled %d instructions (seed=0x%x%s) -> %s (%s)'
              % (len(insns), args.seed,
                 ' flatten' if args.flatten else '',
                 args.out_vasm, args.out_layout))
        return 0
    except VmcError as e:
        print('vmc: error: %s' % e, file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as e:
        print('vmc: error: %s' % e, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
