#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
# c2vasm.py — C 子集 -> vasm 自动翻译器 (A2 原型, 2026-08-28)
# 流水线: lexer -> recursive descent parser -> AST -> 栈式 vasm 代码生成
# 支持子集: uint32_t/uint64_t 变量; 字面量(dec/hex); 二元 + - * / % & | ^ << >>
#             比较 < <= > >= == !=; for/while/if-else; return
#             复合赋值 op=(除 %/= 逐位 op 均可) 与 x++/x--
# 不含: 函数调用/指针/数组/IO/浮点/字符串
# 内存布局: 参数从偏移 0 起(每槽 8B), 局部变量紧随; 返回槽 --out-off(默认 0x1000)
# 用法: python c2vasm.py <in.c> [--fn NAME] [--out-off N] [--out file|stdout]
import argparse
import re
import sys

# ---------------------------------------------------------------------------
# lexer
# ---------------------------------------------------------------------------
TOK_NUM, TOK_ID, TOK_OP, TOK_LP, TOK_RP, TOK_LB, TOK_RB, TOK_SEMI, TOK_COMMA = range(9)
KEYWORDS = {'uint64_t', 'uint32_t', 'if', 'else', 'while', 'for', 'return'}
TWO_CH = {'<<', '>>', '<=', '>=', '==', '!=',
          '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=', '++', '--'}


def tokenize(text):
    toks = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == '#':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c.isdigit():
            j = i
            while j < n and (text[j].isdigit() or text[j] in 'xXabcdefABCDEF'):
                j += 1
            while j < n and text[j] in 'uUlL':
                j += 1  # 吞掉 ull/ul 后缀
            toks.append((TOK_NUM, text[i:j].rstrip('uUlL'), i))
            i = j
            continue
        if c.isalpha() or c == '_':
            j = i
            while j < n and (text[j].isalnum() or text[j] == '_'):
                j += 1
            toks.append((TOK_ID, text[i:j], i))
            i = j
            continue
        two = text[i:i + 2]
        if two in TWO_CH:
            toks.append((TOK_OP, two, i))
            i += 2
            continue
        if c in '+*-/%&|^<>=!':
            toks.append((TOK_OP, c, i))
            i += 1
            continue
        if c == '(':
            toks.append((TOK_LP, '(', i)); i += 1; continue
        if c == ')':
            toks.append((TOK_RP, ')', i)); i += 1; continue
        if c == '{':
            toks.append((TOK_LB, '{', i)); i += 1; continue
        if c == '}':
            toks.append((TOK_RB, '}', i)); i += 1; continue
        if c == ';':
            toks.append((TOK_SEMI, ';', i)); i += 1; continue
        if c == ',':
            toks.append((TOK_COMMA, ',', i)); i += 1; continue
        raise SyntaxError('lexer: unexpected char %r at %d' % (c, i))
    return toks


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------
class Expr:  # value expression
    def __init__(self, kind, value=None, left=None, op=None, right=None):
        self.kind = kind
        self.value = value
        self.left = left
        self.op = op
        self.right = right


class Stmt:  # statement
    def __init__(self, kind, **kw):
        self.kind = kind
        self.__dict__.update(kw)


# ---------------------------------------------------------------------------
# parser (recursive descent)
# ---------------------------------------------------------------------------
class Parser:
    def __init__(self, toks):
        self.toks = toks
        self.p = 0

    def peek(self):
        return self.toks[self.p] if self.p < len(self.toks) else (TOK_SEMI, '', -1)

    def next(self):
        t = self.peek()
        self.p += 1
        return t

    def expect(self, kind, txt=None):
        t = self.next()
        if t[0] != kind or (txt is not None and t[1] != txt):
            raise SyntaxError('parse: expected %r got %r' % (txt or kind, t[1]))
        return t

    def parse(self):
        self.expect(TOK_ID, 'uint64_t')
        name = self.expect(TOK_ID)[1]
        params = self.parse_params()
        self.expect(TOK_LB)
        body = self.parse_block_stmts()
        self.expect(TOK_RB)
        return name, params, body

    def parse_params(self):
        self.expect(TOK_LP)
        params = []
        while self.peek()[0] != TOK_RP:
            self.expect(TOK_ID, 'uint64_t')
            params.append(self.expect(TOK_ID)[1])
            if self.peek()[0] == TOK_COMMA:
                self.next()
        self.expect(TOK_RP)
        return params

    def parse_block_stmts(self):
        stmts = []
        while self.peek()[0] != TOK_RB:
            stmts.append(self.parse_stmt())
        return stmts

    def parse_stmt(self):
        t = self.peek()
        if t[0] == TOK_SEMI:
            self.next()
            return Stmt('empty')
        if t[1] == 'if':
            self.next()
            self.expect(TOK_LP)
            cond = self.parse_expr()
            self.expect(TOK_RP)
            then_s = self.parse_stmt()
            else_s = None
            if self.peek()[1] == 'else':
                self.next()
                else_s = self.parse_stmt()
            return Stmt('if', cond=cond, then_s=then_s, else_s=else_s)
        if t[1] == 'while':
            self.next()
            self.expect(TOK_LP)
            cond = self.parse_expr()
            self.expect(TOK_RP)
            body = self.parse_stmt()
            return Stmt('while', cond=cond, body=body)
        if t[1] == 'for':
            self.next()
            self.expect(TOK_LP)
            init = self.parse_stmt()
            cond = self.parse_expr() if self.peek()[0] != TOK_SEMI else Expr('const', 1)
            self.expect(TOK_SEMI)
            incr = None
            if self.peek()[0] != TOK_RP:
                # for-incr 三种形态: var++/-- | var op= expr | var = expr
                if (self.peek()[0] == TOK_ID and
                        self.toks[self.p + 1][0] == TOK_OP and
                        self.toks[self.p + 1][1] in ('++', '--')):
                    name = self.next()[1]
                    op = self.next()[1]
                    incr = Stmt('inc', target=Expr('var', name),
                                delta=1 if op == '++' else -1)
                else:
                    e = self.parse_expr()
                    t2 = self.peek()
                    if t2[0] == TOK_OP and t2[1] == '=':
                        self.next()
                        v = self.parse_expr()
                        incr = Stmt('assign', target=e, value=v)
                    elif (t2[0] == TOK_OP and
                          t2[1] in ('+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=')):
                        self.next()
                        v = self.parse_expr()
                        incr = Stmt('cop', target=e, op=t2[1][:-1], value=v)
                    else:
                        raise SyntaxError('parse: unsupported for-increment')
            self.expect(TOK_RP)
            body = self.parse_stmt()
            return Stmt('for', init=init, cond=cond, incr=incr, body=body)
        if t[1] == 'return':
            self.next()
            e = self.parse_expr()
            self.expect(TOK_SEMI)
            return Stmt('return', expr=e)
        if t[0] == TOK_LB:
            self.next()
            body = self.parse_block_stmts()
            self.expect(TOK_RB)
            return Stmt('block', body=body)
        if t[1] in ('uint64_t', 'uint32_t'):
            self.next()
            name = self.expect(TOK_ID)[1]
            if self.peek()[1] == '=':
                self.next()
                e = self.parse_expr()
                self.expect(TOK_SEMI)
                return Stmt('decl', name=name, init=e)
            self.expect(TOK_SEMI)
            return Stmt('decl', name=name, init=None)
        # assignment family
        target = self.parse_expr()
        t2 = self.peek()
        if t2[0] == TOK_OP and t2[1] == '=':
            self.next()
            e = self.parse_expr()
            self.expect(TOK_SEMI)
            return Stmt('assign', target=target, value=e)
        if t2[0] == TOK_OP and t2[1] in ('+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>='):
            self.next()
            e = self.parse_expr()
            self.expect(TOK_SEMI)
            return Stmt('cop', target=target, op=t2[1][:-1], value=e)
        if t2[0] == TOK_OP and t2[1] in ('++', '--'):
            self.next()
            self.expect(TOK_SEMI)
            return Stmt('inc', target=target, delta=1 if t2[1] == '++' else -1)
        raise SyntaxError('parse: unexpected statement %r' % t[1])

    # precedence climbing
    PREC = {'|': 1, '^': 2, '&': 3, '<<': 4, '>>': 4,
            '+': 5, '-': 5, '*': 6, '/': 6, '%': 6,
            '==': 2, '!=': 2, '<': 3, '<=': 3, '>': 3, '>=': 3}

    def parse_expr(self, min_prec=0):
        left = self.parse_primary()
        while True:
            t = self.peek()
            if t[0] != TOK_OP:
                break
            prec = self.PREC.get(t[1])
            if prec is None:
                break
            if prec < min_prec:
                break
            op = t[1]
            if op in ('==', '!=', '<', '<=', '>', '>='):
                # 比较作为整体结果: 原生成 0/1; 直接构建成比较节点 (低优先级分组)
                self.next()
                right = self.parse_expr(prec + 1)
                left = Expr('bin', left=left, op=op, right=right)
                continue
            self.next()
            right = self.parse_expr(prec + 1)
            left = Expr('bin', left=left, op=op, right=right)
        return left

    def parse_primary(self):
        t = self.next()
        if t[0] == TOK_NUM:
            v = int(t[1], 0)
            return Expr('const', v)
        if t[0] == TOK_ID:
            return Expr('var', t[1])
        if t[0] == TOK_LP:
            e = self.parse_expr()
            self.expect(TOK_RP)
            return e
        raise SyntaxError('parse: unexpected primary %r' % t[1])


# ---------------------------------------------------------------------------
# codegen -> vasm
# ---------------------------------------------------------------------------
def gen_var_offsets(params, stmts):
    """参数 off=0..; 局部变量追加. 返回 {name:off} 与 total_locals_end."""
    offs = {}
    off = 0
    for p in params:
        offs[p] = off
        off += 8
    locals_seen = set()

    def walk(node):
        if isinstance(node, Stmt):
            if node.kind == 'decl' and node.name not in offs:
                locals_seen.add(node.name)
            for k in ('then_s', 'else_s', 'body', 'init'):
                v = getattr(node, k, None)
                if v is not None:
                    walk(v)
            if node.kind == 'block':
                for s in node.body:
                    walk(s)
        elif isinstance(node, Expr) and node.kind == 'bin':
            walk(node.left)
            walk(node.right)

    for s in stmts:
        walk(s)
    for name in sorted(locals_seen):
        offs[name] = off
        off += 8
    return offs


class Codegen:
    def __init__(self, offs, out_off):
        self.offs = offs
        self.out_off = out_off
        self.lines = []
        self.label_seq = 0
        self.stack_depth = 0  # 提示用

    def emit(self, line):
        self.lines.append(line)

    def label(self):
        self.label_seq += 1
        return 'L%d' % self.label_seq

    # -- expressions: 结果留栈顶 --
    def cx(self, e):
        if e.kind == 'const':
            self.emit('    push64 %d' % e.value)
        elif e.kind == 'var':
            self.emit('    push32 %d' % self.offs[e.value])
            self.emit('    load64')
        elif e.kind == 'bin':
            self.cx(e.left)
            self.cx(e.right)
            op = e.op
            m = {'+': 'add', '-': 'sub', '*': 'mul', '/': 'divu', '%': 'modu',
                 '&': 'and', '|': 'or', '^': 'xor', '<<': 'shl', '>>': 'shr',
                 '==': 'cmpeq', '!=': 'cmpne', '<': 'cmpltu', '<=': 'cmpleu',
                 '>': 'cmpgtu', '>=': 'cmpgeu'}
            self.emit('    %s' % m[op])
        else:
            raise SyntaxError('codegen: bad expr %r' % e.kind)

    # -- statements --
    def st(self, s):
        k = s.kind
        if k == 'empty':
            return
        if k == 'block':
            for x in s.body:
                self.st(x)
            return
        if k == 'decl':
            if s.init is not None:
                self.cx(s.init)
                self.store(self.offs[s.name])
            return
        if k == 'assign':
            self.cx(s.value)
            self.store(self.offs[s.target.value])
            return
        if k == 'cop':
            # x op= e  -> load x; e; op; store x
            self.cx(Expr('var', s.target.value))
            self.cx(s.value)
            self.emit('    %s' % {'+': 'add', '-': 'sub', '*': 'mul', '/': 'divu',
                                  '%': 'modu', '&': 'and', '|': 'or', '^': 'xor',
                                  '<<': 'shl', '>>': 'shr'}[s.op])
            self.store(self.offs[s.target.value])
            return
        if k == 'inc':
            self.cx(Expr('var', s.target.value))
            self.emit('    push64 %d' % s.delta)
            self.emit('    add' if s.delta > 0 else '    sub')
            self.store(self.offs[s.target.value])
            return
        if k == 'if':
            l_else = self.label()
            l_end = self.label()
            self.cx(s.cond)
            self.emit('    jz %s' % l_else)
            self.st(s.then_s)
            self.emit('    jmp %s' % l_end)
            self.emit('%s:' % l_else)
            if s.else_s is not None:
                self.st(s.else_s)
            self.emit('%s:' % l_end)
            return
        if k == 'while':
            l_start = self.label()
            l_end = self.label()
            self.emit('%s:' % l_start)
            self.cx(s.cond)
            self.emit('    jz %s' % l_end)
            self.st(s.body)
            self.emit('    jmp %s' % l_start)
            self.emit('%s:' % l_end)
            return
        if k == 'for':
            l_start = self.label()
            l_end = self.label()
            self.st(s.init)
            self.emit('%s:' % l_start)
            self.cx(s.cond)
            self.emit('    jz %s' % l_end)
            self.st(s.body)
            if s.incr is not None:
                self.st(s.incr)
            self.emit('    jmp %s' % l_start)
            self.emit('%s:' % l_end)
            return
        if k == 'return':
            self.cx(s.expr)
            self.store(self.out_off)
            self.emit('    halt')
            return
        raise SyntaxError('codegen: bad stmt %r' % k)

    def store(self, off):
        self.emit('    push32 %d' % off)
        self.emit('    swap')
        self.emit('    store64')


# ---------------------------------------------------------------------------
# 函数切片: 只提取目标函数体(排除 main/interfaces), 再交给 lexer/parser
# ---------------------------------------------------------------------------
def extract_function(src, name=None):
    if name is None:
        m = re.search(r'\buint(?:32|64)_t\s+[A-Za-z_][A-Za-z0-9_]*\s*\(', src)
        if not m:
            raise SyntaxError('no uint*_t function found')
        name = m.group(0).split()[-1][:-1].rstrip('(')
        m = re.search(r'\buint(?:32|64)_t\s+%s\s*\(' % re.escape(name), src)
    else:
        m = re.search(r'\buint(?:32|64)_t\s+%s\s*\(' % re.escape(name), src)
    if not m:
        raise SyntaxError('function not found: %s' % name)
    i = src.find('{', m.end())
    if i < 0:
        raise SyntaxError('function %s has no body' % name)
    depth, j = 1, i + 1
    while j < len(src) and depth:
        if src[j] == '{':
            depth += 1
        elif src[j] == '}':
            depth -= 1
        j += 1
    if depth:
        raise SyntaxError('function %s: unbalanced braces' % name)
    return name, src[m.start():j]


def parse_function(src):
    """返回 (name, params, body-ast)."""
    name, text = extract_function(src)
    toks = tokenize(text)
    n2, params, body = Parser(toks).parse()
    assert n2 == name
    return name, params, body


def compile_ast(name, params, body, out_off):
    offs = gen_var_offsets(params, body)
    g = Codegen(offs, out_off)
    for s in body:
        g.st(s)
    g.emit('    halt')
    return g.lines, offs


def compile_function(src, out_off=0x1000):
    name, params, body = parse_function(src)
    lines, offs = compile_ast(name, params, body, out_off)
    text = [
        '; generated by tools/c2vasm.py (A2 prototype) — do not edit',
        '; function: %s(%s)' % (name, ', '.join(params)),
        '; frame: params/locals %s; return slot @%d' % (offs, out_off),
        '',
    ] + lines
    return '\n'.join(text) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description='C 子集 -> vasm 翻译器 (A2)')
    ap.add_argument('src', help='C 子集源文件(单函数)')
    ap.add_argument('--fn', default=None, help='函数名(未用时自动)')
    ap.add_argument('--out-off', type=lambda s: int(s, 0), default=0x1000,
                    help='返回槽偏移(默认 0x1000)')
    ap.add_argument('--out', default=None, help='输出 vasm (默认 stdout)')
    args = ap.parse_args(argv)
    src = open(args.src, encoding='utf-8').read()
    out = compile_function(src, args.out_off)
    if args.out:
        with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
            f.write(out)
        print('c2vasm: wrote %s' % args.out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == '__main__':
    sys.exit(main())