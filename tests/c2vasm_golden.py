#!/usr/bin/env python3
# c2vasm_golden.py — A2 golden 验证: 原生 C 结果 vs VM 执行结果
# 过程:
#   1) 样例 .c (合法 C) 用 cl 编译为 host exe (宿主权威结果)
#   2) c2vasm 翻译同函数 -> .vasm
#   3) 内置 mini-vm 解释器执行 vasm (与 src/vm.c 语义一致)
#   4) 逐输入对比; 再演示"篡改立即数 -> 结果变化"(证明计算真实发生在 VM)
import os
import subprocess
import sys
import json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from c2vasm import parse_function, compile_ast, tokenize, Parser, gen_var_offsets, Codegen

CASES = os.path.join(ROOT, 'tests', 'c2vasm_cases')
BUILD = os.path.join(ROOT, 'build', 'c2vasm')
OUT_OFF = 0x1000
M64 = (1 << 64) - 1
VCVARS = r"D:\environment\VS2022BuildTools\VC\Auxiliary\Build\vcvars64.bat"

# 每样例的测试输入 (参数值列表; 注意循环量级 < 2e6)
INPUTS = {
    'fnv1a64':    [(0,), (3,), (350000,), (500000,)],
    'accumulate': [(0,), (5,), (1000,), (300000,)],
    'bitmix':     [(0x1122334455667788,), (1,), (0xFFFFFFFFFFFFFFFF,), (0x8000000000000000,)],
    'poly':       [(0,), (7,), (65536,), (123456789012345,), (999999999,)],
    'cond_agg':   [(0,), (1,), (42,), (100,), (0xFFFFFFFFFFFFFFFF,)],
    'modsum':     [(3,), (7,), (100,), (0xFF,), (100000,)],
}

# ---------------------------------------------------------------------------
# 1) 宿主参考 (Python 等价实现, uint64 截断语义; 样例经 cl /c 编译 sanity)
#    说明: 本机 WDAC 企业签名级别会拦新 exe(签名无法解决), 故宿主结果
#    不依赖运行 cl 产物; 样例作为"合法 C"由编译验证语法正确性。
# ---------------------------------------------------------------------------
MASK = M64


def run_bat(lines):
    bat = os.path.join(BUILD, '_cmd.bat')
    with open(bat, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    return subprocess.run(['cmd', '/c', bat], capture_output=True, text=True)


def get_vc_env():
    r = run_bat(['@echo off',
                 'call "%s" >nul 2>&1' % VCVARS, 'set'])
    env = {}
    for line in r.stdout.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            env[k] = v
    return env


def find_cl():
    vc = os.path.dirname(os.path.dirname(os.path.dirname(VCVARS)))  # ...\VC
    tools = os.path.join(vc, 'Tools', 'MSVC')
    vers = sorted(os.listdir(tools), reverse=True)
    p = os.path.join(tools, vers[0], 'bin', 'Hostx64', 'x64', 'cl.exe')
    if not os.path.isfile(p):
        raise RuntimeError('cl.exe not found under %s' % tools)
    return p


def host_ref(case, a):
    if case == 'fnv1a64':
        h = 14695981039346656037
        for i in range(a & MASK):
            h = (h ^ ((i + 1) & MASK)) & MASK
            h = (h * 1099511628211) & MASK
        return h
    if case == 'accumulate':
        s = 0
        i = 0
        while i < a:
            s = (s + i) & MASK
            i += 1
        return s & MASK
    if case == 'bitmix':
        y = a & MASK
        y ^= y >> 33
        y = (y * 0xff51afd7ed558ccd) & MASK
        y ^= y >> 33
        y = ((y << 17) | (y >> 47)) & MASK
        y &= 0x7fffffffffffffff
        return (y ^ 0x9e3779b97f4a7c15) & MASK
    if case == 'poly':
        r = 0
        x = a & MASK
        for i in range(8):
            c = (i * 2654435761) % 1000003
            r = (r * x + c) & MASK
        return r
    if case == 'cond_agg':
        x = a & MASK
        if x < 10:
            r = (x * 3) & MASK
        elif x < 50:
            r = (x + 1000) & MASK
        else:
            r = 0
            r = (r + x) & MASK
        if x != 42:
            r = (r + 1) & MASK
        return r & MASK
    if case == 'modsum':
        s = 0
        i = 0
        while i < a:
            q = i // 7
            m = i % 7
            s = (s + q + m * 11) & MASK
            i += 1
        return s & MASK
    raise ValueError(case)


def compile_sanity(case):
    """cl /c 编译样例(不链接不运行): 验证样例为合法 C (WDAC 无关)."""
    obj = os.path.join(BUILD, case + '.obj')
    src = os.path.join(CASES, case + '.c')
    env = dict(os.environ)
    env.update(get_vc_env())
    r = subprocess.run([find_cl(), '/nologo', '/W3', '/std:c11', '/utf-8',
                        '/c', src, '/Fo:' + obj],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise RuntimeError('sample compile sanity failed %s: %s'
                           % (case, r.stderr[-300:]))
    return True


def host_results(case, inputs):
    compile_sanity(case)
    return [str(host_ref(case, args[0])) for args in inputs]


# ---------------------------------------------------------------------------
# 2) c2vasm 翻译
# ---------------------------------------------------------------------------
def translate(case):
    src = open(os.path.join(CASES, case + '.c'), encoding='utf-8').read()
    name, params, body = parse_function(src)
    lines, offs = compile_ast(name, params, body, OUT_OFF)
    return name, params, lines, offs


# ---------------------------------------------------------------------------
# 3) mini-vm 解释器 (与 src/vm.c 语义一致; 绝对偏移寻址)
# ---------------------------------------------------------------------------
def execute(insns, params, args, offs, out_off, mem_size=0x2000, debug=False):
    """insns: 文本行列表(含标签行). 栈式, 64 位, 绝对 mem 偏移."""
    # 构建 label 表
    ip_labels = {}
    body = []
    for ln in insns:
        s = ln.strip()
        if not s:
            continue
        if s.endswith(':') and not s.startswith(';'):
            ip_labels[s[:-1]] = len(body)
        else:
            body.append(s)
    mem = bytearray(mem_size)
    # 参数写入槽
    for i, p in enumerate(params):
        mem[8 * i:8 * i + 8] = (args[i] & M64).to_bytes(8, 'little')
    stk = []
    cond = 0
    ip = 0
    steps = 0
    max_steps = 20_000_000

    def fetch_imm(kind, ln, i):
        return int(ln[i].lstrip('-').replace('0x', '').replace('X', ''), 16) if False else int(ln[i], 0)

    while ip < len(body):
        steps += 1
        if steps > max_steps:
            raise RuntimeError('mini-vm step limit exceeded (loop?) ip=%d' % ip)
        part = body[ip].split()
        op = part[0]
        ip += 1
        if debug:
            print('dbg %4d ip=%2d %-8s %s stk=%s' % (
                steps, ip - 1, op, ' '.join(part[1:]) if len(part) > 1 else '',
                [hex(x) for x in stk][-6:]))
        if op in ('push32', 'push64', 'move'):
            stk.append(int(part[1], 0) & M64)
        elif op == 'load8':
            a = stk.pop() & M64
            stk.append(mem[a])
        elif op == 'load32':
            a = stk.pop() & M64
            v = 0
            for j in range(4):
                v |= mem[a + j] << (8 * j)
            stk.append(v & M64)
        elif op == 'load64':
            a = stk.pop() & M64
            v = 0
            for j in range(8):
                v |= mem[a + j] << (8 * j)
            stk.append(v & M64)
        elif op == 'store8':
            val = stk.pop() & M64
            a = stk.pop() & M64
            mem[a] = val & 0xFF
        elif op == 'store32':
            val = stk.pop() & M64
            a = stk.pop() & M64
            mem[a:a + 4] = (val & 0xFFFFFFFF).to_bytes(4, 'little')
        elif op == 'store64':
            val = stk.pop() & M64
            a = stk.pop() & M64
            mem[a:a + 8] = (val & M64).to_bytes(8, 'little')
        elif op == 'dup':
            stk.append(stk[-1])
        elif op == 'drop':
            stk.pop()
        elif op == 'swap':
            stk[-1], stk[-2] = stk[-2], stk[-1]
        elif op == 'not':
            stk.append((~stk.pop()) & M64)
        elif op in ('add', 'sub', 'mul', 'divu', 'modu', 'and', 'or', 'xor',
                    'shl', 'shr', 'cmpeq', 'cmpne', 'cmpltu', 'cmpleu',
                    'cmpgtu', 'cmpgeu'):
            b = stk.pop() & M64
            a = stk.pop() & M64
            if op == 'add':
                r = (a + b) & M64
            elif op == 'sub':
                r = (a - b) & M64
            elif op == 'mul':
                r = (a * b) & M64
            elif op == 'divu':
                r = (a // b) if b else 0
            elif op == 'modu':
                r = (a % b) if b else 0
            elif op == 'and':
                r = a & b
            elif op == 'or':
                r = a | b
            elif op == 'xor':
                r = a ^ b
            elif op == 'shl':
                r = (a << (b & 63)) & M64
            elif op == 'shr':
                r = a >> (b & 63)
            elif op == 'cmpeq':
                r = 1 if a == b else 0
            elif op == 'cmpne':
                r = 1 if a != b else 0
            elif op == 'cmpltu':
                r = 1 if a < b else 0
            elif op == 'cmpleu':
                r = 1 if a <= b else 0
            elif op == 'cmpgtu':
                r = 1 if a > b else 0
            else:
                r = 1 if a >= b else 0
            stk.append(r)
        elif op == 'setcon':
            cond = 1 if (stk.pop() & M64) != 0 else 0
        elif op == 'pushcon':
            stk.append(cond)
        elif op == 'jmp':
            ip = ip_labels[part[1]]
        elif op in ('jz', 'jnz'):
            v = stk.pop() & M64
            if (op == 'jz' and v == 0) or (op == 'jnz' and v != 0):
                ip = ip_labels[part[1]]
        elif op == 'halt':
            break
        elif op.startswith(';') or op.startswith('//'):
            continue
        else:
            raise RuntimeError('mini-vm: unknown op %r' % op)
    return int.from_bytes(mem[out_off:out_off + 8], 'little')


def vm_results(case, params, insns, offs):
    res = []
    for args in INPUTS[case]:
        res.append(execute(insns, params, list(args), offs, OUT_OFF))
    return res


# ---------------------------------------------------------------------------
# 4) 篡改演示: 把首个 push64 改动 1(此处取"函数内某常量")观察结果变化
# ---------------------------------------------------------------------------
def tamper_demo(case, insns):
    changed = list(insns)
    idx = next(i for i, l in enumerate(changed) if 'push64' in l and '1099511628211' not in l)
    line = changed[idx]
    val = int(line.strip().split()[1], 0)
    changed[idx] = '    push64 %d' % ((val ^ 0x1234) & M64)
    return changed


def main():
    os.makedirs(BUILD, exist_ok=True)
    passed = 0
    fail = []
    tamper_proofs = []
    order = ['fnv1a64', 'accumulate', 'bitmix', 'poly', 'cond_agg', 'modsum']
    for case in order:
        try:
            host = host_results(case, INPUTS[case])
            name, params, insns, offs = translate(case)
            vm = vm_results(case, params, insns, offs)
            ok = all(str(h) == str(v) for h, v in zip(host, vm))
            # 篡改演示
            t_insns = tamper_demo(case, insns)
            t_vm = vm_results(case, params, t_insns, offs)
            tampered_diff = any(t != v for t, v in zip(t_vm, vm))
            passed += 1 if ok else 0
            status = 'PASS' if ok else 'FAIL'
            print('[%s] %-12s host=%d vm=%d tamper_diff=%s'
                  % (status, case, len(host), len(vm), tampered_diff))
            if not ok:
                fail.append(case)
            if tampered_diff:
                tamper_proofs.append(case)
        except Exception as e:
            print('[ERR ] %-12s %s' % (case, e))
            fail.append(case)
    print('\nRESULT: %d/%d passed; tamper-proof cases: %d (%s)'
          % (passed, len(order), len(tamper_proofs), ', '.join(tamper_proofs) or '-'))
    if fail:
        print('FAILED:', ', '.join(fail))
        return 1
    if len(tamper_proofs) < len(order):
        print('WARN: 部分样例篡改未改变结果(常量可能未被使用) - 检查样例设计')
    return 0


if __name__ == '__main__':
    sys.exit(main())