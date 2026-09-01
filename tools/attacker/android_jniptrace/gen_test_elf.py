#!/usr/bin/env python3
"""gen_test_elf.py — 生成最小 ELF64 测试样本 (含 .symtab/.dynsym)
用于宿主编译验证 elfparse 解析器 (无 NDK/gcc-elf 环境的替代)。

产物: test_lib.so — 模拟 libprot.so 的 JNI 导出符号
"""
import struct
import sys

def cstr(s):
    return s.encode() + b'\x00'

def build(out="test_lib.so"):
    # --- 节名 ---
    names = ["", ".text", ".symtab", ".strtab", ".dynsym", ".dynstr",
             ".shstrtab"]
    shstr = b""
    shstr_off = {}
    for n in names:
        shstr_off[n] = len(shstr)
        shstr += cstr(n)
    shstr += b"\x00"
    shstr_size = len(shstr)

    # --- 符号 ---
    # .symtab 符号: 静态 (prot_antidebug_scan 等)
    symtab_names = ["", "prot_antidebug_scan", "prot_antidebug_detected",
                    "is_debugger_attached", "main"]
    strtab = b""
    strtab_off = {}
    for n in symtab_names:
        strtab_off[n] = len(strtab)
        strtab += cstr(n)
    strtab += b"\x00"

    # .dynsym 符号: JNI 导出 (Java_com_prot_demo_Prot_nativeIsDebugged)
    dynsym_names = ["", "Java_com_prot_demo_Prot_nativeIsDebugged",
                    "Java_com_prot_demo_Prot_nativeVerifyLicense"]
    dynstr = b""
    dynstr_off = {}
    for n in dynsym_names:
        dynstr_off[n] = len(dynstr)
        dynstr += cstr(n)
    dynstr += b"\x00"

    def sym(st_name, st_info, st_shndx, st_value, st_size):
        return struct.pack("<IBBHQQ", st_name, st_info, 0, st_shndx,
                           st_value, st_size)

    symtab = b""
    symtab += sym(0, 0, 0, 0, 0)                       # null
    symtab += sym(strtab_off["prot_antidebug_scan"], 0x12, 1, 0x1000, 0x40)
    symtab += sym(strtab_off["prot_antidebug_detected"], 0x12, 1, 0x1040, 0x20)
    symtab += sym(strtab_off["is_debugger_attached"], 0x11, 3, 0x2000, 4)
    symtab += sym(strtab_off["main"], 0x12, 1, 0x1060, 0x80)

    dynsym = b""
    dynsym += sym(0, 0, 0, 0, 0)                       # null
    dynsym += sym(dynstr_off["Java_com_prot_demo_Prot_nativeIsDebugged"],
                  0x12, 1, 0x1100, 0x30)
    dynsym += sym(dynstr_off["Java_com_prot_demo_Prot_nativeVerifyLicense"],
                  0x12, 1, 0x1130, 0x60)

    # --- 布局 ---
    # 简易布局: 头部(64B) + .text(0x2000) + .symtab + .strtab + .dynsym + .dynstr + shstrtab
    text_size = 0x2000
    off = 64
    text_off = off; off += text_size
    symtab_off = off; off += len(symtab)
    strtab_off_abs = off; off += len(strtab)
    dynsym_off = off; off += len(dynsym)
    dynstr_off_abs = off; off += len(dynstr)
    shstr_off_abs = off; off += shstr_size
    # 节头表 (放在文件末尾)
    shoff = off
    shnum = len(names)
    off += shnum * 64
    total = off
    sh = b""
    def shdr(name_off, stype, addr, offset, size, link, entsize):
        return struct.pack("<IIQQQQIIQQ", name_off, stype, 0, addr, offset,
                           size, link, 0, 0, entsize)

    sh += shdr(0, 0, 0, 0, 0, 0, 0)                          # null
    sh += shdr(shstr_off[".text"], 1, 0x1000, text_off, text_size, 0, 0)
    sh += shdr(shstr_off[".symtab"], 2, 0, symtab_off, len(symtab), 3, 5)
    sh += shdr(shstr_off[".strtab"], 3, 0, strtab_off_abs, len(strtab), 0, 0)
    sh += shdr(shstr_off[".dynsym"], 11, 0, dynsym_off, len(dynsym), 5, 6)
    sh += shdr(shstr_off[".dynstr"], 3, 0, dynstr_off_abs, len(dynstr), 0, 0)
    sh += shdr(shstr_off[".shstrtab"], 3, 0, shstr_off_abs, shstr_size, 0, 0)  # .shstrtab

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0, 0, 0, 0, 0, 0, 0]),
        3,          # e_type: ET_DYN (shared object)
        62,         # e_machine: EM_X86_64
        1,          # e_version
        0,          # e_entry
        0,          # e_phoff
        shoff,      # e_shoff = 节表偏移
        0,          # e_flags
        64,         # e_ehsize
        0,          # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        shnum,      # e_shnum
        6           # e_shstrndx
    )
    assert len(ehdr) == 64

    with open(out, "wb") as f:
        f.write(ehdr)
        f.write(b"\x90" * text_size)          # .text (nop 填充)
        f.write(symtab)
        f.write(strtab)
        f.write(dynsym)
        f.write(dynstr)
        f.write(shstr)
        f.write(sh)                           # 节头表
    print(f"wrote {out} ({total} bytes)")

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "test_lib.so")
