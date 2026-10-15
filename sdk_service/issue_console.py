#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
# issue_console.py — 本机图形化签发台 (sdk_service GUI, 中文界面)
# 流程: Taildrop 收 .req → 打开本工具 → 核对(双通道) → 签发 → license 发回
# 依赖: python + tkinter(标准库) + tools/vmenc.py; 私钥用本机备份副本。
# 界面: 仅本机使用(不发给客户)。
import argparse
import datetime
import json
import os
import subprocess
import sys
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import vmenc

DEFAULT_KEY = os.path.join(ROOT, 'sdk_service', 'keys', 'prot-priv-backup.json')
DEFAULT_PUB = os.path.join(ROOT, 'sdk_service', 'keys', 'pub-der.c')
DEFAULT_LOG = os.path.join(ROOT, 'sdk_service', 'issue-log.csv')
TAILDROP_DIR = os.path.join(os.path.expanduser('~'), 'Downloads')


def load_req(path):
    with open(path, 'r', encoding='utf-8') as f:
        req = json.load(f)
    if req.get('schema') != 'prot-req/1':
        raise vmenc.VasmError('不支持的申请文件 schema: %r' % req.get('schema'))
    mid = vmenc.parse_machine_id_override(req.get('machine_id_hex', '0'))
    if not mid:
        raise vmenc.VasmError('申请文件缺少有效的 machine_id')
    return req, mid


def issue_direct(key_path, req_path, serial, tier, expires,
                 out_dir, log_path, note_extra=''):
    """签发核心(与 GUI 解耦, 可命令行/测试直接调用). 返回 license 绝对路径."""
    req, mid = load_req(req_path)
    if not serial.isascii():
        raise vmenc.VasmError('serial 必须为 ASCII')
    os.makedirs(out_dir, exist_ok=True)
    license_out = os.path.join(out_dir, 'license.txt')
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as tf:
        json.dump({'serial': serial, 'machine_id': mid}, tf)
        tmp_json = tf.name
    try:
        import argparse as _a
        args = _a.Namespace(
            key_path=key_path, json_path=tmp_json,
            machine_id_override=str(mid), tier=tier, expires=expires,
            customer=req['customer'],
            note='%s %sreq_nonce=%s req_at=%s' % (
                req.get('note', ''), note_extra or '',
                req.get('nonce', '?'), req.get('requested_at', '?')),
            license_out=license_out, log=log_path)
        vmenc.cmd_issue(args)
    finally:
        os.unlink(tmp_json)
    return license_out, req


class IssueConsole:
    def __init__(self, root):
        self.root = root
        self.req = None
        self.req_path = None
        self.checked_ok = False
        self.last_license = None
        root.title('授权签发台 (sdk_service A-1)')
        root.geometry('720x560')
        self._build()
        self.log('就绪: 等待 .req (Taildrop 落盘在 %s)' % TAILDROP_DIR)

    def _build(self):
        pad = {'padx': 8, 'pady': 4}
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill='both', expand=True)
        main.columnconfigure(0, weight=1)

        top = ttk.Frame(main)
        top.grid(row=0, column=0, sticky='ew', **pad)
        ttk.Button(top, text='打开 .req', command=self.pick_req).pack(side='left')
        self.req_entry = ttk.Entry(top)
        self.req_entry.pack(side='left', fill='x', expand=True, padx=6)
        ttk.Button(top, text='Taildrop 目录', command=self.open_downloads).pack(side='left')

        info = ttk.LabelFrame(main, text='申请信息')
        info.grid(row=1, column=0, sticky='ew', **pad)
        self.lbl_info = tk.Label(info, anchor='w', justify='left', font=('Consolas', 10))
        self.lbl_info.pack(fill='x', padx=8, pady=6)
        self.set_info('(未加载)')

        chk = ttk.LabelFrame(main, text='双通道核对 (客户口头报来的 MACHINE_ID)')
        chk.grid(row=2, column=0, sticky='ew', **pad)
        cf = ttk.Frame(chk)
        cf.pack(fill='x', padx=8, pady=6)
        self.voice_var = tk.StringVar()
        ttk.Entry(cf, textvariable=self.voice_var, width=24,
                  font=('Consolas', 10)).pack(side='left')
        ttk.Button(cf, text='核对', command=self.do_check).pack(side='left', padx=6)
        self.chk_state = tk.Label(cf, text='未核对', fg='gray')
        self.chk_state.pack(side='left')

        par = ttk.LabelFrame(main, text='签发参数')
        par.grid(row=3, column=0, sticky='ew', **pad)
        pf = ttk.Frame(par)
        pf.pack(fill='x', padx=8, pady=6)
        ttk.Label(pf, text='serial:').pack(side='left')
        self.serial_var = tk.StringVar(value='DEMO-2026-ABCDEFGH')
        ttk.Entry(pf, textvariable=self.serial_var, width=26,
                  font=('Consolas', 10)).pack(side='left', padx=4)
        ttk.Label(pf, text='tier:').pack(side='left')
        self.tier_var = tk.StringVar(value='1')
        ttk.Combobox(pf, textvariable=self.tier_var, values=('0', '1', '2'),
                     width=4, state='readonly').pack(side='left', padx=4)
        ttk.Label(pf, text='expires(0=永久):').pack(side='left')
        self.expires_var = tk.StringVar(value='0')
        ttk.Entry(pf, textvariable=self.expires_var, width=12,
                  font=('Consolas', 10)).pack(side='left', padx=4)
        ttk.Label(pf, text='私钥:').pack(side='left')
        self.key_var = tk.StringVar(value=DEFAULT_KEY)
        ttk.Entry(pf, textvariable=self.key_var, width=22,
                  font=('Consolas', 8)).pack(side='left', padx=4)

        act = ttk.Frame(main)
        act.grid(row=4, column=0, sticky='ew', **pad)
        self.issue_btn = ttk.Button(act, text='签发并生成回执',
                                    command=self.issue, state='disabled')
        self.issue_btn.pack(side='left')
        ttk.Button(act, text='验签自检', command=self.verify_last).pack(
            side='left', padx=6)
        ttk.Button(act, text='复制回执文本', command=self.copy_receipt).pack(
            side='left')

        logf = ttk.LabelFrame(main, text='签发日志 / 台账')
        logf.grid(row=5, column=0, sticky='nsew', **pad)
        main.rowconfigure(5, weight=1)
        self.logbox = scrolledtext.ScrolledText(logf, height=10,
                                                font=('Consolas', 9))
        self.logbox.pack(fill='both', expand=True, padx=8, pady=6)

    def log(self, msg):
        self.logbox.insert('end', '%s  %s\n' % (
            datetime.datetime.now().strftime('%H:%M:%S'), msg))
        self.logbox.see('end')

    def set_info(self, text):
        self.lbl_info.configure(text=text)

    def open_downloads(self):
        os.startfile(TAILDROP_DIR)

    def pick_req(self):
        p = filedialog.askopenfilename(
            title='选择 .req 申请文件', filetypes=[('申请文件', '*.req'), ('所有文件', '*.*')])
        if not p:
            return
        self.req_entry.delete(0, 'end')
        self.req_entry.insert(0, p)
        try:
            self.load_req(p)
        except Exception as e:
            self.log('载入失败: %s' % e)

    def load_req(self, path):
        req, mid = load_req(path)
        self.req, self.req_path = req, path
        self.checked_ok = False
        self.chk_state.configure(text='未核对', fg='gray')
        self.issue_btn.configure(state='disabled')
        self.serial_var.set('DEMO-2026-ABCDEFGH')
        self.set_info(
            '客户: %s\n机器码: %s  (十进制 %d)\nnonce: %s\n申请时间: %s\n'
            '产品: %s    备注: %s' % (
                req['customer'], req['machine_id_hex'], mid,
                req['nonce'], req['requested_at'], req['product'],
                req.get('note') or '-'))
        self.log('已载入: %s (客户=%s)' % (path, req['customer']))

    def do_check(self):
        if self.req is None:
            messagebox.showwarning('提示', '请先打开 .req')
            return
        voice = self.voice_var.get().strip().lower().replace('0x', '')
        want = self.req['machine_id_hex'].lower().replace('0x', '')
        self.checked_ok = (voice == want)
        self.chk_state.configure(
            text='一致 ✓' if self.checked_ok else '不一致 ✗', 
            fg='green' if self.checked_ok else 'red')
        self.issue_btn.configure(state='normal' if self.checked_ok else 'disabled')
        self.log('双通道核对: %s' % ('一致' if self.checked_ok else '不一致'))

    def issue(self):
        if self.req is None or not self.checked_ok:
            return
        key = self.key_var.get().strip()
        if not os.path.isfile(key):
            messagebox.showerror('错误', '私钥不存在: %s' % key)
            return
        serial = self.serial_var.get().strip()
        if not serial.isascii():
            messagebox.showerror('错误', 'serial 必须为 ASCII')
            return
        try:
            tier = int(self.tier_var.get())
            expires = int(self.expires_var.get())
        except ValueError:
            messagebox.showerror('错误', 'tier/expires 必须是整数')
            return
        out_dir = os.path.join(ROOT, 'sdk_service', 'licenses',
                               '%s-%s' % (self.req['customer'],
                                          self.req['nonce'][:8]))
        try:
            self.last_license, _ = issue_direct(
                key, self.req_path, serial, tier, expires,
                out_dir, DEFAULT_LOG)
        except Exception as e:
            self.log('签发失败: %s' % e)
            messagebox.showerror('签发失败', str(e))
            return
        self.log('签发成功: %s' % self.last_license)
        self.verify_last(silent=True)
        self.log('回执: 已复制到剪贴板; license.txt 在 %s (拖入 Taildrop 发给客户)'
                 % self.last_license)

    def receipt_text(self):
        if not self.req:
            return ''
        return ('SERIAL     = %s\nMACHINE_ID = %s\nTIER       = %s\n'
                'EXPIRES    = %s\nlicense    = %s\n\n'
                '邮件模板: 主题 [授权] SN-<订单号> license; 附件 license.txt; '
                '正文: 请将附件 license.txt 放到程序目录后重启。'
                '序列号 <订单号> 已绑定当前机器，换机需重新申请。' % (
                    self.serial_var.get(), self.req['machine_id_hex'],
                    self.tier_var.get(), self.expires_var.get(),
                    self.last_license or '-'))

    def copy_receipt(self):
        t = self.receipt_text()
        if not t:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(t)
        self.log('回执文本已复制')

    def verify_last(self, silent=False):
        if not self.last_license or not os.path.isfile(DEFAULT_PUB):
            if not silent:
                messagebox.showinfo('提示', '尚未签发或公钥缺失')
            return
        try:
            import base64
            import re
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            fields = {}
            with open(self.last_license, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        k, _, v = line.partition('=')
                        fields[k] = v
            text = open(DEFAULT_PUB, encoding='utf-8').read()
            nums = re.findall(r'0[xX][0-9a-fA-F]+',
                              re.search(r'\{([^}]+)\}', text).group(1))
            der = bytes(int(n, 16) for n in nums)
            sig = base64.b64decode(fields['SIGNATURE'])
            pub = serialization.load_der_public_key(der)
            mid = vmenc.parse_machine_id_override(fields['MACHINE_ID'])
            msg = vmenc.license_message(
                fields['SERIAL'], mid, int(fields['TIER']),
                int(fields['EXPIRES']))
            pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            self.log('验签自检: VALID')
        except Exception as e:
            self.log('验签自检: INVALID (%s)' % type(e).__name__)


def main():
    ap = argparse.ArgumentParser(description='授权签发台 GUI')
    ap.add_argument('--req', dest='req', default=None,
                    help='启动即载入的 .req 路径 (可选)')
    args = ap.parse_args()
    root = tk.Tk()
    app = IssueConsole(root)
    if args.req:
        try:
            app.req_entry.insert(0, args.req)
            app.load_req(args.req)
        except Exception as e:
            app.log('载入失败: %s' % e)
    root.mainloop()


if __name__ == '__main__':
    main()