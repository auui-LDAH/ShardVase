#!/usr/bin/env python3
# prot_wizard.py — 保护接入向导 (P0, prot_sdk/wizard)
# 流程: 选择工程目录 -> 生成骨架(业务模板) -> 配置密钥/序列号 -> 构建 -> smoke
# 核心函数 generate_project/build_project 与 GUI 解耦 (可无头调用/测试)。
import json
import os
import shutil
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))  # <repo>/prot_sdk/wizard -> <repo>
SKELETON = os.path.join(REPO_ROOT, 'prot_sdk', 'skeleton')

SKEL_FILES = ['app_main.c', 'prot_shell.h', 'strings.txt', 'version.rc',
              'license_hash.vasm', 'license_mix.vasm', 'license_verify.vasm',
              'license_gate.vasm', 'build_skeleton.ps1']
VASMS = ['license_hash.vasm', 'license_mix.vasm', 'license_verify.vasm',
         'license_gate.vasm']


def generate_project(project_dir, app_name=None, display_name=None,
                     serial='DEMO-2026-ABCDEFGH', key_mode='new',
                     pub_blob_path=None, lite=False, business_name=None):
    """生成骨架工程 (纯逻辑, GUI 与测试共用). 返回工程路径."""
    project_dir = os.path.abspath(project_dir)
    os.makedirs(project_dir, exist_ok=True)
    app_name = app_name or 'protected_app'
    display_name = display_name or app_name
    if not business_name:
        business_name = 'business_' + (app_name.replace('-', '_')) + '.c'

    # 1. 复制骨架文件 (不覆盖已有)
    for f in SKEL_FILES:
        dst = os.path.join(project_dir, f)
        if not os.path.exists(dst):
            shutil.copy2(os.path.join(SKELETON, f), dst)

    # 业务模板 -> 为工程命名
    dst_biz = os.path.join(project_dir, business_name)
    if not os.path.exists(dst_biz):
        shutil.copy2(os.path.join(SKELETON, 'business_stub.c'), dst_biz)

    # 2. 配置
    cfg = {
        'schema': 'prot-project/1',
        'app_name': app_name,
        'display_name': display_name,
        'serial': serial,
        'key_mode': key_mode,          # new | pub
        'key_pub_blob': os.path.abspath(pub_blob_path) if pub_blob_path else '',
        'lite': lite,
        'out_dir': os.path.join(project_dir, 'build'),
        'repo_path': REPO_ROOT,
        'generated_at': __import__('datetime').datetime.now(
            __import__('datetime').timezone.utc).isoformat(),
    }
    with open(os.path.join(project_dir, 'build-skeleton.json'), 'w',
              encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write('\n')

    # vm_build.json (不存在才建; serial 用户配置)
    vb = os.path.join(project_dir, 'vm_build.json')
    if not os.path.exists(vb):
        with open(vb, 'w', encoding='utf-8') as f:
            json.dump({'serial': serial, 'machine_id': 0}, f)

    return project_dir


def build_project(project_dir, powershell='powershell.exe',
                  out=None, log_cb=None):
    """调 build_skeleton.ps1 (纯逻辑). 返回 (rc, 输出文本)."""
    script = os.path.join(project_dir, 'build_skeleton.ps1')
    if not os.path.isfile(script):
        raise RuntimeError('build_skeleton.ps1 missing (run wizard first)')
    cmd = [powershell, '-NoProfile', '-ExecutionPolicy', 'Bypass',
           '-File', script, '-Project', project_dir]
    if out:
        cmd += ['-Out', out]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    text = r.stdout + '\n' + r.stderr
    if log_cb:
        log_cb(text)
    return r.returncode, text


class ProtWizard:
    def __init__(self, root):
        self.root = root
        root.title('保护接入向导 (prot_sdk P0)')
        root.geometry('760x620')
        self._build()
        self.log('就绪: 骨架来源 %s' % SKELETON)

    def _build(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill='both', expand=True)
        main.columnconfigure(0, weight=1)

        # 步骤 1: 工程
        f1 = ttk.LabelFrame(main, text='1. 工程 (新目录: 将生成骨架工程)')
        f1.grid(row=0, column=0, sticky='ew', pady=4)
        r1 = ttk.Frame(f1); r1.pack(fill='x', padx=8, pady=4)
        ttk.Button(r1, text='选择目录', command=self.pick_dir).pack(side='left')
        self.dir_var = tk.StringVar()
        ttk.Entry(r1, textvariable=self.dir_var, width=60).pack(
            side='left', fill='x', expand=True, padx=6)
        r2 = ttk.Frame(f1); r2.pack(fill='x', padx=8, pady=2)
        ttk.Label(r2, text='产品名(显示):').pack(side='left')
        self.disp_var = tk.StringVar(value='my-tool')
        ttk.Entry(r2, textvariable=self.disp_var, width=16).pack(side='left', padx=4)
        ttk.Label(r2, text='exe 名:').pack(side='left')
        self.app_var = tk.StringVar(value='my_tool')
        ttk.Entry(r2, textvariable=self.app_var, width=16).pack(side='left', padx=4)
        ttk.Label(r2, text='序列号:').pack(side='left')
        self.serial_var = tk.StringVar(value='DEMO-2026-ABCDEFGH')
        ttk.Entry(r2, textvariable=self.serial_var, width=22).pack(side='left', padx=4)

        # 步骤 2: 密钥
        f2 = ttk.LabelFrame(main, text='2. 密钥模式')
        f2.grid(row=1, column=0, sticky='ew', pady=4)
        r3 = ttk.Frame(f2); r3.pack(fill='x', padx=8, pady=4)
        self.key_mode = tk.StringVar(value='new')
        ttk.Radiobutton(r3, text='新密钥 (开发/演示, 构建自动自签+smoke)',
                        variable=self.key_mode, value='new').pack(side='left')
        ttk.Radiobutton(r3, text='引用正式公钥 (pub-blob.c, 授权由签发体系下发)',
                        variable=self.key_mode, value='pub').pack(side='left', padx=8)
        r4 = ttk.Frame(f2); r4.pack(fill='x', padx=8, pady=2)
        ttk.Label(r4, text='pub-blob.c 路径:').pack(side='left')
        self.pub_var = tk.StringVar()
        ttk.Entry(r4, textvariable=self.pub_var, width=50).pack(
            side='left', fill='x', expand=True, padx=6)
        ttk.Button(r4, text='浏览', command=self.pick_pub).pack(side='left')

        # 步骤 3: 选项
        f3 = ttk.LabelFrame(main, text='3. 选项')
        f3.grid(row=2, column=0, sticky='ew', pady=4)
        r5 = ttk.Frame(f3); r5.pack(fill='x', padx=8, pady=4)
        self.lite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r5, text='Lite 模式 (内部工具: 隐藏咨询提示, 其余保护不变)',
                        variable=self.lite_var).pack(side='left')
        ttk.Button(r5, text='生成工程', command=self.do_gen).pack(side='right')
        ttk.Button(r5, text='构建 + smoke', command=self.do_build).pack(
            side='right', padx=6)

        # 日志
        logf = ttk.LabelFrame(main, text='日志')
        logf.grid(row=3, column=0, sticky='nsew', pady=4)
        main.rowconfigure(3, weight=1)
        self.logbox = scrolledtext.ScrolledText(logf, height=14, font=('Consolas', 9))
        self.logbox.pack(fill='both', expand=True, padx=8, pady=6)

    def log(self, msg):
        self.logbox.insert('end', msg + '\n')
        self.logbox.see('end')

    def pick_dir(self):
        p = filedialog.askdirectory(title='选择工程目录 (新建/空目录)')
        if p:
            self.dir_var.set(p)

    def pick_pub(self):
        p = filedialog.askopenfilename(filetypes=[('公钥 C 数组', '*.c')])
        if p:
            self.pub_var.set(p)

    def do_gen(self):
        d = self.dir_var.get().strip()
        if not d:
            messagebox.showwarning('提示', '请先选择工程目录')
            return
        try:
            generate_project(
                d, app_name=self.app_var.get().strip() or None,
                display_name=self.disp_var.get().strip() or None,
                serial=self.serial_var.get().strip() or 'DEMO-2026-ABCDEFGH',
                key_mode=self.key_mode.get(),
                pub_blob_path=self.pub_var.get().strip() or None,
                lite=self.lite_var.get())
            self.log('工程已生成: %s' % d)
            self.log('在业务文件 (business_*.c) 中写你的逻辑, 然后 [构建 + smoke]')
        except Exception as e:
            self.log('生成失败: %s' % e)

    def do_build(self):
        d = self.dir_var.get().strip()
        if not d:
            messagebox.showwarning('提示', '请先选择工程目录')
            return
        self.log('构建中 (首次约 1-3 分钟)...')
        self.root.update_idletasks()
        try:
            rc, text = build_project(d, log_cb=self.log)
            self.log('构建结束 rc=%d' % rc)
        except Exception as e:
            self.log('构建失败: %s' % e)


def main():
    root = tk.Tk()
    ProtWizard(root)
    root.mainloop()


if __name__ == '__main__':
    main()