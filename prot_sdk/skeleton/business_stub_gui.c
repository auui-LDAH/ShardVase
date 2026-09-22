/*
 * business_stub_gui.c — GUI 业务层模板 (prot_sdk/skeleton)
 *
 * 与 business_stub.c 的关系:
 *   同一个业务契约 (prot_business_main), 区别只在**业务的形态**:
 *     business_stub.c      控制台业务 (printf 输出)
 *     本文件               窗口业务 (建窗 + 消息循环)
 *
 * 保护壳 (app_main.c) **两者完全相同** —— 见 GUI_GUIDE.md。
 * 之所以能这样, 是因为构建时用 /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup
 * 让标准 main() 在 WINDOWS 子系统中工作, 壳不需要变成 WinMain。
 *
 * ---------------------------------------------------------------------------
 * 本文件提供两项 GUI 特有能力:
 *   1. **序列号输入窗口** (prot_shell_serial_provider)
 *      解决"GUI 双击运行无 stdin"问题。壳用 /alternatename 弱符号解析:
 *      本函数存在 -> 壳弹窗收集序列号; 不存在 -> 壳回退 stdin (行为不变)。
 *      **故控制台工程零影响**, 这是向后兼容的关键。
 *   2. **主窗口 + 消息循环** (prot_business_main)
 *
 * 用法:
 *   1. 用 -Gui 构建: build_skeleton.ps1 -Project <dir> -Gui
 *   2. 把 CreateMainWindow 之后的部分换成你的真实 UI
 *   3. 按授权分级控制功能: ctx->license_tier (0 试用 / 1 正式 / 2 高级)
 *
 * 实测经验 (2026-09-21):
 *   · GUI 子系统程序没有控制台, 但 **stdout 在被重定向时仍可写** ——
 *     构建期 smoke 的判据 ('license: 1') 与诊断输出都不受影响。
 *   · 对话框/子窗口用 **程序化创建** (CreateWindowExW) 而非手写
 *     DLGTEMPLATE —— 后者字面对齐易错, 前者可读且可维护。
 */
#include <stdio.h>
#include <string.h>

#include <windows.h>

#include "prot_shell.h"

/* tier 上限与壳内定义 (PROT_LICENSE_TIER_PREMIUM=2) 一致 */
#define PROT_BUSINESS_TIER_PREMIUM_HINT 2

/* 窗口类名 */
#define GUI_MAIN_CLASS   L"ProtSdkGuiSkel"
#define GUI_SERIAL_CLASS L"ProtSdkSerialInput"

static const prot_business_ctx* g_ctx = NULL;  /* 主窗口过程读取的授权上下文 */

/* ---------------------------------------------------------------------------
 * 示例业务函数: 纯函数 (适合迁移进 VM, 无 IO 依赖)
 * 与 business_stub.c 中同名函数一致, 便于对照与 VM 化。
 * ------------------------------------------------------------------------- */
static unsigned long long business_calc(const char* serial, uint64_t hwid)
{
    unsigned long long seed = 1469598103934665603ull; /* FNV basis (示意) */
    size_t i;
    for (i = 0; serial[i] && i < 8; i++) {
        seed ^= (unsigned char)serial[i];
        seed *= 1099511628211ull;
    }
    seed ^= hwid;
    return seed;
}

/* ===========================================================================
 * 序列号输入窗口
 * ===========================================================================
 *
 * 为什么需要它: 保护壳默认从 stdin 读序列号; **GUI 程序双击运行没有
 * stdin**, 实测结果为序列号为空 -> license: 0 -> 拒绝运行。
 *
 * 设计: 用一个模态子窗口 + 编辑框收集序列号, 点"确定"后写回缓冲。
 * 不用 .rc 资源 (保持骨架"少文件易复制"), 也不用 DLGTEMPLATE
 * (字面对齐易错), 而是程序化 CreateWindowExW。
 */

/* 子窗口控件 ID */
#define IDC_EDIT 2001
#define IDC_OK   2002

typedef struct serial_ui {
    HWND   edit;
    HWND   ok;
    char*  out;       /* 输出缓冲 (由调用方提供) */
    unsigned cap;
    int    accepted;  /* 用户点了确定 */
    int    done;      /* 窗口已关闭 */
} serial_ui;

static LRESULT CALLBACK serial_wndproc(HWND hwnd, UINT msg, WPARAM wp,
                                       LPARAM lp)
{
    serial_ui* ui = (serial_ui*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lp;
        ui = (serial_ui*)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ui);
        ui->edit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            15, 40, 300, 24, hwnd, (HMENU)(INT_PTR)IDC_EDIT,
            cs->hInstance, NULL);
        ui->ok = CreateWindowExW(
            0, L"BUTTON", L"\u786e\u5b9a",          /* 确定 */
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            245, 75, 70, 26, hwnd, (HMENU)(INT_PTR)IDC_OK,
            cs->hInstance, NULL);
        CreateWindowExW(0, L"STATIC",
                        L"\u8bf7\u8f93\u5165\u6388\u6743\u5e8f\u5217\u53f7:",  /* 请输入授权序列号: */
                        WS_CHILD | WS_VISIBLE,
                        15, 15, 300, 20, hwnd, NULL, cs->hInstance, NULL);
        SetFocus(ui->edit);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_OK || LOWORD(wp) == IDOK) {
            if (ui != NULL && ui->out != NULL) {
                GetWindowTextA(ui->edit, ui->out, (int)ui->cap);
                ui->accepted = (ui->out[0] != '\0');
            }
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wp) == IDCANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (ui != NULL) {
            ui->done = 1;
        }
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* 显示序列号输入窗口 (模态: 内部跑自己的消息循环)。
 * 返回 0 = 用户确认且缓冲非空; 非 0 = 取消/失败。 */
static int show_serial_input(char* out, unsigned cap)
{
    static int registered = 0;
    HINSTANCE hinst = GetModuleHandleW(NULL);
    serial_ui ui;
    HWND hwnd;
    MSG msg;
    RECT rc;
    int w = 350, h = 150;
    int x, y;

    if (out == NULL || cap == 0) {
        return -1;
    }
    out[0] = '\0';

    if (!registered) {
        WNDCLASSEXW wc;
        ZeroMemory(&wc, sizeof(wc));
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = serial_wndproc;
        wc.hInstance     = hinst;
        wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = GUI_SERIAL_CLASS;
        if (RegisterClassExW(&wc) == 0) {
            return -1;
        }
        registered = 1;
    }

    ZeroMemory(&ui, sizeof(ui));
    ui.out = out;
    ui.cap = cap;

    /* 居中于屏幕 */
    rc.left = 0; rc.top = 0; rc.right = w; rc.bottom = h;
    AdjustWindowRect(&rc, WS_CAPTION | WS_SYSMENU, FALSE);
    w = rc.right - rc.left;
    h = rc.bottom - rc.top;
    x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        GUI_SERIAL_CLASS, L"\u8f6f\u4ef6\u6388\u6743",   /* 软件授权 */
        WS_CAPTION | WS_SYSMENU | WS_POPUP,
        x, y, w, h, NULL, NULL, hinst, &ui);
    if (hwnd == NULL) {
        return -1;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    /* 本地模态消息循环: 直到窗口销毁 */
    while (!ui.done && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.hwnd == hwnd || IsChild(hwnd, msg.hwnd)) {
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
                SendMessageW(hwnd, WM_COMMAND, IDC_OK, 0);
                continue;
            }
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
                SendMessageW(hwnd, WM_COMMAND, IDCANCEL, 0);
                continue;
            }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return ui.accepted ? 0 : -1;
}

/* ---------------------------------------------------------------------------
 * 壳调用的序列号提供者 —— **定义此函数即覆盖壳内默认实现**
 *
 * 壳用 MSVC 的 /alternatename 弱符号机制解析:
 *   · 本函数存在   -> 壳调用它 (GUI 弹窗收集序列号)
 *   · 本函数不存在 -> 链接到壳内默认实现 -> 回退 stdin
 * 故控制台工程**行为完全不变** (已实测: 未定义时 rc=-1 -> 回退 stdin)。
 * ------------------------------------------------------------------------- */
/* 判断是否应该弹出输入窗口 —— 即"真双击运行"场景。
 *
 * ## 判据的选择依据（实测，2026-09-21）
 *
 * 第一版用 `GetFileType(stdin) != FILE_TYPE_UNKNOWN` 判断，**是错的**：
 * 实测 stdin 在"双击/无控制台/管道/普通启动"**四种场景下都返回
 * FILE_TYPE_CHAR(2)** —— 该判据恒为假，导致真双击时反而不弹窗
 * （实测表现为进程直接退出 rc=1，等于没修）。
 *
 * 改用 GetConsoleWindow()，实测能唯一区分：
 *   | 场景                          | console_window |
 *   |-------------------------------|----------------|
 *   | 双击（无控制台）               | **NULL**       |
 *   | 命令行 / CI（继承父控制台）     | 非 NULL        |
 *
 * 结论：**无控制台 = 双击 = 弹窗**；有控制台 = 自动化/命令行 = 回退 stdin。
 * 这样构建脚本的 smoke（重定向运行，有控制台）不会被弹窗阻塞。
 */
static int should_show_dialog(void)
{
    return GetConsoleWindow() == NULL;
}

/* 从环境变量取序列号 (用于 CI / 构建期 smoke: 显式、可测、无交互) */
static int serial_from_env(char* buf, unsigned cap)
{
    DWORD n = GetEnvironmentVariableA("PROT_SERIAL", buf, cap);
    if (n > 0 && n < cap) {
        return 0;
    }
    buf[0] = '\0';
    return -1;
}

/* 从 exe 同目录的 serial.txt 取序列号 (用于产品部署: 序列号随包交付,
 * 双击即用, 用户无需输入)。首行非空即采用, 自动去掉行尾换行。 */
static int serial_from_file(char* buf, unsigned cap)
{
    char path[MAX_PATH];
    char exe[MAX_PATH];
    FILE* f;
    size_t n;
    char* slash;

    if (GetModuleFileNameA(NULL, exe, (DWORD)sizeof(exe)) == 0) {
        return -1;
    }
    slash = strrchr(exe, '\\');
    if (slash == NULL) {
        return -1;
    }
    *(slash + 1) = '\0';
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%sserial.txt", exe);

    /* 用 fopen_s 而非 fopen: 后者在 MSVC /W4 下触发 C4996 弃用警告,
     * 而本项目编译参数是 /WX(警告即错误)。 */
    if (fopen_s(&f, path, "r") != 0 || f == NULL) {
        return -1;
    }
    if (fgets(buf, (int)cap, f) == NULL) {
        fclose(f);
        buf[0] = '\0';
        return -1;
    }
    fclose(f);
    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }
    return (n > 0) ? 0 : -1;
}

int prot_shell_serial_provider(char* buf, unsigned cap)
{
    /* 获取顺序 (显式来源优先, 弹窗是最后手段):
     *   1. 环境变量 PROT_SERIAL  —— CI / 构建期 smoke (无交互)
     *   2. exe 旁 serial.txt     —— 产品部署 (序列号随包交付, 双击即用)
     *   3. 无控制台 (真双击)     —— 弹窗收集
     *   4. 有控制台              —— 返回 -1, 壳回退 stdin (行为不变)
     */
    if (serial_from_env(buf, cap) == 0) {
        printf("\u5e8f\u5217\u53f7\u6765\u81ea\u73af\u5883\u53d8\u91cf PROT_SERIAL\n");
        fflush(stdout);
        return 0;
    }
    if (serial_from_file(buf, cap) == 0) {
        printf("\u5e8f\u5217\u53f7\u6765\u81ea serial.txt\n");
        fflush(stdout);
        return 0;
    }
    if (!should_show_dialog()) {
        return -1;  /* 有控制台 -> 自动化/命令行 -> 壳回退 stdin */
    }
    if (show_serial_input(buf, cap) == 0) {
        printf("\u5e8f\u5217\u53f7\u7531 GUI \u5bf9\u8bdd\u6846\u63d0\u4f9b\n");
        fflush(stdout);
        return 0;
    }
    /* 取消 -> 返回非 0, 壳回退 stdin (便于命令行/CI 场景) */
    printf("\u5bf9\u8bdd\u6846\u53d6\u6d88 - \u56de\u9000 stdin\n");
    fflush(stdout);
    return -1;
}

/* ===========================================================================
 * 主窗口
 * =========================================================================== */

static LRESULT CALLBACK main_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;   /* /W4 /WX: 未使用的参数必须显式忽略 */
    switch (msg) {
    case WM_CREATE:
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == 1 && g_ctx != NULL) {
            wchar_t buf[256];
            _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                         L"serial=%hs\ntier=%u\nexpires=%u\nmachine=0x%016llx",
                         g_ctx->serial,
                         (unsigned)g_ctx->license_tier,
                         (unsigned)g_ctx->license_expires,
                         (unsigned long long)g_ctx->machine_id);
            MessageBoxW(hwnd, buf, L"\u6388\u6743\u4fe1\u606f",  /* 授权信息 */
                        MB_OK | MB_ICONINFORMATION);
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static HWND create_main_window(HINSTANCE hinst, const wchar_t* title)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    HWND btn;

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = main_wndproc;
    wc.hInstance     = hinst;
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = GUI_MAIN_CLASS;
    if (RegisterClassExW(&wc) == 0) {
        return NULL;
    }

    hwnd = CreateWindowExW(
        0, GUI_MAIN_CLASS, title, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 720, 480,
        NULL, NULL, hinst, NULL);
    if (hwnd == NULL) {
        return NULL;
    }

    /* 一个示例按钮: 点它显示授权信息 (演示业务可读授权上下文) */
    btn = CreateWindowExW(0, L"BUTTON",
                          L"\u67e5\u770b\u6388\u6743\u4fe1\u606f", /* 查看授权信息 */
                          WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                          20, 20, 160, 32, hwnd, (HMENU)1, hinst, NULL);
    (void)btn;
    return hwnd;
}

/* -- 业务入口 (壳在授权门通过后调用; 返回值 = 程序退出码) ------------------ */
int prot_business_main(const prot_business_ctx* ctx)
{
    HINSTANCE hinst;
    HWND hwnd;
    MSG msg;
    unsigned long long seed;
    wchar_t title[160];

    if (ctx == NULL || !ctx->license_ok) {
        return 1; /* 防御: 授权未通过不应到达这里 */
    }
    g_ctx = ctx;

    seed = business_calc(ctx->serial, ctx->machine_id);

    /* 诊断输出: GUI 下无控制台, 但重定向时仍可见 (构建期 smoke 依赖此行为) */
    printf("  business: gui mode serial=%s tier=%u seed=0x%016llx\n",
           ctx->serial, (unsigned)ctx->license_tier,
           (unsigned long long)seed);
    if (ctx->license_tier >= PROT_BUSINESS_TIER_PREMIUM_HINT) {
        printf("  business: premium features enabled\n");
    }
    fflush(stdout);

    hinst = GetModuleHandleW(NULL);
    _snwprintf_s(title, _countof(title), _TRUNCATE,
                 L"ProtSdk GUI \u9aa8\u67b6 \u2014 tier=%u",
                 (unsigned)ctx->license_tier);

    hwnd = create_main_window(hinst, title);
    if (hwnd == NULL) {
        fprintf(stderr, "business: CreateWindow failed (err=%lu)\n",
                (unsigned long)GetLastError());
        return 3;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
