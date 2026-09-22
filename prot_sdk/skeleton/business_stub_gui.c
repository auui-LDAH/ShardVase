/*
 * business_stub_gui.c — GUI 业务层模板 (prot_sdk/skeleton)
 *
 * 与 business_stub.c 的关系:
 *   同一个业务契约 (prot_business_main), 区别只在**业务的形态**:
 *     business_stub.c      控制台业务 (printf 输出)
 *     本文件               窗口业务 (建窗 + 消息循环)
 *
 * 保护壳 (app_main.c) **两者完全相同、零改动** —— 见 GUI_GUIDE.md。
 * 之所以能这样, 是因为构建时用 /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup
 * 让标准 main() 在 WINDOWS 子系统中工作, 壳不需要变成 WinMain。
 *
 * 用法:
 *   1. 用 -Gui 构建 (build_skeleton.ps1 -Gui), 或在向导中选 GUI 形态;
 *   2. 在 prot_business_main 里建你的主窗口 (本文件已给可运行的最小窗口);
 *   3. 把 CreateMainWindow 之后的部分换成你的真实 UI;
 *   4. 按授权分级控制功能: ctx->license_tier (0 试用 / 1 正式 / 2 高级)。
 *
 * 注意 (实测经验):
 *   · GUI 子系统程序没有控制台窗口, 但 **stdout 在被重定向时仍可写**
 *     (实测 subprocess 捕获与文件重定向均正常)。故保护壳的诊断输出、
 *     以及构建期 smoke 测试的判据 ('license: 1') 都不受影响。
 *   · 若你的产品需要"双击运行时不弹控制台", 这正是 -Gui 的作用。
 *     反之若希望保留控制台便于排障, 用普通 (CONSOLE) 构建。
 */
#include <stdio.h>
#include <string.h>

#include <windows.h>

#include "prot_shell.h"

/* tier 上限与壳内定义 (PROT_LICENSE_TIER_PREMIUM=2) 一致 */
#define PROT_BUSINESS_TIER_PREMIUM_HINT 2

/* 窗口类名 (单实例场景下用固定名即可) */
#define GUI_WNDCLASS L"ProtSdkGuiSkel"

static const prot_business_ctx* g_ctx = NULL;  /* 窗口过程读取的授权上下文 */

/* -- 示例业务函数: 纯函数 (适合迁移进 VM, 无 IO 依赖) -------------------- */
/* 与 business_stub.c 中同名函数一致, 便于对照与 VM 化。 */
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

/* -- 窗口过程 ---------------------------------------------------------- */
static LRESULT CALLBACK gui_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;   /* /W4 /WX: 未使用的参数必须是显式的 (警告即错误) */
    switch (msg) {
    case WM_CREATE:
        return 0;

    case WM_COMMAND:
        /* 示例: 命令 1 = 显示授权信息 (演示业务可读授权上下文) */
        if (LOWORD(wp) == 1 && g_ctx != NULL) {
            wchar_t buf[256];
            _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                         L"serial=%hs\ntier=%u\nexpires=%u\nmachine=0x%016llx",
                         g_ctx->serial,
                         (unsigned)g_ctx->license_tier,
                         (unsigned)g_ctx->license_expires,
                         (unsigned long long)g_ctx->machine_id);
            MessageBoxW(hwnd, buf, L"\u6388\u6743\u4fe1\u606f",
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

/* -- 建主窗口 ---------------------------------------------------------- */
static HWND gui_create_main_window(HINSTANCE hinst, const wchar_t* title)
{
    WNDCLASSEXW wc;
    HWND hwnd;

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = gui_wndproc;
    wc.hInstance     = hinst;
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = GUI_WNDCLASS;
    if (RegisterClassExW(&wc) == 0) {
        return NULL;
    }

    /* 居中显示的固定尺寸窗口 (真实产品替换为你的窗口/对话框) */
    hwnd = CreateWindowExW(
        0, GUI_WNDCLASS, title,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 720, 480,
        NULL, NULL, hinst, NULL);
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

    hwnd = gui_create_main_window(hinst, title);
    if (hwnd == NULL) {
        /* 建窗失败: 属业务故障, 返回非 0 让调用方/脚本能察觉。
         * 注意不要在这里 printf 依赖控制台存在 —— 已用 stderr 兜底。 */
        fprintf(stderr, "business: CreateWindow failed (err=%lu)\n",
                (unsigned long)GetLastError());
        return 3;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    /* 标准消息循环 */
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam; /* 业务正常结束 -> 程序退出码 */
}
