/*
 * libprot.c — Android 原生保护核心 (EXTENSION_PLAN A1)
 *
 * 提供 JNI 接口给 Java/Kotlin:
 *   nativeVerifyLicense(serial, licenseText) -> 0/1/错误码
 *   nativeCheckIntegrity()                  -> 0/1 (ELF .text CRC)
 *   nativeIsDebugged()                      -> 0/1 (ptrace/TracerPid)
 *
 * 依赖: NDK (CMake). RSA 验签走 JNI->JCA (Signature/PKCS1v1.5+SHA256),
 * 避免 libprot.so 携带 OpenSSL 体积; DER 公钥由 vmenc.py
 * keygen --blob-out-der 生成 (demo/gen/prot_pubkey_der.c)。
 *
 * 纯逻辑 (消息构建/解析/分级) 复用 examples/cross_platform/license_auth_common.c,
 * 字节级与 Windows vmenc 一致。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "../license_auth.h"

/* DER SPKI 公钥 (vmenc.py keygen --blob-out-der 生成) */
extern const uint8_t g_prot_pubkey_der[];
extern const size_t g_prot_pubkey_der_len;

/* ELF .text 段 CRC 基准 (构建期烧录; A1 简单版: 由单独工具生成) */
extern const uint32_t g_prot_text_crc_baked;

/* ---------- ELF .text CRC ---------- */
static uint32_t elf_crc32(const uint8_t* data, size_t len);

/* JNI: 校验授权 (serial + license 文本) -> JCA 验签 */
JNIEXPORT jint JNICALL
Java_com_prot_demo_Prot_nativeVerifyLicense(JNIEnv* env, jobject thiz,
                                            jstring jserial, jstring jlicense)
{
    const char* serial = (*env)->GetStringUTFChars(env, jserial, NULL);
    const char* lic = (*env)->GetStringUTFChars(env, jlicense, NULL);
    jint rc = 0;

    (void)thiz;   /* JNI 签名要求, 本函数不使用: 其余 JNI 入口同样显式 (void) */

    /* 解析 license 文本 (跨平台): SERIAL/PRODUCT/TIER/EXPIRES/SIGNATURE */
    char s_serial[64] = {0};
    char s_prod[64] = {0};
    char s_sig_b64[1024] = {0};
    char line[1024];
    uint32_t tier = PROT_TIER_FULL;
    uint32_t expires = 0;
    int have_serial = 0, have_prod = 0, have_sig = 0;
    const char* p = lic;

    /* 逐行解析 (简版: 用 strtok 风格, 跨平台纯 C) */
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t ln = nl ? (size_t)(nl - p) : strlen(p);
        size_t i;
        char key[32] = {0};
        const char* val;
        if (ln >= sizeof(line)) ln = sizeof(line) - 1;
        memcpy(line, p, ln); line[ln] = '\0';
        for (i = 0; i < ln && line[i] != '='; i++) key[i] = line[i];
        key[i] = '\0';
        val = strchr(line, '=');
        if (val) {
            val++;
            prot_auth_strip_crlf((char*)val);
            if (strcmp(key, "SERIAL") == 0) { strncpy(s_serial, val, sizeof(s_serial) - 1); have_serial = 1; }
            else if (strcmp(key, "PRODUCT") == 0) { strncpy(s_prod, val, sizeof(s_prod) - 1); have_prod = 1; }
            else if (strcmp(key, "SIGNATURE") == 0) { strncpy(s_sig_b64, val, sizeof(s_sig_b64) - 1); have_sig = 1; }
        }
        if (!nl) break;
        p = nl + 1;
    }

    if (have_serial && have_prod && have_sig &&
        strcmp(s_serial, serial) == 0 && strcmp(s_prod, PROT_PRODUCT) == 0) {
        /* 构建消息 -> 调 JCA 验签 (Java 侧 impl, 或本文件后 JNI call) */
        uint8_t msg[256];
        size_t mlen = prot_auth_build_message(serial, 0, tier, expires, msg, sizeof(msg));
        /* NOTE: 实际验签由 Java 侧完成 (JCA Signature), 此处返回 1 表示
         * 消息构建 + 格式通过; 完整 JCA 验签链路见 Prot.java。
         * 安全: 生产必须让 Java 侧真正验签 (base64(SIGNATURE) + Signature.verify)。 */
        (void)mlen;
        rc = 1;
    }

    (*env)->ReleaseStringUTFChars(env, jserial, serial);
    (*env)->ReleaseStringUTFChars(env, jlicense, lic);
    return rc;
}

/* JNI: 完整性自检 (ELF .text CRC) */
JNIEXPORT jint JNICALL
Java_com_prot_demo_Prot_nativeCheckIntegrity(JNIEnv* env, jobject thiz)
{
    /* ELF 自身 .text 定位 (跨 Android API 通用): /proc/self/exe 读映射太复杂,
     * 生产用 dl_iterate_phdr / __attribute__((section)) 导入 CRC。
     * 骨架: 返回 g_prot_text_crc_baked 非 0 = 构建期已烧录。 */
    (void)env; (void)thiz;
    return g_prot_text_crc_baked != 0u ? 1 : 0;
}

/* JNI: 反调试 (TracerPid) */
JNIEXPORT jint JNICALL
Java_com_prot_demo_Prot_nativeIsDebugged(JNIEnv* env, jobject thiz)
{
    FILE* f = fopen("/proc/self/status", "r");
    char line[256];
    int traced = 0;
    (void)env; (void)thiz;
    if (f == NULL) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid > 0) traced = 1;
            break;
        }
    }
    fclose(f);
    return traced ? 1 : 0;
}

/* ---- A2: 反 Frida / 反 Xposed ---- */
JNIEXPORT jint JNICALL
Java_com_prot_demo_Prot_nativeDetectHook(JNIEnv* env, jobject thiz)
{
    /* 扫描 /proc/self/maps: frida-agent / gum / xposed 特征 */
    FILE* f = fopen("/proc/self/maps", "r");
    char line[512];
    int hit = 0;
    const char* items[] = { "frida", "gum-js", "xposed", "de.robv.android", NULL };
    (void)env; (void)thiz;
    if (f == NULL) return 0;
    while (fgets(line, sizeof(line), f)) {
        int i;
        for (i = 0; items[i]; i++) {
            if (strstr(line, items[i]) != NULL) {
                hit = 1;
                break;
            }
        }
        if (hit) break;
    }
    fclose(f);
    /* 补充: 扫描已加载 .so 列表 (dl_iterate_phdr 或 /proc/self/maps 已覆盖) */
    return hit ? 1 : 0;
}

/* ---- A2: 看门狗线程 (周期重校验完整性与反调试) ---- */
static int g_wd_stop = 0;
static pthread_t g_wd_thread;

static void* wd_loop(void* arg)
{
    (void)arg;
    while (!g_wd_stop) {
        usleep(5 * 1000 * 1000); /* 5s 周期 */
        /* 生产: 调 nativeIsDebugged/nativeCheckIntegrity/nativeDetectHook,
         * 命中按策略处理 (这里返回 JNI bool 由 Java 侧决定 EXIT)。 */
    }
    return NULL;
}

JNIEXPORT void JNICALL
Java_com_prot_demo_Prot_nativeStartWatchdog(JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    if (g_wd_thread == 0) {
        g_wd_stop = 0;
        pthread_create(&g_wd_thread, NULL, wd_loop, NULL);
    }
}

JNIEXPORT void JNICALL
Java_com_prot_demo_Prot_nativeStopWatchdog(JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    g_wd_stop = 1;
    if (g_wd_thread) {
        pthread_join(g_wd_thread, NULL);
        g_wd_thread = 0;
    }
}

/* ---- CRC32 (标准 0xEDB88320, 与 Windows prot_crc32 同语义) ----
 * A1 骨架助手: 待 nativeCheckIntegrity 接上 dl_iterate_phdr 自定位后即被调用。
 * 在此之前无人引用 —— 显式标注, 否则 -Wall -Wextra -Werror 下是硬错误
 * (2026-10-06 真实 NDK 交叉编译暴露)。`used` 抑制 -Wunused-function。 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((used))
#endif
static uint32_t elf_crc32(const uint8_t* data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    for (i = 0; i < len; i++) {
        int bit;
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int)(crc & 1u));
    }
    return crc ^ 0xFFFFFFFFu;
}