/*
 * version.h — 版本规范 (RELEASE §1, 单一事实来源)
 *
 * 语义化版本 MAJOR.MINOR.PATCH:
 *   MAJOR: 破坏性接口/格式变化 (license 载荷、blob 格式、demo_mem 等)
 *   MINOR: 新能力 (指令/检测项/兼容格式扩展)
 *   PATCH: 缺陷修复
 * 版本号只在本文件修改; build.ps1 / version.rc / --version 均读它, 不得二次硬编码。
 */
#ifndef PROT_VERSION_H
#define PROT_VERSION_H

#define PROT_VERSION_MAJOR 1
#define PROT_VERSION_MINOR 0
#define PROT_VERSION_PATCH 0

#define PROT_VERSION_STR "1.0.0"

/* RC 资源文件用的逗号分隔版本 (version.rc FILEVERSION/PRODUCTVERSION) */
#define PROT_VERSION_RC_NUM 1,0,0,0

#endif /* PROT_VERSION_H */
