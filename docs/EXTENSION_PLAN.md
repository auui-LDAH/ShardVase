# 保护体系延申规划 — Android 原生 SO（A）+ 跨平台许可服务化（C）

> 版本：2026-08-25 v1 · 状态：**规划完成，未开工** · 关联：`docs/THREATMODEL.md`（威胁模型）·
> `docs/CONTRACT.md`（契约/算法）· `tools/vmenc.py`（RSA 签发核心）· `docs/ATTACK_DRILL*.md`（攻防实证）。
> 本文档规划保护套件**跨越 Windows x64 平台**的延申：
> **A** Android 原生 .so 保护（ARM/ELF 移植）+ **C** 跨平台许可与授权服务化 SDK。

---

## 1. 项目保护边界回顾（延申的事实基础）

### 1.1 当前能力（Windows x64 已实证）
- **伪造锚点**：RSA-2048 离线签发（license/blob/吊销/分级授权/试用期）——私钥离线不可伪造；
- **防分析**：VM 字节码（多 VM 拆分/opcode 置换/语义变异/运行态解密）+ 字符串加密 + N4 间接化 + N1 自变形；
- **防篡改**：文件级 CRC（.text/.rdata/.pdata）+ 运行期 IAT 校验（G2 补洞）+ 看门狗 + N3 冗余；
- **防盗用**：机器绑定 + 分级授权 + 吊销 + 试用期；
- **在线增强**：N5 会话期望值 + 在线吊销 + blob 网络下发（不可重放，实证）。

### 1.2 已知边界（四轮+补充 57 项实证）
| 边界 | 性质 | 延申注意点 |
|------|------|-----------|
| D2a 明文 dump（运行期可取证） | 设计/已知 | Android SO **同样适用**——需同样处理 |
| 离线可 patch（离线优先不锁死） | 设计决策 D2 | Android 出海**离线场景更频繁**，决策保持 |
| 单镜像可还原（多 VM+N5 阻断） | 设计/已知 | Android 若移植 VM 引擎，复用同一架构 |
| DLL 劫持（安装目录可写） | 环境约束 | Android 无同款（APK 沙箱），但**重打包**是替代面 |

---

## 2. 延申目标与原则

### 2.1 目标
1. **A**：Android 原生 .so 用核心校验（license/完整性/防篡改）受到同等保护，
   VM 引擎/自变形/多因子反调试在 ARM/ELF 上落地；
2. **C**：把 RSA 授权体系抽象为**跨平台 SDK**（Android/iOS/Windows/桌面 共一套
   签发与验证），签发中心（vmenc.py）复用，客户端验签逻辑平台一致；
3. 攻防测试矩阵在 Android 上重跑对应项。

### 2.2 原则
- **不动 Windows 侧已验证能力**（回归零影响）；
- **授权/许可优先服务化（C）**——成本最低、收益最大、跨平台一致；
- **VM 引擎移植（A）量力而行**——先移植核心校验进 SO，引擎用**轻量混淆替代**
  完整 VM（OLLVM/自加密段），后续再强化；
- 保持离线优先决策（D2），服务端为可选增强。

---

## 3. A — Android 原生 SO 保护

### 3.1 目标产物
`libprot.so`（ARM64-v8a 为主，armeabi-v7a 可选），含：
- **授权验签**（RSA-2048 PKCS1 v1.5 SHA-256，与 Windows ver 语义一致）；
- **完整性自检**（ELF .text 段 CRC + APK 签名校验 v2/v3 转交 Java 层）；
- **防篡改看门狗**（定时重校验）；
- **反调试/反 Frida**（Android 语义：ptrace/TracerPid + Frida/Xposed 特征）；
- **关键校验逻辑**（序列号/授权状态判定）——用 VM 或轻量混淆保护。

### 3.2 平台差异映射（Windows → Android）

| 模块 | Windows x64 | Android ARM64 | 复用/重写 |
|------|-------------|---------------|-----------|
| RSA 验签 | BCrypt (BCRYPT_RSAPUBLIC_BLOB) | JCA `Signature`/OpenSSL, 公钥编码需适配 | **重写**验签调用（公钥 blob 格式转换） |
| 授权消息构建 | `prot_license_build_message` | 同格式（hard 字节序一致） | **复用**逻辑（纯 C） |
| VM 引擎 | x64 汇编 + PE + MSVC | ARM64 + ELF + NDK Clang | **重写**（指令集/窗口解密调度） |
| 反调试 | PEB/NtQuery/硬件断点/计时 | ptrace/TracerPid + 无硬件断点 API | **重写**（Android 语义） |
| 反 DBI | 进程内存扫描 | Frida/Xposed 扫描（/proc/self/maps + 内存特征） | **重写**（生态不同） |
| 完整性 | PE 3 段 CRC + IAT | ELF .text CRC + APK 签名 | **重写**（段/签名格式） |
| 字符串加密 | strcrypt（C） | 同思路（C/NDK） | **复用**思路，重建生成 |
| 机器绑定 | hostid（卷号/SN） | ANDROID_ID/Build 型号 + 应用沙箱 ID | **重写** |
| 在线增强 N5 | mock/v1/check | 同 API（HTTP/OkHttp → JNI 或 Java 层） | **接口复用** |

### 3.3 移植优先级（分阶段）

**阶段 A1：许可证+完整性核心（最小可用）**
- `libprot.so` 含 RSA 验签 + ELF CRC + 字符串加密 + 机器绑定（ANDROID_ID）；
- Java/Kotlin 层持有授权状态（JNI 调用验签）；
- **工作量 3-5 天**（不含反调试）。

**阶段 A2：反调试/反 DBI + 看门狗**
- ptrace 检测、Frida/Xposed 特征扫描、SELinux 状态、magisk 检测；
- ndk 看门狗线程周期重校验；
- **3-5 天**。

**阶段 A3：核心校验逻辑混淆（VM 或轻量）**
- 方案 A3a：移植 VM 引擎（工作量大，最后一期）；用途校验逻辑进 VM；
- 方案 A3b：OLLVM 混淆 + 自加密段（低成本替代）——**推荐先 A3b**；
- **A3b 2-3 天 / A3a 5-10 天**。

### 3.4 构建与工具链
- NDK r26+ / Clang 17 / API 21+
- Gradle 集成（externalNativeBuild）
- 签名：APK v2/v3（Java 层校验）+ 可选 native 验签回调
- Python 生成器（vmenc 扩展）：生成 .so 内嵌公钥/CRC/种子

---

## 4. C — 跨平台许可与授权服务化 SDK

### 4.1 目标
**一套签发，处处验证**：Windows/Android/iOS/桌面 共用：
- 签发中心（vmenc.py 的 keygen/sign/issue/revoke，**零改动**）；
- license 格式（serial‖mid‖PRODUCT‖tier‖expires‖SIGNATURE）跨平台字节级一致；
- 验签端 SDK 统一语义。

### 4.2 SDK 抽象（`prot/license` 跨平台 API）
```c
/* 平台无关验签接口 (Windows=BCrypt, Android=JCA/OpenSSL, iOS=SecKey) */
int prot_auth_verify(const uint8_t* msg, size_t msg_len,
                     const uint8_t* sig, size_t sig_len);
size_t prot_auth_build_message(const char* serial, uint64_t mid,
                               uint32_t tier, uint32_t expires,
                               uint8_t* out, size_t cap);
```
- 每个平台一个 `license_impl.c`（BCrypt/JCA/OpenSSL/SecKey）；
- 公共 `license_common.c`（消息构建/解析/tier 逻辑——纯 C 复用）；
- 签发器 vbenc.py 已生成 X.509/原始公钥 + 各平台编码（BCRYPT blob / DER / SPKI）。

### 4.3 平台验证适配
| 平台 | RSA 算法 | 验签 API | 公钥格式 |
|------|----------|----------|----------|
| Windows x64 | RSA-PKCS1v1.5 + SHA256 | BCrypt | BCRYPT_RSAPUBLIC_BLOB（已实现） |
| Android ARM | RSA/ECB-PKCS1Padding | JCA `Signature` / OpenSSL | **DER 公钥**（需 vmenc 导出） |
| iOS | RSA PKCS1 | SecKeyVerifySignature | X.509 / raw key |
| 签发中心 | 纯 Python | — | 私钥 JSON（已实现） |

### 4.4 服务端（可选，M3.2 延申）
- 若启用在线：跨平台统一 `/v1/check`（serial/mid/tier/build）——与 N5 一致；
- 会话期望值（N5）在 Android 侧重放不可用（同一套）；
- **工作量**：SDK 抽象 + 双平台 impl（Android JCA + iOS 备好）= 3-5 天；
  vmenc 扩展公钥多格式导出 = 1 天。

---

## 5. 实施路线图（合并 A + C）

```
阶段 0 (0.5d): 边界确认 —— 已验证 (本文档)
阶段 C1 (3-5d): 跨平台许可证 SDL —— vmenc 导出 DER 公钥 + license_common.c
                + Android impl (JCA) + Windows 回归
阶段 A1 (3-5d): Android libprot.so —— RSA 验签 + ELF CRC + 字符串 + 绑定
阶段 A2 (3-5d): 反调试/反 Frida/看门狗 (ndk)
阶段 A3 (2-5d): 校验逻辑轻量混淆 (OLLVM/自加密)  [VM 移植可选后续]
阶段 T1 (2-3d): Android 攻防测试矩阵 (迁移四轮对应项)
合计: 15-25 天
```

## 6. 风险与缓解

| 风险 | 等级 | 缓解 |
|------|------|------|
| Android 生态碎片化（厂商/root/系统签名） | 中 | 目标 API 21+；重签名重打包是最主要威胁 → 服务端激活兜底（D2 外延） |
| Frida/Xposed 检测是持久战 | 高 | 只做特征检测 + 建议服务端激活增强（检测到插桩→要求在线） |
| VM 引擎移植成本高 | 中 | A3b 轻量混淆先行（OLLVM/自加密段），VM 移植后置 |
| ARM 架构差异导致 CRC 误报 | 中 | NDK 下对齐规则与 Windows 不同，需单独测试 |
| 密钥管理跨平台 | 中 | 私钥只在签发中心（vmenc），各平台仅嵌公钥 |

## 7. 决策点

| 编号 | 决策 | 选项 | 推荐 |
|------|------|------|------|
| E1 | 先 C 还是先 A | C 先行（SDK 复用）/ A 先行 | **C 先行**（授权服务化是跨平台基石，A 依赖其验签） |
| E2 | A3 用轻量混淆或 VM 移植 | OLLVM/自加密段 / 完整 VM | **先轻量混淆**（VM 成本高，A3b 快速见效） |
| E3 | Android 在线激活是否必需 | 可选 / 强制 | **可选**（保持 D2 离线优先；反 Frida 后建议在线） |
| E4 | 是否做 iOS | 备好 impl / 暂不做 | **备好代码，暂不发布**（iOS 受限平台） |

## 8. 待办清单
1. [x] 拍板 E1-E4（C 先行 / 轻量混淆 / 离线可选 / iOS 备好）。
2. [x] **C1 完成（2026-08-26）**：
   - vmenc.py `keygen --blob-out-der` 导出 **DER SPKI 公钥**（Android JCA /
     iOS SecKey），cryptography 8 轮权威验证全 VALID（294/293B）；
   - `examples/cross_platform/license_auth.h` + `license_auth_common.c`
     （跨平台消息构建/验签接口，字节级与 vmenc/Windows 一致）；
   - C1 消息格式 + 签名链路交叉验证通过（45B 载荷 + 256B sig）。
3. [x] **A1 完成（2026-08-26）**：`examples/cross_platform/android/` ——
   libprot.c（JNI nativeVerifyLicense/nativeCheckIntegrity/nativeIsDebugged）+
   CMakeLists（NDK ARM64）+ prot_test.c **宿主编译 ALL PASS**（消息 45B
   字节一致 / crc32 0xCBF43926 / 解析）。
4. [x] **A2 完成（2026-08-26）**：libprot.c 增 nativeDetectHook（frida/gum/
   xposed maps 扫描）+ pthread 看门狗（5s 周期）+ Prot.java（JCA
   SHA256withRSA 验签 + envCheck 汇总 + watchdog 绑定）；CMake 链 log/pthread/dl。
5. [ ] A3：轻量混淆（OLLVM/自加密段）。
6. [ ] T1：Android 攻防测试矩阵（需 NDK 构建产物/真机）。