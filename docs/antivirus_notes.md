# 杀软部署资料（AV 实测用，2026-08-28 调研）

> 全部官方渠道；链接经 HEAD 验证（200）。静默参数均**官方未公开文档**，
> 需在 VM 中实测（±普通安装器常规行为）。

## 镜像（用户下载中 → 放入 `E:\download\iso\`）
- Win10 Enterprise Eval / Win11 评估 ISO（来源不限，ID 记得区分）

## 虚拟机
- 方案：VirtualBox（宿主机已有？未装则官网免费下载）
- VM 目录：`E:\vms\`（一个 VM 一个子目录，镜像共享）

## 杀软直链（官方）
| 产品 | 直链 | 大小 | 备注 |
|------|------|------|------|
| 360 安全卫士 | `https://dl.360safe.com/inst.exe`（在线安装器，推荐）<br>`https://down.360safe.com/setup.exe`(完整包) | ~4MB / ~— | 静默参数未确认（社区 `/S`?）实测 |
| 火绒 6.0 | `https://www.huorong.cn/product/downloadHr60.php?pro=hr60`（x86，301→直链）<br>`https://down-tencent.huorong.cn/sysdiag-all-x64-6.0.11.3-2026.08.27.1.exe`（x64 直链，**含版本日期，更新会变**） | 71MB | 用 PHP 入口跟随 301 最稳；静默 `-s`（论坛流传，需实测）|
| 腾讯电脑管家 | `https://pm.myapp.com/invc/xfspeed/qqpcmgr/download/QQPCDownload_home_310053.exe` | ~— | 在线安装器；静默参数未确认 |
| Defender | Win10/11 内置默认开启 | — | 无需安装 |

## 安装顺序建议（每 VM）
1. 装系统（Autounattend → 自动登录 → WinRM 开）
2. 装 VirtualBox Guest Additions（共享文件夹）
3. 拷贝样本集（`E:\download\samples\` → VM `C:\avtest\`）
4. 装杀软（每 VM 一种？或每 VM 装 4 个会互相打架——**每 VM 一种**，3 个 VM 各装一种 + 一个纯 Defender 基线 = 4 VM？或复用：先全测基线（无第三方）→ 逐个装）
   - 建议:镜像多的话直接 4 VM 并行（每 VM 一种）；镜像有限则 2 VM 循环复用（快照回滚）
5. 测试序列（每个杀软×样本）：静态扫描 → 落地 → 执行 → 长驻 → SmartScreen 模拟（下载提示）
6. 快照留存（每个"干净+杀软"状态存快照，复用）

## 测试记录表模板
| 环境 | 杀软(版本) | 样本 | 签名 | 静态 | 落地 | 执行 | 长驻 | 报毒名 |
|------|------------|------|------|------|------|------|------|--------|