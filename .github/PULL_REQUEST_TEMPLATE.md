<!--
感谢贡献！请先读 CONTRIBUTING.md（含本项目已知的坑）。
带 * 的项请务必填写 —— 本项目最看重"可验证"。
-->

## 改了什么 *

<!-- 1-3 句。新增模块请写明模块名与能力位 -->

## 为什么 *

<!-- 问题 / 动机。修 bug 请说明复现方式 -->

## 如何验证 *

- [ ] `tools/release_check.ps1` **40/40 PASS**（默认；发版前另跑 `-WithSkeleton -WithMutation -WithMigration`，共 43 项）
- [ ] `python tools/modcheck.py` 无漂移
- [ ] （新增模块）已按 `docs/MODULE_GUIDE.md` 五步走完
- [ ] （新增模块）已在 **两个宿主**（`demo/main.c` + `prot_sdk/skeleton/app_main.c`）加 `#ifdef`
- [ ] （改数字/文档）数字来自实测，非估算

<details>
<summary>验证输出（粘贴关键行）</summary>

```
（粘贴 release_check 结果或相关测试输出）
```

</details>

## 诚实边界 *

<!-- 这个改动**没有**解决什么？已知限制是什么？写不出说明还没测过。 -->

- 本改动**未**解决：
- 新增限制：

## 检查清单

- [ ] 未引入第三方依赖（C 侧仅标准库/Windows API；Python 侧仅标准库）
- [ ] `.ps1` 改动后确认保留了 UTF-8 BOM（首 3 字节 `EF BB BF`）
- [ ] 未修改检查器来让检查通过
- [ ] 提交信息说明了验证方式

## 相关 Issue

<!-- 如 Fixes #123 -->
