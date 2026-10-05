# Vendored: Unicorn Engine 2.1.4（源码裁剪版）

- 上游：<https://github.com/unicorn-engine/unicorn>，tag `2.1.4`
  （tarball：<https://codeload.github.com/unicorn-engine/unicorn/tar.gz/refs/tags/2.1.4>）
- 用途：MT6250 的 CPU 模拟（只编 ARM 客体 + x86_64/aarch64 宿主 TCG 后端），
  由 zig 构建系统直接编译（见 `build.zig` 的 `buildUnicorn`），不链接系统库、不用 cmake。
- `CMakeLists.txt`（含 `cmake/`）保留原样：`build.zig` 里的文件清单与编译选项
  照抄自它，注释里的行号以它为准。

## 相对上游裁剪掉的内容

- `tests/`、`samples/`、`bindings/`、`docs/`、`msvc/`
- Rust/Go 打包文件（`Cargo.toml`、`build.rs`、`go.mod` 等）与上游的
  `build.zig`/`build.zig.zon`（后者面向旧版 Zig，且只是 cmake 的壳，我们不用）
- `qemu/target/` 仅保留 `arm`（MT6250 的 ARM7EJ-S 是 ARMv5TE，其余 8 个客体架构用不上）
- `qemu/libdecnumber/`（仅 ppc/s390x 需要）
- `qemu/tcg/` 宿主后端仅保留 `i386`（x86_64）与 `aarch64`

需要其他客体架构或宿主后端时，从上游 tarball 把对应目录拷回来，并按
`CMakeLists.txt` 补 `build.zig` 里的文件清单。

## 许可

`COPYING`（GPLv2，QEMU 部分）、`COPYING_GLIB`/`COPYING.LGPL2`（glib_compat
部分）随源码保留。
