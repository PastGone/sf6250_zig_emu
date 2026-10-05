# unicorn QEMU 配置头（预生成，勿手改）

unicorn 2.1.4 构建时需要 QEMU 的 configure 链路生成 `config-host.h`（宿主侧，
随 OS 变化）与 `config-target.h`（guest 侧，与宿主 OS 无关）。这里预生成后
入库，构建时不再依赖 shell 脚本，可离线复现。build.zig 按目标 OS 选择：

- `common/`：`config-target.h` + 被裁剪架构的占位头
  （`uc.c` 会无条件 include 各客体架构的 `qemu/target/<arch>/unicorn.h`，
  本工程只编 ARM，其余用空文件顶上）
- `linux/`：Linux/x86_64 宿主的 `config-host.h`，用 configure 链路生成：
  ```sh
  sh $UC/qemu/configure --cc=cc "--extra-cflags=-DUNICORN_HAS_ARM -fPIC " \
      --target-list=arm-softmmu
  sh $UC/qemu/scripts/create_config < config-host.mak > config-host.h
  ```
- `windows/`：Windows 宿主的 `config-host.h`，直接取自上游
  `msvc/config-host.h`（MSVC/x64 预生成版，对 zig cc 的 mingw 环境同样适用）

换宿主架构或加客体架构时按上面命令重新生成对应目录。
