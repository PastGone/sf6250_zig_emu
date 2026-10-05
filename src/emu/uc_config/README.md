# unicorn QEMU 配置头（预生成，勿手改）

`config-host.h` 与 `config-target.h` 由 unicorn 2.1.4 自带的 QEMU configure 链路
确定性生成，这里按「宿主 linux/x86_64 + 客体 arm-softmmu」生成后入库，
构建时不再依赖 shell 脚本，可离线复现。

换宿主架构或加客体架构时重新生成：

```sh
sh $UC/qemu/configure --cc=cc "--extra-cflags=-DUNICORN_HAS_ARM -fPIC " \
    --target-list=arm-softmmu
sh $UC/qemu/scripts/create_config < config-host.mak > config-host.h
sh $UC/qemu/scripts/create_config < arm-softmmu/config-target.mak > config-target.h
```
