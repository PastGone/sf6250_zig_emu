/* 占位头：uc.c 无条件 include 各客体架构的 qemu/target/<arch>/unicorn.h，
 * 但本工程只编 ARM，这些架构的源目录已裁剪（见 vendor/unicorn/VENDORED.md）。
 * uc.c 中对它们的引用都在 UNICORN_HAS_<ARCH> 宏守卫内，空文件即可。 */
