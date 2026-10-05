# sf6250_zig_emu

MT6250（MTK 功能机 GSM/GPRS 基带 SoC）的模拟器：Zig 编写，CPU 用 Unicorn
（QEMU TCG）跑固件，SDL3 开 LCD 窗口。

## 环境要求

1. **Zig 0.16.x** —— 唯一的工具链依赖。不需要 cmake、Visual Studio、也不需要
   系统安装 SDL3 / unicorn：两者都从源码构建并静态链入可执行文件。
2. **首次构建需要联网**，拉取 build.zig.zon 里声明的依赖（axe 日志库、
   castholm/SDL 源码包及其 lazy 依赖），之后完全离线可构建。

支持的平台：

- Linux x86_64 / aarch64（已验证）
- Windows x86_64：可在 Windows 上装 zig 直接 `zig build`，也可以在 Linux 上
  交叉编译（编译已验证；exe 在真机上的运行待验证）
- macOS 暂不支持：缺 macOS 版 QEMU 配置头，见 `src/emu/c/uc_config/README.md`

## 构建与运行

```sh
zig build                    # 首次会联网抓依赖并从源码编 SDL3 + unicorn，几分钟属正常
zig build run -- --lenient   # 跑固件 + 外设探针（黑盒记录固件访问的未实现寄存器）
zig build run -- --lcd       # 跑完后开 240x320 LCD 窗口并进入事件循环
zig build test
```

命令行开关：

- 第一个非 `--` 的位置参数是固件镜像路径；不带时用仓库自带的
  `res/AHONG50_11B_PCB01_gprs_MT6250_S00.D27D__11B_W11_32__V0010.bin`
- `--lenient`：宽容模式，访问未实现外设不停下（读回 0），用于一次性摸清
  固件碰了哪些寄存器地址；不加则碰到未映射地址立即停下报 PC
- `--trace`：逐条指令打印 PC

注意：

- 不通过 `zig build run`（它会把工作目录钉在仓库根）、而是直接执行
  `zig-out/bin/sf6250_zig_emu` 时，请在仓库根目录下运行，或显式传镜像路径
- Debug 构建体积大（几十 MB）且 TCG 未开优化，日常使用建议
  `zig build -Doptimize=ReleaseFast`

## 交叉编译 Windows

```sh
zig build -Dtarget=x86_64-windows-gnu
# 产物：zig-out/bin/sf6250_zig_emu.exe（+ .pdb 调试文件）
```

构建脚本会按目标 OS 自动选择预生成的 QEMU 配置头与平台层源文件，
无需任何额外配置。

## 仓库结构

```
src/emu/            模拟器：unicorn C API 薄封装 / 机器骨架（内存映射 + 外设探针）/ SDL3 LCD
src/emu/c/uc_config/  预生成的 QEMU 配置头（host 侧按 OS 选择，详见其中 README）
src/mtk_boot_image/ MTK SF_BOOT 固件镜像解析（GFH / BRLYT / EMI_INFO…）
vendor/unicorn/     unicorn 2.1.4 源码裁剪版（仅 ARM 客体，裁剪说明见 VENDORED.md）
res/                测试固件（AHONG50 MT6250 整片 flash dump）
docs/               MT6250 数据手册（PDF 与文字提取版）
```

## 现状与路线

- [x] 镜像解析、一级 Bootloader 装载进 SRAM、Thumb 起跑、flash XIP 窗口
- [x] MMIO 桩 + 外设访问探针（`--lenient` 已摸出 18 个寄存器地址，
      集中在 0xA001/0xA005/0xA017 等 APB/AHB 段）
- [ ] 按探针数据逐个实现外设（LCD 控制器、keypad 矩阵、timer、UART…）
- [ ] framebuffer 接入 SDL 窗口，跑出 MAUI 画面
