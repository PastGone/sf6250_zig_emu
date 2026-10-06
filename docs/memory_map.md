# MT6250 内存映射（Memory Map）

> 这是整个模拟器最底层、也最容易出隐蔽 bug 的一层。本文把散落在 `machine.zig`
> 的 `map` 结构、`mt6250-wiring.md` 的「内存图」、以及各次实测记录里关于**地址空间**
> 的信息集中起来，作为唯一权威来源。改任何映射前先回看这里。
>
> 来源与可信度：
> - **run761 参考实现**的内存图——它用崩溃点逐个验证过，是主要依据（`mt6250-wiring.md` §内存图）。
> - **本模拟器的实际映射**——`machine.zig` 的 `map` 结构 + 各 `memMap` 调用。
> - **实测修正**——EMI 重映射时机、flash XIP 线性映射、`0x10947980` 须为 RAM 等，
>   由运行时 trace 确认。

---

## 1. 完整地址空间总览

下表是合并 run761 + 我们实测后的**权威视图**。`模拟器映射` 列标注本模拟器当前怎么挂这块。

| 起始 | 大小 | 用途 | 模拟器映射 | 可信度 |
|---|---|---|---|---|
| `0x0000_0000` | 8 MB | 系统 RAM（EMI 重映射后）。BL 从 0x0 读自身 GFH | boot 阶段先挂 flash 视图（`mapFlashWindow`），首次 EMI 命令(`0xA01800A0` 写)触发 `bootrom.onBusCommand` 把它**重映射成 8MB 可写 RAM** | 确认 |
| `0x0900_0000` | 1 KB | LCD 图层机制（Layer0-3 @`0xBC/0xEC/0x11C/0x14C`，触发 @`0x0C`） | 未显式映射，靠 `--lenient` 4KB 页兜底 | run761 有；我们的 LCM 是 `0xA0450000` |
| `0x0E00_0000` | 16 MB | LCD 显存 / 显示驱动区 | 未显式映射，靠 `--lenient` 兜底 | run761(run229 暴露) |
| `0x1000_0000` | 16 MB | NOR flash XIP 窗口（零拷贝、只读可执行） | `mapFlashWindow`：`memMapPtr(0x1000_0000, img.len, R/X)` | 确认 |
| `0x4000_0000` | 8 MB | 共享内存 | 未显式映射，靠 `--lenient` 兜底 | run761 有 |
| `0x5000_0000` | 4 KB | IRQ 回调区（MT6252 风格，第 4 步中断核对） | 未显式映射，靠 `--lenient` 兜底 | run761 有 |
| `0x6100_0000` | 16 MB | **外设区（run761 标注）**；实测 MAUI `main(0x1002040C)` 写 `0x610c0008` | **未映射**（见 §4 缺口） | 待确认 |
| `0x7000_0000` | 2 MB | 片内 SRAM（BL load_addr `0x70008000` 落此） | `mapSram`：`memMap(0x7000_0000, 2MB, RWX)` | 确认 |
| `0x8000_0000` | 32 MB | APB 外设窗口 | `mapPeriphStubs`：`mmioMap(0x8000_0000, 32MB, …)` | 确认 |
| `0x8200_0000` | 64 MB | 外部 RAM（MAUI 重定位运行地 `0x84Exxxxx`、BL 堆/共享区） | `mapExternalRam`：`memMap(0x8200_0000, 64MB, RWX)` | 确认 |
| `0xA000_0000` | 16 MB | AHB 外设寄存器 | `mapPeriphStubs`：`mmioMap(0xA000_0000, 16MB, …)` | 确认 |
| `0xE000_0000` | 16 MB | 真实显示缓冲 | 未显式映射，靠 `--lenient` 兜底 | run761(run483 暴露) |
| `0xF000_0000` | 8 MB | RAMF0（Nucleus OS 数据区：就绪标志 `0xF05DDF64/40`、调度栈 `0xF0424000`） | `mapRamF0`：`memMap(0xF000_0000, 8MB, RWX)` | 确认 |

> **注意 run761 与我们代码的两处差异**：
> 1. run761 把 `0x6100_0000` 标成「外设区」，但我们实际的外设窗口是 `0x8000_0000`(APB)
>    和 `0xA000_0000`(AHB)。`0x6100_0000` 在我们代码里**完全没映射**，只在 `--lenient`
>    下被 4KB 页兜底。它到底是什么需要实测确认（见 §4）。
> 2. `0x0900/0x0E00/0xE000/0x4000/0x5000_0000` 在 run761 内存图里，我们因 `--lenient`
>    兜底能跑过，但**不在显式映射中**——意味着这些区一旦被取指或严格模式就会炸。

---

## 2. 模拟器代码里的实际映射

所有映射在 `machine.zig` 的 `map` 结构定义（`machine.zig:18-43`），并在
`Machine` 的 `loadBootloader` 流程里逐个 `memMap`。

### 2.1 `map` 常量（`machine.zig:19-43`）

```zig
pub const map = struct {
    pub const boot_view_base      = 0x0000_0000;
    pub const boot_view_size      = 0x100_0000;   // 16MB（flash 视图）
    pub const boot_view_ram_size  = 0x80_0000;    // 8MB（EMI 重映射后的 RAM）
    pub const sram_base           = 0x7000_0000;
    pub const sram_size           = 0x0020_0000;  // 2MB
    pub const flash_window_base   = 0x1000_0000;
    pub const apb_base            = 0x8000_0000;
    pub const apb_size            = 0x200_0000;   // 32MB
    pub const ahb_base            = 0xa000_0000;
    pub const ahb_size            = 0x1000_0000;  // 16MB
    pub const ramf0_base          = 0xf000_0000;
    pub const ramf0_size          = 0x0080_0000;  // 8MB
};
```

### 2.2 各 `memMap` 调用

| 函数 | 位置 | 映射内容 |
|---|---|---|
| `mapSram` | `machine.zig:349-353` | `0x7000_0000` + 2MB，RWX |
| `mapExternalRam` | `machine.zig:359-364` | `0x8200_0000` + 64MB，RWX |
| `mapRamF0` | `machine.zig:370-375` | `0xF000_0000` + 8MB，RWX |
| `mapPeriphStubs` | `machine.zig:379-389` | AHB `0xA000_0000`+16MB 与 APB `0x8000_0000`+32MB 走 MMIO 钩子（接线外设给行为，其余读 0/写丢弃并记名） |
| `mapFlashWindow` | `machine.zig:394-411` | `0x1000_0000` 挂整片 flash（`R/X`，`--flash-rw` 时加 `W`）；`0x0000_0000` 另挂一份 flash 视图供 BL 读自身 GFH |
| EMI 重映射 | `bootrom.zig:83-89`（`onBusCommand`，首次 `0xA01800A0` 写触发） | 把 `0x0` 从 flash 视图**重映射成 8MB 可写 RAM**（`boot_view_ram_size`），并在 0x0 安装 BootROM RAM 函数。BL 随后 `bx 0x0` 调用它 |

### 2.3 `--lenient` 的 4KB 页兜底（`diag.zig:752-762`）

宽容模式下，任何**读/写未映射**的地址会就地映射所在 4KB 页（RW、内容 0）再放行：

```zig
if (m.lenient) {
    switch (typ) {
        c.UC_MEM_READ_UNMAPPED, c.UC_MEM_WRITE_UNMAPPED => {
            const page = address & ~@as(u64, 0xFFF);
            m.eng.memMap(page, 0x1000, rw) catch {}; // 已映射则忽略
        },
        else => {},
    }
    // 取指未映射无法放行 → 记「取指失败」日志
}
```

**含义**：§1 里标「靠 `--lenient` 兜底」的区域，跑 `--lenient` 时不会崩，但行为
是「零填充的匿名页」，不是真实硬件。这些区一旦在严格模式或被取指，就会暴露。
**这是 §4 缺口的来源，也是后续要严格模式跑通前必须显式映射的清单。**

---

## 3. 关键分区详解

### 3.1 `0x0000_0000` 系统 RAM（EMI 重映射）
- boot 阶段：`mapFlashWindow` 把 flash 视图挂在 0x0，`0x0000_08a8` 正是 BL 自己的 GFH。
- BL 发首次 EMI 总线命令（`0xA01800A0` 写）后，`bootrom.onBusCommand` 把 0x0
  **重映射成 8MB 可写 RAM**，并在 0x0 装 BootROM RAM 函数（`mov r0,#0; bx lr`）。
- BL 随后 `bx 0x0` 调用它（正常流程，不是崩溃；`until` 哨兵因此是 `0xFFFFFFF0` 而非 0）。

### 3.2 `0x1000_0000` flash XIP
- 整片 flash 线性映射：`file offset 0x20000 ↔ load 0x10020000`、`0x8752b0 ↔ 0x108752b0`。
- MAUI 直接在上面 XIP；`0x10008061`(Thumb 入口) 是 BL2 入口。
- 注意：MAUI 的「装载源」`0x10DD1358`、`ALICE` 结构 `0x108E65A8`、DMA 描述符表
  `0x10DA1A68` 都在这 16MB 窗口内，是 flash 里的静态数据（高熵、压缩/加扰）。

### 3.3 `0x1094_7980 ~ 0x10F3_9680` 解压代码区（**必须是 RAM**）
- 这是 `0xA0520000` 传输引擎的 DMA 目标。固件 `memcpy(FIFO, 0x10DD1358, 0x2000)`
  后写 `0xA0530000+0x04=19` 触发**装载/解压**，然后校验 `*(0x10947980)=="CAKE"`。
- **实测确证**（诊断 `--dma-copy`）：DMA 能写进 `0x10947980` ⇒ 真机这里是 **RAM**
  不是 NOR。当前 `0x10947980` 落在 flash XIP 窗口（`0x1000_0000+0x94_7980`），
  是错的——应改成 RAM 映射（见 `HANDOFF.md` §9.8 的「下一步」）。
- 范围 ≡ DMA 配置 `+0x00=0x10947980`、`+0x04=0x10F39680`（约 10.4MB）。

### 3.4 `0x7000_0000` SRAM
- BL 代码与运行时代码都在这里（服务表 `0x70042000`、ARM 分发链 `0x70008200`、
  ExtBL 拷贝 `0x70004b80`、BRLYT 校验 `0x7000842c`）。2MB 已实测够用（早期 1MB 会顶到）。

### 3.5 `0x8200_0000` 外部 RAM
- MAUI 被重定位到这里执行（`0x84Exxxxx`）。包含 BL 堆、共享数据。64MB 由 run688/run761
  确认（32MB 不够）。

### 3.6 `0xF000_0000` RAMF0
- Nucleus OS 数据区。就绪标志 `0xF05DDF64`/`0xF05DDF40` 就绪后 OS 才起调度；
  调度栈 `0xF0424000`。之前不映射时靠 `--lenient` 逐个 4KB 页兜底，会把故障表刷满
  （MAUI 一路写到 `0xF045xxxx`），故显式映射了整块 8MB。

### 3.7 外设窗口（APB `0x8000_0000` / AHB `0xA000_0000`）
- 各外设基址见 `periph.zig` 的 `known_regions` 表 + `HANDOFF.md` §4。
- 已接线的（寄存器文件/特殊行为）：UART1-3、SF、RTC、AUXADC、GPT、HIF0/1、NLI_ARB、
  ACFG GPIO、A002 GPIO-CLK、CLK_PLL、EMI、传输引擎 `0xA052/0xA053`、LCM 等。
- **未接线的**（仍走「读 0/写丢弃」兜底）：见 `periph.zig` 的 `known_regions` 里
  只命名没分支的（如 `0xA000` CHIP-ID 只读已接，其余按访问现场补）。

---

## 4. 已知缺口 / 待确认

按优先级：

1. **`0x10947980~0x10F39680` 应改 RAM 映射**（最高优先，关乎关机根因）。
   当前落在 flash XIP 里是错误的；需把它从 `0x1000_0000` 窗口切出、另挂 RAM。
   但有个矛盾：装载源 `0x10DD1358` 也在 `0x1000_0000` 窗口内——若整段改 RAM，
   第一次搬运的源还没装载。范围可能要分段（前半 RAM、后半 flash）或源另有出处。
   见 `HANDOFF.md` §9.8。

2. **`0x6100_0000`（16MB）无任何映射**。run761 标为「外设区」，实测 MAUI
   `main(0x1002040C)` 写 `0x610c0008`。我们当前外设窗口是 `0x80/0xA0`，这块是黑盒。
   需要反编译 `0x1002040C` 确认它是什么（可能是某块外部存储控制器或显示相关）。
   当前只在 `--lenient` 下被 4KB 页兜底；严格模式会崩。

3. **`0x0900/0x0E00/0xE000/0x4000/0x5000_0000` 未显式映射**。run761 内存图里有
   （LCD 图层、LCD 显存、真显存、共享内存、IRQ 回调区），我们靠 `--lenient` 兜底。
   要拿下显示/LCD 就必须显式映射并接线。

4. **`0x1FFFFFFF` 边界越界读**（`0x1ffffffe`）。出现在**关机/异常路径**上
   （停机自旋时读到的越界地址），不是正常执行流，属内存映射缺口的附带现象；等
   CAKE 装载真正实现、正常流程不走到关机路径后，这条不会触发。

---

## 5. 与关机根因的关系

关机根因是 `0xA0520000` 装载后 `*(0x10947980)=="CAKE"` 校验失败（见 `HANDOFF.md` §9.8）。
它直接取决于本内存映射的两个事实：

- `0x10947980` **必须可写**（⇒ 是 RAM，不是 NOR XIP）——已用 `--dma-copy`/`--flash-rw` 验证。
- 源 `0x10DD1358` 在 flash XIP 内（静态数据）——说明装载是「flash 里的高熵数据
  → 经 `0xA0530000` 引擎变换 → 落到 RAM `0x10947980`」。

内存映射若划错（如把 `0x10947980` 当 flash），DMA 写不进 → 校验永远失败。
所以**修内存映射（§4.1）是修关机的前提条件之一**，与还原 `0xA0530000` 变换算法并列。
