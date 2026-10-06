//! 外设接线：MMIO 读写行为 + 各外设模型（UART/CLK/EMI/LCM/GPIO/SF/RTC）。
//!
//! 每个已接线寄存器都对应 docs/mt6250-wiring.md 里的一条实证；未接线的地址
//! 只记录（首次访问记 pc/lr）后读 0 / 写丢弃——这就是「黑盒推进」的抓手。

const std = @import("std");
const log = @import("../log.zig");
const uc = @import("unicorn.zig");
const c = uc.c;
const machine = @import("machine.zig");
const Machine = machine.Machine;
const bootrom = @import("bootrom.zig");

/// 已接线的寄存器区块（地址→名字）。行为依据见 docs/mt6250-wiring.md。
pub const known_regions = [_]struct { base: u32, name: []const u8 }{
    .{ .base = 0xA000_0000, .name = "CHIP-ID/启动模式" },
    .{ .base = 0xA006_0000, .name = "UART1/中断使能" },
    .{ .base = 0xA052_0000, .name = "传输/DMA引擎" },
    .{ .base = 0xA005_0000, .name = "CLK/PLL" },
    .{ .base = 0xA006_0000, .name = "UART1(AT)" },
    .{ .base = 0xA007_0000, .name = "UART2" },
    .{ .base = 0xA008_0000, .name = "UART3(LOG)" },
    .{ .base = 0xA014_0000, .name = "SF(串行flash)" },
    .{ .base = 0xA018_0000, .name = "EMI/总线命令" },
    .{ .base = 0xA01F_0000, .name = "OSTD(OS timer)" },
    .{ .base = 0xA045_0000, .name = "LCM" },
    .{ .base = 0xA071_0000, .name = "RTC" },
    .{ .base = 0xA073_0000, .name = "ACFG GPIO" },
};

fn regionName(addr: u32) ?[]const u8 {
    for (known_regions) |r| {
        if (addr >= r.base and addr < r.base + 0x1_0000) return r.name;
    }
    return null;
}

/// addr 落在哪个 UART 块（UART1/2/3 各 64KB 间隔）
fn uartIndex(addr: u32) ?usize {
    if (addr >= 0xA006_0000 and addr < 0xA009_0000) {
        return (addr - 0xA006_0000) >> 16;
    }
    return null;
}

/// MMIO 回调的区域上下文：apb/ahb 两个区域共用回调，必须区分基址
pub const RegionCtx = struct {
    machine: *Machine,
    base: u64,
};

/// 固件串口输出：存进行缓冲，行终止时按行打出。
/// \r\n 折成一次换行（否则每行会多出一条空日志）。
fn uartPutc(self: *Machine, i: usize, b: u8) void {
    if (b == '\r' or b == '\n') {
        if (b == '\n' and self.uart_cr[i]) {
            self.uart_cr[i] = false; // CRLF 的后半个，已换过行
            return;
        }
        self.uart_cr[i] = (b == '\r');
        if (self.uart_len[i] > 0) {
            log.info(@src(), "[UART{d} TX] {s}", .{ i + 1, self.uart_line[i][0..self.uart_len[i]] });
            self.uart_len[i] = 0;
        }
        return;
    }
    const printable = (b >= 0x20 and b < 0x7f) or b == '\t';
    self.uart_line[i][self.uart_len[i]] = if (printable) b else '?';
    self.uart_len[i] += 1;
    if (self.uart_len[i] >= 120) {
        log.info(@src(), "[UART{d} TX] {s}", .{ i + 1, self.uart_line[i][0..self.uart_len[i]] });
        self.uart_len[i] = 0;
    }
}

/// 已接线寄存器的读行为；其余记录后读 0
fn periphRead(self: *Machine, addr: u32, size: u32) u64 {
    // 时钟切换握手（BL 0x70008aac~0x70008aba）：写命令后轮询 bit7，
    // 0x300F0000→等 bit7=1，0x700F0000→等 bit7=0（0x100F0000 推测同为 1）
    if (addr == 0xA005_0090) {
        return switch (self.clk_cmd) {
            0x300F_0000, 0x100F_0000 => 0x80,
            else => 0x00,
        };
    }
    // PLL 锁定状态：bit1=锁定（BL 0x7000868e 轮询；写 0xA0050300/0x308 配置后等它）
    if (addr == 0xA005_0318) return 0x2;
    // EMI/总线命令状态：bit0=0（命令已完成，BL 0x70008FA8 轮询的位）
    if (addr == 0xA018_00A0) return 0x00;
    // 中断全局控制（0xA0030000/08）：回读保留（MAUI sub_10037A84 读改写）
    if (addr == 0xA003_0000) return self.intc_ctrl;
    if (addr == 0xA003_0008) return self.intc_ctrl8;
    // 串行 flash 控制器（SF，0xA0140000）：控制/状态 + 数据窗口两个区段
    if ((addr >= 0xA014_0000 and addr < 0xA014_0100) or (addr >= 0xA014_0800 and addr < 0xA014_0810)) {
        return sfcRead(self, addr - 0xA014_0000, size);
    }
    // RTC（0xA0710000）：寄存器文件，写入值读回（数据手册 RTC 章）
    if (addr >= 0xA071_0000 and addr < 0xA071_0100) {
        return leRead(self.rtc_regs[0..], addr - 0xA071_0000, size);
    }
    // 中断控制器（0xA0760000）：+0x1A0 读 = bit8 无中断 / 低 8 位中断号
    // （MAUI sub_100230A0 的读法）；+0x1A0 的其它位回读保留
    if (addr >= 0xA076_0000 and addr < 0xA076_0100) {
        if (addr - 0xA076_0000 == 0x1A0) {
            if (self.irq_pending < 0) return (@as(u32, self.irq_status_raw) | 0x100);
            return @as(u32, @intCast(self.irq_pending)) & 0xFF;
        }
        return 0;
    }
    // 芯片标识/启动模式寄存器（0xA0000000）：见 chip_regs 字段注释
    if (addr >= 0xA000_0000 and addr < 0xA000_0010) {
        return leRead(self.chip_regs[0..], addr - 0xA000_0000, size);
    }
    // 传输/DMA 引擎（0xA0520000）：见 xfer_regs 字段注释
    if (addr >= 0xA052_0000 and addr < 0xA052_0100) {
        var v = leRead(self.xfer_regs[0..], addr - 0xA052_0000, size);
        // +0x34 的 bit31 = 传输完成（固件写启动位后等它置位）
        if (addr - 0xA052_0000 == 0x34) v |= 0x8000_0000;
        return v;
    }

    if (uartIndex(addr) != null) {
        const off = addr & 0xFFFF;
        if (off == 0x14) return 0x60; // LSR：THRE|TEMT（发送器空闲）
        if (off == 0x00) return 0x00; // RBR：无接收数据
    }

    if (self.recordFault(addr, "read")) {
        const site = accessSite(self);
        if (regionName(addr)) |n| {
            log.info(@src(), "  外设读 {s}+0x{x:0>4} size={d} -> 0（未接线）pc=0x{x:0>8} lr=0x{x:0>8}", .{ n, addr & 0xFFFF, size, site.pc, site.lr });
        } else {
            log.info(@src(), "  外设桩读 @0x{x:0>8} size={d} pc=0x{x:0>8} lr=0x{x:0>8}", .{ addr, size, site.pc, site.lr });
        }
    }
    return 0;
}

/// 触发访问的现场（pc/lr）：未接线外设的「谁在访问」必须能直接回答，
/// 否则只能靠猜。第一次见到某地址时记录。
fn accessSite(self: *Machine) struct { pc: u32, lr: u32 } {
    var pc: u32 = 0;
    var lr: u32 = 0;
    _ = c.uc_reg_read(self.eng.handle, c.UC_ARM_REG_PC, &pc);
    _ = c.uc_reg_read(self.eng.handle, c.UC_ARM_REG_LR, &lr);
    return .{ .pc = pc, .lr = lr };
}

/// 小端读：字节缓冲 off 起 size 字节（外设寄存器宽度 1/2/4）
fn leRead(buf: []const u8, off: u32, size: u32) u64 {
    var v: u64 = 0;
    var i: u32 = 0;
    while (i < size) : (i += 1) {
        const a = off + i;
        if (a >= buf.len) break;
        v |= @as(u64, buf[a]) << @intCast(8 * i);
    }
    return v;
}

/// 小端写：把 value 的低 size 字节写进缓冲
fn leWrite(buf: []u8, off: u32, size: u32, value: u64) void {
    var i: u32 = 0;
    while (i < size) : (i += 1) {
        const a = off + i;
        if (a >= buf.len) break;
        buf[a] = @truncate(value >> @intCast(8 * i));
    }
}

/// SF（串行 flash）控制器寄存器读。位语义全部由固件轮询序列反推：
///   +0x00 bit0=忙（本模型恒 0）、bit1=命令完成（= bit2&bit3 同时为 1）、
///         bit2/bit3/bit4=固件写的控制位（回读保留）        ← BL2 驱动
///   +0x04 状态标志（bit0 参与 +0x00 bit4 判定）
///   +0x08 bit8=命令完成                                  ← MAUI 驱动
///   +0x10 命令字节数、+0x14 响应字节数
///   +0x40/+0x44 控制 bank：bit9|bit10 = 启动，bit13 = 完成 ← MAUI 驱动
///   +0x800 起数据窗口（命令/地址在前，响应从 [len] 开始）
///
/// BL2 的驱动（XIP 0x1000d702/0x1000d752）只碰 +0x00/+0x04/+0x10/+0x14/+0x800；
/// MAUI 的驱动（XIP 0x10859fd8/0x1085a03e，运行时拷到低 RAM 0x00000e00 执行）
/// 额外碰 +0x08/+0x40/+0x44/+0x804。两处都实测过轮询序列。
fn sfcRead(self: *Machine, off: u32, size: u32) u64 {
    if (off == 0x00) {
        const done: u32 = if (self.sfc_ctrl & 0xC == 0xC) 0x2 else 0;
        return (self.sfc_ctrl & ~@as(u32, 0x3)) | done;
    }
    if (off == 0x04) return self.sfc_flags;
    if (off == 0x08) {
        const done2: u32 = if (self.sfc_ctrl2 & 0x600 == 0x600) 0x100 else 0;
        return (self.sfc_status8 & ~@as(u32, 0x100)) | done2;
    }
    if (off == 0x10) return self.sfc_len;
    if (off == 0x14) return self.sfc_mode;
    if (off == 0x40) return self.sfc_ctrl_a;
    if (off == 0x44) {
        const done2: u32 = if (self.sfc_ctrl2 & 0x600 == 0x600) 0x2000 else 0;
        return (self.sfc_ctrl2 & ~@as(u32, 0x2000)) | done2;
    }
    if (off >= 0x800 and off < 0x800 + self.sfc_fifo.len) return leRead(self.sfc_fifo[0..], off - 0x800, size);
    return 0;
}

fn sfcWrite(self: *Machine, off: u32, size: u32, value: u64) void {
    if (off == 0x00) {
        self.sfc_ctrl = @truncate(value);
        // bit2|bit3 同时置位 = 固件启动一次命令（XIP 0x1000d702：先置 bit3，再置 bit2）
        if (self.sfc_ctrl & 0xC == 0xC) sfcExec(self);
        return;
    }
    if (off == 0x04) {
        self.sfc_flags = @truncate(value);
        return;
    }
    if (off == 0x08) {
        self.sfc_status8 = @truncate(value);
        return;
    }
    if (off == 0x10) {
        self.sfc_len = @truncate(value);
        return;
    }
    if (off == 0x14) {
        self.sfc_mode = @truncate(value);
        return;
    }
    if (off == 0x40) {
        self.sfc_ctrl_a = @truncate(value);
        return;
    }
    if (off == 0x44) {
        self.sfc_ctrl2 = @truncate(value);
        return;
    }
    if (off >= 0x800 and off < 0x800 + self.sfc_fifo.len) {
        leWrite(self.sfc_fifo[0..], off - 0x800, size, value);
        return;
    }
}

/// 执行一次 SF 命令并填响应。命令字节 = 数据窗口第 0 字节（固件就是这么写的），
/// 响应放在 [len] 之后——固件读回的位置是 0xA0140800 + len
/// （XIP 0x1000d8ce：r1 = 0xA0140800 + len，再逐字节拷进目标缓冲）。
/// 已实证的命令：
///   0xAF 读电子 ID → 0，固件据此回退去发 0x9F（XIP 0x1000d98e）
///   0x9F JEDEC RDID → 固件自带支持表（XIP 0x1000ca2c）第一项 2c cb 18
///   0x05 RDSR / 0x70 RFSR → 状态轮询（XIP 0x1000a5da 的等待循环）
fn sfcExec(self: *Machine) void {
    const op: u8 = self.sfc_fifo[0];
    const resp: []const u8 = switch (op) {
        0x9F => &[_]u8{ 0x2C, 0xCB, 0x18 },
        0xAF => &[_]u8{0x00},
        // RDSR：空闲 NOR 的 WIP=0、错误位全 0
        0x05 => &[_]u8{0x00},
        // RFSR（Micron 专有）：bit7=1 表示 P/E 控制器就绪，其余是错误位
        0x70 => &[_]u8{0x80},
        // 其余（WREN/擦除/编程等）当前不建模，返回 0xFF = 无响应
        else => &[_]u8{ 0xFF, 0xFF, 0xFF },
    };
    const base: u32 = self.sfc_len; // 响应紧跟在命令/地址字节之后
    for (resp, 0..) |b, i| {
        const a = base + i;
        if (a < self.sfc_fifo.len) self.sfc_fifo[a] = b;
    }
    if (self.sfc_op_counts[op] == 0) {
        const site = accessSite(self);
        log.info(@src(), "  [SF] 命令 0x{x:0>2} 首次: 写 {d} 字节 读 {d} 字节 fifo={x:0>2} {x:0>2} {x:0>2} {x:0>2} pc=0x{x:0>8} lr=0x{x:0>8}", .{
            op,               self.sfc_len,     self.sfc_mode,
            self.sfc_fifo[0], self.sfc_fifo[1], self.sfc_fifo[2],
            self.sfc_fifo[3], site.pc,          site.lr,
        });
    }
    self.sfc_cmds_run += 1;
    self.sfc_op_counts[op] += 1;
}

/// 已接线寄存器的写行为；其余记录后丢弃
fn periphWrite(self: *Machine, addr: u32, size: u32, value: u64) void {
    if (uartIndex(addr)) |i| {
        const off = addr & 0xFFFF;
        if (off == 0x0000) { // THR：固件串口发送
            uartPutc(self, i, @truncate(value));
            return;
        }
        // 0xA0060000 区 +0x40..+0xA4 是中断使能/清位寄存器（IDA 反编译
        // sub_10092F34「使能 IRQ n」/ sub_10092A4C「清」的写点，值为 1<<n 掩码）
        if (i == 0 and ((off >= 0x40 and off <= 0x47) or (off >= 0x80 and off <= 0x87) or
            (off >= 0xA0 and off <= 0xA7)))
        {
            const mask: u32 = @truncate(value);
            switch (off) {
                0x40, 0xA0 => self.intc_en_lo |= mask,
                0x44, 0xA4 => self.intc_en_hi |= mask,
                0x80 => self.intc_en_lo &= ~mask,
                0x84 => self.intc_en_hi &= ~mask,
                else => {},
            }
            return;
        }
    }
    if (addr == 0xA005_0090) { // 时钟切换命令
        if (self.recordFault(addr, "clk-cmd")) {
            log.info(@src(), "  时钟切换命令 write 0x{x}", .{value});
        }
        self.clk_cmd = @truncate(value);
        return;
    }
    if (addr == 0xA018_00A0) { // EMI/总线命令：busy 位写后自清
        if (self.recordFault(addr, "emi-cmd")) {
            log.info(@src(), "  EMI 总线命令 write 0x{x}（busy 自清）", .{value});
        }
        // 首次总线命令触发的 0x0 重映射（模拟器扮演 BootROM 的部分）在 bootrom.zig
        if (!self.remaped_low_ram) bootrom.onBusCommand(self);
        return;
    }
    // 串行 flash 控制器（SF）与 RTC 的写侧
    if ((addr >= 0xA014_0000 and addr < 0xA014_0100) or (addr >= 0xA014_0800 and addr < 0xA014_0810)) {
        sfcWrite(self, addr - 0xA014_0000, size, value);
        return;
    }
    if (addr >= 0xA071_0000 and addr < 0xA071_0100) {
        leWrite(self.rtc_regs[0..], addr - 0xA071_0000, size, value);
        return;
    }
    if (addr == 0xA003_0000) {
        self.intc_ctrl = @truncate(value);
        if (!self.irq_logged) {
            self.irq_logged = true;
            const site = accessSite(self);
            log.info(@src(), "  [INTC] 全局使能 0xA0030000 = 0x{x} pc=0x{x:0>8}（中断已开）", .{ value, site.pc });
        }
        return;
    }
    if (addr == 0xA003_0008) {
        self.intc_ctrl8 = @truncate(value);
        return;
    }
    // 中断控制器：写 +0x1A8 = 确认（清 pending）；0xA0060040/44/80/84 = 使能置位/清位
    if (addr >= 0xA076_0000 and addr < 0xA076_0100) {
        if (addr - 0xA076_0000 == 0x1A8) {
            if (self.irq_pending >= 0 and !self.irq_logged) {
                self.irq_logged = true;
                log.info(@src(), "  [INTC] 中断 {d} 已确认（ack）", .{self.irq_pending});
            }
            self.irq_pending = -1;
        }
        return;
    }
    // 芯片标识寄存器组：也接受写入（真机是只读 eFuse，固件不会写；留着便于调试）
    if (addr >= 0xA000_0000 and addr < 0xA000_0010) {
        leWrite(self.chip_regs[0..], addr - 0xA000_0000, size, value);
        return;
    }
    // ── 诊断开关 --cake-patch ──────────────────────────────────────────
    // 固件在 DMA 启动后校验传输起始地址（+0x00 配置）处的 magic == "CAKE"
    // （0x10032714 `cmp`，不等就 assert → 关机）。真机这个值由传输引擎搬运/
    // 解扰产生，我们没实现该硬件行为，先用固件自己的期望值补上，用来验证
    // 「这是不是唯一的卡点」。正式修法是实现 0xA0520000 的真实传输。
    if (self.cake_patch and addr == 0xA052_0080 and value == 1) {
        const dst = leRead(self.xfer_regs2[0..], 0x100, 4);
        _ = c.uc_mem_write(self.eng.handle, dst, "CAKE", 4);
        log.info(@src(), "  [cake-patch] DMA 启动 → 起始 0x{x:0>8} 写入 \"CAKE\"", .{dst});
    }
    // 传输/DMA 引擎（0xA0520000）：寄存器文件；+0x34 的 bit31 在读取时置位。
    // 注意实际基址是 0xA051FFE0（固件把 r4 先 +0x20 再用），所以范围向下扩。
    if (addr >= 0xA051_FF00 and addr < 0xA052_0100) {
        const off = addr - 0xA051_FF00;
        // 引擎的「描述符」寄存器写入是定位搬运源/目标的关键，前 80 次全部记现场
        if (self.xfer_writes < 400) {
            const site = accessSite(self);
            log.info(@src(), "  [传输引擎] 写 0x{x:0>8} = 0x{x:0>8} size={d} pc=0x{x:0>8} lr=0x{x:0>8}", .{
                addr, value, size, site.pc, site.lr,
            });
        }
        self.xfer_writes += 1;
        leWrite(self.xfer_regs2[0..], off, size, value);
        return;
    }
    if (addr >= 0xA052_1000 and addr < 0xA053_0000) {
        // 数据窗口：固件先往这里成片写数据、再启动 DMA——内容就是搬运的源数据
        self.xfer_fifo_writes += 1;
        if (self.xfer_fifo_writes <= 64) {
            const site = accessSite(self);
            log.info(@src(), "  [DMA-FIFO] 写 0x{x:0>8} = 0x{x:0>8} size={d} pc=0x{x:0>8}", .{
                addr, value, size, site.pc,
            });
        }
        return;
    }

    if (self.recordFault(addr, "write")) {
        const site = accessSite(self);
        if (regionName(addr)) |n| {
            log.info(@src(), "  外设写 {s}+0x{x:0>4} size={d} value=0x{x} pc=0x{x:0>8} lr=0x{x:0>8}", .{ n, addr & 0xFFFF, size, value, site.pc, site.lr });
        } else {
            log.info(@src(), "  外设桩写 @0x{x:0>8} size={d} value=0x{x} pc=0x{x:0>8} lr=0x{x:0>8}", .{ addr, size, value, site.pc, site.lr });
        }
    }
}

pub fn onMmioRead(_: ?*c.uc_engine, offset: u64, size: c_uint, user: ?*anyopaque) callconv(.c) u64 {
    const ctx: *RegionCtx = @ptrCast(@alignCast(user.?));
    return periphRead(ctx.machine, @truncate(ctx.base + offset), size);
}

pub fn onMmioWrite(_: ?*c.uc_engine, offset: u64, size: c_uint, value: u64, user: ?*anyopaque) callconv(.c) void {
    const ctx: *RegionCtx = @ptrCast(@alignCast(user.?));
    periphWrite(ctx.machine, @truncate(ctx.base + offset), size, value);
}
