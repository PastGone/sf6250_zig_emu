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
    .{ .base = 0xA005_0000, .name = "CLK/PLL" },
    .{ .base = 0xA006_0000, .name = "UART1(AT)" },
    .{ .base = 0xA007_0000, .name = "UART2" },
    .{ .base = 0xA008_0000, .name = "UART3(LOG)" },
    .{ .base = 0xA014_0000, .name = "SF(串行flash)" },
    .{ .base = 0xA018_0000, .name = "EMI/总线命令" },
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

/// 固件串口输出：存进行缓冲，\n / \r / 满行时按行打出
fn uartPutc(self: *Machine, i: usize, b: u8) void {
    const printable = (b >= 0x20 and b < 0x7f) or b == '\t';
    if (self.uart_len[i] < 120) {
        self.uart_line[i][self.uart_len[i]] = if (printable) b else '?';
        self.uart_len[i] += 1;
    }
    if (b == '\n' or b == '\r' or self.uart_len[i] >= 120) {
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
    // 串行 flash 控制器（SF，0xA0140000）：控制/状态 + 数据窗口两个区段
    if ((addr >= 0xA014_0000 and addr < 0xA014_0100) or (addr >= 0xA014_0800 and addr < 0xA014_0810)) {
        return sfcRead(self, addr - 0xA014_0000, size);
    }
    // RTC（0xA0710000）：寄存器文件，写入值读回（数据手册 RTC 章）
    if (addr >= 0xA071_0000 and addr < 0xA071_0100) {
        return leRead(self.rtc_regs[0..], addr - 0xA071_0000, size);
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

/// SF（串行 flash）控制器寄存器读。位语义由固件轮询序列反推：
///   +0x00 bit0=忙（本模型恒 0）、bit1=命令完成（= bit2&bit3 同时为 1）、
///         bit2/bit3/bit4=固件写的控制位（回读保留）
///   +0x04 状态标志、+0x10 命令字节数、+0x14 响应字节数、+0x800 起数据窗口
fn sfcRead(self: *Machine, off: u32, size: u32) u64 {
    if (off == 0x00) {
        const done: u32 = if (self.sfc_ctrl & 0xC == 0xC) 0x2 else 0;
        return (self.sfc_ctrl & ~@as(u32, 0x3)) | done;
    }
    if (off == 0x04) return self.sfc_flags;
    if (off == 0x10) return self.sfc_len;
    if (off == 0x14) return self.sfc_mode;
    if (off >= 0x800 and off < 0x804) return leRead(self.sfc_fifo[0..], off - 0x800, size);
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
    if (off == 0x10) {
        self.sfc_len = @truncate(value);
        return;
    }
    if (off == 0x14) {
        self.sfc_mode = @truncate(value);
        return;
    }
    if (off >= 0x800 and off < 0x804) {
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
        if (addr & 0xFFFF == 0x0000) { // THR：固件串口发送
            uartPutc(self, i, @truncate(value));
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
