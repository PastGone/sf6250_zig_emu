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
const alice = @import("alice.zig");

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
    .{ .base = 0xA00C_0000, .name = "GPT(通用定时器)" },
    .{ .base = 0xA00E_0000, .name = "PWM" },
    .{ .base = 0xA013_0000, .name = "MSDC(SD控制器)" },
    .{ .base = 0xA015_0000, .name = "AUXADC(辅助ADC)" },
    .{ .base = 0xA075_0000, .name = "ACCDET(配件检测)" },
    .{ .base = 0xA019_0000, .name = "HIF0(主机接口)" },
    .{ .base = 0xA01A_0000, .name = "HIF1(主机接口)" },
    .{ .base = 0xA01B_0000, .name = "NLI_ARB(外部存储接口仲裁)" },
    .{ .base = 0xA01F_0000, .name = "OSTD(OS timer)" },
    .{ .base = 0xA045_0000, .name = "LCM" },
    .{ .base = 0xA002_0000, .name = "A002 GPIO/CLK" },
    .{ .base = 0xA017_0000, .name = "A017(文档未覆盖)" },
    .{ .base = 0xA01C_0000, .name = "A01C(文档未覆盖)" },
    .{ .base = 0xA003_0000, .name = "中断控制器" },
    .{ .base = 0xA001_0000, .name = "A001(文档未覆盖)" },
    .{ .base = 0xA051_0000, .name = "A051(文档未覆盖)" },
    .{ .base = 0xA054_0000, .name = "A054(文档未覆盖)" },
    .{ .base = 0xA070_0000, .name = "A070(文档未覆盖)" },
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
    // CLK/PLL 配置寄存器（0xA0050000 起）：整块接成寄存器文件（见 onMmioWrite 同区块注释）
    if (addr >= 0xA005_0000 and addr < 0xA005_1000) {
        return leRead(self.clk_regs[0..], addr - 0xA005_0000, size);
    }
    // EMI 初始化完成状态（0xA0180040）：MAUI sub_10070886 轮询 `(*(u32*)0xA0180040)
    // & 0xF == 1`（低 4 位 == 1 = DRAM 训练/EMI 初始化完成）。真机由 EMI 控制器在
    // 训练完成后置位；模拟器不做 DRAM 训练，直接给「完成」值放行，否则固件在此
    // 5 百万次忙等（实测）。
    if (addr == 0xA018_0040) return 0x1;
    // EMI/总线命令（0xA0180080 起，整块接成寄存器文件）。
    // 依据见 HANDOFF §9.8 / wiring 文档：BL sub_70008F94 用它发命令、等 bit31，
    // 并读 +0xA8/+0xAC 做时序校准（伪代码要求差值落在 [51,73]，dword_70009000
    // = -1301、阈值 dword_70009004 = 599 均为实测）。此前只接了 0xA01800A0 单点，
    // 实际基址是 0xA0180080（还有 +0x80/+0x88/+0xA4 等寄存器）。
    if (addr >= 0xA018_0080 and addr < 0xA018_00C0) {
        const off = addr - 0xA018_0000;
        if (off == 0xA0) { // 命令/状态位：busy 位（bit0/bit31）读恒 0 = 已完成
            if (self.emi_reads < 10) {
                const site = accessSite(self);
                log.info(@src(), "  [EMI读] +0x{x:0>2} pc=0x{x:0>8} lr=0x{x:0>8} size={d} -> 0", .{
                    off, site.pc, site.lr, size,
                });
            }
            self.emi_reads += 1;
            return 0x00;
        }
        if (off == 0xA8) return 0x00; // 校准起始计数
        if (off == 0xAC) return 0x3C; // 结束计数（60，落在 [51,73] 内）
        return leRead(self.emi_regs[0..], off, size);
    }
    // EMI 配置 bank（0xA0180800 起，DRAM 时序寄存器）。BL/MAUI 写时序值后
    // 读回；MAUI sub_1005D0F4 先把 +0x808 |= 0x144，再轮询 +0x820 的 bit2
    // = 配置生效/命令完成（未置位则死循环，实测 1900 万次）。给该位置位放行。
    if (addr >= 0xA018_0800 and addr < 0xA018_0C00) {
        const off = addr - 0xA018_0000;
        var v = leRead(self.emi_regs[0..], off, size);
        if (off == 0x820) v |= 0x4;
        return v;
    }
    // EMI +0x0104：自由运行时基。MAUI sub_100706A4（XIP 0x100706A4）就两句
    // `ldr r0,=0xA0180100; ldr r0,[r0,#4]; bx lr` —— 直接返回 *(u32*)0xA0180104；
    // 调用方（如 0x10021212 存进 OS 时间变量 0xF03D004C+0x10）把它当单调计数器。
    // 未接线时恒读 0 → 时间永不前进，调度等待循环在 0x1007BCE6 空转（实测该地址
    // 被读 1748 万次）。按指令数推进（右移 4 ≈ 每 16 条指令 +1），给出递增时基。
    if (addr == 0xA018_0104) return @truncate(self.instrs >> 4);
    // 中断全局控制（0xA0030000/08）：回读保留（MAUI sub_10037A84 读改写）
    if (addr == 0xA003_0000) return self.intc_ctrl;
    if (addr == 0xA003_0008) return self.intc_ctrl8;
    // 串行 flash 控制器（SF，0xA0140000）：控制/状态 + 数据窗口两个区段
    if ((addr >= 0xA014_0000 and addr < 0xA014_0100) or (addr >= 0xA014_0800 and addr < 0xA014_0810)) {
        return sfcRead(self, addr - 0xA014_0000, size);
    }
    // AUXADC 辅助 ADC（0xA0150000）：DAT0~DAT11 是只读采样值（低 10 位有效）。
    // 数据手册只给寄存器图，采样值按「电池正常、没插充电器、常温」给合理默认，
    // 免得固件读到 0 误判成低电/无电池而关机。
    if (addr >= 0xA015_0000 and addr < 0xA015_0100) {
        const off = addr - 0xA015_0000;
        return switch (off) {
            0x10 => 0x2A4, // DAT0 VBAT ≈ 3.7V（10-bit，参考 2.8V 半分压）
            0x14 => 0x000, // DAT1 ISENSE 无充电电流
            0x18 => 0x000, // DAT2 CHRIN 未接充电器
            0x1C => 0x180, // DAT3 VBATTMP 常温
            else => leRead(self.auxadc_regs[0..], off, size),
        };
    }
    // GPT 通用定时器（0xA00C0000）：寄存器文件。STA(+0x10) 回 0 = 无超时事件
    if (addr >= 0xA00C_0000 and addr < 0xA00C_0040) {
        const off = addr - 0xA00C_0000;
        var v = leRead(self.gpt_regs[0..], off, size);
        // +0x10 = STA 事件位：MAUI 0x1006B844 的等待循环读它并测 bit1
        // （`ldrh r1,[r3,#0x10]; ands r1,#2; orrs r1,r2; beq loop`）——未置位就
        // 原地空转（实测 200M 预算末尾卡在此 4 条指令的环里）。模拟器不做定时，
        // 直接把定时器 1 的事件位置位放行（固件写 +0x10 清位仍可生效）。
        if (off == 0x10 and size == 2) v |= 0x2;
        return v;
    }
    // OSTD 系统定时器（0xA01F0000）：寄存器文件 + +0x08 bit1=就绪。
    // MAUI sub_10022710：读 +0x0C 断言 >= 1000（固件 sub_100227FC 已写入 0x1207），
    // 再写 CON(+0x00) 后轮询 +0x08 的 bit1（未置位则 600 次后 panic 450）。
    // 未接线时两者读 0 → 断言失败，随后滑进 0xF072BD7C 崩溃处理链（实测）。
    if (addr >= 0xA01F_0000 and addr < 0xA01F_0100) {
        const off = addr - 0xA01F_0000;
        var v = leRead(self.ostd_regs[0..], off, size);
        if (off == 0x08 and size == 2) v |= 0x2; // bit1 = 定时器就绪
        return v;
    }
    // LCM/LCD 控制器（0xA0450000）：面板 ID 应答 + 寄存器文件（见 machine 字段注释）。
    // +0xF00 写命令 0xD3(Read ID4) 后，+0xF10 逐字节返回 [00 00 93 41]；+0x00 bit0=忙=0。
    if (addr >= 0xA045_0000 and addr < 0xA045_2000) {
        const off = addr - 0xA045_0000;
        if (off == 0xF10) { // 数据口：从响应队列逐字节弹出（空则回 0）
            var v: u64 = 0;
            var i: u32 = 0;
            while (i < size) : (i += 1) {
                const b: u8 = if (self.lcm_fifo_pos < self.lcm_fifo_len) blk: {
                    const x = self.lcm_fifo[self.lcm_fifo_pos];
                    self.lcm_fifo_pos += 1;
                    break :blk x;
                } else 0;
                v |= @as(u64, b) << @intCast(8 * i);
            }
            return v;
        }
        return leRead(self.lcm_regs[0..], off, size);
    }
    // HIF0/HIF1 主机接口（0xA0190000 / 0xA01A0000，数据手册 4.16 章）：
    // 寄存器文件 + 数据窗口；STA(+0x00) 的 bit0=BUSY 恒 0（空闲）
    if (addr >= 0xA019_0000 and addr < 0xA019_0400) {
        return leRead(self.hif_regs[0..], addr - 0xA019_0000, size);
    }
    if (addr >= 0xA01A_0000 and addr < 0xA01A_0400) {
        return leRead(self.hif1_regs[0..], addr - 0xA01A_0000, size);
    }
    // NLI_ARB 外部存储器接口仲裁（0xA01B0000）：寄存器文件，CS(+0x14) 用复位值
    if (addr >= 0xA01B_0000 and addr < 0xA01B_0100) {
        const off = addr - 0xA01B_0000;
        if (off == 0x14) return self.nli_cs;
        return leRead(self.nli_regs[0..], off, size);
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
    // 传输/解压引擎（0xA0530000）+ 数据窗口：寄存器文件（见 onMmioWrite 同区块注释）
    if (addr >= 0xA053_0000 and addr < 0xA053_2000) {
        return leRead(self.xfer2_regs[0..], addr - 0xA053_0000, size);
    }
    // 以下为「已确认外设但语义未深究」的寄存器文件块（读写一致即可，不伪造硬件
    // 行为）。ACFG GPIO(0xA0730000)/A002 GPIO-CLK(0xA0020000) 数据手册有章节；
    // A017/A051/A054/A070 文档(1/2/3.md)未覆盖，先黑盒接上、语义记 HANDOFF 待查。
    if (addr >= 0xA002_0000 and addr < 0xA002_1000) return leRead(self.a002_regs[0..], addr - 0xA002_0000, size);
    if (addr >= 0xA017_0000 and addr < 0xA017_1000) return leRead(self.a017_regs[0..], addr - 0xA017_0000, size);
    if (addr >= 0xA051_0000 and addr < 0xA051_1000) return leRead(self.a051_regs[0..], addr - 0xA051_0000, size);
    if (addr >= 0xA054_0000 and addr < 0xA054_1000) return leRead(self.a054_regs[0..], addr - 0xA054_0000, size);
    if (addr >= 0xA070_0000 and addr < 0xA070_1000) return leRead(self.a070_regs[0..], addr - 0xA070_0000, size);
    if (addr >= 0xA01C_0000 and addr < 0xA01C_0200) return leRead(self.a01c_regs[0..], addr - 0xA01C_0000, size);
    if (addr >= 0xA003_0000 and addr < 0xA003_0100) return leRead(self.a003_regs[0..], addr - 0xA003_0000, size);
    // A001 寄存器文件。+0x228 是「启动模式/正常启动」标志位域：BL2 侧有一个
    // setter（XIP 0x100088B4：`ldr r0,=0xA0010220; ldrh r1,[r0,#8]; orrs r1,#1;
    // strh r1,[r0,#8]`）和三个 getter（0x10008D54 取 bit2、0x10008D68 取 bit0、
    // 0x10008D78 取 bit3）。MAUI 侧 crt0 链（0x100211F8）读 bit0 存进 *(u16*)0xF03D004E，
    // 而 sub_10092E04 原样返回它、0x10021C74 处「== 1 才写 magic 0x26409001」；
    // 位为 0 则 0x100308CC 的关机检查失败 → 走关机（run12 实测）。
    // 真机由 BootROM/BL 在启动链里置位；本模拟器的 BootROM 模型不覆盖该 strap，
    // 故按「正常 flash 启动」给出 bit0 = 1（写入仍可回读，setter 语义不受影响）。
    if (addr >= 0xA001_0000 and addr < 0xA001_0400) {
        const off = addr - 0xA001_0000;
        var v = leRead(self.a001_regs[0..], off, size);
        if (off == 0x228 and size == 2) v |= 0x1;
        return v;
    }
    if (addr >= 0xA073_0000 and addr < 0xA073_1000) return leRead(self.acfg_regs[0..], addr - 0xA073_0000, size);
    // PWM（0xA00E0000）/ MSDC（0xA0130000）/ ACCDET（0xA0750000）：寄存器文件，
    // 见 §字段注释（数据手册均有章节；无卡/无配件时读 0 是合理默认）。
    if (addr >= 0xA00E_0000 and addr < 0xA00E_1000) return leRead(self.pwm_regs[0..], addr - 0xA00E_0000, size);
    if (addr >= 0xA013_0000 and addr < 0xA013_1000) return leRead(self.msdc_regs[0..], addr - 0xA013_0000, size);
    if (addr >= 0xA075_0000 and addr < 0xA075_0100) return leRead(self.accdet_regs[0..], addr - 0xA075_0000, size);
    // 2 号传输/DMA 引擎（0xA0230000）：寄存器文件 + 读 +0x0C 恒为「已完成」。
    // 轮询点 0x1008E904（sub_1008E900 读 +0x0C）；未接线时该地址被读 630 万次
    // 而 sub_100276C4 在其中死循环（见 dma2_regs 字段注释）。
    if (addr >= 0xA023_0000 and addr < 0xA023_0100) {
        const off = addr - 0xA023_0000;
        var v = leRead(self.dma2_regs[0..], off, size);
        if (off == 0x0C) v |= 0x1; // bit0 = 传输完成
        return v;
    }
    // 传输/DMA 引擎（0xA0520000）：见 xfer_regs 字段注释
    if (addr >= 0xA052_0000 and addr < 0xA052_0100) {
        var v = leRead(self.xfer_regs[0..], addr - 0xA052_0000, size);
        // +0x34 的 bit31 = 传输完成（固件写启动位后等它置位）
        if (addr - 0xA052_0000 == 0x34) v |= 0x8000_0000;
        return v;
    }
    // 传输/DMA 引擎数据窗口（0xA0521000 起 0x2000）：固件先把源数据 memcpy 进来，
    // 再用 memcmp（本体 XIP 0x1009101A；调用点 0x10040D52 / 0x10040D78）校验窗口内容。
    // 写入侧早已接进 xfer_fifo，**读取侧此前漏接** → memcmp 读到全 0 判不等，
    // 0x10040D5A 处把状态字节置上错误位 → 触发「Fatal Error (0xa02, 0x1)」并走
    // TST 内存转储（run14 实测）。补上读取即可让固件看到自己写进去的数据。
    if (addr >= 0xA052_1000 and addr < 0xA052_3000) {
        return leRead(self.xfer_fifo[0..], addr - 0xA052_1000, size);
    }

    if (uartIndex(addr) != null) {
        const off = addr & 0xFFFF;
        if (off == 0x14) return 0x60; // LSR：THRE|TEMT（发送器空闲）
        if (off == 0x00) return 0x00; // RBR：无接收数据
        // 其余 UART 寄存器（IER/IIR/LCR/MCR/MSR/中断使能等）：黑盒返回 0，
        // 不再进故障表——这些是各 UART 共用的标准寄存器，读 0 是「空闲/无中断」态。
        return 0;
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
        return; // 其余 UART 寄存器写忽略（不进故障表，黑盒建模）
    }
    if (addr == 0xA005_0090) { // 时钟切换命令
        log.info(@src(), "  时钟切换命令 write 0x{x}", .{value});
        self.clk_cmd = @truncate(value);
        return;
    }
    // CLK/PLL 配置寄存器写（整块寄存器文件，0xA0050090 命令点已在上面特判）
    if (addr >= 0xA005_0000 and addr < 0xA005_1000) {
        leWrite(self.clk_regs[0..], addr - 0xA005_0000, size, value);
        return;
    }
    if (addr >= 0xA018_0080 and addr < 0xA018_00C0) { // EMI/总线命令整块
        const off = addr - 0xA018_0000;
        if (off == 0xA0) { // 命令/状态：busy 位写后自清 + 首次命令触发 0x0 重映射
            if (self.emi_writes < 20) {
                log.info(@src(), "  [EMI写] +0x{x:0>2} =0x{x} pc=0x{x:0>8} lr=0x{x:0>8}", .{
                    off, value, accessSite(self).pc, accessSite(self).lr,
                });
            }
            self.emi_writes += 1;
            // 首次总线命令触发的 0x0 重映射（模拟器扮演 BootROM 的部分）在 bootrom.zig
            if (!self.remaped_low_ram) bootrom.onBusCommand(self);
            leWrite(self.emi_regs[0..], off, size, 0); // 写后清零（busy=0）
            return;
        }
        leWrite(self.emi_regs[0..], off, size, value);
        return;
    }
    // EMI 配置 bank（0xA0180800 起，DRAM 时序寄存器）：寄存器文件，写入可读回
    if (addr >= 0xA018_0800 and addr < 0xA018_0C00) {
        leWrite(self.emi_regs[0..], addr - 0xA018_0000, size, value);
        return;
    }
    // AUXADC / GPT / HIF / NLI_ARB 写侧：一律寄存器文件（写入值可读回），
    // 固件做的配置才不会丢。AUXADC 的 DAT* 是只读采样值，读侧会覆盖掉。
    if (addr >= 0xA015_0000 and addr < 0xA015_0100) {
        leWrite(self.auxadc_regs[0..], addr - 0xA015_0000, size, value);
        return;
    }
    if (addr >= 0xA00C_0000 and addr < 0xA00C_0040) {
        leWrite(self.gpt_regs[0..], addr - 0xA00C_0000, size, value);
        return;
    }
    // OSTD 系统定时器（0xA01F0000）：寄存器文件，写入值可读回（+0x0C=0x1207 等）
    if (addr >= 0xA01F_0000 and addr < 0xA01F_0100) {
        leWrite(self.ostd_regs[0..], addr - 0xA01F_0000, size, value);
        return;
    }
    // LCM/LCD 控制器（0xA0450000）：写 +0xF00 命令后装填 +0xF10 响应队列，其余寄存器文件
    if (addr >= 0xA045_0000 and addr < 0xA045_2000) {
        const off = addr - 0xA045_0000;
        if (off == 0xF00) {
            self.lcm_fifo_pos = 0;
            self.lcm_fifo_len = 0;
            switch (@as(u8, @truncate(value))) {
                0xD3 => { // ILI9341 Read ID4：dummy,dummy,0x93,0x41 → (b2<<8)|b3 = 0x9341
                    self.lcm_fifo[0] = 0x00;
                    self.lcm_fifo[1] = 0x00;
                    self.lcm_fifo[2] = 0x93;
                    self.lcm_fifo[3] = 0x41;
                    self.lcm_fifo_len = 4;
                },
                else => {},
            }
        }
        leWrite(self.lcm_regs[0..], off, size, value);
        return;
    }
    if (addr >= 0xA019_0000 and addr < 0xA019_0400) {
        leWrite(self.hif_regs[0..], addr - 0xA019_0000, size, value);
        return;
    }
    if (addr >= 0xA01A_0000 and addr < 0xA01A_0400) {
        leWrite(self.hif1_regs[0..], addr - 0xA01A_0000, size, value);
        return;
    }
    if (addr >= 0xA01B_0000 and addr < 0xA01B_0100) {
        const off = addr - 0xA01B_0000;
        if (off == 0x14) { // NLI_ARB_CS
            self.nli_cs = @truncate(value);
            return;
        }
        leWrite(self.nli_regs[0..], off, size, value);
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
    // ── DMA 启动（+0x80 写 1）──────────────────────────────────────────
    // 固件先把源数据 memcpy 进 FIFO（0xA0521000），再写 +0x80 的 bit0 启动。
    // 把 FIFO 内容打出来，就能确认「这一趟到底搬的是什么」。
    if (addr == 0xA052_0080 and (value & 1) != 0) {
        dumpFifo(self, 0);
        dumpFifo(self, 32);
        // 诊断开关 --dma-copy：实现「DMA 把 FIFO 内容搬到 +0x00 目标」这一真实
        // 硬件行为，用来判别固件那次 CAKE 校验到底是不是 1:1 搬运的结果。
        // （真机目标必可写，所以配 --flash-rw；正式确定后再决定映射。）
        if (self.dma_copy) {
            const dst = leRead(self.xfer_regs2[0..], 0x100, 4);
            const n: usize = @min(self.xfer_fifo.len, 0x2000);
            _ = c.uc_mem_write(self.eng.handle, dst, &self.xfer_fifo, n);
            log.info(@src(), "  [DMA搬运] FIFO 0x{x} 字节 → 目标 0x{x:0>8}", .{ n, dst });
        }
        // 诊断开关 --cake-patch：用固件自己的期望值补上 magic，验证这是不是
        // 唯一卡点。正式修法是实现真实搬运，到时删掉这个分支。
        if (self.cake_patch) {
            const dst = leRead(self.xfer_regs2[0..], 0x100, 4);
            _ = c.uc_mem_write(self.eng.handle, dst, "CAKE", 4);
            log.info(@src(), "  [cake-patch] DMA 启动 → 起始 0x{x:0>8} 写入 \"CAKE\"", .{dst});
        }
    }
    // 传输/解压引擎（0xA0530000）+ 数据窗口（0xA0531000 起）：BL(0x10008994)
    // 与 MAUI(sub_1003A448) 共用。+0x00 状态(16位位域)、+0x04 命令(3=复位、
    // 19=触发)、+0x08~+0x24 参数、+0x2C 状态；+0x1000 起是数据窗口。
    // 先接成寄存器文件并记现场；触发后的数据变换（固件随后校验目标处 ==
    // "CAKE"）需要还原私有算法后再补。
    if (addr >= 0xA053_0000 and addr < 0xA053_2000) {
        const off = addr - 0xA053_0000;
        if (off < 0x100 and self.xfer2_writes < 60) {
            const site = accessSite(self);
            log.info(@src(), "  [引擎2] 写 +0x{x:0>3} = 0x{x:0>8} pc=0x{x:0>8} lr=0x{x:0>8}", .{
                off, value, site.pc, site.lr,
            });
        }
        self.xfer2_writes += 1;
        leWrite(self.xfer2_regs[0..], off, size, value);
        // +0x04 = 19：硬件 ALICE 解码引擎「触发」。固件（MAUI sub_100324B8）先配好
        // 0xA0520000 的 ALICE 区间寄存器与 DMA 目标，随后调用 sub_1003A448 写 19，
        // 紧接着校验 *(0x10947980) == "CAKE"。真机由该硬件把 flash 0x108E65A8 处的
        // ALICE_1 blob 解压到目标；这里用同一套算法（src/emu/alice.zig）在宿主侧
        // 等价实现，写入 DMA 目标寄存器（0xA0520000 +0x00）。
        if (off == 4 and @as(u32, @truncate(value)) == 19) aliceDecodeToTarget(self);
        return;
    }
    // 以下寄存器文件块（读侧已加）：ACFG GPIO / A002 GPIO-CLK / A017 / A051 / A054 /
    // A070。统一「写入值可读回」，固件配置不丢；不伪造任何硬件行为。
    if (addr >= 0xA002_0000 and addr < 0xA002_1000) {
        leWrite(self.a002_regs[0..], addr - 0xA002_0000, size, value);
        return;
    }
    if (addr >= 0xA017_0000 and addr < 0xA017_1000) {
        leWrite(self.a017_regs[0..], addr - 0xA017_0000, size, value);
        return;
    }
    if (addr >= 0xA051_0000 and addr < 0xA051_1000) {
        leWrite(self.a051_regs[0..], addr - 0xA051_0000, size, value);
        return;
    }
    if (addr >= 0xA054_0000 and addr < 0xA054_1000) {
        leWrite(self.a054_regs[0..], addr - 0xA054_0000, size, value);
        return;
    }
    if (addr >= 0xA070_0000 and addr < 0xA070_1000) {
        leWrite(self.a070_regs[0..], addr - 0xA070_0000, size, value);
        return;
    }
    if (addr >= 0xA01C_0000 and addr < 0xA01C_0200) {
        leWrite(self.a01c_regs[0..], addr - 0xA01C_0000, size, value);
        return;
    }
    if (addr >= 0xA003_0000 and addr < 0xA003_0100) {
        leWrite(self.a003_regs[0..], addr - 0xA003_0000, size, value);
        return;
    }
    if (addr >= 0xA001_0000 and addr < 0xA001_0400) {
        leWrite(self.a001_regs[0..], addr - 0xA001_0000, size, value);
        return;
    }
    // 2 号传输/DMA 引擎（0xA0230000）：寄存器文件，写入可回读（见字段注释）
    if (addr >= 0xA023_0000 and addr < 0xA023_0100) {
        leWrite(self.dma2_regs[0..], addr - 0xA023_0000, size, value);
        return;
    }
    if (addr >= 0xA073_0000 and addr < 0xA073_1000) {
        leWrite(self.acfg_regs[0..], addr - 0xA073_0000, size, value);
        return;
    }
    if (addr >= 0xA00E_0000 and addr < 0xA00E_1000) {
        leWrite(self.pwm_regs[0..], addr - 0xA00E_0000, size, value);
        return;
    }
    if (addr >= 0xA013_0000 and addr < 0xA013_1000) {
        leWrite(self.msdc_regs[0..], addr - 0xA013_0000, size, value);
        return;
    }
    if (addr >= 0xA075_0000 and addr < 0xA075_0100) {
        leWrite(self.accdet_regs[0..], addr - 0xA075_0000, size, value);
        return;
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
    if (addr >= 0xA052_1000 and addr < 0xA052_3000) {
        // 数据窗口：固件 memcpy 源数据进来、再启动 DMA——内容就是搬运的源数据
        const off = addr - 0xA052_1000;
        leWrite(self.xfer_fifo[0..], off, size, value);
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

/// 0xA0530000 硬件 ALICE 解码引擎的等价实现：把 flash 里唯一的 ALICE_1 blob
/// （0x108E65A8，即 MAUI sub_100324B8 逐字节校验 'A''L''I''C''E''_''1' 的位置）
/// 解压进 DMA 目标（0xA0520000 +0x00，固件配为 0x10947980）。
///
/// 依据（HANDOFF §9.8 + 实测）：目标范围 0x10947980..0x10F39680 = 0x5F1D00 字节，
/// 与离线解压输出长度 0x5F1CFE 吻合（差 2 字节为块对齐填充）；固件紧随其后
/// 校验 *(0x10947980) == "CAKE"，而解压输出正好以 "CAKE" 开头。
fn aliceDecodeToTarget(self: *Machine) void {
    const img = self.img orelse return;
    const blob_va: u32 = 0x108E_65A8;
    const off = blob_va - machine.map.flash_window_base;
    if (off >= img.data.len) {
        log.err(@src(), "ALICE blob 0x{x:0>8} 超出镜像范围", .{blob_va});
        return;
    }
    const decoded = alice.decompress(self.allocator, img.data[off..]) catch |e| {
        log.err(@src(), "ALICE 解压失败 ({s})", .{@errorName(e)});
        return;
    };
    defer self.allocator.free(decoded);
    const dst = leRead(self.xfer_regs2[0..], 0x100, 4);
    if (c.uc_mem_write(self.eng.handle, dst, decoded.ptr, decoded.len) != c.UC_ERR_OK) {
        log.err(@src(), "ALICE 写目标 0x{x:0>8} 失败 (len=0x{x})", .{ dst, decoded.len });
        return;
    }
    var magic: [4]u8 = undefined;
    const ok = c.uc_mem_read(self.eng.handle, dst, &magic, 4) == c.UC_ERR_OK;
    log.info(@src(), "  [ALICE] 引擎触发 → 解压 {d} 字节 → 目标 0x{x:0>8} magic={s}", .{
        decoded.len, dst, if (ok) magic[0..4] else "????",
    });
}

/// dump 传输引擎 FIFO（0xA0521000）的 32 字节——启动 DMA 时的源数据
fn dumpFifo(self: *const Machine, base: usize) void {
    var line: [128]u8 = undefined;
    var len: usize = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const part = std.fmt.bufPrint(line[len..], "{x:0>2} ", .{self.xfer_fifo[base + i]}) catch break;
        len += part.len;
    }
    log.info(@src(), "  [DMA源] fifo+0x{x:0>2}: {s}", .{ base, line[0..len] });
}

pub fn onMmioWrite(_: ?*c.uc_engine, offset: u64, size: c_uint, value: u64, user: ?*anyopaque) callconv(.c) void {
    const ctx: *RegionCtx = @ptrCast(@alignCast(user.?));
    periphWrite(ctx.machine, @truncate(ctx.base + offset), size, value);
}
