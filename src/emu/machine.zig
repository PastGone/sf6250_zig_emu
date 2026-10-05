//! 机器骨架：地址空间、CPU 起跑、以及“跑到未实现的外设就报出来”的探针。
//!
//! 现在的策略是**黑盒推进**：先把 BL 装进 SRAM 跑起来，凡访问到我们还没实现的
//! 地址就记下 PC 与地址并停下，逐步把外设补上。

const std = @import("std");
const log = @import("../log.zig");
const mtk = @import("../mtk_boot_image/mtk_boot_image.zig");
const uc = @import("unicorn.zig");
const c = uc.c;

/// MT6250 地址空间。除 SRAM 外基本都是*推测*，需要靠实测（固件访问地址）校正。
pub const map = struct {
    /// boot 阶段的 flash 视图：BL 从这里读到自己的 GFH（实测 0x000008a8）
    pub const boot_view_base = 0x0000_0000;

    /// 片内 SRAM：BL 的 load_addr 0x70008000 就落在这里（已由镜像确认）
    pub const sram_base = 0x7000_0000;
    pub const sram_size = 0x0004_0000; // 256KB（推测）

    /// flash/EMI 窗口：MAUI 的 load_addr = 0x1000_0000 + 文件偏移，说明整片
    /// flash 被线性映射到这里，MAUI 直接在上面 XIP（已由镜像确认）
    pub const flash_window_base = 0x1000_0000;

    /// 外设寄存器：apb 段到外部 RAM（0x82000000，run761 实测）为止
    pub const apb_base = 0x8000_0000;
    pub const apb_size = 0x200_0000;
    pub const ahb_base = 0xa000_0000;
    pub const ahb_size = 0x1000_0000;
};

const max_faults = 256;

/// 已接线的寄存器区块（地址→名字）。行为依据见 docs/mt6250-wiring.md。
pub const known_regions = [_]struct { base: u32, name: []const u8 }{
    .{ .base = 0xA005_0000, .name = "CLK/PLL" },
    .{ .base = 0xA006_0000, .name = "UART1(AT)" },
    .{ .base = 0xA007_0000, .name = "UART2" },
    .{ .base = 0xA008_0000, .name = "UART3(LOG)" },
    .{ .base = 0xA018_0000, .name = "EMI/总线命令" },
    .{ .base = 0xA045_0000, .name = "LCM" },
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
const RegionCtx = struct {
    machine: *Machine,
    base: u64,
};

pub const Machine = struct {
    allocator: std.mem.Allocator,
    eng: uc.Engine,
    img: ?*const mtk.BootImage = null,

    instrs: u64 = 0,
    trace: bool = false,
    /// 宽容模式：碰到未实现的地址不停下，假装访问成功（读回 0），用来一次性
    /// 摸清固件会碰到哪些外设
    lenient: bool = false,

    hook_code: c.uc_hook = 0,
    hook_mem: c.uc_hook = 0,
    hook_tblwr: c.uc_hook = 0,
    tbl_wr: u32 = 0,
    bp_logged: bool = false,
    bp_bss: bool = false,

    regions: [2]RegionCtx = undefined,
    /// UART1/2/3 的行缓冲（固件串口输出，按 \n / \r / 满行刷新）
    uart_line: [3][121]u8 = undefined,
    uart_len: [3]usize = @splat(0),
    /// 0xA0050090 时钟切换命令寄存器的当前命令（写后状态位按命令应答）
    clk_cmd: u32 = 0,

    /// 末尾执行轨迹（诊断用：看停机/空转前在跑什么）
    exec_hist: [256]u32 = @splat(0),
    exec_hist_pos: usize = 0,

    /// 去重后的未映射访问地址（用来反推外设分布）
    fault_addrs: [max_faults]u64 = @splat(0),
    fault_count: usize = 0,
    fault_kinds: [max_faults][:0]const u8 = undefined,
    fault_counts: [max_faults]u64 = @splat(0),

    pub fn init(allocator: std.mem.Allocator) !*Machine {
        // ARM7EJ-S 是 ARMv5TEJ，Unicorn 没有该型号，用同为 ARMv5TEJ 的 ARM926 近似。
        // MTK 的 BL 是 Thumb 代码，因此以 THUMB 模式起跑（不对再切回 ARM 模式）。
        const eng = try uc.Engine.open(c.UC_ARCH_ARM, c.UC_MODE_ARM926 | c.UC_MODE_THUMB);
        errdefer eng.close();

        const m = try allocator.create(Machine);
        m.* = .{ .allocator = allocator, .eng = eng };

        try m.eng.hookCode(&m.hook_code, onCode, m);
        try m.eng.hookMemInvalid(&m.hook_mem, onMemInvalid, m);
        // 监视 BL 回调表区的写入（诊断：谁注册了/没人注册）
        try m.eng.hookMem(&m.hook_tblwr, c.UC_HOOK_MEM_WRITE, 0x7000A100, 0x7000A1FF, onTblWrite, m);
        return m;
    }

    pub fn deinit(self: *Machine) void {
        self.eng.close();
        self.allocator.destroy(self);
    }

    /// 把片内 SRAM 挂上（RWX）
    pub fn mapSram(self: *Machine) !void {
        try self.eng.memMap(map.sram_base, map.sram_size, uc.Perm.combine(&.{
            .read, .write, .exec,
        }));
    }

    /// 外部 RAM（0x82000000 起 64MB）：BL 堆与共享数据区、MAUI 重定位目标
    /// （run761 实测 MAUI 在 0x84Exxxxx 执行）——见 docs/mt6250-wiring.md 内存图
    pub fn mapExternalRam(self: *Machine) !void {
        const base = 0x8200_0000;
        const size = 0x400_0000;
        try self.eng.memMap(base, size, uc.Perm.combine(&.{ .read, .write, .exec }));
        log.info(@src(), "外部 RAM: 0x{x:0>8}..0x{x:0>8} ({d} MB, RWX)", .{ base, base + size, size >> 20 });
    }

    /// 外设窗口挂成 MMIO：已接线的寄存器按 docs/mt6250-wiring.md 给行为，
    /// 其余读 0/写丢弃并记名——这是「黑盒推进」的抓手。
    pub fn mapPeriphStubs(self: *Machine) !void {
        self.regions[0] = .{ .machine = self, .base = map.ahb_base };
        self.regions[1] = .{ .machine = self, .base = map.apb_base };
        try self.eng.mmioMap(map.ahb_base, map.ahb_size, onMmioRead, &self.regions[0], onMmioWrite, &self.regions[0]);
        try self.eng.mmioMap(map.apb_base, map.apb_size, onMmioRead, &self.regions[1], onMmioWrite, &self.regions[1]);
        log.info(@src(), "外设: 0x{x:0>8}..0x{x:0>8}, 0x{x:0>8}..0x{x:0>8}（{d} 个区块已接线，其余读 0/写丢弃）", .{
            map.ahb_base,      map.ahb_base + map.ahb_size,
            map.apb_base,      map.apb_base + map.apb_size,
            known_regions.len,
        });
    }

    /// 把整份 flash 以 XIP 方式挂在 0x1000_0000（零拷贝，只读可执行）。
    /// 依据：MAUI 的 file offset 0x20000 ↔ load_addr 0x10020000，第二段
    /// 0x8752b0 ↔ 0x108752b0，即 flash 被线性映射到 0x1000_0000 起。
    pub fn mapFlashWindow(self: *Machine, img: *const mtk.BootImage) !void {
        const perms = uc.Perm.combine(&.{ .read, .exec });

        try self.eng.memMapPtr(map.flash_window_base, img.data.len, perms, @constCast(img.data.ptr));
        log.info(@src(), "flash 窗口: 0x{x:0>8}..0x{x:0>8} ({d} 字节, 只读可执行)", .{
            map.flash_window_base, map.flash_window_base + img.data.len, img.data.len,
        });

        // BL 会去读 0x000008a8（= flash 偏移 0x8a8，正是它自己的 GFH），
        // 说明 boot 阶段 flash 在 0x0 还有一个视图（推测：BootROM 的映射窗口）。
        try self.eng.memMapPtr(map.boot_view_base, img.data.len, perms, @constCast(img.data.ptr));
        log.info(@src(), "boot 视图: 0x{x:0>8}..0x{x:0>8}", .{
            map.boot_view_base, map.boot_view_base + img.data.len,
        });
    }

    /// 按镜像信息把一级 Bootloader 装进 SRAM，并把寄存器摆成 BootROM 跳转后的样子
    pub fn loadBootloader(self: *Machine, img: *const mtk.BootImage) !void {
        const bl = mtk.find(img, mtk.file_type.bl) orelse return error.NoBootloader;
        const code = mtk.payload(img, bl);
        if (code.len == 0) return error.EmptyBootloader;

        try self.mapSram();
        // FILE_INFO 头不在 load_addr 处的内容里：正文从 load_addr + hdr_size 开始
        try self.eng.memWrite(bl.load_addr + bl.hdr_size, code);
        self.img = img;

        const pc: u32 = bl.load_addr +% bl.jump_offset;
        const sp: u32 = map.sram_base + map.sram_size - 0x100;

        try self.eng.regWrite(c.UC_ARM_REG_SP, &sp);
        try self.eng.regWrite(c.UC_ARM_REG_PC, &pc);
        // Supervisor 模式、IRQ/FIQ 关（Thumb 位由 UC_MODE_THUMB 设置）
        const cpsr: u32 = 0xd3;
        try self.eng.regWrite(c.UC_ARM_REG_CPSR, &cpsr);

        log.info(@src(), "BL: {d} 字节 @0x{x:0>8}, pc=0x{x:0>8} sp=0x{x:0>8}", .{
            code.len, bl.load_addr, pc, sp,
        });
    }

    /// 跑最多 budget 条指令；停下来时把原因打到日志
    pub fn run(self: *Machine, budget: u64) void {
        const begin = self.readPc() catch 0;
        self.instrs = 0;

        self.eng.emuStart(begin, 0, 0, budget) catch |err| {
            log.warn(@src(), "CPU 停止: {s} ({d} 条指令), pc=0x{x:0>8}", .{
                uc.Engine.strerror(err), self.instrs, self.readPc() catch 0,
            });
        };

        log.info(@src(), "执行 {d} 条指令, 最终 pc=0x{x:0>8}", .{ self.instrs, self.readPc() catch 0 });
        self.dumpExecHist();
        self.reportFaults();
    }

    pub fn readPc(self: *const Machine) !u32 {
        var v: u32 = 0;
        try self.eng.regRead(c.UC_ARM_REG_PC, &v);
        return v;
    }

    /// 末尾执行轨迹：按时间顺序打印最近的 PC（诊断空转/停机原因）
    fn dumpExecHist(self: *const Machine) void {
        const n = @min(self.exec_hist_pos, self.exec_hist.len);
        if (n == 0) return;
        var buf: [256 * 10]u8 = undefined;
        var len: usize = 0;
        var i: usize = 0;
        const start = if (self.exec_hist_pos > n) self.exec_hist_pos % n else 0;
        while (i < n) : (i += 1) {
            const pc = self.exec_hist[(start + i) % self.exec_hist.len];
            const part = std.fmt.bufPrint(buf[len..], "{x:0>8} ", .{pc}) catch break;
            len += part.len;
        }
        log.info(@src(), "末尾轨迹: {s}", .{buf[0..len]});
    }

    /// 记下地址；返回 true 表示这是第一次见到
    fn recordFault(self: *Machine, addr: u64, kind: [:0]const u8) bool {
        for (0..self.fault_count) |i| {
            if (self.fault_addrs[i] == addr) {
                self.fault_counts[i] += 1;
                return false;
            }
        }
        if (self.fault_count >= max_faults) return false;
        self.fault_addrs[self.fault_count] = addr;
        self.fault_kinds[self.fault_count] = kind;
        self.fault_counts[self.fault_count] = 1;
        self.fault_count += 1;
        return true;
    }

    fn reportFaults(self: *const Machine) void {
        // 按访问次数降序：排最前的往往是被轮询的状态寄存器
        var idx: [max_faults]usize = undefined;
        for (0..self.fault_count) |i| idx[i] = i;
        const less = struct {
            fn f(ctx: []const u64, a: usize, b: usize) bool {
                return ctx[b] < ctx[a];
            }
        }.f;
        std.mem.sort(usize, idx[0..self.fault_count], self.fault_counts[0..self.fault_count], less);
        for (idx[0..self.fault_count]) |i| {
            log.info(@src(), "  未实现访问 #{d}: {s} @0x{x:0>8} x{d}", .{
                i, self.fault_kinds[i], self.fault_addrs[i], self.fault_counts[i],
            });
        }
    }
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

    if (uartIndex(addr) != null) {
        const off = addr & 0xFFFF;
        if (off == 0x14) return 0x60; // LSR：THRE|TEMT（发送器空闲）
        if (off == 0x00) return 0x00; // RBR：无接收数据
    }

    if (self.recordFault(addr, "read")) {
        if (regionName(addr)) |n| {
            log.info(@src(), "  外设读 {s}+0x{x:0>4} size={d} -> 0（未接线）", .{ n, addr & 0xFFFF, size });
        } else {
            log.info(@src(), "  外设桩读 @0x{x:0>8} size={d} -> 0", .{ addr, size });
        }
    }
    return 0;
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
        return;
    }

    if (self.recordFault(addr, "write")) {
        if (regionName(addr)) |n| {
            log.info(@src(), "  外设写 {s}+0x{x:0>4} size={d} value=0x{x}", .{ n, addr & 0xFFFF, size, value });
        } else {
            log.info(@src(), "  外设桩写 @0x{x:0>8} size={d} value=0x{x}", .{ addr, size, value });
        }
    }
}

fn onMmioRead(_: ?*c.uc_engine, offset: u64, size: c_uint, user: ?*anyopaque) callconv(.c) u64 {
    const ctx: *RegionCtx = @ptrCast(@alignCast(user.?));
    return periphRead(ctx.machine, @truncate(ctx.base + offset), size);
}

fn onMmioWrite(_: ?*c.uc_engine, offset: u64, size: c_uint, value: u64, user: ?*anyopaque) callconv(.c) void {
    const ctx: *RegionCtx = @ptrCast(@alignCast(user.?));
    periphWrite(ctx.machine, @truncate(ctx.base + offset), size, value);
}

fn onCode(engine: ?*c.uc_engine, address: u64, size: u32, user: ?*anyopaque) callconv(.c) void {
    const m: *Machine = @ptrCast(@alignCast(user));
    m.instrs += 1;
    m.exec_hist[m.exec_hist_pos % m.exec_hist.len] = @truncate(address);
    m.exec_hist_pos += 1;
    if (address == 0x70009b20 and !m.bp_bss) {
        m.bp_bss = true;
        var r0: u32 = 0;
        var r1: u32 = 0;
        var r2: u32 = 0;
        var r3: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &r2);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R3, &r3);
        log.info(@src(), "  [断点] 0x70009b20 BSS清理: r0=0x{x:0>8} r1=0x{x:0>8} r2=0x{x:0>8} r3=0x{x:0>8}", .{ r0, r1, r2, r3 });
    }
    if (address == 0x10008061) {
        log.info(@src(), "★ 阶段切换: 进入 BL2 (0x10008061)", .{});
    }
    if (address == 0x10020301) {
        log.info(@src(), "★ 阶段切换: 进入 MAUI (0x10020301)", .{});
    }
    if (address == 0x700082e0 and !m.bp_logged) {
        m.bp_logged = true;
        var r0: u32 = 0;
        var r1: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [断点] 0x700082e0 入口: r0=0x{x:0>8} r1=0x{x:0>8} lr=0x{x:0>8}", .{ r0, r1, lr });
        m.dumpExecHist();
        // 导出运行时 SRAM hex，供离线反汇编（蹦床 + 传参处两段）
        inline for (.{ 0x70008200, 0x70009200, 0x70009300, 0x70009400, 0x70009500, 0x70009600, 0x70009700, 0x70009800, 0x70009900, 0x70009A00 }) |base| {
            var mem: [0x100]u8 = undefined;
            if (c.uc_mem_read(engine, base, &mem, mem.len) == c.UC_ERR_OK) {
                var hx: [3 * 0x100]u8 = undefined;
                var n: usize = 0;
                for (mem) |b| {
                    const p = std.fmt.bufPrint(hx[n..], "{x:0>2}", .{b}) catch break;
                    n += p.len;
                }
                log.info(@src(), "RUNTIMESRAM:{x:0>8}:{s}", .{ base, hx[0..n] });
            }
        }
    }
    if (m.trace) {
        log.debug(@src(), "pc=0x{x:0>8} size={d}", .{ address, size });
    }
}

/// 回调表写监视：记录 PC 与写入值（前 32 次）
fn onTblWrite(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    if (address == 0x7000A114) {
        var pc: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [表写] pc=0x{x:0>8} lr=0x{x:0>8} -> [0x{x:0>8}] = 0x{x:0>8}", .{
            pc, lr, address, @as(u64, @bitCast(value)),
        });
    }
    m.tbl_wr += 1;
    return true;
}

fn onMemInvalid(
    uc_engine: ?*c.uc_engine,
    typ: c.uc_mem_type,
    address: u64,
    size: c_int,
    value: i64,
    user: ?*anyopaque,
) callconv(.c) bool {
    const m: *Machine = @ptrCast(@alignCast(user));

    const kind: [:0]const u8 = switch (typ) {
        c.UC_MEM_READ_UNMAPPED => "read unmapped",
        c.UC_MEM_WRITE_UNMAPPED => "write unmapped",
        c.UC_MEM_FETCH_UNMAPPED => "fetch unmapped",
        c.UC_MEM_READ_PROT => "read protected",
        c.UC_MEM_WRITE_PROT => "write protected",
        c.UC_MEM_FETCH_PROT => "fetch protected",
        else => "invalid",
    };
    _ = m.recordFault(address, kind);

    var pc: u32 = 0;
    _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);

    if (m.lenient) {
        // 读写未映射：自动映射所在 4KB 页（RW，内容为 0）再放行——探针框架
        // 的能力，让容量探测/预分配式访问自然通过。取指未映射无法放行。
        switch (typ) {
            c.UC_MEM_READ_UNMAPPED, c.UC_MEM_WRITE_UNMAPPED => {
                const page = address & ~@as(u64, 0xFFF);
                const rw: u32 = c.UC_PROT_READ | c.UC_PROT_WRITE;
                m.eng.memMap(page, 0x1000, rw) catch {}; // 已映射则忽略
            },
            else => {},
        }
        log.debug(@src(), "{s} @0x{x:0>8} size={d} pc=0x{x:0>8} (宽容放行)", .{
            kind, address, size, pc,
        });
        return true;
    }

    log.warn(@src(), "{s} @0x{x:0>8} size={d} value=0x{x} pc=0x{x:0>8}", .{
        kind, address, size, @as(u64, @bitCast(value)), pc,
    });

    m.eng.emuStop() catch {};
    return false;
}
