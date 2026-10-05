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
    pub const boot_view_size = 0x100_0000;
    /// EMI 重映射后 0x0 变成的 RAM 大小（run761 地图：0x0 = 8MB 系统 RAM）
    pub const boot_view_ram_size = 0x80_0000;

    /// 片内 SRAM：BL 的 load_addr 0x70008000 就落在这里（已由镜像确认）
    pub const sram_base = 0x7000_0000;
    pub const sram_size = 0x0020_0000; // 2MB（run761 写 1MB，实测执行冲到 1MB 顶，再扩试探）

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

// BootROM 交接上下文（模拟器扮演 BootROM 合成，见 docs/mt6250-wiring.md）
// 地址选在 0x70041000+：BL 的 BSS 清理范围全部止于 0x70040000 以下
const bootrom_ctx_base: u32 = 0x7004_1000;
const bootrom_svc_table: u32 = 0x7004_2000;
const bootrom_svc_code: u32 = 0x7004_2100;

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
    hook_lowram: c.uc_hook = 0,
    lowram_wr: u32 = 0,
    hook_svcwr: c.uc_hook = 0,
    svc_wr: u32 = 0,
    bp_logged: bool = false,
    bp_bss: bool = false,
    bp_brlyt: bool = false,
    bss_calls: u32 = 0,
    bss_last_r0: u32 = 0,
    bss_last_r1: u32 = 0,
    remaped_low_ram: bool = false,
    last_r10: u32 = 0,
    wild_jumped: bool = false,
    stack_exec: bool = false,
    flash_entered: bool = false,
    /// 进入 BL2 入口 / init_dispatch 的次数（判断「阶段交接」还是「重启循环」）
    bl2_entries: u32 = 0,
    init_entries: u32 = 0,

    regions: [2]RegionCtx = undefined,
    /// UART1/2/3 的行缓冲（固件串口输出，按 \n / \r / 满行刷新）
    uart_line: [3][121]u8 = undefined,
    uart_len: [3]usize = @splat(0),
    /// 0xA0050090 时钟切换命令寄存器的当前命令（写后状态位按命令应答）
    clk_cmd: u32 = 0,

    // ── 串行 flash 控制器（SF，0xA0140000）──────────────────────────────
    // 依据：BL2 的 flash 识别流程（XIP 0x1000a8b4 → 0x1000d968 → 0x1000d890）。
    // 固件把「命令字节」写进数据窗口 0xA0140800，长度写 +0x10，**读回字节数**写
    // +0x14（不是命令！0x1000d8c2 存的是第 4 个参数），随后写 0xA0140000
    // bit2|bit3 启动，轮询 bit1=完成、bit0=空闲。
    /// +0x00 控制/状态（bit2|bit3 同时置位 = 命令完成，bit0 = 忙）
    sfc_ctrl: u32 = 0,
    /// +0x04 状态位（bit0 参与固件对 +0x00 bit4 的判定）
    sfc_flags: u32 = 0,
    /// +0x10 写进数据窗口的命令字节数（命令 + 地址）
    sfc_len: u32 = 0,
    /// +0x14 命令后要读回的响应字节数
    sfc_mode: u32 = 0,
    /// +0x800 起 4 字节数据窗口：[0..len) = 命令/地址，[len..) = 响应
    sfc_fifo: [4]u8 = @splat(0),
    /// 已执行的 SF 命令数（日志限流用）
    sfc_cmds_run: u32 = 0,
    /// 各命令字节的累计次数（run 结束打印，看 BL2 到底在干什么）
    sfc_op_counts: [256]u32 = @splat(0),

    // ── RTC（0xA0710000）────────────────────────────────────────────────
    // 依据：《MT6250 数据手册》RTC 章 + BL 0x70008f00 的初始化序列。
    // 寄存器文件语义 = 写入值读回（固件每写一个值就轮询读回比对）。
    /// RTC 寄存器堆（0x00~0xFF，16 位寄存器，冷启动全 0）
    rtc_regs: [0x100]u8 = @splat(0),

    /// 末尾执行轨迹（诊断用：看停机/空转前在跑什么）
    exec_hist: [1024]u32 = @splat(0),
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
        // 监视低 RAM（0x0~0x10000）写入：内核 RAM 函数安装区
        try m.eng.hookMem(&m.hook_lowram, c.UC_HOOK_MEM_WRITE, 0x0, 0xFFFF, onLowRamWrite, m);
        // 监视服务表+服务代码写入：谁改写了我们登记的服务指针/代码
        try m.eng.hookMem(&m.hook_svcwr, c.UC_HOOK_MEM_WRITE, bootrom_svc_table, bootrom_svc_code + 0x20, onSvcTableWrite, m);
        // 监视 init_dispatch 代码区写入：确认是否有代码被运行时改写
        try m.eng.hookMem(&m.hook_lowram, c.UC_HOOK_MEM_WRITE, 0x7000_82E0, 0x7000_8340, onLowRamWrite, m);
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

    /// EMI 重映射后 0x0 变成的 RAM 大小（run761 地图：0x0 = 8MB 系统 RAM）
    pub const boot_view_ram_size = 0x80_0000;
    /// 外部 RAM（0x82000000 起 64MB）：BL 堆与共享数据区、MAUI 重定位目标
    /// （run761 实测 MAUI 在 0x84Exxxxx 执行）——见 docs/mt6250-wiring.md 内存图
    pub fn mapExternalRam(self: *Machine) !void {
        const base = 0x8200_0000;
        const size = 0x400_0000;
        try self.eng.memMap(base, size, uc.Perm.combine(&.{ .read, .write, .exec }));
        log.info(@src(), "外部 RAM: 0x{x:0>8}..0x{x:0>8} ({d} MB, RWX)", .{ base, base + size, size >> 20 });
    }

    /// 合成 BootROM 共享数据区 + 服务表（模拟器扮演 BootROM 的部分）。
    /// 布局依据 IDA 反编译：
    ///   - [ctx+0x8A8]   bit1 → sub_70008266 的模式标志（v1 填 0 走默认路径）
    ///   - [ctx+0x8DC]   服务表指针（init_dispatch 注册进 0x7000a114）
    ///   - [ctx+0x28]    TLV 总大小（service_call_dispatch 的遍历上界）
    ///   - [ctx+0x00]    TLV 首记录：0x6b422101（TLV_SIZE_RECORD）+ 4，终止符 0x6820d104
    /// 服务表 +0x00/+0x08/+0x18/+0x34 → 四个服务，先实现为「返回 0」，
    /// 参数通过 onCode 的 svc 日志观察后逐步充实。
    fn setupBootromContext(self: *Machine, image: []const u8) !void {
        const ctx: u32 = bootrom_ctx_base;
        const svc: u32 = bootrom_svc_table;
        const svc_code: u32 = bootrom_svc_code;

        // TLV：首记录 0x6b422101 + 长度 4，终止符 0x6820d104
        try self.eng.memWrite(ctx, &.{ 0x01, 0x21, 0x42, 0x6b });
        try self.eng.memWrite(ctx + 4, &.{ 4, 0, 0, 0 });
        try self.eng.memWrite(ctx + 8, &.{ 0x04, 0xd1, 0x20, 0x68 });
        // [ctx+0x28] = TLV 总大小
        try self.eng.memWrite(ctx + 0x28, &.{ 0x0c, 0, 0, 0 });
        // [ctx+0x8DC] = 服务表指针
        try self.eng.memWrite(ctx + 0x8DC, &.{
            @truncate(bootrom_svc_table),
            @truncate(bootrom_svc_table >> 8),
            @truncate(bootrom_svc_table >> 16),
            @truncate(bootrom_svc_table >> 24),
        });
        // 服务表：+0x00/+0x08/+0x18/+0x34 → 四个服务函数
        const slots = [_]u32{ 0x00, 0x08, 0x18, 0x34 };
        for (slots, 0..) |off, i| {
            const a = svc + off;
            // 函数指针必须带 Thumb 位（bit0=1），否则 blx 切到 ARM 模式
            // 执行 Thumb 桩字节 → 条件跳过 → 滑进零区
            const fnptr = svc_code + @as(u32, @intCast(i)) * 4 + 1;
            try self.eng.memWrite(a, &.{
                @truncate(fnptr),
                @truncate(fnptr >> 8),
                @truncate(fnptr >> 16),
                @truncate(fnptr >> 24),
            });
        }
        // 服务函数体：movs r0,#0; bx lr（Thumb: 00 20 70 47）
        for (0..4) |i| {
            try self.eng.memWrite(svc_code + @as(u32, @intCast(i)) * 4, &.{ 0x00, 0x20, 0x70, 0x47 });
        }
        // BRLYT 表副本 @ctx+0x208：BL 校验 strcmp(r7,"BRLYT") 后按 20 字节槽
        // 扫描 index==2 的 ExtBL 槽位并调用装载器（0x70008e78）
        if (image.len >= 0x200 + 0x208) {
            try self.eng.memWrite(ctx + 0x208, image[0x200..][0..0x208]);
        }
        log.info(@src(), "BootROM 上下文: ctx=0x{x:0>8} 服务表=0x{x:0>8} 服务代码=0x{x:0>8}", .{ ctx, svc, svc_code });
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
        // 整个镜像区（GFH 头链 + 载荷）一起装载——真机 BootROM 拷全镜像，
        // BL 的记录查找器（sub_70008C10 → sub_700095d8）会在 SRAM 的
        // 头副本里按 GFH type 找 FILE_INFO/ANTI_CLONE 等记录
        const whole = img.data[bl.offset..][0..bl.total_size];
        try self.eng.memWrite(bl.load_addr, whole);
        self.img = img;

        const pc: u32 = bl.load_addr +% bl.jump_offset;
        const sp: u32 = map.sram_base + map.sram_size - 0x100;

        try self.eng.regWrite(c.UC_ARM_REG_SP, &sp);
        try self.eng.regWrite(c.UC_ARM_REG_PC, &pc);
        // BootROM 交接：r10 = 共享数据区（BL 全程不赋值，只作为入参使用）。
        // 结构由 BootROM 预先备好，这里合成最小版本（见 setupBootromContext）。
        try self.setupBootromContext(img.data);
        const ctx: u32 = bootrom_ctx_base;
        // 入口指令流（实测）：mrs/orr/msr 关中断 → mov r10, r4 → blx 初始化链。
        // BootROM 把共享数据指针放在 r4，BL 自己拷进 r10。
        try self.eng.regWrite(c.UC_ARM_REG_R4, &ctx);
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

        // until 不能用 0：BL 会合法跳到 0x0 调用 BootROM 安装的 RAM 函数，
        // until=0 会在执行前拦截它
        self.eng.emuStart(begin, 0xFFFF_FFF0, 0, budget) catch |err| {
            log.warn(@src(), "CPU 停止: {s} ({d} 条指令), pc=0x{x:0>8}", .{
                uc.Engine.strerror(err), self.instrs, self.readPc() catch 0,
            });
        };

        log.info(@src(), "执行 {d} 条指令, 最终 pc=0x{x:0>8}", .{ self.instrs, self.readPc() catch 0 });
        {
            var cpsr: u32 = 0;
            var sp: u32 = 0;
            _ = self.eng.regRead(c.UC_ARM_REG_CPSR, &cpsr) catch {};
            _ = self.eng.regRead(c.UC_ARM_REG_SP, &sp) catch {};
            log.info(@src(), "停止现场: cpsr=0x{x:0>8} (T={d}, mode=0x{x}) sp=0x{x:0>8}", .{
                cpsr, (cpsr >> 5) & 1, cpsr & 0x1F, sp,
            });
            var mem: [0x80]u8 = undefined;
            if (c.uc_mem_read(self.eng.handle, 0x7000_82C0, &mem, mem.len) == c.UC_ERR_OK) {
                var hx: [3 * 0x80]u8 = undefined;
                var n: usize = 0;
                for (mem) |b| {
                    const p = std.fmt.bufPrint(hx[n..], "{x:0>2} ", .{b}) catch break;
                    n += p.len;
                }
                log.info(@src(), "STOPMEM 0x700082c0: {s}", .{hx[0..n]});
            }
            // 运行时低 SRAM：BL 会把 ExtBL 装载器/拷贝来的例程放在 0x70004000 区，
            // 停机时 dump 出来才能离线反汇编（静态镜像里没有这段）
            self.dumpMem(0x7000_4B80);
            self.dumpMem(0x7000_4D00);
        }
        self.dumpExecHist();
        self.reportFaults();
        self.reportSfcOps();
    }

    /// SF 命令直方图：BL2 阶段靠它判断「在读还是在写、是不是写-校验死循环」
    fn reportSfcOps(self: *const Machine) void {
        var total: u64 = 0;
        for (self.sfc_op_counts) |n| total += n;
        if (total == 0) return;
        var buf: [512]u8 = undefined;
        var len: usize = 0;
        for (self.sfc_op_counts, 0..) |n, op| {
            if (n == 0) continue;
            const p = std.fmt.bufPrint(buf[len..], "{x:0>2}:{d} ", .{ op, n }) catch break;
            len += p.len;
        }
        log.info(@src(), "SF 命令直方图（共 {d} 条）: {s}", .{ total, buf[0..len] });
    }

    pub fn readPc(self: *const Machine) !u32 {
        var v: u32 = 0;
        try self.eng.regRead(c.UC_ARM_REG_PC, &v);
        return v;
    }

    /// 运行时内存 hex dump（离线反汇编用）：0x100 字节一段
    fn dumpMem(self: *const Machine, base: u32) void {
        var mem: [0x100]u8 = undefined;
        if (c.uc_mem_read(self.eng.handle, base, &mem, mem.len) != c.UC_ERR_OK) return;
        var hx: [3 * 0x100]u8 = undefined;
        var n: usize = 0;
        for (mem) |b| {
            const p = std.fmt.bufPrint(hx[n..], "{x:0>2}", .{b}) catch break;
            n += p.len;
        }
        log.info(@src(), "RUNTIMEMEM:{x:0>8}:{s}", .{ base, hx[0..n] });
    }

    /// 末尾执行轨迹：按时间顺序打印最近的 PC（诊断空转/停机原因）
    fn dumpExecHist(self: *const Machine) void {
        const n = @min(self.exec_hist_pos, self.exec_hist.len);
        if (n == 0) return;
        var buf: [1024 * 10]u8 = undefined;
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
        // 首次总线命令 = EMI 已配置完毕：0x0 的 NOR boot 视图重映射为 RAM
        // （真机行为：GFH 早期从 NOR 视图读，之后 0x0 变成可写 RAM，
        //  BL 在 0x0~0x8E0 现场构建共享数据表，见 wiring 文档卡点一节）
        if (!self.remaped_low_ram) {
            self.remaped_low_ram = true;
            self.eng.memUnmap(map.boot_view_base, map.boot_view_size) catch {};
            self.eng.memMap(map.boot_view_base, map.boot_view_ram_size, uc.Perm.combine(&.{
                .read, .write, .exec,
            })) catch {};
            // BootROM 安装的 RAM 函数（ARM: mov r0,#0; bx lr）——BL 重映射后
            // 会跳到 0x0 调用它（实机行为：BootROM 在低 RAM 装内核函数）
            self.eng.memWrite(map.boot_view_base, &.{
                0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
                0x1E, 0xFF, 0x2F, 0xE1, // bx lr
            }) catch {};
            log.info(@src(), "  EMI 重映射: 0x{x:0>8} NOR 视图 → {d}MB 可写 RAM + BootROM RAM 函数", .{
                map.boot_view_base, map.boot_view_ram_size >> 20,
            });
        }
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
    if (address == 0x70009b20) {
        m.bss_calls += 1;
        var r0: u32 = 0;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        std.debug.print("[BSS #{d}] 0x{x:0>8} -> 0x{x:0>8} lr=0x{x:0>8}\n", .{ m.bss_calls, r0, r1, lr });
        m.bss_last_r0 = r0;
        m.bss_last_r1 = r1;
    }
    // 服务函数调用日志（BootROM 服务：0x70042100 + i*4）
    if (address >= 0x7004_2100 and address < 0x7004_2110) {
        var a0: u32 = 0;
        var a1r: u32 = 0;
        var a2r: u32 = 0;
        var a3r: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &a0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &a1r);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &a2r);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R3, &a3r);
        log.info(@src(), "  [BootROM服务] pc=0x{x:0>8} r0=0x{x:0>8} r1=0x{x:0>8} r2=0x{x:0>8} r3=0x{x:0>8}", .{ address, a0, a1r, a2r, a3r });
        if (a0 >= 0x7000_0000 and a0 < 0x7004_0000) {
            var buf: [32]u8 = undefined;
            if (c.uc_mem_read(engine, a0, &buf, buf.len) == c.UC_ERR_OK) {
                var hx: [3 * 32]u8 = undefined;
                var n: usize = 0;
                for (buf) |b| {
                    const p = std.fmt.bufPrint(hx[n..], "{x:0>2} ", .{b}) catch break;
                    n += p.len;
                }
                log.info(@src(), "  [BootROM服务] *r0 = {s}", .{hx[0..n]});
            }
        }
    }
    // r10(sl) 变化跟踪：定位它在哪里被清零/改写
    {
        var r10: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R10, &r10);
        if (r10 != m.last_r10) {
            if (m.instrs > 100000 or m.last_r10 != 0) {
                log.info(@src(), "  [r10变化] pc=0x{x:0>8} sl: 0x{x:0>8} → 0x{x:0>8} (instrs={d})", .{ address, m.last_r10, r10, m.instrs });
            }
            m.last_r10 = r10;
        }
    }
    if (m.instrs < 16) {
        var code: [8]u8 = @splat(0);
        _ = c.uc_mem_read(engine, address, &code, code.len);
        log.info(@src(), "  [入口] #{d} pc=0x{x:0>8} bytes={x:0>2}{x:0>2} {x:0>2}{x:0>2}", .{
            m.instrs, address, code[0], code[1], code[2], code[3],
        });
    }
    // 首次越界执行：PC 冲出已知代码区（>0x7000b000）时记录现场
    // 服务区之后的无人区被执行 = 滑行起点，抓第一现场
    if (address >= 0x7004_3000 and address < 0x701F_D000 and !m.stack_exec) {
        m.stack_exec = true;
        var lr: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        log.info(@src(), "  [滑行起点] pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            address, lr, sp, m.instrs,
        });
        m.dumpExecHist();
    }
    // 栈区被执行 = 返回地址/函数指针损坏，抓第一现场
    if (address >= 0x701FE000 and !m.stack_exec) {
        m.stack_exec = true;
        var lr: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        log.info(@src(), "  [栈执行] pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            address, lr, sp, m.instrs,
        });
        m.dumpExecHist();
    }
    if (address >= 0x7004_2110 and address < 0x701F_D000 and !m.wild_jumped) {
        m.wild_jumped = true;
        var lr: u32 = 0;
        var r0: u32 = 0;
        var r1r: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1r);
        log.info(@src(), "  [越界执行] pc=0x{x:0>8} lr=0x{x:0>8} r0=0x{x:0>8} r1=0x{x:0>8} (instrs={d})", .{
            address, lr, r0, r1r, m.instrs,
        });
        m.dumpExecHist();
    }
    if (address == 0x7000_844a and !m.bp_brlyt) {
        m.bp_brlyt = true;
        var r7: u32 = 0;
        var base: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R7, &r7);
        _ = c.uc_mem_read(engine, 0x7000_A0E4, &base, 4);
        var buf: [16]u8 = @splat(0);
        _ = c.uc_mem_read(engine, r7, &buf, buf.len);
        log.info(@src(), "  [BRLYT校验] 全局[0x7000a0e4]=0x{x:0>8} r7=基址+0x208=0x{x:0>8} 内容={s}", .{ base, r7, buf });
    }
    // 阶段入口：hook 报的是取指地址。Thumb 入口的 bit0 不在取指地址里，
    // 所以 0x10008061（镜像里的 Thumb 入口）实际表现为 0x10008060。
    if (address == 0x1000_8060) {
        m.bl2_entries += 1;
        if (m.bl2_entries <= 8 or m.bl2_entries % 64 == 0) {
            log.info(@src(), "★ 阶段切换: 进入 BL2 #{d} (0x10008061, 取指 0x10008060) instrs={d}", .{
                m.bl2_entries, m.instrs,
            });
        }
    }
    // 第一次在 flash/XIP 窗口执行：确认「谁在什么时候开始跑 flash 里的代码」
    if (address >= 0x1000_0000 and address < 0x1100_0000 and !m.flash_entered) {
        m.flash_entered = true;
        var lr: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        log.info(@src(), "  [flash 执行] 首次在 XIP 窗口取指 pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            address, lr, sp, m.instrs,
        });
    }
    if (address == 0x1002_0300) {
        log.info(@src(), "★ 阶段切换: 进入 MAUI (0x10020301, 取指 0x10020300)", .{});
    }
    if (address == 0x700082e0) {
        m.init_entries += 1;
        if (m.init_entries <= 8 or m.init_entries % 64 == 0) {
            log.info(@src(), "  [init_dispatch] 第 {d} 次进入 instrs={d}", .{ m.init_entries, m.instrs });
        }
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

/// 服务表写监视：抓改写服务指针的代码（前 16 次）
fn onSvcTableWrite(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    if (m.svc_wr < 16) {
        var pc: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [服务表写] pc=0x{x:0>8} lr=0x{x:0>8} -> [0x{x:0>8}] = 0x{x:0>8}", .{
            pc, lr, address, @as(u64, @bitCast(value)),
        });
    }
    m.svc_wr += 1;
    return true;
}

/// 低 RAM 写监视：EMI 重映射后谁在安装 RAM 函数（前 24 次）
fn onLowRamWrite(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    if (m.lowram_wr < 24) {
        var pc: u32 = 0;
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
        log.info(@src(), "  [低RAM写] pc=0x{x:0>8} -> [0x{x:0>8}] = 0x{x:0>8}", .{
            pc, address, @as(u64, @bitCast(value)),
        });
    }
    m.lowram_wr += 1;
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
        if (typ == c.UC_MEM_FETCH_UNMAPPED or typ == c.UC_MEM_FETCH_PROT) {
            log.info(@src(), "  [取指失败] {s} 目标=0x{x:0>8} pc=0x{x:0>8} ← 跳转指令在此", .{
                kind, address, pc,
            });
        } else {
            log.debug(@src(), "{s} @0x{x:0>8} size={d} pc=0x{x:0>8} (宽容放行)", .{
                kind, address, size, pc,
            });
        }
        return true;
    }

    log.warn(@src(), "{s} @0x{x:0>8} size={d} value=0x{x} pc=0x{x:0>8}", .{
        kind, address, size, @as(u64, @bitCast(value)), pc,
    });

    m.eng.emuStop() catch {};
    return false;
}
