//! 机器骨架：地址空间、CPU 起跑、装载与执行。
//!
//! 分工（拆分见 docs/REFACTOR.md）：
//! - `machine.zig`  地址空间 + Machine 结构 + init/装载/run + 故障表
//! - `periph.zig`   外设接线（MMIO 读写 + SF/RTC 等设备模型）
//! - `diag.zig`     宿主侧诊断钩子（轨迹/断点/写监视/非法访问）
//! - `bootrom.zig`  BootROM 仿真（上下文合成 + EMI 重映射）

const std = @import("std");
const log = @import("../log.zig");
const mtk = @import("../mtk_boot_image/mtk_boot_image.zig");
const uc = @import("unicorn.zig");
const c = uc.c;
const periph = @import("periph.zig");
const diag = @import("diag.zig");
const bootrom = @import("bootrom.zig");

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

    regions: [2]periph.RegionCtx = undefined,
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

        try m.eng.hookCode(&m.hook_code, diag.onCode, m);
        try m.eng.hookMemInvalid(&m.hook_mem, diag.onMemInvalid, m);
        // 监视 BL 回调表区的写入（诊断：谁注册了/没人注册）
        try m.eng.hookMem(&m.hook_tblwr, c.UC_HOOK_MEM_WRITE, 0x7000A100, 0x7000A1FF, diag.onTblWrite, m);
        // 监视低 RAM（0x0~0x10000）写入：内核 RAM 函数安装区
        try m.eng.hookMem(&m.hook_lowram, c.UC_HOOK_MEM_WRITE, 0x0, 0xFFFF, diag.onLowRamWrite, m);
        // 监视服务表+服务代码写入：谁改写了我们登记的服务指针/代码
        try m.eng.hookMem(&m.hook_svcwr, c.UC_HOOK_MEM_WRITE, bootrom.svc_table, bootrom.svc_code + 0x20, diag.onSvcTableWrite, m);
        // 监视 init_dispatch 代码区写入：确认是否有代码被运行时改写
        try m.eng.hookMem(&m.hook_lowram, c.UC_HOOK_MEM_WRITE, 0x7000_82E0, 0x7000_8340, diag.onLowRamWrite, m);
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

    /// 外设窗口挂成 MMIO：已接线的寄存器按 docs/mt6250-wiring.md 给行为，
    /// 其余读 0/写丢弃并记名——这是「黑盒推进」的抓手。
    pub fn mapPeriphStubs(self: *Machine) !void {
        self.regions[0] = .{ .machine = self, .base = map.ahb_base };
        self.regions[1] = .{ .machine = self, .base = map.apb_base };
        try self.eng.mmioMap(map.ahb_base, map.ahb_size, periph.onMmioRead, &self.regions[0], periph.onMmioWrite, &self.regions[0]);
        try self.eng.mmioMap(map.apb_base, map.apb_size, periph.onMmioRead, &self.regions[1], periph.onMmioWrite, &self.regions[1]);
        log.info(@src(), "外设: 0x{x:0>8}..0x{x:0>8}, 0x{x:0>8}..0x{x:0>8}（{d} 个区块已接线，其余读 0/写丢弃）", .{
            map.ahb_base,             map.ahb_base + map.ahb_size,
            map.apb_base,             map.apb_base + map.apb_size,
            periph.known_regions.len,
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
        try bootrom.setupBootromContext(self, img.data);
        const ctx: u32 = bootrom.ctx_base;
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
    pub fn dumpExecHist(self: *const Machine) void {
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
    pub fn recordFault(self: *Machine, addr: u64, kind: [:0]const u8) bool {
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
