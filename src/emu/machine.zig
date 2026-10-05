//! 机器骨架：地址空间、CPU 起跑、以及“跑到未实现的外设就报出来”的探针。
//!
//! 现在的策略是**黑盒推进**：先把 BL 装进 SRAM 跑起来，凡访问到我们还没实现的
//! 地址就记下 PC 与地址并停下，逐步把外设补上。

const std = @import("std");
const log = @import("../log.zig");
const mtk = @import("../mtk_boot_image/mtk_boot_image.zig");
const uc = @import("unicorn.zig");
const c = @import("unicorn_c.zig").c;

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

    /// 外设寄存器：MTK 基带常见落在这两段，具体分布待实测
    pub const apb_base = 0x8000_0000;
    pub const apb_size = 0x1000_0000;
    pub const ahb_base = 0xa000_0000;
    pub const ahb_size = 0x1000_0000;
};

const max_faults = 32;

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

    /// 去重后的未映射访问地址（用来反推外设分布）
    fault_addrs: [max_faults]u64 = @splat(0),
    fault_count: usize = 0,
    fault_kinds: [max_faults][:0]const u8 = undefined,

    pub fn init(allocator: std.mem.Allocator) !*Machine {
        // ARM7EJ-S 是 ARMv5TEJ，Unicorn 没有该型号，用同为 ARMv5TEJ 的 ARM926 近似。
        // MTK 的 BL 是 Thumb 代码，因此以 THUMB 模式起跑（不对再切回 ARM 模式）。
        const eng = try uc.Engine.open(c.UC_ARCH_ARM, c.UC_MODE_ARM926 | c.UC_MODE_THUMB);
        errdefer eng.close();

        const m = try allocator.create(Machine);
        m.* = .{ .allocator = allocator, .eng = eng };

        try m.eng.hookCode(&m.hook_code, onCode, m);
        try m.eng.hookMemInvalid(&m.hook_mem, onMemInvalid, m);
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

    /// 把外设窗口整段挂成 MMIO 桩：读回 0、写丢弃，但把地址记下来。
    /// 这是“黑盒推进”的抓手——先让固件跑起来，再按它真正访问的寄存器逐个实现。
    pub fn mapPeriphStubs(self: *Machine) !void {
        try self.eng.mmioMap(map.ahb_base, map.ahb_size, onMmioRead, self, onMmioWrite, self);
        try self.eng.mmioMap(map.apb_base, map.apb_size, onMmioRead, self, onMmioWrite, self);
        log.info(@src(), "外设桩: 0x{x:0>8}..0x{x:0>8}, 0x{x:0>8}..0x{x:0>8}（读 0 / 写丢弃）", .{
            map.ahb_base, map.ahb_base + map.ahb_size,
            map.apb_base, map.apb_base + map.apb_size,
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

        log.info(@src(), "执行 {d} 条指令", .{self.instrs});
        self.reportFaults();
    }

    pub fn readPc(self: *const Machine) !u32 {
        var v: u32 = 0;
        try self.eng.regRead(c.UC_ARM_REG_PC, &v);
        return v;
    }

    /// 记下地址；返回 true 表示这是第一次见到
    fn recordFault(self: *Machine, addr: u64, kind: [:0]const u8) bool {
        for (0..self.fault_count) |i| {
            if (self.fault_addrs[i] == addr) return false;
        }
        if (self.fault_count >= max_faults) return false;
        self.fault_addrs[self.fault_count] = addr;
        self.fault_kinds[self.fault_count] = kind;
        self.fault_count += 1;
        return true;
    }

    fn reportFaults(self: *const Machine) void {
        for (0..self.fault_count) |i| {
            log.info(@src(), "  未实现访问 #{d}: {s} @0x{x:0>8}", .{
                i, self.fault_kinds[i], self.fault_addrs[i],
            });
        }
    }
};

fn onMmioRead(_: ?*c.uc_engine, offset: u64, size: c_uint, user: ?*anyopaque) callconv(.c) u64 {
    const m: *Machine = @ptrCast(@alignCast(user));
    const addr = map.ahb_base + offset;
    if (m.recordFault(addr, "read")) {
        log.info(@src(), "  外设桩读 @0x{x:0>8} size={d} -> 0", .{ addr, size });
    }
    return 0;
}

fn onMmioWrite(_: ?*c.uc_engine, offset: u64, size: c_uint, value: u64, user: ?*anyopaque) callconv(.c) void {
    const m: *Machine = @ptrCast(@alignCast(user));
    const addr = map.ahb_base + offset;
    if (m.recordFault(addr, "write")) {
        log.info(@src(), "  外设桩写 @0x{x:0>8} size={d} value=0x{x}", .{ addr, size, value });
    }
}

fn onCode(_: ?*c.uc_engine, address: u64, size: u32, user: ?*anyopaque) callconv(.c) void {
    const m: *Machine = @ptrCast(@alignCast(user));
    m.instrs += 1;
    if (m.trace) {
        log.debug(@src(), "pc=0x{x:0>8} size={d}", .{ address, size });
    }
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
