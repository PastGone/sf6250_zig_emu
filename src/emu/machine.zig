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

    /// RAMF0：OS 数据区（run761 内存图；就绪标志 0xF05DDF64、调度栈 0xF0424000）
    pub const ramf0_base = 0xf000_0000;
    pub const ramf0_size = 0x0080_0000;
};

const max_faults = 768;

/// 关键地址（命中即报一次）：MAUI crt0 装载器入口——参考实现 run761 用同样的
/// 地址做「RAMF0 是否被装载」的判据（见其 [loader] 探针）。
pub const landmarks = [_]u32{
    0x100c347c, 0x100c3508, 0x100c353c, 0x100c3570,
    // MAUI 早期流程地标（参考实现 run761 的说法：0x10020488 是 OS init 链入口，
    // 0x7000A800 是 crt0 拷到 SRAM 的内核入口，内核从那里 bx 过去执行）
    0x100203ac, 0x10020488, 0x7000a800, 0x10022a40,
    0x100283e0,
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
    hook_ramf0wr: c.uc_hook = 0,
    ramf0_wr: u32 = 0,
    /// 关键地址命中表（装载器/阶段入口，每个只报一次）
    landmark_hit: [landmarks.len]bool = @splat(false),
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
    /// 是否已在低 RAM（EMI 重映射后的 0x0 区）执行过拷进去的代码
    low_ram_entered: bool = false,
    /// RAMF0（0xF0000000）里第一次执行到的地址（MAUI 会把代码拷进去跑）
    ramf0_entry: u32 = 0,
    /// 是否已抓到「跳进 RAMF0 顶部零区」的第一现场
    ramf0_slide: bool = false,
    /// --ramf0-lr：诊断开关。MAUI 的 XIP 代码用静态 veneer 表（XIP 0x10078c78+）
    /// 调用 0xf0727000~0xf072c2cd 的「RAM 补丁代码」，但实测**没有任何装载器**
    /// 写过该区域（BL/BL2 里连该地址范围的字面量都没有；MAUI crt0 的段表也不含
    /// 它；运行时写监视零命中）——所以取指必然拿到 0x0000 并滑到 RAMF0 顶端。
    /// 打开后遇到该区域取指就等价于 `bx lr`（参考实现 run761 run539 也是这么
    /// 处理「RAM 区域被误执行」的），用来判断这段代码是不是必经之路。
    ramf0_lr: bool = false,
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
    // 依据：两代驱动的实测轮询序列
    //  - BL2（XIP 0x1000d890/0x1000d702）：数据窗口写命令，+0x10 写长度，
    //    +0x14 写**读回字节数**（不是命令！0x1000d8c2 存的是第 4 个参数），
    //    +0x00 写 bit2|bit3 启动，轮询 bit1=完成、bit0=空闲
    //  - MAUI（XIP 0x10859fd8/0x1085a03e，运行时拷到低 RAM 0x00000e00 跑）：
    //    +0x44 写 bit9|bit10 启动并轮询 bit13=完成，另轮询 +0x08 bit8=完成
    /// +0x00 控制/状态（bit2|bit3 同时置位 = 命令完成，bit0 = 忙）
    sfc_ctrl: u32 = 0,
    /// +0x04 状态位（bit0 参与固件对 +0x00 bit4 的判定）
    sfc_flags: u32 = 0,
    /// +0x08 状态位（bit8 = MAUI 驱动的命令完成位）
    sfc_status8: u32 = 0,
    /// +0x40 控制 bank 低半（MAUI 驱动只写不读，回读保留）
    sfc_ctrl_a: u32 = 0,
    /// +0x44 控制 bank 高半（bit9|bit10 = 命令进行中 → bit13 = 完成）
    sfc_ctrl2: u32 = 0,
    /// +0x10 写进数据窗口的命令字节数（命令 + 地址）
    sfc_len: u32 = 0,
    /// +0x14 命令后要读回的响应字节数
    sfc_mode: u32 = 0,
    /// +0x800 起数据窗口：[0..len) = 命令/地址，[len..) = 响应
    /// （MAUI 驱动会写到 +0x804，所以留 8 字节）
    sfc_fifo: [8]u8 = @splat(0),
    /// 已执行的 SF 命令数（日志限流用）
    sfc_cmds_run: u32 = 0,
    /// 各命令字节的累计次数（run 结束打印，看 BL2 到底在干什么）
    sfc_op_counts: [256]u32 = @splat(0),

    // ── 中断（IDA 反编译实证，详见 docs/mt6250-wiring.md）──────────────
    // MAUI 的 ISR 分发器 sub_10021F50：读 0xA07601A0 拿中断号 → 查 LISR 表
    // 0xF03D0310+12*irq → 调用 → 写 0xA07601A8 确认。
    //   sub_100230A0: if (v & 0x100) return -1; else return v & 0xFF;
    // 使能/屏蔽在 0xA0060040/44（置位）与 0x80/84（清位）（sub_10092F34/A4C）。
    /// 0xA07601A0：bit8=无中断，低 8 位=当前中断号
    irq_pending: i32 = -1,
    /// 0xA07601A0 的原始寄存器值（回读保留位）
    irq_status_raw: u32 = 0x100,
    /// 0xA0060000 区的中断使能/清零寄存器（低 32 位源 + 高 32 位源）
    intc_en_lo: u32 = 0,
    intc_en_hi: u32 = 0,
    /// 0xA0030000（16 位）：全局中断控制；MAUI 收尾 sub_10037A84(1) 置 0x2201
    intc_ctrl: u16 = 0,
    /// 0xA0030008（16 位）：MAUI 收尾写 0x1971
    intc_ctrl8: u16 = 0,
    /// 周期 tick：每 tick_interval 条指令置一次 pending（0 = 关闭）
    tick_interval: u64 = 0,
    next_tick: u64 = 0,
    /// tick 用的中断号（11 = OSTD/OS timer，18 = GPT，见 LISR 注册处）
    tick_irq: u8 = 11,
    /// 是否已交付过中断（诊断计数）
    irq_count: u32 = 0,
    /// 是否已打印过首次中断确认
    irq_logged: bool = false,
    /// CR 上报路径的轨迹是否已 dump（诊断）
    cr_trace_dumped: bool = false,
    /// 装载原语调用计数（诊断）
    loader_calls: u32 = 0,
    /// CPSR.I 采样跟踪（诊断：固件到底有没有开 CPU 中断）
    i_bit_last: bool = true,
    /// 采样上限（避免刷屏）
    i_bit_samples: u32 = 0,
    /// IRQ 现场：进入中断时保存，异常返回后恢复
    irq_active: bool = false,
    irq_ret: u32 = 0,
    irq_saved_regs: [16]u32 = @splat(0),
    irq_saved_cpsr: u32 = 0,

    // ── RTC（0xA0710000）────────────────────────────────────────────────
    // 依据：《MT6250 数据手册》RTC 章 + BL 0x70008f00 的初始化序列。
    // 寄存器文件语义 = 写入值读回（固件每写一个值就轮询读回比对）。
    /// RTC 寄存器堆（0x00~0xFF，16 位寄存器，冷启动全 0）
    rtc_regs: [0x100]u8 = @splat(0),

    // ── 芯片标识/启动模式寄存器（0xA0000000）────────────────────────────
    // 依据（两处固件行为 + 参考实现 run761 独立结论一致）：
    //  - MAUI 芯片识别函数 XIP 0x10033338 读 +0x00/+0x08（16 位）：
    //    +0x08 必须等于 0x625A（代码 0x6218 + 0x42，即 "6250A" = MT6250A），
    //    否则一路 branch 到 0x1003346e 比对失败 → 死循环刷
    //    "# HW=MT0000 , SW=MT625"
    //  - BL2 启动模式检查 XIP 0x1000a15c 读 +0x04 低字节：bit7=0 → 返回 0
    //    （调用点 0x100098c6 按返回值分流）
    //  - 成功路径还会把 +0x04 低字节按 "Chip SW second version: %02d" 打出来
    chip_regs: [0x10]u8 = .{
        0x50, 0x62, 0x00, 0x00, // +0x00 芯片 ID = 0x6250 (MT6250)
        0x00, 0x00, 0x00, 0x00, // +0x04 启动模式/second version = 0
        0x5A, 0x62, 0x00, 0x00, // +0x08 芯片版本 = 0x625A (MT6250A)
        0x00, 0x00, 0x00, 0x00,
    },
    // ── 传输/DMA 引擎（0xA0520000）──────────────────────────────────────
    // 依据：MAUI XIP 0x1003267a~0x100326fa 的实测序列——写参数到 +0x08、
    // 控制位到 +0x80/+0x84（bit0 启动），写长度到 +0x3C，写启动位到 +0x34，
    // 然后轮询 +0x34 的 bit31 = 传输完成。参考实现 run761 独立得到同一结论
    // （它把 0xA0530000 一带称为 “DMA 控制器”，见其 [dma-dump] 探针）。
    // 模型：寄存器文件 + 传输立即完成（读 +0x34 时 bit31 恒置位）。
    xfer_regs: [0x100]u8 = @splat(0),
    /// 传输引擎寄存器写入次数 / 是否已停止打印现场
    xfer_writes: u32 = 0,
    xfer_logged: bool = false,

    /// UART 行缓冲上一个字符是 \r（用于把 CRLF 折成一次换行）
    uart_cr: [3]bool = @splat(false),

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
        // 监视 RAMF0 写入：crt0 装载器把驱动/表段搬进来时，第一现场立刻可见
        try m.eng.hookMem(&m.hook_ramf0wr, c.UC_HOOK_MEM_WRITE, map.ramf0_base, map.ramf0_base + map.ramf0_size - 1, diag.onRamF0Write, m);
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

    /// RAMF0（0xF0000000 起 8MB）：MAUI/Nucleus 的 OS 数据区——就绪标志
    /// 0xF05DDF64/0xF05DDF40、调度器栈 0xF0424000。依据 docs/mt6250-wiring.md
    /// 内存图（run761 逐个崩溃点验证）。之前没映射时靠 --lenient 逐页兜底，
    /// 既慢又会把故障表刷满（实测 MAUI 会一路写到 0xF045xxxx）。
    pub fn mapRamF0(self: *Machine) !void {
        const base = map.ramf0_base;
        const size = map.ramf0_size;
        try self.eng.memMap(base, size, uc.Perm.combine(&.{ .read, .write, .exec }));
        log.info(@src(), "RAMF0: 0x{x:0>8}..0x{x:0>8} ({d} MB, RWX)", .{ base, base + size, size >> 20 });
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
            // 停机 PC 所在页：卡点常常是「运行时拷进 RAM 的代码」，只有现场 dump 才有
            const pc = self.readPc() catch 0;
            self.dumpMem(pc & ~@as(u32, 0xFF));
            // RAMF0 入口页：MAUI 拷进去执行的代码（静态镜像里也没有）
            if (self.ramf0_entry != 0) self.dumpMem(self.ramf0_entry & ~@as(u32, 0xFF));
            // 低 RAM 0x0 起始页：ARM 异常向量表装在这里（0x18 = IRQ 入口）
            self.dumpMem(0x0000_0000);
            // BootROM/SRAM 蹦床区：MAUI crt0 会从 flash 拷一段到这里（含 IRQ 入口 0x700096B0）
            self.dumpMem(0x7000_9600);
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
