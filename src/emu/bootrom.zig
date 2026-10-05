//! BootROM 仿真：模拟器扮演片上 mask ROM 的那部分行为。
//!
//! - `setupBootromContext`：合成 BL 交接的共享数据区（TLV/BRLYT 副本/服务表）
//! - `onBusCommand`：EMI 总线命令触发的 0x0 重映射 + BootROM RAM 函数安装
//!
//! 行为依据：docs/mt6250-wiring.md（全部有实测支撑）。

const std = @import("std");
const log = @import("../log.zig");
const uc = @import("unicorn.zig");
const machine = @import("machine.zig");
const Machine = machine.Machine;
const map = machine.map;

// BootROM 交接上下文（模拟器扮演 BootROM 合成，见 docs/mt6250-wiring.md）
// 地址选在 0x70041000+：BL 的 BSS 清理范围全部止于 0x70040000 以下
pub const ctx_base: u32 = 0x7004_1000;
pub const svc_table: u32 = 0x7004_2000;
pub const svc_code: u32 = 0x7004_2100;

/// 合成 BootROM 共享数据区 + 服务表（模拟器扮演 BootROM 的部分）。
/// 布局依据 IDA 反编译：
///   - [ctx+0x8A8]   bit1 → sub_70008266 的模式标志（v1 填 0 走默认路径）
///   - [ctx+0x8DC]   服务表指针（init_dispatch 注册进 0x7000a114）
///   - [ctx+0x28]    TLV 总大小（service_call_dispatch 的遍历上界）
///   - [ctx+0x00]    TLV 首记录：0x6b422101（TLV_SIZE_RECORD）+ 4，终止符 0x6820d104
/// 服务表 +0x00/+0x08/+0x18/+0x34 → 四个服务，先实现为「返回 0」，
/// 参数通过 onCode 的 svc 日志观察后逐步充实。
pub fn setupBootromContext(self: *Machine, image: []const u8) !void {

    // TLV：首记录 0x6b422101 + 长度 4，终止符 0x6820d104
    try self.eng.memWrite(ctx_base, &.{ 0x01, 0x21, 0x42, 0x6b });
    try self.eng.memWrite(ctx_base + 4, &.{ 4, 0, 0, 0 });
    try self.eng.memWrite(ctx_base + 8, &.{ 0x04, 0xd1, 0x20, 0x68 });
    // [ctx+0x28] = TLV 总大小
    try self.eng.memWrite(ctx_base + 0x28, &.{ 0x0c, 0, 0, 0 });
    // [ctx+0x8DC] = 服务表指针
    try self.eng.memWrite(ctx_base + 0x8DC, &.{
        @truncate(svc_table),
        @truncate(svc_table >> 8),
        @truncate(svc_table >> 16),
        @truncate(svc_table >> 24),
    });
    // 服务表：+0x00/+0x08/+0x18/+0x34 → 四个服务函数
    const slots = [_]u32{ 0x00, 0x08, 0x18, 0x34 };
    for (slots, 0..) |off, i| {
        const a = svc_table + off;
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
        try self.eng.memWrite(ctx_base + 0x208, image[0x200..][0..0x208]);
    }
    log.info(@src(), "BootROM 上下文: ctx=0x{x:0>8} 服务表=0x{x:0>8} 服务代码=0x{x:0>8}", .{ ctx_base, svc_table, svc_code });
}

/// 0xA01800A0（EMI/总线命令）的写副作用：首次总线命令 = EMI 已配置完毕，
/// 0x0 的 NOR boot 视图重映射为 8MB RAM，并在 0x0 装一个 BootROM RAM 函数
/// （ARM: mov r0,#0; bx lr）——BL 重映射后会跳到 0x0 调用它。
/// 依据：docs/mt6250-wiring.md「BootROM 安装的 RAM 函数」一节（实测行为）。
pub fn onBusCommand(self: *Machine) void {
    self.remaped_low_ram = true;
    self.eng.memUnmap(map.boot_view_base, map.boot_view_size) catch {};
    self.eng.memMap(map.boot_view_base, map.boot_view_ram_size, uc.Perm.combine(&.{
        .read, .write, .exec,
    })) catch {};
    self.eng.memWrite(map.boot_view_base, &.{
        0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr
    }) catch {};
    log.info(@src(), "  EMI 重映射: 0x{x:0>8} NOR 视图 → {d}MB 可写 RAM + BootROM RAM 函数", .{
        map.boot_view_base, map.boot_view_ram_size >> 20,
    });
}
