const std = @import("std");

const log = @import("log.zig");
const mtk = @import("mtk_boot_image/mtk_boot_image.zig");
const emu = @import("emu/emu.zig");

/// LCD 尺寸：真机面板参数还没拿到，先按功能机常见的 240x320 开窗口。
const lcd_width = 240;
const lcd_height = 320;

/// 待模拟的固件：原始字节 + 解析结果。
/// `image` 不拥有数据，其 `data` 指向这里的 `data`（由调用方的 arena 持有）。
const Firmware = struct {
    data: []const u8,
    image: mtk.BootImage,
};

/// 读文件并解析成 Firmware；失败时已经把原因打到日志里，返回 null。
fn loadFirmware(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ?Firmware {
    const data = mtk.loadFile(io, allocator, path) catch |err| {
        log.err(@src(), "failed to load \"{s}\" (rc={s})", .{ path, @errorName(err) });
        return null;
    };

    var fw: Firmware = .{ .data = data, .image = undefined };
    mtk.parse(data, &fw.image) catch |err| {
        log.err(@src(), "failed to parse \"{s}\" (rc={s})", .{ path, @errorName(err) });
        return null;
    };
    return fw;
}

pub fn main(init: std.process.Init) !void {
    // 镜像缓冲区与 argv 都活到进程结束，交给 Init 的 arena 即可。
    const arena = init.arena.allocator();
    const io = init.io;
    log.init(io, init.environ_map) catch |e| {
        std.debug.print("failed to init logger: {s}\n", .{@errorName(e)});
        return;
    };
    defer log.deinit();

    const args = try init.minimal.args.toSlice(arena);
    // 第一个非 --xxx 的参数才是镜像路径，其余当开关处理
    const path = firstPositional(args) orelse mtk.default_image;

    const fw = loadFirmware(io, arena, path) orelse return;

    log.info(@src(), "parsed \"{s}\"", .{path});
    mtk.dump(&fw.image);

    const lcd_only = hasArg(args, "--lcd");

    // 1. CPU：把 BL 装进 SRAM 跑一段，看它先碰到哪些外设
    var mach = try emu.Machine.init(arena);
    defer mach.deinit();
    mach.trace = hasArg(args, "--trace");
    mach.lenient = hasArg(args, "--lenient");

    mach.loadBootloader(&fw.image) catch |err| {
        log.err(@src(), "failed to load bootloader (rc={s})", .{@errorName(err)});
        return;
    };
    mach.mapFlashWindow(&fw.image) catch |err| {
        log.err(@src(), "failed to map flash window (rc={s})", .{@errorName(err)});
        return;
    };
    mach.mapExternalRam() catch |err| {
        log.err(@src(), "failed to map external RAM (rc={s})", .{@errorName(err)});
        return;
    };
    // 外设层常驻：已接线寄存器给行为，其余读 0/写丢弃并记名
    mach.mapPeriphStubs() catch |err| {
        log.err(@src(), "failed to map peripherals (rc={s})", .{@errorName(err)});
        return;
    };
    mach.run(20_000_000);

    // 2. LCD：窗口 + 一帧占位画面；带 --lcd 时进入事件循环
    var disp = try emu.Display.init("MT6250", lcd_width, lcd_height, 2);
    defer disp.deinit();

    @memset(disp.pixels, 0xff00_3000); // 占位：背光亮、无画面
    disp.present();

    while (lcd_only and disp.pump()) {
        disp.delay(8);
    }
}

fn hasArg(args: []const []const u8, flag: []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, flag)) return true;
    }
    return false;
}

fn firstPositional(args: []const []const u8) ?[]const u8 {
    for (args[1..]) |a| {
        if (!std.mem.startsWith(u8, a, "--")) return a;
    }
    return null;
}
