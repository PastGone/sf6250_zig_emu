const std = @import("std");

const log = @import("log.zig");
const mtk = @import("mtk_boot_image/mtk_boot_image.zig");

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
    const path = if (args.len > 1) args[1] else mtk.default_image;

    const fw = loadFirmware(io, arena, path) orelse return;

    log.info(@src(), "parsed \"{s}\"", .{path});
    mtk.dump(&fw.image);

    // 下一步：用 fw.image 里的 load_addr / entry_point 把 BL 装进内存再开跑。
}
