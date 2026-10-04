const std = @import("std");

const log = @import("log.zig");
const mtk = @import("mtk_boot_image.zig");

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

    const data = mtk.loadFile(io, arena, path) catch |err| {
        log.err(@src(), "failed to load \"{s}\" (rc={s})", .{ path, @errorName(err) });
        return;
    };

    var img: mtk.BootImage = undefined;
    mtk.parse(data, &img) catch |err| {
        log.err(@src(), "failed to parse \"{s}\" (rc={s})", .{ path, @errorName(err) });
        return;
    };

    log.info(@src(), "parsed \"{s}\"", .{path});
    mtk.dump(&img);
}
