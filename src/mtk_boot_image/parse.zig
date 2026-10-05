//! 解析入口：把内存中的镜像缓冲区解成 `BootImage`。

const std = @import("std");
const Io = std.Io;

const fmt = @import("format.zig");
const image = @import("image.zig");

pub const ParseError = error{
    TooSmall,
    BadBoot,
    BadBrlyt,
    OutOfMemory,
    Io,
};

/// 把整个文件读进一块由 allocator 分配的缓冲区
pub fn loadFile(io: Io, allocator: std.mem.Allocator, path: []const u8) ParseError![]u8 {
    const file = Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only }) catch {
        return ParseError.Io;
    };
    defer file.close(io);

    const len = file.length(io) catch return ParseError.Io;
    const buf = allocator.alloc(u8, @intCast(len)) catch return ParseError.OutOfMemory;

    const n = file.readPositionalAll(io, buf, 0) catch {
        allocator.free(buf);
        return ParseError.Io;
    };
    if (n != buf.len) {
        allocator.free(buf);
        return ParseError.Io;
    }
    return buf;
}

/// 解析内存中的镜像。out.data 会指向 buf，不复制数据。
pub fn parse(buf: []const u8, out: *image.BootImage) ParseError!void {
    out.* = .{};

    if (buf.len < fmt.brlyt_offset + fmt.brlyt_min_size)
        return ParseError.TooSmall;

    out.data = buf;

    // 1. 设备头
    out.boot = fmt.GenBootHeader.read(buf);
    if (!out.boot.isValid()) return ParseError.BadBoot;

    // 2. BRLYT 布局头 + region 表
    out.brlyt = fmt.BromLayoutHeader.read(buf[fmt.brlyt_offset..]);
    if (!out.brlyt.isValid()) return ParseError.BadBrlyt;
    out.brlyt_region_count = out.brlyt.usedRegions();

    // 3. BRLYT 指出的镜像（memory_view 槽位不是文件内偏移）
    for (out.brlyt.region) |rg| {
        if (rg.magic != fmt.brlyt_magic) continue;
        if (rg.kind() != .file_offset) continue;
        _ = image.imageAdd(out, rg.start);
    }
    out.brlyt_image_count = out.image_count;
    // BRLYT 阶段的计数会污染扫描统计，这里清零，让 scan.* 只反映第 4 步。
    out.scan = .{};

    // 4. 扫描补齐剩余的镜像
    image.imageScanAll(out);

    // 5. 剩余空间（镜像表之后的区域）分析
    image.analyzeTail(out);
}
