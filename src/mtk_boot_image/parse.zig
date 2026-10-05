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
    out.boot = fmt.BootHeader.read(buf);
    if (!out.boot.isValid()) return ParseError.BadBoot;

    // 官方期望（mtk_image.c verify_gen_header）：version == 1 且 size == 0x200
    if (out.boot.version != 1 or out.boot.size != 0x200)
        out.checks.boot_header_odd = true;

    // 2. BRLYT 布局头 + region 表
    //    位置自描述（mtk_image.c: bh = ptr + gbh->size）：按 boot.size 定位，
    //    偏离期望偏移时先探测 boot.size 处是否真有 BRLYT，否则回退 0x200 并告警。
    var brlyt_at: usize = fmt.brlyt_offset;
    if (out.boot.size != fmt.brlyt_offset) {
        out.checks.brlyt_offset_moved = true;
        if (@as(usize, out.boot.size) + fmt.brlyt_min_size <= buf.len and
            std.mem.eql(u8, buf[out.boot.size..][0..fmt.brlyt_name.len], fmt.brlyt_name))
        {
            brlyt_at = out.boot.size;
        }
    }

    out.brlyt = fmt.BromLayout.read(buf[brlyt_at..]);
    if (!out.brlyt.isValid()) return ParseError.BadBrlyt;
    out.brlyt_region_count = out.brlyt.usedRegions();
    out.brlyt_offset = @intCast(brlyt_at);

    // 媒体槽位：任一槽位 type 命中官方枚举即取其 flash 编号（后续用于
    // 各镜像 FILE_INFO.flash_type 的交叉核对）
    for (out.brlyt.region) |rg| {
        if (rg.magic != fmt.brlyt_magic) continue;
        if (fmt.brlytMediaFlash(rg.type)) |flash| {
            out.media_flash = flash;
            break;
        }
    }
    if (out.media_flash == null) out.checks.brlyt_no_media_type = true;

    // 副本对账：官方生成器令 header_size_2/total_size_2 与正本相等
    if (out.brlyt.region[0].magic == fmt.brlyt_magic and
        (out.brlyt.region[0].start != out.brlyt.header_size or
            out.brlyt.region[0].end_or_size != out.brlyt.total_size))
    {
        out.checks.brlyt_copy_mismatch = true;
    }

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

    // 官方：BRLYT.header_size 是首个 GFH 链（第一个镜像）的起点
    if (out.brlyt.header_size != 0) {
        var found = false;
        for (out.image[0..out.image_count]) |im| {
            if (im.offset == out.brlyt.header_size) {
                found = true;
                break;
            }
        }
        if (!found) out.checks.first_image_mismatch = true;
    }

    // 5. 剩余空间（镜像表之后的区域）分析
    image.analyzeTail(out);
}
