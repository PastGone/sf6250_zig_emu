//! 字节级小工具：小端读取、定长字符串处理、CRC32 等。
//!
//! 这些函数与 MTK 格式本身无关，只是解析 on-flash 数据时的通用零件。
//! 本子包内所有 on-flash 字段均为小端。

const std = @import("std");

pub fn le16(p: []const u8) u16 {
    return @as(u16, p[0]) | (@as(u16, p[1]) << 8);
}

pub fn le32(p: []const u8) u32 {
    return @as(u32, p[0]) | (@as(u32, p[1]) << 8) |
        (@as(u32, p[2]) << 16) | (@as(u32, p[3]) << 24);
}

/// 拷贝定长字符串：遇到 NUL 结束，非可打印字符替换成 '.'，并去掉尾部空格
pub fn fixedStr(dst: []u8, src: []const u8) void {
    if (dst.len == 0) return;

    const n = @min(src.len, dst.len - 1);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const c = src[i];
        if (c == 0) break;
        dst[i] = if (c >= 0x20 and c < 0x7f) c else '.';
    }
    while (i > 0 and dst[i - 1] == ' ') i -= 1;
    dst[i] = 0;
}

/// 读取 NUL 结尾字符串（不改写内容，遇到非可打印也照样收下）
pub fn readStr(dst: []u8, src: []const u8) void {
    if (dst.len == 0) return;
    const n = @min(src.len, dst.len - 1);
    var i: usize = 0;
    while (i < n and src[i] != 0) : (i += 1) dst[i] = src[i];
    dst[i] = 0;
}

/// 把 NUL 结尾的定长缓冲转成切片，便于格式化输出
pub fn cstr(buf: []const u8) []const u8 {
    return std.mem.sliceTo(buf, 0);
}

/// GFH 体里只有一部分以可读名字开头（FILE_INFO / 工程名），
/// 其余是二进制参数，这里判断一下避免出现 "...." 这种假名字。
pub fn looksLikeStr(p: []const u8) bool {
    if (p.len == 0 or p[0] < 0x20 or p[0] >= 0x7f) return false;

    var count: usize = 0;
    for (p) |c| {
        if (c == 0) break;
        if (c >= 0x20 and c < 0x7f) count += 1;
    }
    return count >= 2;
}

pub fn crc32(data: []const u8) u32 {
    var h = std.hash.crc.Crc32.init();
    h.update(data);
    return h.final();
}

/// 在 [from, to) 中找第一个不等于 needle 的字节偏移，找不到返回 to
pub fn firstNonEqual(data: []const u8, from: usize, to: usize, needle: u8) usize {
    var i = from;
    while (i < to and data[i] == needle) i += 1;
    return i;
}

pub fn lastNonEqual(data: []const u8, from: usize, to: usize, needle: u8) usize {
    var i = to;
    while (i > from and data[i - 1] == needle) i -= 1;
    return i;
}

pub fn findAscii(data: []const u8, from: usize, needle: []const u8) ?u32 {
    const hit = std.mem.indexOfPos(u8, data, from, needle) orelse return null;
    return @intCast(hit);
}

pub fn hexPreview(buf: []u8, data: []const u8) []const u8 {
    var n: usize = 0;
    for (data) |b| {
        if (n + 3 > buf.len) break;
        const part = std.fmt.bufPrint(buf[n..], "{x:0>2} ", .{b}) catch break;
        n += part.len;
    }
    if (n > 0) n -= 1;
    return buf[0..n];
}

test "fixedStr strips trailing spaces and unprintable bytes" {
    var dst: [16]u8 = undefined;

    fixedStr(&dst, "SF_BOOT   ");
    try std.testing.expectEqualStrings("SF_BOOT", cstr(&dst));

    fixedStr(&dst, "AB\x01CD");
    try std.testing.expectEqualStrings("AB.CD", cstr(&dst));
}

test "little endian reads" {
    try std.testing.expectEqual(@as(u16, 0x0102), le16(&.{ 0x02, 0x01 }));
    try std.testing.expectEqual(@as(u32, 0x10203040), le32(&.{ 0x40, 0x30, 0x20, 0x10 }));
}
