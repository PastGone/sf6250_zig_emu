//! BootROM 布局头（BRLYT，位于文件偏移 0x200）。
//!
//! 说明哪些字段来自官方 U-Boot 的 `docs/mtk_image.h.txt`、哪些是本仓库按实测
//! 反推的（反推部分都标了 `推测`），避免把猜测当成规范。

const std = @import("std");
const bytes = @import("bytes.zig");
const le32 = bytes.le32;
const fixedStr = bytes.fixedStr;
const cstr = bytes.cstr;

/// BRLYT 在文件中的位置
pub const offset = 0x200;
/// on-flash 头大小（逐字段读取，不用 @sizeOf 以免受对齐影响）
pub const min_size = 0xb4;

pub const brlyt_name = "BRLYT";
pub const brlyt_magic = 0x42424242;
pub const brlyt_region_size = 20;

/// U-Boot 的 `brom_layout_header` 只描述**一组** magic/type/header_size_2/
/// total_size_2/unused。本镜像在该组之后紧跟着又出现若干同宽度的槽位，
/// 第一个槽位之后还有 7 个，其中 4 个 magic 有效。这里因此按 8 槽位处理：
/// head.region[0] 就是官方那组，region[1..8] 是实测到的额外槽位（推测）。
pub const brlyt_max_regions = 8;

/// MT6250 内部 SRAM 窗口；BL 的 load_addr 0x70008000 就落在其中。
pub const sram_window_base = 0x7000_0000;
pub const sram_window_mask = 0xf000_0000;

/// 高 16 位为 0xfffe 的槽位不作为文件偏移使用（实测其 header_size_2 是 SRAM 地址）。
pub const brlyt_index_reserved = 0xfffe;

pub const RegionKind = enum {
    empty,
    /// start 是文件偏移，size = end - start
    file_offset,
    /// start 是内存/加载视图地址（推测），size 字段直接就是长度
    memory_view,
};

pub const BromLayoutRegion = struct {
    magic: u32 = 0,
    @"type": u32 = 0,
    /// on-flash 字段名 header_size_2
    start: u32 = 0,
    /// on-flash 字段名 total_size_2
    end_or_size: u32 = 0,
    unused: u32 = 0,

    pub fn kind(self: *const BromLayoutRegion) RegionKind {
        if (self.magic != brlyt_magic) return .empty;
        if (brlytRegionIndex(self.@"type") == brlyt_index_reserved) return .memory_view;
        if (self.start & sram_window_mask == sram_window_base) return .memory_view;
        return .file_offset;
    }

    /// file_offset 槽位存的是**结束偏移**；memory_view 槽位存的更像长度。
    pub fn size(self: *const BromLayoutRegion) u32 {
        return switch (self.kind()) {
            .file_offset => self.end_or_size -| self.start,
            .memory_view => self.end_or_size,
            .empty => 0,
        };
    }
};

pub const BromLayoutHeader = struct {
    name: [9]u8 = @splat(0),
    version: u32 = 0,
    header_size: u32 = 0,
    total_size: u32 = 0,
    region: [brlyt_max_regions]BromLayoutRegion = @splat(.{}),

    /// 从 BRLYT 起始处读取；调用方需保证 buf 至少有 min_size 字节。
    pub fn read(buf: []const u8) BromLayoutHeader {
        var h: BromLayoutHeader = .{};
        fixedStr(&h.name, buf);
        h.version = le32(buf[8..]);
        h.header_size = le32(buf[12..]);
        h.total_size = le32(buf[16..]);

        for (0..brlyt_max_regions) |i| {
            const rg = &h.region[i];
            const r = buf[20 + i * brlyt_region_size ..];

            rg.magic = le32(r[0..]);
            rg.@"type" = le32(r[4..]);
            rg.start = le32(r[8..]);
            rg.end_or_size = le32(r[12..]);
            rg.unused = le32(r[16..]);
        }
        return h;
    }

    pub fn isValid(h: *const BromLayoutHeader) bool {
        return std.mem.eql(u8, cstr(&h.name), brlyt_name) and
            h.region[0].magic == brlyt_magic;
    }

    /// magic 有效的槽位数
    pub fn usedRegions(h: *const BromLayoutHeader) u32 {
        var n: u32 = 0;
        for (h.region) |rg| {
            if (rg.magic == brlyt_magic) n += 1;
        }
        return n;
    }
};

pub const BromLayout = struct {
    head: BromLayoutHeader = .{},
    region_count: u32 = 0,
};

pub fn brlytRegionIndex(t: u32) u16 {
    return @truncate(t >> 16);
}

pub fn brlytRegionFlash(t: u32) u16 {
    return @truncate(t);
}

/// flash 编号。官方 mtk_image.h 只给了 GFH_FLASH_TYPE_GEN/NAND 两个值，
/// BRLYT_TYPE_* 的低 16 位也是同一套编号（NOR=0x10007 → flash 7）。
pub const flash_type = struct {
    pub const nand: u8 = 2; // GFH_FLASH_TYPE_NAND
    pub const gen: u8 = 5; // GFH_FLASH_TYPE_GEN
    pub const nor: u8 = 7; // 来自 BRLYT_TYPE_NOR=0x10007 的低位（推测）
};

pub fn flashTypeName(t: u8) []const u8 {
    return switch (t) {
        flash_type.nand => "NAND",
        flash_type.gen => "GEN",
        flash_type.nor => "NOR",
        else => "unknown",
    };
}

test "BRLYT region kind is decided by address window" {
    var rg = BromLayoutRegion{ .magic = brlyt_magic, .@"type" = 0x0001_0007, .start = 0x800, .end_or_size = 0x2980 };
    try std.testing.expectEqual(RegionKind.file_offset, rg.kind());
    try std.testing.expectEqual(@as(u32, 0x2180), rg.size());

    rg = BromLayoutRegion{ .magic = brlyt_magic, .@"type" = 0xfffe_0007, .start = 0x7000_8004, .end_or_size = 0x980 };
    try std.testing.expectEqual(RegionKind.memory_view, rg.kind());
    try std.testing.expectEqual(@as(u32, 0x980), rg.size());

    rg = BromLayoutRegion{};
    try std.testing.expectEqual(RegionKind.empty, rg.kind());
}
