//! 镜像二进制格式定义 —— 对标 U-Boot 的 `docs/mtk_image.h.txt`。
//!
//! 全部 on-flash 结构、魔数、常量集中在本文件（连同把字节绑到字段的
//! read/isValid——那也是格式知识的一部分）；解析流程在 `parse.zig` /
//! `image.zig`，打印在 `dump.zig`。
//! 官方 mtk_image.h 定义过的照抄；官方没有而由本仓库实测反推的部分一律
//! 标 `推测`，避免把猜测当成规范。所有 on-flash 字段为小端。

const std = @import("std");
const bytes = @import("bytes.zig");
const le16 = bytes.le16;
const le32 = bytes.le32;
const fixedStr = bytes.fixedStr;
const readStr = bytes.readStr;
const cstr = bytes.cstr;

// ============================================================
// 1. 设备头（文件偏移 0x000，大小 0x200）
//
// 镜像最开头的 13 字节名字决定这是哪类闪存的 boot 镜像。
// 官方对应：gen_boot_header / EMMC_BOOT|SF_BOOT|SDMMC_BOOT。
// ============================================================

pub const boot_name_emmc = "EMMC_BOOT";
pub const boot_name_sf = "SF_BOOT";
pub const boot_name_sdmmc = "SDMMC_BOOT";

pub const GenBootHeader = struct {
    name: [13]u8 = @splat(0),
    version: u32 = 0,
    size: u32 = 0,

    /// 从镜像开头读取；调用方需保证 buf 至少有 20 字节。
    pub fn read(buf: []const u8) GenBootHeader {
        var h: GenBootHeader = .{};
        fixedStr(&h.name, buf);
        h.version = le32(buf[12..]);
        h.size = le32(buf[16..]);
        return h;
    }

    pub fn isValid(h: *const GenBootHeader) bool {
        const name = cstr(&h.name);
        return std.mem.eql(u8, name, boot_name_sf) or
            std.mem.eql(u8, name, boot_name_emmc) or
            std.mem.eql(u8, name, boot_name_sdmmc);
    }
};

// ============================================================
// 2. BootROM 布局头（BRLYT，文件偏移 0x200）
//
// 官方对应 brom_layout_header。
// ============================================================

/// BRLYT 在文件中的位置
pub const brlyt_offset = 0x200;
/// on-flash 头大小（逐字段读取，不用 @sizeOf 以免受对齐影响）
pub const brlyt_min_size = 0xb4;

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
    type: u32 = 0,
    /// on-flash 字段名 header_size_2
    start: u32 = 0,
    /// on-flash 字段名 total_size_2
    end_or_size: u32 = 0,
    unused: u32 = 0,

    pub fn kind(self: *const BromLayoutRegion) RegionKind {
        if (self.magic != brlyt_magic) return .empty;
        if (brlytRegionIndex(self.type) == brlyt_index_reserved) return .memory_view;
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

    /// 从 BRLYT 起始处读取；调用方需保证 buf 至少有 brlyt_min_size 字节。
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
            rg.type = le32(r[4..]);
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
    var rg = BromLayoutRegion{ .magic = brlyt_magic, .type = 0x0001_0007, .start = 0x800, .end_or_size = 0x2980 };
    try std.testing.expectEqual(RegionKind.file_offset, rg.kind());
    try std.testing.expectEqual(@as(u32, 0x2180), rg.size());

    rg = BromLayoutRegion{ .magic = brlyt_magic, .type = 0xfffe_0007, .start = 0x7000_8004, .end_or_size = 0x980 };
    try std.testing.expectEqual(RegionKind.memory_view, rg.kind());
    try std.testing.expectEqual(@as(u32, 0x980), rg.size());

    rg = BromLayoutRegion{};
    try std.testing.expectEqual(RegionKind.empty, rg.kind());
}

// ============================================================
// 3. GFH 链式头（位于每个镜像起始处，magic "MMM"）
// ============================================================

pub const gfh_file_info_name = "FILE_INFO";

/// on-flash 结构体大小（逐字段读取，不用 @sizeOf 以免受对齐影响）
pub const gfh_common_header_size = 8;
pub const gfh_file_info_size = 0x38;

pub const GfhCommonHeader = struct {
    version: u8 = 0,
    size: u16 = 0,
    type: u16 = 0,
};

pub const gfh_type = struct {
    // 官方 mtk_image.h 定义的类型
    pub const file_info: u16 = 0;
    pub const bl_info: u16 = 1;
    pub const anti_clone: u16 = 2;
    pub const bl_sec_key: u16 = 3;
    pub const brom_cfg: u16 = 7;
    pub const brom_sec_cfg: u16 = 8;

    // MTK 私有类型，官方头未定义；名称与注释均出自本镜像的实测观察
    pub const emi_info: u16 = 0x101; // body 内含 "EMI_INF" 字符串
    pub const maui_102: u16 = 0x102; // 含义未知
    pub const maui_103: u16 = 0x103; // 含义未知
    pub const project_info: u16 = 0x200; // body 内含工程名/版本字符串
    pub const maui_207: u16 = 0x207; // 含义未知
    pub const maui_209: u16 = 0x209; // 含义未知
    pub const maui_20e: u16 = 0x20e; // 含义未知
};

/// GFH 体（body = GFH 头之后的 h.size - 8 字节）。
/// 只有官方 mtk_image.h 定义过的类型做精确字段解析；私有类型只取实测能确认的
/// 部分（字符串/魔数），其余一律保留原始字节预览，不做臆测字段名。
pub const GfhBody = union(enum) {
    empty,
    bl_info: struct {
        attr: u32,
    },
    anti_clone: struct {
        ac_b2k: u8,
        ac_b2c: u8,
        ac_offset: u32,
        ac_len: u32,
    },
    brom_cfg: struct {
        cfg_bits: u32,
        usbdl_by_auto_detect_timeout_ms: u32,
        jump_bl_arm64: u8,
        usbdl_by_kcol0_timeout_ms: u32,
        usbdl_by_flag_timeout_ms: u32,
    },
    brom_sec_cfg: struct {
        cfg_bits: u32,
        customer_name: [33]u8,
    },
    /// 官方只定义 pad[0x20c]，这里只记录长度。
    bl_sec_key: struct {
        pad_len: usize,
    },
    /// body: [0]=version, [4]=flags, [8]="EMI_INF\0"（实测），其余参数未解释
    emi_info: struct {
        version: u32,
        flags: u32,
        magic: [9]u8,
        magic_ok: bool,
    },
    /// body: [0]=工程名(NUL 结尾), [0x80]=版本字符串(实测)，其余未解释
    project_info: struct {
        project: [64]u8,
        version_str: [64]u8,
    },
    /// 未识别类型：保留前 16 字节原始预览
    raw: struct {
        len: usize,
        preview: [16]u8,
    },
};

pub const FileInfo = struct {
    name: [13]u8 = @splat(0),
    unused: u32 = 0,
    file_type: u16 = 0,
    flash_type: u8 = 0,
    sig_type: u8 = 0,
    load_addr: u32 = 0,
    total_size: u32 = 0,
    max_size: u32 = 0,
    hdr_size: u32 = 0,
    sig_size: u32 = 0,
    jump_offset: u32 = 0,
    processed: u32 = 0,
};

pub const sig_type_none: u8 = 0;
pub const sig_type_sha256: u8 = 1;

// 本镜像观测到的 file_type。*推测*：0x108 的名称是我们自己取的，官方文档无此值。
pub const file_type = struct {
    pub const bl: u16 = 0x001; // 一级 Bootloader
    pub const ext_bl: u16 = 0x002; // 二级 / 扩展 Bootloader
    pub const maui: u16 = 0x100; // MAUI 主固件
    pub const maui_108: u16 = 0x108; // 主固件之后的第二段镜像（推测）
};

pub fn gfhMagicOk(p: []const u8) bool {
    return p.len >= gfh_common_header_size and p[0] == 'M' and p[1] == 'M' and p[2] == 'M';
}

pub fn gfhRead(p: []const u8) GfhCommonHeader {
    return .{
        .version = p[3],
        .size = le16(p[4..]),
        .type = le16(p[6..]),
    };
}

pub fn gfhBodyRead(t: u16, size: u16, body: []const u8) GfhBody {
    return switch (t) {
        gfh_type.bl_info => .{ .bl_info = .{ .attr = le32(body[0..]) } },
        gfh_type.anti_clone => .{ .anti_clone = .{
            .ac_b2k = body[0],
            .ac_b2c = body[1],
            .ac_offset = le32(body[4..]),
            .ac_len = le32(body[8..]),
        } },
        gfh_type.brom_cfg => .{
            .brom_cfg = .{
                .cfg_bits = le32(body[0..]),
                .usbdl_by_auto_detect_timeout_ms = le32(body[4..]),
                .jump_bl_arm64 = body[0x4d],
                .usbdl_by_kcol0_timeout_ms = le32(body[0x50..]),
                .usbdl_by_flag_timeout_ms = le32(body[0x54..]),
            },
        },
        gfh_type.brom_sec_cfg => blk: {
            var name: [33]u8 = @splat(0);
            fixedStr(&name, body[4..][0..0x20]);
            break :blk .{ .brom_sec_cfg = .{ .cfg_bits = le32(body[0..]), .customer_name = name } };
        },
        gfh_type.bl_sec_key => .{ .bl_sec_key = .{ .pad_len = if (size > 8) size - 8 else 0 } },
        gfh_type.emi_info => blk: {
            var magic: [9]u8 = @splat(0);
            readStr(&magic, body[8..][0..8]);
            break :blk .{ .emi_info = .{
                .version = le32(body[0..]),
                .flags = le32(body[4..]),
                .magic = magic,
                .magic_ok = std.mem.eql(u8, cstr(&magic), "EMI_INF"),
            } };
        },
        gfh_type.project_info => blk: {
            var project: [64]u8 = @splat(0);
            var ver: [64]u8 = @splat(0);
            readStr(&project, body[0..]);
            // 实测：第二条字符串位于 body+0x80
            readStr(&ver, body[0x80..]);
            break :blk .{ .project_info = .{ .project = project, .version_str = ver } };
        },
        else => blk: {
            var preview: [16]u8 = @splat(0);
            const n = @min(body.len, preview.len);
            @memcpy(preview[0..n], body[0..n]);
            break :blk .{ .raw = .{ .len = if (size > 8) size - 8 else 0, .preview = preview } };
        },
    };
}

pub fn fileInfoRead(p: []const u8) FileInfo {
    var fi: FileInfo = .{};
    fixedStr(&fi.name, p[8..]);
    fi.unused = le32(p[20..]);
    fi.file_type = le16(p[24..]);
    fi.flash_type = p[26];
    fi.sig_type = p[27];
    fi.load_addr = le32(p[28..]);
    fi.total_size = le32(p[32..]);
    fi.max_size = le32(p[36..]);
    fi.hdr_size = le32(p[40..]);
    fi.sig_size = le32(p[44..]);
    fi.jump_offset = le32(p[48..]);
    fi.processed = le32(p[52..]);
    return fi;
}

/// FILE_INFO 的合法性判断，用于全文件扫描时排除误命中
pub fn fileInfoValid(p: []const u8) bool {
    if (p.len < gfh_file_info_size) return false;
    if (!gfhMagicOk(p)) return false;
    if (le16(p[4..]) != gfh_file_info_size) return false;
    if (le16(p[6..]) != gfh_type.file_info) return false;
    if (!std.mem.eql(u8, p[8..][0..gfh_file_info_name.len], gfh_file_info_name)) return false;
    return true;
}

pub fn fileTypeName(t: u16) []const u8 {
    return switch (t) {
        file_type.bl => "BL (1st bootloader)",
        file_type.ext_bl => "ExtBL (2nd bootloader)",
        file_type.maui => "MAUI (main firmware)",
        file_type.maui_108 => "MAUI resource / 2nd image (推测)",
        else => "unknown",
    };
}

pub fn gfhTypeName(t: u16) []const u8 {
    return switch (t) {
        gfh_type.file_info => "FILE_INFO",
        gfh_type.bl_info => "BL_INFO",
        gfh_type.anti_clone => "ANTI_CLONE",
        gfh_type.bl_sec_key => "BL_SEC_KEY",
        gfh_type.brom_cfg => "BROM_CFG",
        gfh_type.brom_sec_cfg => "BROM_SEC_CFG",
        gfh_type.emi_info => "EMI_INFO",
        gfh_type.project_info => "PROJECT_INFO",
        gfh_type.maui_102 => "private",
        gfh_type.maui_103 => "private",
        gfh_type.maui_207 => "private",
        gfh_type.maui_209 => "private",
        gfh_type.maui_20e => "private",
        else => "unknown",
    };
}
