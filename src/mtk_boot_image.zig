//! MediaTek MT6250 (SF_BOOT) 闪存镜像解析器。
//!
//! 说明哪些字段来自官方 U-Boot 的 `docs/mtk_image.h.txt`、哪些是本仓库按实测
//! 反推的（反推部分都标了 `推测`），避免把猜测当成规范。所有 on-flash 字段为小端。

const std = @import("std");
const Io = std.Io;
const log = @import("log.zig");

// ------------------------------------------------------------------
// 1. 设备头（文件偏移 0x000，大小 0x200）
// ------------------------------------------------------------------

pub const boot_name_emmc = "EMMC_BOOT";
pub const boot_name_sf = "SF_BOOT";
pub const boot_name_sdmmc = "SDMMC_BOOT";

pub const GenBootHeader = struct {
    name: [13]u8 = @splat(0),
    version: u32 = 0,
    size: u32 = 0,
};

// ------------------------------------------------------------------
// 2. BootROM 布局头（文件偏移 0x200）
// ------------------------------------------------------------------

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

// ------------------------------------------------------------------
// 3. GFH（GFH = "MMM" 链式头，位于每个镜像起始处）
// ------------------------------------------------------------------

pub const gfh_file_info_name = "FILE_INFO";

pub const GfhCommonHeader = struct {
    version: u8 = 0,
    size: u16 = 0,
    @"type": u16 = 0,
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

// ------------------------------------------------------------------
// 4. 解析结果
// ------------------------------------------------------------------

pub const image_max = 16;
pub const gfh_max = 16;

pub const GfhEntry = struct {
    offset: u32 = 0,
    @"type": u16 = 0,
    size: u16 = 0,
    version: u8 = 0,
    // 仅用于 dump 展示，不是 on-flash 字段：官方头里只有 gfh_file_info 的
    // name[12]，这里要装下 PROJECT_INFO 里的完整工程名，故取 63 字节 + NUL。
    name: [64]u8 = @splat(0),
    body: GfhBody = .empty,
};

/// 完整性/一致性检查的结果。任何一项为真都应该在 dump 里用 warn 报出来。
pub const Integrity = struct {
    sig_unverified: bool = false, // sig_type != NONE，但本工具未做签名验证
    bad_hdr_size: bool = false, // hdr_size > total_size
    sig_overlap: bool = false, // hdr_size + sig_size > total_size
    gfh_chain_mismatch: bool = false, // GFH 链终点 != offset + hdr_size
    gfh_truncated: bool = false, // GFH 数组溢出或未走到 hdr_size

    pub fn any(self: *const Integrity) bool {
        return self.sig_unverified or self.bad_hdr_size or self.sig_overlap or
            self.gfh_chain_mismatch or self.gfh_truncated;
    }
};

pub const Image = struct {
    offset: u32 = 0,
    total_size: u32 = 0,
    end: u32 = 0,
    hdr_size: u32 = 0,
    sig_size: u32 = 0,
    jump_offset: u32 = 0,
    load_addr: u32 = 0,
    entry_point: u32 = 0,
    file_type: u16 = 0,
    flash_type: u8 = 0,
    sig_type: u8 = 0,
    processed: u32 = 0,
    max_size: u32 = 0,
    unused: u32 = 0,
    name: [13]u8 = @splat(0),

    gfh: [gfh_max]GfhEntry = @splat(.{}),
    gfh_count: u32 = 0,
    /// GFH 链实际走到的偏移（用于和 hdr_size 比对）
    gfh_chain_end: u32 = 0,

    payload_crc32: u32 = 0,
    integrity: Integrity = .{},

    /// ARM 入口：Thumb 位（bit0）。jump_offset == 0 表示这段没有代码入口。
    pub fn hasEntry(im: *const Image) bool {
        return im.jump_offset != 0;
    }

    pub fn entryThumb(im: *const Image) u32 {
        return im.entry_point | 1;
    }
};

/// 全文件扫描的统计，用于观察 BRLYT 与扫描各自贡献了多少镜像。
pub const ScanStats = struct {
    candidates: u32 = 0, // 命中的 FILE_INFO 数量
    added: u32 = 0, // 新登记的
    duplicate: u32 = 0, // 与已登记（含 BRLYT）重复的
    rejected: u32 = 0, // FILE_INFO 合法但被拒（越界等）
};

/// 最后一个镜像之后的剩余空间分析。
pub const TailInfo = struct {
    start: u32 = 0, // 最后一个镜像结束处
    first_data: u32 = 0, // 首个非 0xff 偏移（没有则为 start）
    last_data: u32 = 0, // 最后一个非 0xff 偏移 + 1
    nvram_hint: ?u32 = null, // "NVRAM" ASCII 标记首次出现处（若有）
};

pub const BootImage = struct {
    /// 不拥有数据，指向调用者的缓冲区；调用者必须保证数据在 PowderImage 使用期间有效。
    data: []const u8 = &.{},
    boot: GenBootHeader = .{},
    brlyt: BromLayoutHeader = .{},
    brlyt_region_count: u32 = 0,

    project: [64]u8 = @splat(0),

    image: [image_max]Image = @splat(.{}),
    image_count: u32 = 0,
    /// BRLYT 槽位直接给出的镜像数量（扫描之前）
    brlyt_image_count: u32 = 0,

    scan: ScanStats = .{},
    tail: TailInfo = .{},
};

pub const ParseError = error{
    TooSmall,
    BadBoot,
    BadBrlyt,
    OutOfMemory,
    Io,
};

// on-flash 结构体大小（逐字段读取，不用 @sizeOf 以免受对齐影响）
const brlyt_offset = 0x200;
const brom_layout_header_size = 0xb4;
const gfh_common_header_size = 8;
const gfh_file_info_size = 0x38;

pub const default_image =
    "res/AHONG50_11B_PCB01_gprs_MT6250_S00.D27D__11B_W11_32__V0010.bin";

// ------------------------------------------------------------------
// 小工具
// ------------------------------------------------------------------

fn le16(p: []const u8) u16 {
    return @as(u16, p[0]) | (@as(u16, p[1]) << 8);
}

fn le32(p: []const u8) u32 {
    return @as(u32, p[0]) | (@as(u32, p[1]) << 8) |
        (@as(u32, p[2]) << 16) | (@as(u32, p[3]) << 24);
}

/// 拷贝定长字符串：遇到 NUL 结束，非可打印字符替换成 '.'，并去掉尾部空格
fn fixedStr(dst: []u8, src: []const u8) void {
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
fn readStr(dst: []u8, src: []const u8) void {
    if (dst.len == 0) return;
    const n = @min(src.len, dst.len - 1);
    var i: usize = 0;
    while (i < n and src[i] != 0) : (i += 1) dst[i] = src[i];
    dst[i] = 0;
}

/// 把 NUL 结尾的定长缓冲转成切片，便于格式化输出
fn cstr(buf: []const u8) []const u8 {
    return std.mem.sliceTo(buf, 0);
}

/// GFH 体里只有一部分以可读名字开头（FILE_INFO / 工程名），
/// 其余是二进制参数，这里判断一下避免出现 "...." 这种假名字。
fn looksLikeStr(p: []const u8) bool {
    if (p.len == 0 or p[0] < 0x20 or p[0] >= 0x7f) return false;

    var count: usize = 0;
    for (p) |c| {
        if (c == 0) break;
        if (c >= 0x20 and c < 0x7f) count += 1;
    }
    return count >= 2;
}

fn gfhMagicOk(p: []const u8) bool {
    return p.len >= gfh_common_header_size and p[0] == 'M' and p[1] == 'M' and p[2] == 'M';
}

fn gfhRead(p: []const u8) GfhCommonHeader {
    return .{
        .version = p[3],
        .size = le16(p[4..]),
        .@"type" = le16(p[6..]),
    };
}

fn gfhBodyRead(t: u16, size: u16, body: []const u8) GfhBody {
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

fn fileInfoRead(p: []const u8) FileInfo {
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
fn fileInfoValid(p: []const u8) bool {
    if (p.len < gfh_file_info_size) return false;
    if (!gfhMagicOk(p)) return false;
    if (le16(p[4..]) != gfh_file_info_size) return false;
    if (le16(p[6..]) != gfh_type.file_info) return false;
    if (!std.mem.eql(u8, p[8..][0..gfh_file_info_name.len], gfh_file_info_name)) return false;
    return true;
}

fn crc32(data: []const u8) u32 {
    var h = std.hash.crc.Crc32.init();
    h.update(data);
    return h.final();
}

/// 在 [from, to) 中找第一个不等于 needle 的字节偏移，找不到返回 to
fn firstNonEqual(data: []const u8, from: usize, to: usize, needle: u8) usize {
    var i = from;
    while (i < to and data[i] == needle) i += 1;
    return i;
}

fn lastNonEqual(data: []const u8, from: usize, to: usize, needle: u8) usize {
    var i = to;
    while (i > from and data[i - 1] == needle) i -= 1;
    return i;
}

fn findAscii(data: []const u8, from: usize, needle: []const u8) ?u32 {
    const hit = std.mem.indexOfPos(u8, data, from, needle) orelse return null;
    return @intCast(hit);
}

fn hexPreview(buf: []u8, data: []const u8) []const u8 {
    var n: usize = 0;
    for (data) |b| {
        if (n + 3 > buf.len) break;
        const part = std.fmt.bufPrint(buf[n..], "{x:0>2} ", .{b}) catch break;
        n += part.len;
    }
    if (n > 0) n -= 1;
    return buf[0..n];
}

// ------------------------------------------------------------------
// 镜像表
// ------------------------------------------------------------------

fn imageFindSlot(img: *BootImage, offset: u32) ?*Image {
    for (img.image[0..img.image_count]) |*im| {
        if (im.offset == offset) return im;
    }
    return null;
}

/// 遍历一个镜像的 GFH 链，直到 hdr_size 结束。
/// 走完以后用 gfh_chain_end 与 hdr_size 比对，不一致说明我们对 GFH 链的理解
/// 或这份数据有问题，应当告警而不是静默丢弃。
fn imageCollectGfh(img: *BootImage, im: *Image) void {
    const base = img.data;
    var cur: usize = im.offset + gfh_file_info_size;
    const end: usize = im.offset + im.hdr_size;

    if (im.hdr_size < gfh_file_info_size or end > img.data.len) {
        im.integrity.bad_hdr_size = true;
        im.gfh_chain_end = @intCast(cur);
        return;
    }

    while (cur + gfh_common_header_size <= end) {
        if (im.gfh_count >= gfh_max) {
            im.integrity.gfh_truncated = true;
            break;
        }
        if (!gfhMagicOk(base[cur..])) break;

        const h = gfhRead(base[cur..]);
        if (h.size < gfh_common_header_size or cur + h.size > end) break;

        const e = &im.gfh[im.gfh_count];
        e.offset = @intCast(cur);
        e.@"type" = h.@"type";
        e.size = h.size;
        e.version = h.version;
        const body = base[cur + 8 ..][0 .. h.size - 8];
        e.body = gfhBodyRead(h.@"type", h.size, body);

        if (looksLikeStr(body)) fixedStr(&e.name, body);

        if (h.@"type" == gfh_type.project_info and looksLikeStr(body))
            fixedStr(&img.project, body);

        im.gfh_count += 1;
        cur += h.size;
    }

    im.gfh_chain_end = @intCast(cur);
    if (im.gfh_chain_end != end) im.integrity.gfh_chain_mismatch = true;
}

/// 登记（并解析）一个位于 offset 处的镜像；offset 重复时直接复用已有条目。
/// 返回：加载到哪个槽位（找不到返回 null）
fn imageAdd(img: *BootImage, offset: u32) ?*Image {
    if (img.image_count >= image_max) return null;
    if (offset + gfh_file_info_size > img.data.len) return null;
    if (!fileInfoValid(img.data[offset..])) return null;

    const fi = fileInfoRead(img.data[offset..]);
    if (fi.total_size == 0 or offset + fi.total_size > img.data.len) {
        img.scan.rejected += 1;
        return null;
    }

    if (imageFindSlot(img, offset) != null) {
        img.scan.duplicate += 1;
        return null; // 已登记（通常由 BRLYT 先行登记）
    }

    const im = &img.image[img.image_count];
    img.image_count += 1;
    im.* = .{};

    im.offset = offset;
    im.total_size = fi.total_size;
    im.end = offset + fi.total_size;
    im.hdr_size = fi.hdr_size;
    im.sig_size = fi.sig_size;
    im.jump_offset = fi.jump_offset;
    im.load_addr = fi.load_addr;
    im.entry_point = fi.load_addr +% fi.jump_offset;
    im.file_type = fi.file_type;
    im.flash_type = fi.flash_type;
    im.sig_type = fi.sig_type;
    im.processed = fi.processed;
    im.max_size = fi.max_size;
    im.unused = fi.unused;
    fixedStr(&im.name, img.data[offset + 8 ..]);

    // 完整性：本工具不做签名验证，但至少把需要留意的点标记出来
    if (im.sig_type != sig_type_none) im.integrity.sig_unverified = true;
    if (im.hdr_size > im.total_size) im.integrity.bad_hdr_size = true;
    if (im.hdr_size +| im.sig_size > im.total_size) im.integrity.sig_overlap = true;

    imageCollectGfh(img, im);
    im.payload_crc32 = crc32(payload(img, im));

    // 保持按 offset 升序
    var i: usize = img.image_count - 1;
    while (i > 0) : (i -= 1) {
        if (img.image[i - 1].offset <= img.image[i].offset) break;
        const tmp = img.image[i];
        img.image[i] = img.image[i - 1];
        img.image[i - 1] = tmp;
    }
    return imageFindSlot(img, offset);
}

/// BRLYT 只描述 bootloader 部分，其余镜像（MAUI 等）只能靠扫描补齐。
/// 命中一个镜像后直接跳到它的 end —— 镜像体内部不可能再嵌一个合法的 FILE_INFO，
/// 继续逐字节扫只会增加误命中风险。
fn imageScanAll(img: *BootImage) void {
    const size = img.data.len;
    var off: usize = 0;

    while (off + gfh_file_info_size <= size and img.image_count < image_max) {
        if (!fileInfoValid(img.data[off..])) {
            off += 1;
            continue;
        }

        img.scan.candidates += 1;
        if (imageAdd(img, @intCast(off))) |im| {
            img.scan.added += 1;
            const next = im.end;
            off = if (next > off) next else off + 1;
        } else {
            off += 1;
        }
    }
}

fn analyzeTail(img: *BootImage) void {
    var last_end: u32 = 0;
    for (img.image[0..img.image_count]) |im| {
        if (im.end > last_end) last_end = im.end;
    }
    const size = img.data.len;
    if (last_end >= size) return;

    const first = firstNonEqual(img.data, last_end, size, 0xff);
    img.tail.start = last_end;
    img.tail.first_data = @intCast(first);
    img.tail.last_data = @intCast(lastNonEqual(img.data, last_end, size, 0xff));
    img.tail.nvram_hint = findAscii(img.data, first, "NVRAM");
}

// ------------------------------------------------------------------
// 对外接口
// ------------------------------------------------------------------

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
pub fn parse(buf: []const u8, out: *BootImage) ParseError!void {
    out.* = .{};

    if (buf.len < brlyt_offset + brom_layout_header_size)
        return ParseError.TooSmall;

    out.data = buf;

    // 1. 设备头
    fixedStr(&out.boot.name, buf);
    out.boot.version = le32(buf[12..]);
    out.boot.size = le32(buf[16..]);

    const boot_name = cstr(&out.boot.name);
    if (!std.mem.eql(u8, boot_name, boot_name_sf) and
        !std.mem.eql(u8, boot_name, boot_name_emmc) and
        !std.mem.eql(u8, boot_name, boot_name_sdmmc))
    {
        return ParseError.BadBoot;
    }

    // 2. BRLYT 布局头 + region 表
    const b = buf[brlyt_offset..];
    fixedStr(&out.brlyt.name, b);
    out.brlyt.version = le32(b[8..]);
    out.brlyt.header_size = le32(b[12..]);
    out.brlyt.total_size = le32(b[16..]);

    for (0..brlyt_max_regions) |i| {
        const rg = &out.brlyt.region[i];
        const r = b[20 + i * brlyt_region_size ..];

        rg.magic = le32(r[0..]);
        rg.@"type" = le32(r[4..]);
        rg.start = le32(r[8..]);
        rg.end_or_size = le32(r[12..]);
        rg.unused = le32(r[16..]);

        if (rg.magic == brlyt_magic) out.brlyt_region_count += 1;
    }

    if (!std.mem.eql(u8, cstr(&out.brlyt.name), brlyt_name) or
        out.brlyt.region[0].magic != brlyt_magic)
    {
        return ParseError.BadBrlyt;
    }

    // 3. BRLYT 指出的镜像（memory_view 槽位不是文件内偏移）
    for (out.brlyt.region) |rg| {
        if (rg.magic != brlyt_magic) continue;
        if (rg.kind() != .file_offset) continue;
        _ = imageAdd(out, rg.start);
    }
    out.brlyt_image_count = out.image_count;
    // BRLYT 阶段的计数会污染扫描统计，这里清零，让 scan.* 只反映第 4 步。
    out.scan = .{};

    // 4. 扫描补齐剩余的镜像
    imageScanAll(out);

    // 5. 剩余空间（镜像表之后的区域）分析
    analyzeTail(out);
}

/// 按 file_type 查找镜像，找不到返回 null
pub fn find(img: *const BootImage, ft: u16) ?*const Image {
    for (img.image[0..img.image_count]) |*im| {
        if (im.file_type == ft) return im;
    }
    return null;
}

/// 取镜像正文（跳过 GFH 头）
pub fn payload(img: *const BootImage, im: *const Image) []const u8 {
    if (im.hdr_size >= im.total_size or im.end > img.data.len) return &.{};
    const start = im.offset + im.hdr_size;
    return img.data[start..][0 .. im.total_size - im.hdr_size];
}

/// 打印完整结构（走 log.info；可疑之处用 log.warn）
pub fn dump(img: *const BootImage) void {
    log.info(@src(), "MTK flash image: {d} bytes (0x{x})", .{ img.data.len, img.data.len });
    log.info(@src(), "  device header @0x000: name=\"{s}\" version={d} size=0x{x}", .{
        cstr(&img.boot.name), img.boot.version, img.boot.size,
    });
    log.info(@src(), "  BRLYT @0x200: name=\"{s}\" version={d} header_size=0x{x} total_size=0x{x} ({d}/{d} regions used)", .{
        cstr(&img.brlyt.name),
        img.brlyt.version,
        img.brlyt.header_size,
        img.brlyt.total_size,
        img.brlyt_region_count,
        brlyt_max_regions,
    });

    if (img.project[0] != 0)
        log.info(@src(), "  project: \"{s}\"", .{cstr(&img.project)});

    for (0..brlyt_max_regions) |i| {
        const rg = &img.brlyt.region[i];

        if (rg.magic != brlyt_magic) {
            log.info(@src(), "    region[{d}]: <empty>", .{i});
            continue;
        }

        const index = brlytRegionIndex(rg.@"type");
        const flash = brlytRegionFlash(rg.@"type");

        switch (rg.kind()) {
            .memory_view => {
                log.info(@src(), "    region[{d}]: index=0x{x:0>4} flash=0x{x:0>4} memory view addr=0x{x:0>8} size=0x{x:0>8} flags=0x{x:0>8}", .{
                    i, index, flash, rg.start, rg.size(), rg.unused,
                });
                if (index != brlyt_index_reserved) {
                    log.warn(@src(), "      region[{d}]: index != 0xfffe 但 start 落在 SRAM 窗口，语义待确认", .{i});
                }
            },
            .file_offset => {
                var label: []const u8 = "<unresolved>";
                for (img.image[0..img.image_count]) |*candidate| {
                    if (candidate.offset == rg.start) label = fileTypeName(candidate.file_type);
                }
                log.info(@src(), "    region[{d}]: index=0x{x:0>4} flash=0x{x:0>4} @0x{x:0>8}..0x{x:0>8} size=0x{x:0>8} flags=0x{x:0>8} -> {s}", .{
                    i, index, flash, rg.start, rg.end_or_size, rg.size(), rg.unused, label,
                });
            },
            .empty => {},
        }
    }

    log.info(@src(), "  images: {d} (brlyt={d} scan={d}, scan candidates={d}, dup={d}, rejected={d})", .{
        img.image_count,
        img.brlyt_image_count,
        img.image_count - img.brlyt_image_count,
        img.scan.candidates,
        img.scan.duplicate,
        img.scan.rejected,
    });
    if (img.scan.added + img.brlyt_image_count != img.image_count) {
        log.warn(@src(), "    image count mismatch: brlyt({d}) + scan added({d}) != {d}", .{
            img.brlyt_image_count, img.scan.added, img.image_count,
        });
    }

    for (img.image[0..img.image_count], 0..) |*p, i| {
        const im = p;
        log.info(@src(), "    [{d}] @0x{x:0>8}..0x{x:0>8} size=0x{x:0>8} type=0x{x:0>3} ({s}) load=0x{x:0>8} entry=0x{x:0>8} jump=0x{x} sig={d} flash={d} ({s}) processed={d} max=0x{x} hdr=0x{x} payload=0x{x} crc32=0x{x:0>8}", .{
            i,
            im.offset,
            im.end,
            im.total_size,
            im.file_type,
            fileTypeName(im.file_type),
            im.load_addr,
            im.entry_point,
            im.jump_offset,
            im.sig_type,
            im.flash_type,
            flashTypeName(im.flash_type),
            im.processed,
            im.max_size,
            im.hdr_size,
            payload(img, im).len,
            im.payload_crc32,
        });

        if (im.hasEntry()) {
            log.info(@src(), "        arm entry: thumb=0x{x:0>8} (bit0 set)", .{im.entryThumb()});
        } else {
            log.info(@src(), "        arm entry: <none> (jump_offset == 0)", .{});
        }

        if (im.integrity.any()) {
            if (im.integrity.sig_unverified)
                log.warn(@src(), "        ! sig_type={d} 但本工具未做任何签名/校验和验证", .{im.sig_type});
            if (im.integrity.bad_hdr_size)
                log.warn(@src(), "        ! hdr_size(0x{x}) 与 total_size(0x{x}) 不自洽", .{ im.hdr_size, im.total_size });
            if (im.integrity.sig_overlap)
                log.warn(@src(), "        ! hdr_size+sig_size(0x{x}) 超过 total_size(0x{x})", .{ im.hdr_size +| im.sig_size, im.total_size });
            if (im.integrity.gfh_chain_mismatch)
                log.warn(@src(), "        ! GFH 链终点 0x{x} != offset+hdr_size 0x{x}", .{ im.gfh_chain_end, im.offset + im.hdr_size });
            if (im.integrity.gfh_truncated)
                log.warn(@src(), "        ! GFH 条目数超过上限 {d}，链可能不完整", .{gfh_max});
        }

        for (im.gfh[0..im.gfh_count]) |e| {
            // body 摘要可能比较长（PROJECT_INFO 要放下完整工程名），给足空间
            var preview_buf: [512]u8 = undefined;
            const extra = switch (e.body) {
                .empty => std.fmt.bufPrint(&preview_buf, "", .{}) catch "",
                .bl_info => |v| std.fmt.bufPrint(&preview_buf, " attr=0x{x:0>8}", .{v.attr}) catch "",
                .anti_clone => |v| std.fmt.bufPrint(&preview_buf, " ac_b2k={d} ac_b2c={d} ac_offset=0x{x} ac_len=0x{x}", .{ v.ac_b2k, v.ac_b2c, v.ac_offset, v.ac_len }) catch "",
                .brom_cfg => |v| std.fmt.bufPrint(&preview_buf, " cfg=0x{x} usbdl_auto={d}ms jump_bl_arm64={d} kcol0={d}ms flag={d}ms", .{
                    v.cfg_bits,
                    v.usbdl_by_auto_detect_timeout_ms,
                    v.jump_bl_arm64,
                    v.usbdl_by_kcol0_timeout_ms,
                    v.usbdl_by_flag_timeout_ms,
                }) catch "",
                .brom_sec_cfg => |v| std.fmt.bufPrint(&preview_buf, " cfg=0x{x} customer=\"{s}\"", .{ v.cfg_bits, cstr(&v.customer_name) }) catch "",
                .bl_sec_key => |v| std.fmt.bufPrint(&preview_buf, " pad=0x{x}", .{v.pad_len}) catch "",
                .emi_info => |v| std.fmt.bufPrint(&preview_buf, " emi_ver={d} flags=0x{x} magic=\"{s}\"{s}", .{
                    v.version, v.flags, cstr(&v.magic), if (v.magic_ok) "" else " (魔数不符)",
                }) catch "",
                // 工程名已经在 name 字段里出现，这里只补 body 里的版本串
                .project_info => |v| std.fmt.bufPrint(&preview_buf, " version=\"{s}\"", .{cstr(&v.version_str)}) catch "",
                .raw => |v| blk: {
                    var hex_buf: [96]u8 = undefined;
                    break :blk std.fmt.bufPrint(&preview_buf, " raw[0x{x}]={s}", .{ v.len, hexPreview(&hex_buf, &v.preview) }) catch "";
                },
            };

            log.info(@src(), "        gfh @0x{x:0>8} type=0x{x:0>4} ({s: <12}) size=0x{x:0>3} ver={d} {s}{s}{s}{s}", .{
                e.offset,
                e.@"type",
                gfhTypeName(e.@"type"),
                e.size,
                e.version,
                if (e.name[0] != 0) "name=\"" else "",
                cstr(&e.name),
                if (e.name[0] != 0) "\"" else "",
                extra,
            });
        }
    }

    if (img.tail.start != 0) {
        const t = &img.tail;
        log.info(@src(), "  tail: @0x{x:0>8}..0x{x:0>8} size=0x{x} erased until 0x{x:0>8}, data 0x{x:0>8}..0x{x:0>8}", .{
            t.start,
            img.data.len,
            img.data.len - t.start,
            t.first_data,
            t.first_data,
            t.last_data,
        });
        if (t.nvram_hint) |hint|
            log.info(@src(), "        hint: 找到 NVRAM 标记 @0x{x:0>8}（该区域大概率是 NVRAM/FS，本工具未解析）", .{hint});
    }
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
