//! 镜像二进制格式定义 —— 对标 U-Boot 的 `docs/mtk_image.h.txt`。
//!
//! 分三个区：
//! 1. **官方定义区**：与 mtk_image.h 逐行对应的 extern 结构/联合/枚举，
//!    纯布局描述，无解析逻辑；`comptime` 断言钉死大小，写错立刻编译失败。
//!    标「本工程未用」的是官方为 NAND 介质 / LK 阶段等定义的，收进来仅为对齐参考。
//! 2. **实测扩展区**：官方头没有、由本镜像实测反推的部分（一律标 *推测*）：
//!    BRLYT 的额外槽位、私有 GFH 类型、GfhBody tagged union 等。
//! 3. **解析函数区**：把字节读成值的函数。官方部分通过「拷贝到栈上官方
//!    结构」来读——偏移由布局保证，不再手写；这样也规避了在任意字节偏移上
//!    转 extern 指针的对齐问题。
//!
//! 解析流程在 `parse.zig` / `image.zig`，打印在 `dump.zig`。
//! 所有 on-flash 字段为小端。

const std = @import("std");
const bytes = @import("bytes.zig");
const le16 = bytes.le16;
const le32 = bytes.le32;
const fixedStr = bytes.fixedStr;
const readStr = bytes.readStr;
const cstr = bytes.cstr;

// ============================================================
// 1. 官方定义区（docs/mtk_image.h.txt 1:1）
// ============================================================

// ------------------------------------------------------------
// NOR/SD/eMMC 通用启动头（官方 gen_boot_header）
// ------------------------------------------------------------

/// 固定填充到 0x200 字节
pub const GenBootHeader = extern union {
    fields: extern struct {
        name: [12]u8, // 启动设备名称
        version: u32, // 头版本
        size: u32, // 镜像/数据大小
    },
    pad: [0x200]u8, // 原始字节视图
};

pub const SF_BOOT_NAME = "SF_BOOT";
pub const EMMC_BOOT_NAME = "EMMC_BOOT";
pub const SDMMC_BOOT_NAME = "SDMMC_BOOT";

// ------------------------------------------------------------
// NAND 启动头（官方 nand_boot_header）——本工程未用（MT6250 走 NOR）
// ------------------------------------------------------------

pub const NandBootHeader = extern union {
    fields: extern struct {
        name: [12]u8, // "BOOTLOADER!"
        version: [4]u8, // "V006"
        id: [8]u8, // "NFIINFO"
        ioif: u16,
        pagesize: u16,
        addrcycles: u16,
        oobsize: u16,
        pages_of_block: u16,
        numblocks: u16,
        writesize_shift: u16,
        erasesize_shift: u16,
        dummy: [60]u8,
        ecc_parity: [28]u8,
    },
    data: [0x80]u8,
};

pub const NAND_BOOT_NAME = "BOOTLOADER!";
pub const NAND_BOOT_VERSION = "V006";
pub const NAND_BOOT_ID = "NFIINFO";

// ------------------------------------------------------------
// BRLYT 布局头（官方 brom_layout_header）
// ------------------------------------------------------------

/// 注意：官方头内嵌**一组**槽位（magic..unused 共 20 字节）；
/// 本镜像在该组之后还有同宽度槽位，见实测扩展区的 BromLayoutRegion。
pub const BromLayoutHeader = extern struct {
    name: [8]u8, // "BRLYT"
    version: u32, // 布局头版本
    header_size: u32, // 头大小
    total_size: u32, // 总大小
    magic: u32, // 槽位魔数 0x42424242
    type: u32, // 镜像类型，见 BrlytImgType
    header_size_2: u32, // 头大小副本
    total_size_2: u32, // 总大小副本
    unused: u32,
};

pub const BRLYT_NAME = "BRLYT";
pub const BRLYT_MAGIC: u32 = 0x42424242;

pub const BrlytImgType = enum(u32) {
    invalid = 0,
    nand = 0x10002,
    emmc = 0x10005,
    nor = 0x10007,
    sdmmc = 0x10008,
    snand = 0x10009,
};

/// NOR/SD/eMMC 组合设备头——本工程未用（按区段单独解析）
pub const GenDeviceHeader = extern struct {
    boot: GenBootHeader,
    brlyt: extern union {
        layout: BromLayoutHeader,
        pad: [0x400]u8,
    },
};

// ------------------------------------------------------------
// GFH 链式头（官方各 GFH 结构）
// ------------------------------------------------------------

pub const GfhCommonHeader = extern struct {
    magic: [3]u8, // 固定 "MMM"
    version: u8,
    size: u16, // 当前 GFH 结构大小
    type: u16, // GFH 类型，见 GfhType
};

pub const GFH_HEADER_MAGIC = "MMM";

pub const GfhType = enum(u16) {
    file_info = 0,
    bl_info = 1,
    anti_clone = 2,
    bl_sec_key = 3,
    brom_cfg = 7,
    brom_sec_cfg = 8,
};

pub const GfhFileInfo = extern struct {
    gfh: GfhCommonHeader,
    name: [12]u8, // "FILE_INFO"
    unused: u32,
    file_type: u16,
    flash_type: u8, // 见 GfhFlashType
    sig_type: u8, // 见 GfhSigType
    load_addr: u32,
    total_size: u32,
    max_size: u32,
    hdr_size: u32,
    sig_size: u32,
    jump_offset: u32,
    processed: u32,
};

pub const GFH_FILE_INFO_NAME = "FILE_INFO";

/// 官方只定义 nand/gen 两个值；本镜像实测还出现 nor=7，见实测扩展区 flash_type。
pub const GfhFlashType = enum(u8) {
    nand = 2,
    gen = 5,
};

pub const GfhSigType = enum(u8) {
    none = 0,
    sha256 = 1,
};

pub const GfhBlInfo = extern struct {
    gfh: GfhCommonHeader,
    attr: u32,
};

pub const GfhBromCfg = extern struct {
    gfh: GfhCommonHeader,
    cfg_bits: u32,
    usbdl_by_auto_detect_timeout_ms: u32,
    unused: [0x45]u8,
    jump_bl_arm64: u8,
    unused2: [2]u8,
    usbdl_by_kcol0_timeout_ms: u32,
    usbdl_by_flag_timeout_ms: u32,
    pad: u32,
};

pub const GFH_BROM_CFG_USBDL_BY_AUTO_DETECT_TIMEOUT_EN: u32 = 0x02;
pub const GFH_BROM_CFG_USBDL_AUTO_DETECT_DIS: u32 = 0x10;
pub const GFH_BROM_CFG_USBDL_BY_KCOL0_TIMEOUT_EN: u32 = 0x80;
pub const GFH_BROM_CFG_USBDL_BY_FLAG_TIMEOUT_EN: u32 = 0x100;
pub const GFH_BROM_CFG_JUMP_BL_ARM64_EN: u32 = 0x1000;
pub const GFH_BROM_CFG_JUMP_BL_ARM64: u32 = 0x64;

pub const GfhBlSecKey = extern struct {
    gfh: GfhCommonHeader,
    pad: [0x20c]u8,
};

pub const GfhAntiClone = extern struct {
    gfh: GfhCommonHeader,
    ac_b2k: u8,
    ac_b2c: u8,
    pad: u16,
    ac_offset: u32,
    ac_len: u32,
};

pub const GfhBromSecCfg = extern struct {
    gfh: GfhCommonHeader,
    cfg_bits: u32,
    customer_name: [0x20]u8,
    pad: u32,
};

pub const BROM_SEC_CFG_JTAG_EN: u32 = 1;
pub const BROM_SEC_CFG_UART_EN: u32 = 2;

/// 官方把各 GFH 子头组合成一个总头；实际镜像里它们是**链式**排布的，
/// 本工程未用（组合头只是字面移植）。
pub const GfhHeader = extern struct {
    file_info: GfhFileInfo,
    bl_info: GfhBlInfo,
    brom_cfg: GfhBromCfg,
    bl_sec_key: GfhBlSecKey,
    anti_clone: GfhAntiClone,
    brom_sec_cfg: GfhBromSecCfg,
};

// ------------------------------------------------------------
// LK 镜像头（官方 lk_header）——本工程未用
// ------------------------------------------------------------

pub const LkHdr = extern union {
    fields: extern struct {
        magic: u32,
        size: u32,
        name: [32]u8,
        loadaddr: u32,
        mode: u32,
    },
    data: [512]u8,
};

pub const LK_PART_MAGIC: u32 = 0x58881688;

// ============================================================
// 2. 实测扩展区（官方头没有，由本镜像观测反推，一律视为 *推测*）
// ============================================================

// -- 别名：解析侧沿用与子包 API 一致的名字 -------------------

pub const boot_name_emmc = EMMC_BOOT_NAME;
pub const boot_name_sf = SF_BOOT_NAME;
pub const boot_name_sdmmc = SDMMC_BOOT_NAME;
pub const brlyt_name = BRLYT_NAME;
pub const brlyt_magic = BRLYT_MAGIC;
pub const gfh_file_info_name = GFH_FILE_INFO_NAME;

// -- 设备头解析侧 -------------------------------------------

/// 设备头的解析值（name 官方是 [12]；此前误写 [13] 会 overlap version 首字节）
pub const BootHeader = struct {
    name: [12]u8 = @splat(0),
    version: u32 = 0,
    size: u32 = 0,

    /// 从镜像开头读取（拷贝到栈上官方结构，规避任意对齐）
    pub fn read(buf: []const u8) BootHeader {
        var raw: GenBootHeader = undefined;
        raw.pad = @splat(0);
        @memcpy(std.mem.asBytes(&raw.fields), buf[0..@sizeOf(@TypeOf(raw.fields))]);
        return .{ .name = raw.fields.name, .version = raw.fields.version, .size = raw.fields.size };
    }

    pub fn isValid(h: *const BootHeader) bool {
        const name = cstr(&h.name);
        return std.mem.eql(u8, name, boot_name_sf) or
            std.mem.eql(u8, name, boot_name_emmc) or
            std.mem.eql(u8, name, boot_name_sdmmc);
    }
};

// -- BRLYT 扩展槽位 -----------------------------------------

/// BRLYT 在文件中的位置
pub const brlyt_offset = 0x200;
/// 官方头 0x28 + 7 个扩展槽位
pub const brlyt_min_size = 0xb4;
pub const brlyt_region_size = 20;

/// 官方 `brom_layout_header` 内嵌一组槽位；本镜像在该组之后又出现同宽度的
/// 槽位（第一个槽位之后还有 7 个，其中 4 个 magic 有效）。按 8 槽位处理：
/// region[0] 就是官方那组，region[1..8] 是实测到的额外槽位（*推测*）。
pub const brlyt_max_regions = 8;

/// 高 16 位为 0xfffe 的槽位不作为文件偏移使用（实测其 header_size_2 是 SRAM 地址）
pub const brlyt_index_reserved = 0xfffe;

/// MT6250 内部 SRAM 窗口；BL 的 load_addr 0x70008000 就落在其中
pub const sram_window_base = 0x7000_0000;
pub const sram_window_mask = 0xf000_0000;

pub const RegionKind = enum {
    empty,
    /// start 是文件偏移，size = end - start
    file_offset,
    /// start 是内存/加载视图地址（*推测*），size 字段直接就是长度
    memory_view,
};

/// 与官方头内嵌槽位同宽度的组（官方字段名 header_size_2 / total_size_2）
pub const BromLayoutRegion = extern struct {
    magic: u32 = 0,
    type: u32 = 0,
    start: u32 = 0, // on-flash 字段名 header_size_2
    end_or_size: u32 = 0, // on-flash 字段名 total_size_2
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

/// BRLYT 的解析值：官方头 + 实测扩展槽位
pub const BromLayout = struct {
    name: [8]u8 = @splat(0),
    version: u32 = 0,
    header_size: u32 = 0,
    total_size: u32 = 0,
    region: [brlyt_max_regions]BromLayoutRegion = @splat(.{}),

    /// 从 BRLYT 起始处读取；调用方需保证 buf 至少有 brlyt_min_size 字节
    pub fn read(buf: []const u8) BromLayout {
        var h: BromLayout = .{};
        var raw: BromLayoutHeader = undefined;
        @memcpy(std.mem.asBytes(&raw), buf[0..@sizeOf(BromLayoutHeader)]);
        h.name = raw.name;
        h.version = raw.version;
        h.header_size = raw.header_size;
        h.total_size = raw.total_size;
        h.region[0] = .{
            .magic = raw.magic,
            .type = raw.type,
            .start = raw.header_size_2,
            .end_or_size = raw.total_size_2,
            .unused = raw.unused,
        };
        for (1..brlyt_max_regions) |i| {
            @memcpy(
                std.mem.asBytes(&h.region[i]),
                buf[@sizeOf(BromLayoutHeader) + (i - 1) * brlyt_region_size ..][0..brlyt_region_size],
            );
        }
        return h;
    }

    pub fn isValid(h: *const BromLayout) bool {
        return std.mem.eql(u8, cstr(&h.name), brlyt_name) and
            h.region[0].magic == brlyt_magic;
    }

    /// magic 有效的槽位数
    pub fn usedRegions(h: *const BromLayout) u32 {
        var n: u32 = 0;
        for (h.region) |rg| {
            if (rg.magic == brlyt_magic) n += 1;
        }
        return n;
    }
};

pub fn brlytRegionIndex(t: u32) u16 {
    return @truncate(t >> 16);
}

/// 槽位 type 若命中官方媒体枚举（BrlytImgType），返回其 flash 编号（低 16 位）。
/// 真机固件的槽位 type 多为 (index<<16)|flash 形式，只有媒体槽位会命中；
/// 用于 FILE_INFO.flash_type 的交叉验证（mtk_image.c verify_gfh 的思路）。
pub fn brlytMediaFlash(t: u32) ?u8 {
    return switch (t) {
        @intFromEnum(BrlytImgType.nand) => @truncate(t),
        @intFromEnum(BrlytImgType.emmc) => @truncate(t),
        @intFromEnum(BrlytImgType.nor) => @truncate(t),
        @intFromEnum(BrlytImgType.sdmmc) => @truncate(t),
        @intFromEnum(BrlytImgType.snand) => @truncate(t),
        else => null,
    };
}

pub fn brlytRegionFlash(t: u32) u16 {
    return @truncate(t);
}

/// flash 编号。官方 GfhFlashType 只定义 nand/gen；nor 来自 BRLYT_TYPE_NOR
/// 的低 16 位（*推测*同一套编号）。
pub const flash_type = struct {
    pub const nand: u8 = 2;
    pub const gen: u8 = 5;
    pub const nor: u8 = 7;
};

pub fn flashTypeName(t: u8) []const u8 {
    return switch (t) {
        flash_type.nand => "NAND",
        flash_type.gen => "GEN",
        flash_type.nor => "NOR",
        else => "unknown",
    };
}

// -- GFH 扩展 ------------------------------------------------

/// on-flash 大小（与官方 extern 结构互检，见文件尾 comptime 断言）
pub const gfh_common_header_size = 8;
pub const gfh_file_info_size = 0x38;

/// 解析用类型编号：官方值 + 本镜像观测到的 MTK 私有值（官方头未定义）
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

pub const sig_type_none: u8 = 0;
pub const sig_type_sha256: u8 = 1;

// 本镜像观测到的 file_type。*推测*：0x108 的名称是我们自己取的，官方文档无此值。
pub const file_type = struct {
    pub const bl: u16 = 0x001; // 一级 Bootloader
    pub const ext_bl: u16 = 0x002; // 二级 / 扩展 Bootloader
    pub const maui: u16 = 0x100; // MAUI 主固件
    pub const maui_108: u16 = 0x108; // 主固件之后的第二段镜像（*推测*）
};

/// GFH 体（body = GFH 头之后的 h.size - 8 字节）。
/// 官方定义过的类型经官方 extern 结构解析；私有类型只取实测能确认的部分
/// （字符串/魔数），其余保留原始字节预览，不做臆测字段名。
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

pub fn fileTypeName(t: u16) []const u8 {
    return switch (t) {
        file_type.bl => "BL (1st bootloader)",
        file_type.ext_bl => "ExtBL (2nd bootloader)",
        file_type.maui => "MAUI (main firmware)",
        file_type.maui_108 => "MAUI resource / 2nd image (*推测*)",
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

// ============================================================
// 3. 解析函数区（官方部分拷贝到栈上官方结构再取字段）
// ============================================================

/// GFH 魔数廉价探测（全文件扫描的热路径，逐字节偏移都会调用）
pub fn gfhMagicOk(p: []const u8) bool {
    return p.len >= gfh_common_header_size and p[0] == 'M' and p[1] == 'M' and p[2] == 'M';
}

/// 读 GFH 通用头；调用方需保证 p 至少有 gfh_common_header_size 字节
pub fn gfhRead(p: []const u8) GfhCommonHeader {
    var raw: GfhCommonHeader = undefined;
    @memcpy(std.mem.asBytes(&raw), p[0..gfh_common_header_size]);
    return raw;
}

/// 未能按官方/实测布局解析时的兜底：原始字节预览
fn gfhRawBody(size: u16, entry: []const u8) GfhBody {
    var preview: [16]u8 = @splat(0);
    const body = entry[@min(entry.len, gfh_common_header_size)..];
    const n = @min(body.len, preview.len);
    @memcpy(preview[0..n], body[0..n]);
    return .{ .raw = .{ .len = if (size > gfh_common_header_size) size - gfh_common_header_size else 0, .preview = preview } };
}

/// 读一个 GFH 条目体。`entry` 从 GFH 头（"MMM"）起；`size` 为该条目声明的
/// 总大小（含头）。官方类型的长度不足时退回 raw，不再越界硬读。
pub fn gfhBodyRead(t: u16, size: u16, entry: []const u8) GfhBody {
    const body = entry[gfh_common_header_size..];
    return switch (t) {
        gfh_type.bl_info => blk: {
            if (size < @sizeOf(GfhBlInfo)) break :blk gfhRawBody(size, entry);
            var raw: GfhBlInfo = undefined;
            @memcpy(std.mem.asBytes(&raw), entry[0..@sizeOf(GfhBlInfo)]);
            break :blk .{ .bl_info = .{ .attr = raw.attr } };
        },
        gfh_type.anti_clone => blk: {
            if (size < @sizeOf(GfhAntiClone)) break :blk gfhRawBody(size, entry);
            var raw: GfhAntiClone = undefined;
            @memcpy(std.mem.asBytes(&raw), entry[0..@sizeOf(GfhAntiClone)]);
            break :blk .{ .anti_clone = .{
                .ac_b2k = raw.ac_b2k,
                .ac_b2c = raw.ac_b2c,
                .ac_offset = raw.ac_offset,
                .ac_len = raw.ac_len,
            } };
        },
        gfh_type.brom_cfg => blk: {
            if (size < @sizeOf(GfhBromCfg)) break :blk gfhRawBody(size, entry);
            var raw: GfhBromCfg = undefined;
            @memcpy(std.mem.asBytes(&raw), entry[0..@sizeOf(GfhBromCfg)]);
            break :blk .{ .brom_cfg = .{
                .cfg_bits = raw.cfg_bits,
                .usbdl_by_auto_detect_timeout_ms = raw.usbdl_by_auto_detect_timeout_ms,
                .jump_bl_arm64 = raw.jump_bl_arm64,
                .usbdl_by_kcol0_timeout_ms = raw.usbdl_by_kcol0_timeout_ms,
                .usbdl_by_flag_timeout_ms = raw.usbdl_by_flag_timeout_ms,
            } };
        },
        gfh_type.brom_sec_cfg => blk: {
            if (size < @sizeOf(GfhBromSecCfg)) break :blk gfhRawBody(size, entry);
            var raw: GfhBromSecCfg = undefined;
            @memcpy(std.mem.asBytes(&raw), entry[0..@sizeOf(GfhBromSecCfg)]);
            var name: [33]u8 = @splat(0);
            fixedStr(&name, &raw.customer_name);
            break :blk .{ .brom_sec_cfg = .{ .cfg_bits = raw.cfg_bits, .customer_name = name } };
        },
        gfh_type.bl_sec_key => .{ .bl_sec_key = .{
            .pad_len = if (size > gfh_common_header_size) size - gfh_common_header_size else 0,
        } },
        gfh_type.emi_info => blk: {
            // 私有类型（*推测*）：body = [0]=version, [4]=flags, [8]="EMI_INF\0"
            if (size < gfh_common_header_size + 0x10) break :blk gfhRawBody(size, entry);
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
            // 私有类型（*推测*）：body[0]=工程名(NUL 结尾), body[0x80]=版本字符串
            if (size < gfh_common_header_size + 0x81) break :blk gfhRawBody(size, entry);
            var project: [64]u8 = @splat(0);
            var ver: [64]u8 = @splat(0);
            readStr(&project, body[0..]);
            readStr(&ver, body[0x80..]);
            break :blk .{ .project_info = .{ .project = project, .version_str = ver } };
        },
        else => gfhRawBody(size, entry),
    };
}

/// 读 FILE_INFO；调用方需先用 fileInfoValid 确认（含 size == 0x38）
pub fn fileInfoRead(p: []const u8) GfhFileInfo {
    var raw: GfhFileInfo = undefined;
    @memcpy(std.mem.asBytes(&raw), p[0..gfh_file_info_size]);
    return raw;
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

// ============================================================
// 编译期布局断言：官方结构写错一个字段，这里立刻编译失败
// ============================================================

comptime {
    std.debug.assert(@sizeOf(GenBootHeader) == 0x200);
    std.debug.assert(@sizeOf(NandBootHeader) == 0x80);
    std.debug.assert(@sizeOf(GenDeviceHeader) == 0x600);
    std.debug.assert(@sizeOf(BromLayoutHeader) == 0x28);
    std.debug.assert(@sizeOf(BromLayoutRegion) == brlyt_region_size);
    std.debug.assert(@sizeOf(LkHdr) == 512);

    std.debug.assert(@sizeOf(GfhCommonHeader) == gfh_common_header_size);
    std.debug.assert(@sizeOf(GfhFileInfo) == gfh_file_info_size);
    std.debug.assert(@sizeOf(GfhBlInfo) == 12);
    std.debug.assert(@sizeOf(GfhAntiClone) == 20);
    std.debug.assert(@sizeOf(GfhBromSecCfg) == 0x30);
    std.debug.assert(@sizeOf(GfhBromCfg) == 0x64);

    // BRLYT 最小头 = 官方头 + 7 个扩展槽位
    std.debug.assert(brlyt_min_size == @sizeOf(BromLayoutHeader) +
        (brlyt_max_regions - 1) * @sizeOf(BromLayoutRegion));
}

// 官方枚举与解析用常量互检：两处有一处失衡都会编译失败
comptime {
    std.debug.assert(@intFromEnum(GfhType.file_info) == gfh_type.file_info);
    std.debug.assert(@intFromEnum(GfhType.bl_info) == gfh_type.bl_info);
    std.debug.assert(@intFromEnum(GfhType.anti_clone) == gfh_type.anti_clone);
    std.debug.assert(@intFromEnum(GfhType.bl_sec_key) == gfh_type.bl_sec_key);
    std.debug.assert(@intFromEnum(GfhType.brom_cfg) == gfh_type.brom_cfg);
    std.debug.assert(@intFromEnum(GfhType.brom_sec_cfg) == gfh_type.brom_sec_cfg);

    std.debug.assert(@intFromEnum(GfhSigType.none) == sig_type_none);
    std.debug.assert(@intFromEnum(GfhSigType.sha256) == sig_type_sha256);
    std.debug.assert(@intFromEnum(GfhFlashType.nand) == flash_type.nand);
    std.debug.assert(@intFromEnum(GfhFlashType.gen) == flash_type.gen);
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

test "GfhCommonHeader reads magic and fields from raw bytes" {
    const raw = "\x4d\x4d\x4d\x03\x40\x00\x07\x00" ++ [_]u8{0} ** 0x10;
    const h = gfhRead(raw);
    try std.testing.expectEqualStrings("MMM", &h.magic);
    try std.testing.expectEqual(@as(u8, 3), h.version);
    try std.testing.expectEqual(@as(u16, 0x40), h.size);
    try std.testing.expectEqual(@as(u16, 7), h.type);
}
