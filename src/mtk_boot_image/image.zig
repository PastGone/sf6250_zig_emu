//! 镜像表：解析结果的数据结构，以及 BRLYT / 全文件扫描两个登记入口。

const std = @import("std");

const bytes = @import("bytes.zig");
const fixedStr = bytes.fixedStr;
const crc32 = bytes.crc32;
const looksLikeStr = bytes.looksLikeStr;
const firstNonEqual = bytes.firstNonEqual;
const lastNonEqual = bytes.lastNonEqual;
const findAscii = bytes.findAscii;

const fmt = @import("format.zig");

pub const image_max = 16;
pub const gfh_max = 16;

pub const GfhEntry = struct {
    offset: u32 = 0,
    type: u16 = 0,
    size: u16 = 0,
    version: u8 = 0,
    // 仅用于 dump 展示，不是 on-flash 字段：官方头里只有 gfh_file_info 的
    // name[12]，这里要装下 PROJECT_INFO 里的完整工程名，故取 63 字节 + NUL。
    name: [64]u8 = @splat(0),
    body: fmt.GfhBody = .empty,
};

/// sig_type == sha256 时按 U-Boot 生成器布局（mtk_image.c put_hash）的校验结果。
/// 真机工具的签名布局可能与 U-Boot 不同，不匹配只报告、不当硬错误。
pub const SigSha256 = enum { none, ok, mismatch };

/// 完整性/一致性检查的结果。任何一项为真都应该在 dump 里用 warn 报出来。
pub const Integrity = struct {
    sig_unverified: bool = false, // sig_type != NONE（镜像带签名；结果见 sig_sha256）
    bad_hdr_size: bool = false, // hdr_size > total_size
    sig_overlap: bool = false, // hdr_size + sig_size > total_size
    gfh_chain_mismatch: bool = false, // GFH 链终点 != offset + hdr_size
    gfh_truncated: bool = false, // GFH 数组溢出或未走到 hdr_size
    flash_type_mismatch: bool = false, // FILE_INFO.flash_type 与 BRLYT 媒体类型不符
    sig_sha256: SigSha256 = .none,

    pub fn any(self: *const Integrity) bool {
        return self.sig_unverified or self.bad_hdr_size or self.sig_overlap or
            self.gfh_chain_mismatch or self.gfh_truncated or
            self.flash_type_mismatch or self.sig_sha256 == .mismatch;
    }
};

/// 容器级（设备头 / BRLYT）一致性检查，规则出自 U-Boot mtk_image.c 的
/// verify 路径（verify_gen_header / put_brom_layout_header / put_hash）。
pub const ContainerChecks = struct {
    /// 设备头 version != 1 或 size != 0x200（官方期望）
    boot_header_odd: bool = false,
    /// BRLYT 不在期望偏移 0x200（官方按 boot.size 自描述定位）
    brlyt_offset_moved: bool = false,
    /// 没有任何槽位 type 命中官方媒体枚举 BrlytImgType
    brlyt_no_media_type: bool = false,
    /// header_size_2/total_size_2 副本与正本不一致（官方生成器令二者相等）
    brlyt_copy_mismatch: bool = false,
    /// BRLYT.header_size 处没有镜像起点（官方：首个 GFH 链在这里）
    first_image_mismatch: bool = false,
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
    /// 不拥有数据，指向调用者的缓冲区；调用者必须保证数据在 BootImage 使用期间有效。
    data: []const u8 = &.{},
    boot: fmt.BootHeader = .{},
    brlyt: fmt.BromLayout = .{},
    /// BRLYT 实际所在偏移（官方按 boot.size 自描述定位，通常为 0x200）
    brlyt_offset: u32 = 0,
    brlyt_region_count: u32 = 0,
    /// BRLYT 媒体槽位推导出的 flash 编号（无槽位命中官方枚举时为 null）
    media_flash: ?u8 = null,

    project: [64]u8 = @splat(0),

    image: [image_max]Image = @splat(.{}),
    image_count: u32 = 0,
    /// BRLYT 槽位直接给出的镜像数量（扫描之前）
    brlyt_image_count: u32 = 0,

    checks: ContainerChecks = .{},
    scan: ScanStats = .{},
    tail: TailInfo = .{},
};

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
    var cur: usize = im.offset + fmt.gfh_file_info_size;
    const end: usize = im.offset + im.hdr_size;

    if (im.hdr_size < fmt.gfh_file_info_size or end > img.data.len) {
        im.integrity.bad_hdr_size = true;
        im.gfh_chain_end = @intCast(cur);
        return;
    }

    while (cur + fmt.gfh_common_header_size <= end) {
        if (im.gfh_count >= gfh_max) {
            im.integrity.gfh_truncated = true;
            break;
        }
        if (!fmt.gfhMagicOk(base[cur..])) break;

        const h = fmt.gfhRead(base[cur..]);
        if (h.size < fmt.gfh_common_header_size or cur + h.size > end) break;

        const e = &im.gfh[im.gfh_count];
        e.offset = @intCast(cur);
        e.type = h.type;
        e.size = h.size;
        e.version = h.version;
        const body = base[cur + 8 ..][0 .. h.size - 8];
        e.body = fmt.gfhBodyRead(h.type, h.size, base[cur..]);

        if (looksLikeStr(body)) fixedStr(&e.name, body);

        if (h.type == fmt.gfh_type.project_info and looksLikeStr(body))
            fixedStr(&img.project, body);

        im.gfh_count += 1;
        cur += h.size;
    }

    im.gfh_chain_end = @intCast(cur);
    if (im.gfh_chain_end != end) im.integrity.gfh_chain_mismatch = true;
}

/// 登记（并解析）一个位于 offset 处的镜像；offset 重复时直接复用已有条目。
/// 返回：加载到哪个槽位（找不到返回 null）
pub fn imageAdd(img: *BootImage, offset: u32) ?*Image {
    if (img.image_count >= image_max) return null;
    if (offset + fmt.gfh_file_info_size > img.data.len) return null;
    if (!fmt.fileInfoValid(img.data[offset..])) return null;

    const fi = fmt.fileInfoRead(img.data[offset..]);
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
    if (im.sig_type != fmt.sig_type_none) im.integrity.sig_unverified = true;
    if (im.hdr_size > im.total_size) im.integrity.bad_hdr_size = true;
    if (im.hdr_size +| im.sig_size > im.total_size) im.integrity.sig_overlap = true;

    // FILE_INFO.flash_type 与 BRLYT 媒体类型交叉核对（mtk_image.c verify_gfh）
    if (img.media_flash) |media| {
        if (im.flash_type != media) im.integrity.flash_type_mismatch = true;
    }

    imageCollectGfh(img, im);
    im.payload_crc32 = crc32(payload(img, im));

    // SHA256 尽力校验：U-Boot 生成器布局 = [镜像起点, 终点-32) 的摘要存末
    // 32 字节（put_hash）；变体只覆盖载荷区。真机工具布局可能不同，不匹配
    // 仅报告、不当硬错误。
    if (im.sig_type == fmt.sig_type_sha256 and im.end >= im.offset + im.hdr_size + 32) {
        const tail = img.data[im.end - 32 ..][0..32];
        var digest: [32]u8 = undefined;
        const Sha256 = std.crypto.hash.sha2.Sha256;
        Sha256.hash(img.data[im.offset .. im.end - 32], &digest, .{});
        if (!std.mem.eql(u8, &digest, tail)) {
            Sha256.hash(img.data[im.offset + im.hdr_size .. im.end - 32], &digest, .{});
        }
        im.integrity.sig_sha256 = if (std.mem.eql(u8, &digest, tail))
            SigSha256.ok
        else
            SigSha256.mismatch;
    }

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
pub fn imageScanAll(img: *BootImage) void {
    const size = img.data.len;
    var off: usize = 0;

    while (off + fmt.gfh_file_info_size <= size and img.image_count < image_max) {
        if (!fmt.fileInfoValid(img.data[off..])) {
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

/// 分析最后一个镜像之后的剩余空间
pub fn analyzeTail(img: *BootImage) void {
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
