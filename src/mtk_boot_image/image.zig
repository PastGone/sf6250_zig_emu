//! 镜像表：解析结果的数据结构，以及 BRLYT / 全文件扫描两个登记入口。

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
    /// 不拥有数据，指向调用者的缓冲区；调用者必须保证数据在 BootImage 使用期间有效。
    data: []const u8 = &.{},
    boot: fmt.BootHeader = .{},
    brlyt: fmt.BromLayout = .{},
    brlyt_region_count: u32 = 0,

    project: [64]u8 = @splat(0),

    image: [image_max]Image = @splat(.{}),
    image_count: u32 = 0,
    /// BRLYT 槽位直接给出的镜像数量（扫描之前）
    brlyt_image_count: u32 = 0,

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
