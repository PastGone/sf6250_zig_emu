//! ALICE 解码算法内核（Zig 移植自 donnm/mtk_fw_tools 的 unalice.py）。
//!
//! MTK 功能机固件的主体代码（ALICE_1 / ALICE_2 分区）并非原始存放，而是经过
//! **区间编码（range encoding）+ 位打包（bitpacked）** 压缩的 Thumb 指令流。
//! 真机上固件把它当**硬件解压引擎**调用（BL 0x10008994 / MAUI sub_100324B8：
//! 配寄存器 → 喂字典 → 写触发寄存器 → 轮询结果），CPU 全程不执行解压循环。
//! 本模块是该引擎的算法内核（移植自 unalice.py 对该格式的逆向），既可独立
//! 解压固件做逆向/校验，也作为模拟器里引擎模型的解码实现（见 periph.zig
//! 的 aliceDecodeToTarget：源/目标/参数全部来自固件写入的引擎寄存器）。
//!
//! 与 unalice.py 的差异：
//!   - 只实现「原始解压」（untranslate_bl_blx 的 bl/blx 地址回填是给独立反汇编
//!     用的便利，固件自己产出的代码不依赖它，故这里不 Transl。需要时可加开关）。
//!   - 位流按 MSB-first 读取（与 python bitstring.BitArray 默认一致）。

const std = @import("std");

pub const Error = error{
    BadMagic,
    Truncated,
    DictOutOfRange,
};

const Mapping = struct { addr: u32, len: u32 };

/// 解压一段以 "ALICE_1"/"ALICE_2" 魔数开头的 ALICE blob，返回解码后的 Thumb
/// 指令字节流（小端 16 位指令）。调用方负责释放返回的切片。
pub fn decompress(allocator: std.mem.Allocator, blob: []const u8) ![]u8 {
    if (blob.len < 40) return Error.Truncated;

    const is_v1 = std.mem.eql(u8, blob[0..7], "ALICE_1");
    const is_v2 = std.mem.eql(u8, blob[0..7], "ALICE_2");
    if (!is_v1 and !is_v2) return Error.BadMagic;

    // ---- 头部 ----
    var header_size: u32 = 40;
    if (is_v1) {
        // ALICE_1 可能是 36 字节短头：offset 36 处应为 00 00 FF FF
        const alice1_end: [4]u8 = .{ 0, 0, 0xff, 0xff };
        if (blob.len >= 40 and !std.mem.eql(u8, blob[36..40], &alice1_end)) {
            header_size = 36;
        } else if (blob.len < 40) {
            header_size = 36;
        }
    }

    const base = std.mem.readInt(u32, blob[8..][0..4], .little);
    const mapping_offset_stored = std.mem.readInt(u32, blob[12..][0..4], .little);
    const dict_offset_stored = std.mem.readInt(u32, blob[16..][0..4], .little);
    // unalice.py: mapping_offset -= base - header_size
    const base_adj = base -% header_size;
    const mapping_offset = mapping_offset_stored -% base_adj;
    const dict_offset = dict_offset_stored -% base_adj;

    if (header_size > mapping_offset or mapping_offset > dict_offset or dict_offset > blob.len)
        return Error.Truncated;

    // ---- 区间寄存器（7 个 u16，再追加一个 16 作为稀有指令区间长度）----
    var range_regs: [8]u32 = undefined;
    var i: usize = 0;
    while (i < 7) : (i += 1) {
        range_regs[i] = std.mem.readInt(u16, blob[20 + i * 2 ..][0..2], .little);
    }
    range_regs[7] = 16;

    // offset 34..36 的两字节（header 内）跳过
    var blocksize: u32 = 0;
    if (header_size == 40 and blob.len >= 38) {
        blocksize = std.mem.readInt(u16, blob[36..][0..2], .little);
    }
    if (blocksize == 0) blocksize = 64; // ALICE_1 默认块大小

    const compressed = blob[header_size..mapping_offset];
    const maptable = blob[mapping_offset..dict_offset];
    const dict_region = blob[dict_offset..];

    // ---- 映射表：每个 u32，拆出 addr(低24位) 与 len ----
    var mappings = std.ArrayList(Mapping).initCapacity(allocator, 0) catch |e| return e;
    defer mappings.deinit(allocator);
    {
        var p: usize = 0;
        while (p + 4 <= maptable.len) : (p += 4) {
            const m = std.mem.readInt(u32, maptable[p..][0..4], .little);
            const addr = m & 0x00ff_ffff;
            var length: u32 = m & 0xff00_0000;
            if (length != 0) {
                length = (((m & 0xff00_0000) >> 26) + ((3 * (blocksize / 2)) >> 3)) + 1;
            }
            try mappings.append(allocator, .{ .addr = addr, .len = length });
        }
    }

    // ---- 字典：u16 小端指令数组 ----
    const dict_n = dict_region.len / 2;
    _ = dict_n;

    // ---- 区间寄存器相关向量 ----
    const starts = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var prefixes: [8]u32 = undefined;
    var lengths: [8]u32 = undefined;
    var range_regs_pow: [8]u32 = undefined;
    {
        var k: usize = 0;
        while (k < 8) : (k += 1) {
            prefixes[k] = starts[k] << @intCast(range_regs[k]);
            lengths[k] = range_regs[k] + 3;
        }
        range_regs_pow[0] = 0;
        var k2: usize = 0;
        while (k2 < 7) : (k2 += 1) {
            range_regs_pow[k2 + 1] = std.math.pow(u32, 2, range_regs[k2]);
        }
    }

    // ---- 位流读取（MSB-first）----
    var br = BitReader{ .data = compressed };

    var out = std.ArrayList(u8).initCapacity(allocator, 0) catch |e| return e;
    var byteswritten: usize = 0;
    var numblocks: usize = 0;
    var lastblock = false;
    var lastinstr: u32 = 0;

    const map_n = mappings.items.len;
    const loop_bound_bits: usize = if (map_n > 0)
        (mappings.items[map_n - 1].addr + mappings.items[map_n - 1].len) * 8
    else
        compressed.len * 8;

    while (br.bitpos < loop_bound_bits and br.bitpos + 64 <= compressed.len * 8) {
        // 块边界对齐：每写完 blocksize 字节，跳过当前字节剩余位到下一字节起点
        if (blocksize != 0 and byteswritten % blocksize == 0) {
            if (br.bitpos % 8 != 0) br.bitpos += 8 - (br.bitpos % 8);
            numblocks += 1;
            if (map_n > 1 and (@as(f64, @floatFromInt(numblocks)) / 2.0) / @as(f64, @floatFromInt(map_n - 1)) > 0.999) {
                lastblock = true;
            }
        }

        // 3 位前缀 s 唯一确定区间与长度：starts 即 0..7，peeks 出来的 3 位就是 s
        const s = br.peek(3);
        const l = lengths[s];

        // EOF 启发式（与 unalice.py 一致）：必须在“消费指令位之前”用指令起点处
        // 的后续 64 位判断，否则会多看 l 位、导致提前/延后停止 1 条指令。
        if (lastblock) {
            const ones = br.peekOnes(64);
            if (ones < 2) break;
        }

        const instr = br.read(l);

        if (lastblock) {
            if (instr == 1 and s == 0 and lastinstr == 0xeaff) break;
        }

        var originstr: u32 = 0;
        if (s != 7) {
            var low: u32 = 0;
            var k: usize = 0;
            while (k <= s) : (k += 1) low += range_regs_pow[k];
            const instridx = instr - prefixes[s];
            const didx = low + instridx;
            if (didx * 2 + 2 > dict_region.len) return Error.DictOutOfRange;
            originstr = std.mem.readInt(u16, dict_region[didx * 2 ..][0..2], .little);
        } else {
            originstr = instr & 0xffff;
        }

        lastinstr = originstr;
        try out.append(allocator, @truncate(originstr & 0xff));
        try out.append(allocator, @truncate((originstr >> 8) & 0xff));
        byteswritten += 2;
    }

    return out.toOwnedSlice(allocator);
}

/// MSB-first 位读取器。bitpos 以「位」为单位。
const BitReader = struct {
    data: []const u8,
    bitpos: usize = 0,

    fn read(self: *BitReader, n: usize) u32 {
        var val: u32 = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            if (self.bitpos >= self.data.len * 8) break; // EOF：缺失位按 0 补在低位
            const byte = self.data[self.bitpos / 8];
            const bit = (byte >> @intCast(7 - (self.bitpos % 8))) & 1;
            val = (val << 1) | bit;
            self.bitpos += 1;
        }
        // 已读 i 位为高位，缺失位（n-i）补 0 在低位，等价于 Python 短切片 .uint
        return val << @intCast(n - i);
    }

    fn peek(self: *BitReader, n: usize) u32 {
        const save = self.bitpos;
        const v = self.read(n);
        self.bitpos = save;
        return v;
    }

    /// 统计从当前位置起（不消费）最多 64 位里「1」的个数（EOF 启发式用）。
    fn peekOnes(self: *BitReader, n: usize) usize {
        const avail = @min(n, self.data.len * 8 - self.bitpos);
        var ones: usize = 0;
        var i: usize = 0;
        while (i < avail) : (i += 1) {
            const byte = self.data[(self.bitpos + i) / 8];
            const bit = (byte >> @intCast(7 - ((self.bitpos + i) % 8))) & 1;
            ones += bit;
        }
        return ones;
    }
};
