//! 设备头（文件偏移 0x000，大小 0x200）。
//!
//! 镜像最开头的 13 字节名字决定这是哪类闪存的 boot 镜像。

const std = @import("std");
const bytes = @import("bytes.zig");
const le32 = bytes.le32;
const fixedStr = bytes.fixedStr;
const cstr = bytes.cstr;

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
