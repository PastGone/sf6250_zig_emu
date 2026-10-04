//! 把 `BootImage` 完整打印出来（走 log.info；可疑之处用 log.warn）。

const std = @import("std");
const log = @import("../log.zig");
const bytes = @import("bytes.zig");
const cstr = bytes.cstr;
const hexPreview = bytes.hexPreview;

const brlyt = @import("brlyt.zig");
const gfh = @import("gfh.zig");
const image = @import("image.zig");

pub fn dump(img: *const image.BootImage) void {
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
        brlyt.brlyt_max_regions,
    });

    if (img.project[0] != 0)
        log.info(@src(), "  project: \"{s}\"", .{cstr(&img.project)});

    for (0..brlyt.brlyt_max_regions) |i| {
        const rg = &img.brlyt.region[i];

        if (rg.magic != brlyt.brlyt_magic) {
            log.info(@src(), "    region[{d}]: <empty>", .{i});
            continue;
        }

        const index = brlyt.brlytRegionIndex(rg.@"type");
        const flash = brlyt.brlytRegionFlash(rg.@"type");

        switch (rg.kind()) {
            .memory_view => {
                log.info(@src(), "    region[{d}]: index=0x{x:0>4} flash=0x{x:0>4} memory view addr=0x{x:0>8} size=0x{x:0>8} flags=0x{x:0>8}", .{
                    i, index, flash, rg.start, rg.size(), rg.unused,
                });
                if (index != brlyt.brlyt_index_reserved) {
                    log.warn(@src(), "      region[{d}]: index != 0xfffe 但 start 落在 SRAM 窗口，语义待确认", .{i});
                }
            },
            .file_offset => {
                var label: []const u8 = "<unresolved>";
                for (img.image[0..img.image_count]) |*candidate| {
                    if (candidate.offset == rg.start) label = gfh.fileTypeName(candidate.file_type);
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
            gfh.fileTypeName(im.file_type),
            im.load_addr,
            im.entry_point,
            im.jump_offset,
            im.sig_type,
            im.flash_type,
            brlyt.flashTypeName(im.flash_type),
            im.processed,
            im.max_size,
            im.hdr_size,
            image.payload(img, im).len,
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
                log.warn(@src(), "        ! GFH 条目数超过上限 {d}，链可能不完整", .{image.gfh_max});
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
                gfh.gfhTypeName(e.@"type"),
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
