const std = @import("std");

const log = @import("log.zig");
const mtk = @import("mtk_boot_image/mtk_boot_image.zig");
const emu = @import("emu/emu.zig");

/// LCD 尺寸：真机面板参数还没拿到，先按功能机常见的 240x320 开窗口。
const lcd_width = 240;
const lcd_height = 320;

/// 待模拟的固件：原始字节 + 解析结果。
/// `image` 不拥有数据，其 `data` 指向这里的 `data`（由调用方的 arena 持有）。
const Firmware = struct {
    data: []const u8,
    image: mtk.BootImage,
};

/// 读文件并解析成 Firmware；失败时已经把原因打到日志里，返回 null。
fn loadFirmware(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ?Firmware {
    const data = mtk.loadFile(io, allocator, path) catch |err| {
        log.err(@src(), "failed to load \"{s}\" (rc={s})", .{ path, @errorName(err) });
        return null;
    };

    var fw: Firmware = .{ .data = data, .image = undefined };
    mtk.parse(data, &fw.image) catch |err| {
        log.err(@src(), "failed to parse \"{s}\" (rc={s})", .{ path, @errorName(err) });
        return null;
    };
    return fw;
}

pub fn main(init: std.process.Init) !void {
    // 镜像缓冲区与 argv 都活到进程结束，交给 Init 的 arena 即可。
    const arena = init.arena.allocator();
    const io = init.io;
    log.init(io, init.environ_map) catch |e| {
        std.debug.print("failed to init logger: {s}\n", .{@errorName(e)});
        return;
    };
    defer log.deinit();

    const args = try init.minimal.args.toSlice(arena);
    // ALICE 软件解码子命令：`alice <in.bin> <out.bin>` 把 ALICE 压缩分区解压成
    // Thumb 指令流。用于独立解压/校验固件，也验证本模拟器的软件解码实现。
    if (args.len >= 3 and std.mem.eql(u8, args[1], "alice")) {
        const blob = mtk.loadFile(io, arena, args[2]) catch |e| {
            log.err(@src(), "failed to read ALICE 输入 \"{s}\" ({s})", .{ args[2], @errorName(e) });
            return;
        };
        // 收集所有 ALICE 分区起点（ALICE_1 / ALICE_2 魔数）
        var offs = std.ArrayList(usize).initCapacity(arena, 0) catch |e| return e;
        {
            var p: usize = 0;
            while (p + 7 <= blob.len) : (p += 1) {
                const tail = blob[p..][0..7];
                if (std.mem.eql(u8, tail, "ALICE_1") or std.mem.eql(u8, tail, "ALICE_2")) {
                    try offs.append(arena, p);
                    p += 6; // 跳过魔数，避免重叠匹配
                }
            }
        }
        if (offs.items.len == 0) {
            // 整个文件就是一个裸 ALICE blob
            const decoded = emu.alice.decompress(arena, blob) catch |e| {
                log.err(@src(), "ALICE 解压失败 ({s})", .{@errorName(e)});
                return;
            };
            const out_path = if (args.len >= 4) args[3] else "alice-out.bin";
            std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{ .sub_path = out_path, .data = decoded }) catch |e| {
                log.err(@src(), "写入 \"{s}\" 失败 ({s})", .{ out_path, @errorName(e) });
                return;
            };
            log.info(@src(), "ALICE 解压(裸blob): {d} → {d} 字节 (输出 {s})", .{ blob.len, decoded.len, out_path });
            return;
        }
        // 逐个分区解压：每段从魔数到下一个魔数（最后一段到文件尾）
        for (offs.items, 0..) |off, idx| {
            const end = if (idx + 1 < offs.items.len) offs.items[idx + 1] else blob.len;
            const sub = blob[off..end];
            const decoded = emu.alice.decompress(arena, sub) catch |e| {
                log.err(@src(), "ALICE 分区@{x} 解压失败 ({s})", .{ off, @errorName(e) });
                continue;
            };
            var name: [64]u8 = undefined;
            const n = std.fmt.bufPrint(&name, "alice_{x}.bin", .{off}) catch "alice.bin";
            std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{ .sub_path = n, .data = decoded }) catch |e| {
                log.err(@src(), "写入 {s} 失败 ({s})", .{ n, @errorName(e) });
                continue;
            };
            log.info(@src(), "ALICE 分区[{d}] @{x}: 压缩 {d} → {d} 字节 (输出 {s})", .{ idx, off, sub.len, decoded.len, n });
        }
        return;
    }
    // 第一个非 --xxx 的参数才是镜像路径，其余当开关处理
    const path = firstPositional(args) orelse mtk.default_image;

    const fw = loadFirmware(io, arena, path) orelse return;

    log.info(@src(), "parsed \"{s}\"", .{path});
    mtk.dump(&fw.image);

    const lcd_only = hasArg(args, "--lcd");

    // 1. CPU：把 BL 装进 SRAM 跑一段，看它先碰到哪些外设
    var mach = try emu.Machine.init(arena, init.io);
    defer mach.deinit();
    mach.trace = hasArg(args, "--trace");
    mach.lenient = hasArg(args, "--lenient");
    // 诊断：MAUI 的 RAM 补丁代码区（0xf07xxxxx）在本镜像里无人装载，见字段注释
    mach.ramf0_lr = hasArg(args, "--ramf0-lr");
    // 诊断：flash 窗口也映射为可写（判断 XIP 地址到底会不会被 DMA/固件写）
    mach.flash_rw = hasArg(args, "--flash-rw");
    mach.cake_patch = hasArg(args, "--cake-patch");
    mach.dma_copy = hasArg(args, "--dma-copy");
    // 周期 tick（每 N 条指令一次中断，0 = 关）：用来启动 OS 调度
    mach.tick_interval = tickArg(args);
    mach.tick_irq = @truncate(tickArg2(args, "--tick-irq=", 11));

    mach.loadBootloader(&fw.image) catch |err| {
        log.err(@src(), "failed to load bootloader (rc={s})", .{@errorName(err)});
        return;
    };
    mach.mapFlashWindow(&fw.image) catch |err| {
        log.err(@src(), "failed to map flash window (rc={s})", .{@errorName(err)});
        return;
    };
    mach.mapExternalRam() catch |err| {
        log.err(@src(), "failed to map external RAM (rc={s})", .{@errorName(err)});
        return;
    };
    // MAUI 的 OS 数据区（0xF0000000 起 8MB）：就绪标志/调度栈都在这里
    mach.mapRamF0() catch |err| {
        log.err(@src(), "failed to map RAMF0 (rc={s})", .{@errorName(err)});
        return;
    };
    // 外设层常驻：已接线寄存器给行为，其余读 0/写丢弃并记名
    mach.mapPeriphStubs() catch |err| {
        log.err(@src(), "failed to map peripherals (rc={s})", .{@errorName(err)});
        return;
    };
    mach.run(budgetArg(args));

    // 2. LCD：窗口 + 一帧占位画面；带 --lcd 时进入事件循环
    var disp = try emu.Display.init("MT6250", lcd_width, lcd_height, 2);
    defer disp.deinit();

    @memset(disp.pixels, 0xff00_3000); // 占位：背光亮、无画面
    disp.present();

    while (lcd_only and disp.pump()) {
        disp.delay(8);
    }
}

fn hasArg(args: []const []const u8, flag: []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, flag)) return true;
    }
    return false;
}

fn firstPositional(args: []const []const u8) ?[]const u8 {
    for (args[1..]) |a| {
        if (!std.mem.startsWith(u8, a, "--")) return a;
    }
    return null;
}

/// `--tick=N`：每 N 条指令置一次中断（0 = 关，默认关）
fn tickArg(args: []const []const u8) u64 {
    return tickArg2(args, "--tick=", 0);
}

fn tickArg2(args: []const []const u8, prefix: []const u8, dflt: u64) u64 {
    for (args) |a| {
        if (std.mem.startsWith(u8, a, prefix)) {
            return std.fmt.parseInt(u64, a[prefix.len..], 0) catch dflt;
        }
    }
    return dflt;
}

/// `--budget=N`：指令预算（十进制或 0x 十六进制），默认 100M。
/// 推进启动链时按需缩短，用来快速定位「先撞上谁」。
fn budgetArg(args: []const []const u8) u64 {
    for (args) |a| {
        if (std.mem.startsWith(u8, a, "--budget=")) {
            const v = a["--budget=".len..];
            return std.fmt.parseInt(u64, v, 0) catch 100_000_000;
        }
    }
    return 100_000_000;
}
