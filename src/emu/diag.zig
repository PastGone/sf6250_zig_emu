//! 诊断钩子：PC 轨迹、阶段切换、入口断点、写监视、非法访问处理。
//!
//! 全部是宿主侧观测，不改变 guest 可见行为（唯一的例外是 `onMemInvalid`：
//! `--lenient` 下会替 guest 自动映射 4KB 页放行，见 docs/HANDOFF.md §5）。
//! 卡点定位方法论见 HANDOFF.md §5：先看访问计数/直方图，再动手接线。

const std = @import("std");
const log = @import("../log.zig");
const uc = @import("unicorn.zig");
const c = uc.c;
const machine = @import("machine.zig");
const Machine = machine.Machine;
const map = machine.map;
const bootrom = @import("bootrom.zig");

pub fn onCode(engine: ?*c.uc_engine, address: u64, size: u32, user: ?*anyopaque) callconv(.c) void {
    const m: *Machine = @ptrCast(@alignCast(user));
    m.instrs += 1;
    m.exec_hist[m.exec_hist_pos % m.exec_hist.len] = @truncate(address);
    m.exec_hist_pos += 1;
    if (address == 0x70009b20) {
        m.bss_calls += 1;
        var r0: u32 = 0;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        std.debug.print("[BSS #{d}] 0x{x:0>8} -> 0x{x:0>8} lr=0x{x:0>8}\n", .{ m.bss_calls, r0, r1, lr });
        m.bss_last_r0 = r0;
        m.bss_last_r1 = r1;
    }
    // 服务函数调用日志（BootROM 服务：0x70042100 + i*4）
    if (address >= bootrom.svc_code and address < bootrom.svc_code + 0x10) {
        var a0: u32 = 0;
        var a1r: u32 = 0;
        var a2r: u32 = 0;
        var a3r: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &a0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &a1r);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &a2r);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R3, &a3r);
        log.info(@src(), "  [BootROM服务] pc=0x{x:0>8} r0=0x{x:0>8} r1=0x{x:0>8} r2=0x{x:0>8} r3=0x{x:0>8}", .{ address, a0, a1r, a2r, a3r });
        if (a0 >= 0x7000_0000 and a0 < 0x7004_0000) {
            var buf: [32]u8 = undefined;
            if (c.uc_mem_read(engine, a0, &buf, buf.len) == c.UC_ERR_OK) {
                var hx: [3 * 32]u8 = undefined;
                var n: usize = 0;
                for (buf) |b| {
                    const p = std.fmt.bufPrint(hx[n..], "{x:0>2} ", .{b}) catch break;
                    n += p.len;
                }
                log.info(@src(), "  [BootROM服务] *r0 = {s}", .{hx[0..n]});
            }
        }
    }
    // r10(sl) 变化跟踪：定位它在哪里被清零/改写
    {
        var r10: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R10, &r10);
        if (r10 != m.last_r10) {
            if (m.instrs > 100000 or m.last_r10 != 0) {
                log.info(@src(), "  [r10变化] pc=0x{x:0>8} sl: 0x{x:0>8} → 0x{x:0>8} (instrs={d})", .{ address, m.last_r10, r10, m.instrs });
            }
            m.last_r10 = r10;
        }
    }
    // 关键地址命中（装载器等）：每个地址只报一次
    inline for (machine.landmarks, 0..) |lm, li| {
        if (address == lm and !m.landmark_hit[li]) {
            m.landmark_hit[li] = true;
            var lr: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
            log.info(@src(), "  [地标] pc=0x{x:0>8} lr=0x{x:0>8} (instrs={d})", .{ address, lr, m.instrs });
        }
    }
    if (m.instrs < 16) {
        var code: [8]u8 = @splat(0);
        _ = c.uc_mem_read(engine, address, &code, code.len);
        log.info(@src(), "  [入口] #{d} pc=0x{x:0>8} bytes={x:0>2}{x:0>2} {x:0>2}{x:0>2}", .{
            m.instrs, address, code[0], code[1], code[2], code[3],
        });
    }
    // 首次越界执行：PC 冲出已知代码区（>0x7000b000）时记录现场
    // 服务区之后的无人区被执行 = 滑行起点，抓第一现场
    if (address >= 0x7004_3000 and address < 0x701F_D000 and !m.stack_exec) {
        m.stack_exec = true;
        var lr: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        log.info(@src(), "  [滑行起点] pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            address, lr, sp, m.instrs,
        });
        m.dumpExecHist();
    }
    // 栈区被执行 = 返回地址/函数指针损坏，抓第一现场
    if (address >= 0x701FE000 and !m.stack_exec) {
        m.stack_exec = true;
        var lr: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        log.info(@src(), "  [栈执行] pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            address, lr, sp, m.instrs,
        });
        m.dumpExecHist();
    }
    if (address >= bootrom.svc_code + 0x10 and address < 0x701F_D000 and !m.wild_jumped) {
        m.wild_jumped = true;
        var lr: u32 = 0;
        var r0: u32 = 0;
        var r1r: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1r);
        log.info(@src(), "  [越界执行] pc=0x{x:0>8} lr=0x{x:0>8} r0=0x{x:0>8} r1=0x{x:0>8} (instrs={d})", .{
            address, lr, r0, r1r, m.instrs,
        });
        m.dumpExecHist();
    }
    if (address == 0x7000_844a and !m.bp_brlyt) {
        m.bp_brlyt = true;
        var r7: u32 = 0;
        var base: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R7, &r7);
        _ = c.uc_mem_read(engine, 0x7000_A0E4, &base, 4);
        var buf: [16]u8 = @splat(0);
        _ = c.uc_mem_read(engine, r7, &buf, buf.len);
        log.info(@src(), "  [BRLYT校验] 全局[0x7000a0e4]=0x{x:0>8} r7=基址+0x208=0x{x:0>8} 内容={s}", .{ base, r7, buf });
    }
    // 阶段入口：hook 报的是取指地址。Thumb 入口的 bit0 不在取指地址里，
    // 所以 0x10008061（镜像里的 Thumb 入口）实际表现为 0x10008060。
    if (address == 0x1000_8060) {
        m.bl2_entries += 1;
        if (m.bl2_entries <= 8 or m.bl2_entries % 64 == 0) {
            log.info(@src(), "★ 阶段切换: 进入 BL2 #{d} (0x10008061, 取指 0x10008060) instrs={d}", .{
                m.bl2_entries, m.instrs,
            });
        }
    }
    // 第一次在 flash/XIP 窗口执行：确认「谁在什么时候开始跑 flash 里的代码」
    if (address >= 0x1000_0000 and address < 0x1100_0000 and !m.flash_entered) {
        m.flash_entered = true;
        var lr: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        log.info(@src(), "  [flash 执行] 首次在 XIP 窗口取指 pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            address, lr, sp, m.instrs,
        });
    }
    if (address == 0x1002_0300) {
        log.info(@src(), "★ 阶段切换: 进入 MAUI (0x10020301, 取指 0x10020300)", .{});
    }
    // RAMF0（0xF0000000）里第一次执行：MAUI 会把代码拷进 RAMF0 再经 ARM veneer
    // （XIP 0x10078cd8 起）跳进去跑，记录入口地址以便停机时 dump
    if (address >= map.ramf0_base and address < map.ramf0_base + map.ramf0_size and m.ramf0_entry == 0) {
        m.ramf0_entry = @truncate(address);
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [RAMF0执行] 首次在 RAMF0 取指 pc=0x{x:0>8} lr=0x{x:0>8} (instrs={d})", .{
            address, lr, m.instrs,
        });
    }
    // --ramf0-lr：RAM 补丁区未装载时的诊断旁路（等价 bx lr），见字段注释
    if (m.ramf0_lr and address >= 0xf070_0000 and address < 0xf080_0000) {
        var lr: u32 = 0;
        var cpsr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr);
        cpsr = (cpsr & ~@as(u32, 0x20)) | ((lr & 1) << 5);
        var newpc: u32 = lr & ~@as(u32, 1);
        _ = c.uc_reg_write(engine, c.UC_ARM_REG_PC, &newpc);
        _ = c.uc_reg_write(engine, c.UC_ARM_REG_CPSR, &cpsr);
        if (!m.ramf0_slide) {
            m.ramf0_slide = true;
            log.info(@src(), "  [RAM补丁旁路] pc=0x{x:0>8} 未装载 → 等价 bx lr 到 0x{x:0>8} (instrs={d})", .{
                address, newpc, m.instrs,
            });
        }
        return;
    }
    // RAMF0 里「第一次取到全零指令」= 滑行起点（跳错地址/跑飞后 Thumb 0x0000 = NOP）。
    // 这条日志的第一现场能直接指出是谁跳进来的（lr/sp + 末尾轨迹）。
    if (address >= map.ramf0_base and address < map.ramf0_base + map.ramf0_size and !m.ramf0_slide) {
        var word: [4]u8 = undefined;
        if (c.uc_mem_read(engine, address, &word, word.len) == c.UC_ERR_OK and
            std.mem.eql(u8, &word, &[_]u8{ 0, 0, 0, 0 }))
        {
            m.ramf0_slide = true;
            var lr: u32 = 0;
            var sp: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
            log.info(@src(), "  [RAMF0滑行] 取到零指令 pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
                address, lr, sp, m.instrs,
            });
            m.dumpExecHist();
        }
    }
    // 第一次在低 RAM（EMI 重映射后的 0x0 区）0x1000 以上取指：说明有代码被拷进
    // RAM 执行（MAUI 的早期搬运阶段），这是「静态镜像里没有的代码」的来源线索
    if (address >= 0x1000 and address < 0x0010_0000 and !m.low_ram_entered) {
        m.low_ram_entered = true;
        var lr: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        log.info(@src(), "  [低RAM执行] 首次在 0x0 区 >0x1000 取指 pc=0x{x:0>8} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            address, lr, sp, m.instrs,
        });
    }
    if (address == 0x700082e0) {
        m.init_entries += 1;
        if (m.init_entries <= 8 or m.init_entries % 64 == 0) {
            log.info(@src(), "  [init_dispatch] 第 {d} 次进入 instrs={d}", .{ m.init_entries, m.instrs });
        }
    }
    if (address == 0x700082e0 and !m.bp_logged) {
        m.bp_logged = true;
        var r0: u32 = 0;
        var r1: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [断点] 0x700082e0 入口: r0=0x{x:0>8} r1=0x{x:0>8} lr=0x{x:0>8}", .{ r0, r1, lr });
        m.dumpExecHist();
        // 导出运行时 SRAM hex，供离线反汇编（蹦床 + 传参处两段）
        inline for (.{ 0x70008200, 0x70009200, 0x70009300, 0x70009400, 0x70009500, 0x70009600, 0x70009700, 0x70009800, 0x70009900, 0x70009A00 }) |base| {
            var mem: [0x100]u8 = undefined;
            if (c.uc_mem_read(engine, base, &mem, mem.len) == c.UC_ERR_OK) {
                var hx: [3 * 0x100]u8 = undefined;
                var n: usize = 0;
                for (mem) |b| {
                    const p = std.fmt.bufPrint(hx[n..], "{x:0>2}", .{b}) catch break;
                    n += p.len;
                }
                log.info(@src(), "RUNTIMESRAM:{x:0>8}:{s}", .{ base, hx[0..n] });
            }
        }
    }
    if (m.trace) {
        log.debug(@src(), "pc=0x{x:0>8} size={d}", .{ address, size });
    }
}

/// RAMF0 写监视：crt0 装载器把驱动/表段搬进 OS 数据区时抓第一现场（前 16 次）
pub fn onRamF0Write(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    const m: *Machine = @ptrCast(@alignCast(user));
    // 只关心 0xF0700000+ 的「RAM 代码区」（veneer 表 0x10078cd8 的目标都在这里）；
    // 0xF03Bxxxx/0xF05Exxxx 是 crt0 搬的数据/表段，先不刷屏
    if (address >= 0xf070_0000 and address < 0xf080_0000 and m.ramf0_wr < 16) {
        var pc: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [RAMF0写] pc=0x{x:0>8} lr=0x{x:0>8} -> [0x{x:0>8}] = 0x{x} size={d}", .{
            pc, lr, address, @as(u64, @bitCast(value)), size,
        });
    }
    m.ramf0_wr += 1;
    return true;
}

/// 回调表写监视：记录 PC 与写入值（前 32 次）
pub fn onTblWrite(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    if (address == 0x7000A114) {
        var pc: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [表写] pc=0x{x:0>8} lr=0x{x:0>8} -> [0x{x:0>8}] = 0x{x:0>8}", .{
            pc, lr, address, @as(u64, @bitCast(value)),
        });
    }
    m.tbl_wr += 1;
    return true;
}

/// 服务表写监视：抓改写服务指针的代码（前 16 次）
pub fn onSvcTableWrite(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    if (m.svc_wr < 16) {
        var pc: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [服务表写] pc=0x{x:0>8} lr=0x{x:0>8} -> [0x{x:0>8}] = 0x{x:0>8}", .{
            pc, lr, address, @as(u64, @bitCast(value)),
        });
    }
    m.svc_wr += 1;
    return true;
}

/// 低 RAM 写监视：EMI 重映射后谁在安装 RAM 函数（前 24 次）
pub fn onLowRamWrite(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    if (m.lowram_wr < 24) {
        var pc: u32 = 0;
        _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
        log.info(@src(), "  [低RAM写] pc=0x{x:0>8} -> [0x{x:0>8}] = 0x{x:0>8}", .{
            pc, address, @as(u64, @bitCast(value)),
        });
    }
    m.lowram_wr += 1;
    return true;
}

pub fn onMemInvalid(
    uc_engine: ?*c.uc_engine,
    typ: c.uc_mem_type,
    address: u64,
    size: c_int,
    value: i64,
    user: ?*anyopaque,
) callconv(.c) bool {
    const m: *Machine = @ptrCast(@alignCast(user));

    const kind: [:0]const u8 = switch (typ) {
        c.UC_MEM_READ_UNMAPPED => "read unmapped",
        c.UC_MEM_WRITE_UNMAPPED => "write unmapped",
        c.UC_MEM_FETCH_UNMAPPED => "fetch unmapped",
        c.UC_MEM_READ_PROT => "read protected",
        c.UC_MEM_WRITE_PROT => "write protected",
        c.UC_MEM_FETCH_PROT => "fetch protected",
        else => "invalid",
    };
    _ = m.recordFault(address, kind);

    var pc: u32 = 0;
    _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);

    if (m.lenient) {
        // 读写未映射：自动映射所在 4KB 页（RW，内容为 0）再放行——探针框架
        // 的能力，让容量探测/预分配式访问自然通过。取指未映射无法放行。
        switch (typ) {
            c.UC_MEM_READ_UNMAPPED, c.UC_MEM_WRITE_UNMAPPED => {
                const page = address & ~@as(u64, 0xFFF);
                const rw: u32 = c.UC_PROT_READ | c.UC_PROT_WRITE;
                m.eng.memMap(page, 0x1000, rw) catch {}; // 已映射则忽略
            },
            else => {},
        }
        if (typ == c.UC_MEM_FETCH_UNMAPPED or typ == c.UC_MEM_FETCH_PROT) {
            log.info(@src(), "  [取指失败] {s} 目标=0x{x:0>8} pc=0x{x:0>8} ← 跳转指令在此", .{
                kind, address, pc,
            });
        } else {
            log.debug(@src(), "{s} @0x{x:0>8} size={d} pc=0x{x:0>8} (宽容放行)", .{
                kind, address, size, pc,
            });
        }
        return true;
    }

    log.warn(@src(), "{s} @0x{x:0>8} size={d} value=0x{x} pc=0x{x:0>8}", .{
        kind, address, size, @as(u64, @bitCast(value)), pc,
    });

    m.eng.emuStop() catch {};
    return false;
}
