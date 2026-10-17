//! 诊断钩子：PC 轨迹、阶段切换、入口断点、写监视、非法访问处理。
//!
//! 全部是宿主侧观测，不改变 guest 可见行为（唯一的例外是 `onMemInvalid`：
//! `--lenient` 下会替 guest 自动映射 4KB 页放行，见 docs/HANDOFF.md §5）。
//! 卡点定位方法论见 HANDOFF.md §5：先看访问计数/直方图，再动手接线。

const std = @import("std");
const log = @import("../log.zig");
const init = @import("init");
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
        if (m.bss_calls <= 60 or m.bss_calls % 200 == 0) {
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
    // 装载原语 sub_100023F0（SRAM 0x70009BF0）的调用现场：r0=dst r1=src r2=size。
    // 这是 BL/ExtBL 通用镜像装载器（IDA: sub_10001678 里调它），把每一段的
    // 搬运目标/长度直接打出来，用来回答「0xF07xxxxx 到底谁搬」。
    if (address == 0x7000_9BF0 and m.loader_calls < 40) {
        m.loader_calls += 1;
        var d: u32 = 0;
        var src: u32 = 0;
        var sz: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &d);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &src);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &sz);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [装载] dst=0x{x:0>8} src=0x{x:0>8} size=0x{x} lr=0x{x:0>8} (instrs={d})", .{
            d, src, sz, lr, m.instrs,
        });
    }
    // 致命错误唯一入口（XIP 0x10092FB0）第一现场：r0=code1 r1=code2，并抓 LR +
    // 栈上的返回地址链。固件以 (0xa02, 0x1) 调用时说明某个断言失败；这里要看
    // 「谁调的」——LR 指向调用者指令后的地址，栈顶若干字给出更深的调用链。
    if (address == 0x10092FB0) {
        m.fatal_hits += 1;
        var f0: u32 = 0;
        var f1: u32 = 0;
        var f2: u32 = 0;
        var f3: u32 = 0;
        var flr: u32 = 0;
        var fsp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &f0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &f1);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &f2);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R3, &f3);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &flr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &fsp);
        var fstk: [32 * 4]u8 = undefined;
        var fhex: [32 * 11]u8 = undefined;
        var fhb: usize = 0;
        if (c.uc_mem_read(engine, fsp, &fstk, fstk.len) == c.UC_ERR_OK) {
            var fi: usize = 0;
            while (fi < 32) : (fi += 1) {
                const w = std.mem.readInt(u32, fstk[fi * 4 ..][0..4], .little);
                const p = std.fmt.bufPrint(fhex[fhb..], " 0x{x:0>8}", .{w}) catch break;
                fhb += p.len;
            }
        }
        log.info(@src(), "  [致命错误入口] #{d} code1=0x{x} code2=0x{x} r2=0x{x} r3=0x{x} lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
            m.fatal_hits, f0, f1, f2, f3, flr, fsp, m.instrs,
        });
        log.info(@src(), "  [致命错误栈] sp..+128:{s}", .{fhex[0..fhb]});
        if (!m.fatal_dumped) {
            m.fatal_dumped = true;
            m.dumpExecHist();
        }
    }
    // (0xa02, 0x1) 断言的直接触发者：sub_1008C218(r0) 在 r0>=2 时调 sub_1008C818
    // → fatal(0xa02,1)。抓它的调用者 LR 与实参，定位真正的断言点。
    // 断言现场（XIP 0x1009334A `ldr r0,[r4,#8]; cmp r0,#5`）：r4 = 组件对象指针
    // （sub_10088A20 返回 = *(0xf03b7fbc) + 0x2b4*idx - 0xb51c），看它的 state 字段
    // 实际值，以及它是否从未被初始化。
    if (address == 0x1009334A and m.crash_caller_n < 16) {
        var r4v: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R4, &r4v);
        var st: u32 = 0;
        var f0: u32 = 0;
        var f4: u32 = 0;
        _ = c.uc_mem_read(engine, r4v + 8, &st, 4);
        _ = c.uc_mem_read(engine, r4v, &f0, 4);
        _ = c.uc_mem_read(engine, r4v + 4, &f4, 4);
        var base_ptr: u32 = 0;
        _ = c.uc_mem_read(engine, 0xf03b7fbc, &base_ptr, 4);
        var bm: u8 = 0;
        _ = c.uc_mem_read(engine, 0xf03b7b24, &bm, 1);
        m.crash_caller_n += 1;
        log.info(@src(), "  [断言现场] obj=0x{x:0>8} state(+8)=0x{x} f0=0x{x} f4=0x{x} table=0x{x:0>8} bootmode={d} (instrs={d})", .{
            r4v, st, f0, f4, base_ptr, bm, m.instrs,
        });
    }
    // fatal(0xa02,1) 包装函数 sub_1008C818 的入口：抓原始实参 r0/r1 与调用者 LR。
    if (address == 0x1008C818 and m.crash_caller_n < 8) {
        var w_lr: u32 = 0;
        var w_r0: u32 = 0;
        var w_r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &w_lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &w_r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &w_r1);
        m.crash_caller_n += 1;
        log.info(@src(), "  [fatal包装] #{d} sub_1008C818(r0=0x{x} r1=0x{x}) lr=0x{x:0>8} (instrs={d})", .{
            m.crash_caller_n, w_r0, w_r1, w_lr, m.instrs,
        });
    }
    if (address == 0x1008C218 and m.crash_caller_n < 8) {
        var cr_lr: u32 = 0;
        var cr_r0: u32 = 0;
        var cr_sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &cr_lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &cr_r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &cr_sp);
        if (cr_r0 >= 2) { // 只有 r0>=2 才会走 fatal 分支
            var crstk: [12 * 4]u8 = undefined;
            var crhex: [12 * 11]u8 = undefined;
            var crb: usize = 0;
            if (c.uc_mem_read(engine, cr_sp, &crstk, crstk.len) == c.UC_ERR_OK) {
                var ci: usize = 0;
                while (ci < 12) : (ci += 1) {
                    const w = std.mem.readInt(u32, crstk[ci * 4 ..][0..4], .little);
                    const p = std.fmt.bufPrint(crhex[crb..], " 0x{x:0>8}", .{w}) catch break;
                    crb += p.len;
                }
            }
            m.crash_caller_n += 1;
            log.info(@src(), "  [断言调用者] #{d} sub_1008C218(r0=0x{x}) lr=0x{x:0>8} sp=0x{x:0>8} (instrs={d})", .{
                m.crash_caller_n, cr_r0, cr_lr, cr_sp, m.instrs,
            });
            log.info(@src(), "  [断言栈] sp..+48:{s}", .{crhex[0..crb]});
        }
    }
    // CR 上报入口（0x100283E0）：dump 之前 1024 条 PC，看是谁把 MAUI 逼进
    // 崩溃处理链的（这条链上的 RAM 补丁代码 0xF072BD7C 在本镜像里不存在）
    if (address == 0x100283E0 and !m.cr_trace_dumped) {
        m.cr_trace_dumped = true;
        m.dumpExecHist();
    }
    // 硬件忙等循环（0x10067CF4 `ldrh r0,[r4,#0x14]; lsls r0,#31; beq .`）：固件
    // 在等 *(u16*)(r4+0x14) 的 bit0 置位。r4 = *(u32*)(0x100D1470 + idx*4)
    // （flash 里的指针表）。抓 r4 的实际值 = 到底在等哪个外设寄存器。
    if (address == 0x10067CF4 and m.busywait_n < 8) {
        m.busywait_n += 1;
        var r4v: u32 = 0;
        var lr: u32 = 0;
        var r1v: u32 = 0;
        var r2v: u32 = 0;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R4, &r4v);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1v);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &r2v);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        var v14: u16 = 0;
        var v0: u16 = 0;
        var v2: u16 = 0;
        _ = c.uc_mem_read(engine, r4v + 0x14, &v14, 2);
        _ = c.uc_mem_read(engine, r4v, &v0, 2);
        _ = c.uc_mem_read(engine, r4v + 2, &v2, 2);
        var ret: u32 = 0;
        _ = c.uc_mem_read(engine, sp + 4, &ret, 4);
        log.info(@src(), "  [忙等] #{d} r4=0x{x:0>8} *(r4+0x14)=0x{x:0>4} bit0={d} *(r4)=0x{x:0>4} *(r4+2)=0x{x:0>4} lr=0x{x:0>8} 返回=0x{x:0>8} r1=0x{x:0>8} r2=0x{x:0>8} (instrs={d})", .{
            m.busywait_n, r4v, v14, v14 & 1, v0, v2, lr, ret, r1v, r2v, m.instrs,
        });
        if (m.busywait_n == 1) m.dumpExecHistTail(96);
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
    // 卡点死循环抓取：执行轨迹尾部整段卡在 0x70008b36/38/3a（0x70008b00 函数内的
    // 910 次忙等 + 写外设 0xa0010100/0xa0170140）。把它反复调用的 SRAM 代码原样
    // 落盘 /tmp/sram.bin 与寄存器到 /tmp/emudump.txt，离线反汇编找外层循环。
    if (address >= 0x70008b36 and address <= 0x70008b3a and !m.loop_dumped) {
        m.loop_dumped = true;
        var r0: u32 = 0;
        var r1: u32 = 0;
        var r2: u32 = 0;
        var r3: u32 = 0;
        var r4: u32 = 0;
        var r5: u32 = 0;
        var r10: u32 = 0;
        var sp: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &r2);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R3, &r3);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R4, &r4);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R5, &r5);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R10, &r10);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        // 调用栈：从 sp 往下读 64 字（含已 push 的 lr 与更深的帧），找调用链
        var stk: [64 * 4]u8 = undefined;
        _ = c.uc_mem_read(engine, sp, &stk, stk.len);
        var stkhex: [64 * 11]u8 = undefined;
        var sb: usize = 0;
        var si: usize = 0;
        while (si < 64) : (si += 1) {
            const w = std.mem.readInt(u32, stk[si * 4 ..][0..4], .little);
            const p = std.fmt.bufPrint(stkhex[sb..], " 0x{x:0>8}", .{w}) catch break;
            sb += p.len;
        }
        // 另读 sp 之上的 32 字（部分函数 sub sp 后帧在 sp 之上）
        var stk2: [32 * 4]u8 = undefined;
        var stk2hex: [32 * 11]u8 = undefined;
        var sb2: usize = 0;
        if (sp >= 0x40) {
            _ = c.uc_mem_read(engine, sp - 0x80, &stk2, stk2.len);
            var s2: usize = 0;
            while (s2 < 32) : (s2 += 1) {
                const w = std.mem.readInt(u32, stk2[s2 * 4 ..][0..4], .little);
                const p = std.fmt.bufPrint(stk2hex[sb2..], " 0x{x:0>8}", .{w}) catch break;
                sb2 += p.len;
            }
        }
        var buf: [2048]u8 = undefined;
        const written = std.fmt.bufPrint(&buf, "=== 死循环 0x70008b36 (0x70008af8 内忙等+写外设 0xa0010100/0xa0170140) ===\nr0=0x{x:0>8} r1=0x{x:0>8} r2=0x{x:0>8} r3=0x{x:0>8}\nr4=0x{x:0>8} r5=0x{x:0>8} r10=0x{x:0>8} sp=0x{x:0>8} lr=0x{x:0>8}\ninstrs={d}\n[sp..+256]:{s}\n[sp-0x80..sp]:{s}\n", .{ r0, r1, r2, r3, r4, r5, r10, sp, lr, m.instrs, stkhex[0..sb], stk2hex[0..sb2] }) catch buf[0..0];
        std.Io.Dir.writeFile(std.Io.Dir.cwd(), m.io, .{ .sub_path = "/tmp/emudump.txt", .data = written }) catch {};
        // 另存两段已知已映射的 SRAM 代码（caller 0x70008200 与 delay 0x70008b00）
        var caller: [0x300]u8 = undefined;
        if (c.uc_mem_read(engine, 0x70008200, &caller, caller.len) == c.UC_ERR_OK) {
            std.Io.Dir.writeFile(std.Io.Dir.cwd(), m.io, .{ .sub_path = "/tmp/caller.bin", .data = caller[0..] }) catch {};
        }
        var delay: [0x100]u8 = undefined;
        if (c.uc_mem_read(engine, 0x70008b00, &delay, delay.len) == c.UC_ERR_OK) {
            std.Io.Dir.writeFile(std.Io.Dir.cwd(), m.io, .{ .sub_path = "/tmp/delay.bin", .data = delay[0..] }) catch {};
        }
    }
    // 外层循环驱动抓取：0x70008266 是反复调用 0x70008af8（外设复位例程）的函数入口。
    // 它返回地址 [sp+4] 落在真正“轮询循环”函数里，据此把那段代码落盘反汇编。
    if (address == 0x70008266 and !m.loopfn_dumped) {
        m.loopfn_dumped = true;
        var sp: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        var ret: u32 = 0;
        _ = c.uc_mem_read(engine, sp + 4, &ret, 4); // 0x70008266 的返回地址（loop fn 内）
        var buf: [256]u8 = undefined;
        const w1 = std.fmt.bufPrint(&buf, "=== 0x70008266 入口（返回 @0x{x:0>8}, sp=0x{x:0>8}）===\n[sp+4]=loopfn返回 上方帧@0x{x:0>8}:\n", .{ ret, sp, sp + 4 }) catch buf[0..0];
        std.Io.Dir.writeFile(std.Io.Dir.cwd(), m.io, .{ .sub_path = "/tmp/loopfn.txt", .data = w1 }) catch {};
        // 读 loop fn 的栈帧（sp 之上 0x200 字节）找 loopfn 的返回地址（即 bl 0x70008266 之后）
        var fr: [0x200]u8 = undefined;
        _ = c.uc_mem_read(engine, sp + 4, &fr, fr.len);
        var fh: [0x200 * 11]u8 = undefined;
        var fb: usize = 0;
        var fi: usize = 0;
        while (fi < 0x200 / 4) : (fi += 1) {
            const w = std.mem.readInt(u32, fr[fi * 4 ..][0..4], .little);
            const p = std.fmt.bufPrint(fh[fb..], " 0x{x:0>8}", .{w}) catch break;
            fb += p.len;
        }
        var buf2: [1200]u8 = undefined;
        const w2 = std.fmt.bufPrint(&buf2, "[sp+4..+0x204]:{s}\n", .{fh[0..fb]}) catch buf2[0..0];
        std.Io.Dir.writeFile(std.Io.Dir.cwd(), m.io, .{ .sub_path = "/tmp/loopframe.txt", .data = w2 }) catch {};
        // 读 loop fn 代码：从 ret 往前 0x100 起读 0x200 字节（含函数入口的 push）
        const fbase = (ret & ~@as(u32, 0x1)) -% 0x100;
        var fnbuf: [0x200]u8 = undefined;
        if (c.uc_mem_read(engine, fbase, &fnbuf, fnbuf.len) == c.UC_ERR_OK) {
            std.Io.Dir.writeFile(std.Io.Dir.cwd(), m.io, .{ .sub_path = "/tmp/loopfn.bin", .data = fnbuf[0..] }) catch {};
        }
    }
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
        inline for (.{ 0x70008E00, 0x70008F00, 0x70009000, 0x70009100, 0x70008200, 0x70009200, 0x70009300, 0x70009400, 0x70009500, 0x70009600, 0x70009700, 0x70009800, 0x70009900, 0x70009A00 }) |base| {
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
    // CPSR.I 变化采样（每 4096 条一次）：确认固件有没有开 CPU 中断（诊断用）
    if (m.tick_interval != 0 and (m.instrs & 0xFFF) == 0) {
        var cpsr_i: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr_i);
        const i_now = (cpsr_i & 0x80) != 0;
        if (i_now != m.i_bit_last) {
            m.i_bit_last = i_now;
            if (m.i_bit_samples < 32) {
                m.i_bit_samples += 1;
                log.info(@src(), "  [CPSR.I] → {s} pc=0x{x:0>8} (instrs={d})", .{
                    if (i_now) "关中断" else "开中断",
                    address,
                    m.instrs,
                });
            }
        }
    }

    // T-bit 变化检测（诊断：0x100221f0 运行时 T=0 但代码是 Thumb）。固件全程应
    // 在 Thumb 跑，任何「切到 ARM（T 1→0）」且之后没切回来，就是把 T 清 0 的元凶。
    // flash 区里合法的 Thumb/ARM interworking 会频繁切换 T，所以只记住最后一条
    // 未恢复的 1→0（被 0→1 恢复就清掉），停机时再 dump，避免刷屏。
    // 性能：每条指令都 uc_reg_read(CPSR) 极慢，改为每 64 条采样一次（足够抓住
    // 持续 T=0 的现场，开关点误差 <64 条指令，离线反汇编足够）。
    if ((m.instrs & 0x3F) == 0) {
        var cpsr_t: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr_t);
        const t = (cpsr_t & 0x20) != 0;
        if (t != m.last_t_bit) {
            const prev = m.last_t_bit;
            m.last_t_bit = t;
            if (prev and !t) {
                // 切到 ARM：记住这条（若停机仍未恢复就是元凶）
                var lr: u32 = 0;
                _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
                m.t_arm_switch_pc = @truncate(address);
                m.t_arm_switch_lr = lr;
                m.t_arm_switch_instrs = m.instrs;
            } else if (!prev and t) {
                // 切回 Thumb：说明之前的 ARM 切换是合法 interworking，清掉嫌疑
                m.t_arm_switch_pc = 0;
            }
        }
    }

    // ── 周期 tick 与中断交付（Unicorn 没有注入中断的 API，这里手工模拟
    //    ARM 的 IRQ 异常入口/返回；见 docs/mt6250-wiring.md「中断」一节）──
    // memcpy 到 DMA FIFO 的调用点（0x100325e8 `blx 0x10070570`）：
    // memcpy(r0=dst, r1=src, r2=len)。抓出来确认「搬什么、从哪、多大」。
    if (address == 0x1003_25e8) {
        var r0: u32 = 0;
        var r1: u32 = 0;
        var r2: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R2, &r2);
        log.info(@src(), "  [FIFO拷贝] memcpy(dst=0x{x:0>8}, src=0x{x:0>8}, len=0x{x}({d}))", .{
            r0, r1, r2, r2,
        });
    }
    // 传输引擎操作函数（0x10032670 起，r4 = 寄存器基址）：确认基址到底是多少
    if (address == 0x1003_2670 or address == 0x1003_26ec) {
        var r4: u32 = 0;
        var r5: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R4, &r4);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R5, &r5);
        log.info(@src(), "  [DMA基址] pc=0x{x:0>8}: r4=0x{x:0>8} r5=0x{x:0>8}", .{ address, r4, r5 });
    }
    // DMA 结果校验（0x10032712 `ldr r0,[r0]` / 0x10032714 `cmp r0,r1`）：
    // 固件在传输引擎跑完后读回目标内存比对期望值——我们的 DMA 是「假完成」，
    // 不搬数据，所以这里必然不等 → assert → 关机。抓出双方值确认。
    if (address == 0x1003_2712) {
        var r0: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        log.info(@src(), "  [DMA校验] 目标地址 = 0x{x:0>8}", .{r0});
    }
    if (address == 0x1003_2714) {
        var r0: u32 = 0;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        log.info(@src(), "  [DMA校验] 实际=0x{x:0>8} 期望=0x{x:0>8} → {s}", .{
            r0, r1,
            if (r0 == r1) "通过" else "失败→assert",
        });
    }
    // assert 失败入口（0x1007bd0e）：0x100324b8 的 ALICE_1 校验逐字节检查，
    // 任一字节不匹配就 `bl` 到这里。抓 lr = 具体哪个检查失败。
    if (address == 0x1007_bd0e) {
        var lr: u32 = 0;
        var r4: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R4, &r4);
        var b: [8]u8 = @splat(0);
        const ok = c.uc_mem_read(engine, r4, &b, 8) == c.UC_ERR_OK;
        log.info(@src(), "  [ASSERT失败] lr=0x{x:0>8} r4=0x{x:0>8} 内容={s}", .{
            lr, r4, if (ok) b[0..8] else "??",
        });
        m.dumpExecHistTail(24);
    }
    // 异常上报入口（0x1002E100(r0, r1) → bl 0x100324b8 → assert 打印 → 关机）。
    // 抓调用者 = 触发这次 fatal error 的地方。
    if (address == 0x1002_e100) {
        var lr: u32 = 0;
        var r0: u32 = 0;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        log.info(@src(), "  [异常上报] 0x1002e100: lr=0x{x:0>8} r0=0x{x:0>8} r1={d} (instrs={d})", .{
            lr, r0, r1, m.instrs,
        });
        m.dumpExecHistTail(64);
    }
    // Assert 打印点（0x1008b7a8 = `bl 0x10092b0c` 打 "[%d] Assert fail: Caller
    // Address: 0x%x Line: %d - %s ..."）。可变参数在栈上，抓出来就能知道断言
    // 发生在哪个调用者、第几行。
    if (address == 0x1008_b7a8) {
        var sp: u32 = 0;
        var regs: [4]u32 = @splat(0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &sp);
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0 + @as(c_int, @intCast(i)), &regs[i]);
        }
        var stack: [8]u32 = @splat(0);
        _ = c.uc_mem_read(engine, sp, &stack, 32);
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [ASSERT] r0=0x{x:0>8} r1=0x{x:0>8} r2=0x{x:0>8} r3=0x{x:0>8} lr=0x{x:0>8}", .{
            regs[0], regs[1], regs[2], regs[3], lr,
        });
        log.info(@src(), "  [ASSERT] sp=0x{x:0>8} 栈: {x:0>8} {x:0>8} {x:0>8} {x:0>8} {x:0>8} {x:0>8}", .{
            sp, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5],
        });
    }
    // panic/assert 入口（0x10070788(r0=行号/错误码)）：断言点都经它。
    // 在此 dump 现场 = 直接看到「哪条指令 bl 了它」。
    if (address == 0x1007_0788) {
        var lr: u32 = 0;
        var r0: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        log.info(@src(), "  [PANIC] 0x10070788: code=0x{x} lr=0x{x:0>8} (instrs={d})", .{ r0, lr, m.instrs });
        m.dumpExecHistTail(48);
    }
    // 固件日志：0x10092b0c(r0, r1=字符串) 是 MAUI 的打印/追加入口。把它打的
    // 字符串 dump 出来——异常路径会在这里说出失败原因（实测 0x1003092e 的
    // 关机块就是「打两行日志 → 关机」）。
    if (address == 0x1009_2b0c and m.fw_log_n < 200) {
        m.fw_log_n += 1;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        var sbuf: [160]u8 = @splat(0);
        if (c.uc_mem_read(engine, r1, &sbuf, sbuf.len) == c.UC_ERR_OK) {
            var n: usize = 0;
            while (n < sbuf.len and sbuf[n] != 0) : (n += 1) {}
            var pc: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_PC, &pc);
            var lr: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
            log.info(@src(), "  [固件日志] lr=0x{x:0>8}: {s}", .{ lr, sbuf[0..n] });
        }
    }
    // magic 写入点（0x10021c76 调 sub_10092E04，返回 ==1 才写 magic）
    if (address == 0x1002_1c7a) {
        var r0: u32 = 0;
        var v: u16 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        if (c.uc_mem_read(engine, 0xF03D_004E, &v, 2) != c.UC_ERR_OK) v = 0xffff;
        log.info(@src(), "  [启动模式] sub_10092E04 返回 r0={d}, *(u16*)0xF03D004E={d} → {s} (instrs={d})", .{
            r0,       v,
            if (r0 == 1) "会写 magic" else "不写 magic→后续关机",
            m.instrs,
        });
    }
    // 关机决策比较点（0x100308cc = `cmp r0,r1`，下一条 bne → 关机路径）：
    // 打印 *(0xF03CFE24) 的实际值与期望值
    if (address == 0x1003_08cc) {
        var r0: u32 = 0;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        log.info(@src(), "  [关机检查] *(0xF03CFE24)=0x{x:0>8} 期望=0x{x:0>8} → {s} (instrs={d})", .{
            r0,       r1,
            if (r0 == r1) "通过" else "失败→关机",
            m.instrs,
        });
    }
    // 关机错误处理块入口（0x1003092e：打印两行日志 → bl 0x1002e358 关机）。
    // 它是被分支跳入的（正常路径 0x1003092c 是 `b .` 自旋），这里抓跳转来源。
    if (address == 0x1003_092e) {
        var lr: u32 = 0;
        var r0: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        log.info(@src(), "  [关机错误处理] 0x1003092e: lr=0x{x:0>8} r0=0x{x:0>8} (instrs={d})", .{
            lr, r0, m.instrs,
        });
        m.dumpExecHistTail(512);
    }
    // 关机函数（0x1002e358 起，收尾是 0x1002e37e 写 0xA0030008=0x1971）：
    // 抓 lr = 谁调用了这个关机函数
    if (address == 0x1002_e358) {
        var lr: u32 = 0;
        var r0: u32 = 0;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        log.info(@src(), "  [关机函数] 0x1002e358: lr=0x{x:0>8} r0=0x{x:0>8} r1=0x{x:0>8} (instrs={d})", .{
            lr, r0, r1, m.instrs,
        });
        m.dumpExecHistTail(24);
    }
    // 关机路径入口（0x1002e360）：抓 lr = 谁调用了这个关机函数
    if (address == 0x1002_e360) {
        var lr: u32 = 0;
        var r0: u32 = 0;
        var r1: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        log.info(@src(), "  [关机入口] 0x1002e360: lr=0x{x:0>8} r0=0x{x:0>8} r1=0x{x:0>8} (instrs={d})", .{
            lr, r0, r1, m.instrs,
        });
        m.dumpExecHistTail(24);
    }
    if (m.irq_active and m.irq_trace_n < m.irq_trace.len) {
        m.irq_trace[m.irq_trace_n] = @truncate(address);
        m.irq_trace_n += 1;
    }
    // ── Nucleus 中断上下文诊断 ────────────────────────────────────────────
    // 实测 CPU 到达关机自旋时停在 IRQ 模式（cpsr mode=0x12），说明异常返回
    // 没把模式切回去。两个待验证点：
    //  (a) 0x70009e18 = TCT_Interrupt_Context_Save 的入口判定：读 *0xF0423174
    //      （中断嵌套计数），<=0 就跳过「切 SVC 模式 + 保存任务上下文」
    //  (b) 0x70009f54 = `ldm sp,{...,pc}^` 异常返回：Unicorn 是否真从 SPSR
    //      恢复了 CPSR（ARM 的 ^ 语义，Unicorn 2.1.4 实现可能不完整）
    if (address == 0x7000_9e18 or address == 0x7000_9f34 or address == 0x7000_9f4c) {
        var cpsr: u32 = 0;
        var cnt: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr);
        if (c.uc_mem_read(engine, 0xF042_3174, &cnt, 4) != c.UC_ERR_OK) cnt = 0xdead_beef;
        log.info(@src(), "  [IRQctx] pc=0x{x:0>8} cpsr=0x{x:0>8} (mode=0x{x}) *0xF0423174={d} (instrs={d})", .{
            address, cpsr, cpsr & 0x1F, cnt, m.instrs,
        });
    }
    if (address == 0x7000_9f54) {
        var spsr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SPSR, &spsr);
        var cpsr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr);
        // 关键修复：Unicorn 2.x 的 `ldm sp,{...,pc}^` 异常返回**没有从 SPSR 恢复
        // T 位**（实测：返回后 CPU 停在 ARM 模式、把 Thumb 代码当 ARM 解码 →
        // Invalid instruction，如 0x100221f0）。这里手动把 CPSR.T 对齐到 SPSR.T。
        // SPSR 在 ldm^ 后仍保留进入 IRQ 前的 CPSR（含正确 T 位），可直接取用。
        const fixed = (cpsr & ~@as(u32, 0x20)) | (spsr & 0x20);
        if (fixed != cpsr) {
            _ = c.uc_reg_write(engine, c.UC_ARM_REG_CPSR, &fixed);
        }
        log.info(@src(), "  [IRQret] ldm^ cpsr=0x{x:0>8} spsr=0x{x:0>8} T={d}→{d}", .{ cpsr, spsr, (cpsr >> 5) & 1, (spsr >> 5) & 1 });
        m.irq_ret_probe = true;
    } else if (m.irq_ret_probe) {
        m.irq_ret_probe = false;
        var cpsr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr);
        log.info(@src(), "  [IRQret] 下一条 pc=0x{x:0>8} cpsr=0x{x:0>8} (mode=0x{x})", .{
            address, cpsr, cpsr & 0x1F,
        });
    }
    // MAUI 关机序列入口（0x1002e37e = 写 0xA0030008=0x1971 前）：
    // 抓 lr 与参数，回溯是谁决定关机。
    // 注意：必须放在 irq_active 判断**之前**——实测 CPU 到达这里时仍停在
    // IRQ 模式（cpsr mode=0x12），若放在 else 分支里这个断点永远不触发。
    if (address == 0x1002_e37e or address == 0x1002_e38a) {
        if (!m.shutdown_bp) {
            m.shutdown_bp = true;
            var lr: u32 = 0;
            var r0: u32 = 0;
            var cpsr: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr);
            log.info(@src(), "  [关机] pc=0x{x:0>8}: r0=0x{x:0>8} lr=0x{x:0>8} cpsr=0x{x:0>8} (mode=0x{x}, I={d}) (instrs={d})", .{
                address, r0, lr, cpsr, cpsr & 0x1F, (cpsr >> 7) & 1, m.instrs,
            });
            m.dumpExecHistTail(48);
            m.dumpIrqTrace();
        }
        // 已确认进入关机自旋，直接停机，省掉剩余预算
        if (address == 0x1002_e38a) {
            _ = c.uc_emu_stop(engine);
            return;
        }
    }
    if (m.irq_active) {
        // IRQ 桩用 `subs pc,lr,#4` 返回：PC 回到中断点即视为异常返回。
        // CPSR 应由 CPU 从 SPSR_irq 恢复，这里按「中断不破坏 r0-r12/lr」的
        // 约定把现场写回，保证与真机一致（也兼容 Unicorn 的 bank 行为差异）。
        var leaving = false;
        if (address == m.irq_ret) {
            var i: usize = 0;
            while (i < 13) : (i += 1) {
                _ = c.uc_reg_write(engine, c.UC_ARM_REG_R0 + @as(c_int, @intCast(i)), &m.irq_saved_regs[i]);
            }
            _ = c.uc_reg_write(engine, c.UC_ARM_REG_SP, &m.irq_saved_regs[13]);
            _ = c.uc_reg_write(engine, c.UC_ARM_REG_LR, &m.irq_saved_regs[14]);
            leaving = true;
        } else {
            // RTOS（Nucleus）会在中断里做上下文切换：异常返回后不一定回到中断
            // 点，而是切到另一个任务栈继续跑。所以「回到 irq_ret」不是可靠的
            // 返回判据——实测这里永远不成立，导致 irq_active 卡死、tick 只交付
            // 一次（后续 OS 调度起不来 → MAUI 走关机路径）。可靠判据是 CPU 模式：
            // 离开 IRQ 模式（0x12）即视为这次中断处理结束。
            var mode: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &mode);
            if ((mode & 0x1F) != 0x12) leaving = true;
        }
        if (leaving) {
            // 关键修复：Unicorn 2.x 的异常返回（subs pc,lr,#4 / ldm sp,{...,pc}^）
            // **没有从 SPSR 恢复 T 位**（实测：返回后 CPU 停在 ARM 模式、把 Thumb
            // 代码当 ARM 解码 → Invalid instruction，如 0x100221f0）。无论走哪条返回
            // 路径，这里统一把 CPSR.T 对齐到 SPSR.T（SPSR 仍是进入 IRQ 前的 CPSR，
            // 含中断点的正确 T 位）。
            var spsr: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_SPSR, &spsr);
            var cpsr: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr);
            const fixed = (cpsr & ~@as(u32, 0x20)) | (spsr & 0x20);
            if (fixed != cpsr) {
                _ = c.uc_reg_write(engine, c.UC_ARM_REG_CPSR, &fixed);
            }
            m.irq_active = false;
        }
    }
    if (!m.irq_active) {
        if (m.tick_interval != 0 and m.instrs >= m.next_tick) {
            m.next_tick = m.instrs + m.tick_interval;
            // 只按 OS 是否使能过来决定：0xA0030000 bit0（全局，sub_10037A84 置位）
            // 或 0xA0060040/44 的源使能位（sub_10092F34 置位）
            if ((m.intc_ctrl & 1) != 0 or m.intc_en_lo != 0 or m.intc_en_hi != 0) {
                m.irq_pending = m.tick_irq;
            }
        }
        if (m.irq_pending >= 0) {
            // 真机语义：CPSR.I=1 时 IRQ 被屏蔽（悬起但不动），只有 I=0 才交付。
            // 不检查会踩到「中断入口按 SPSR.I 早退 → pending 不清 → 中断风暴」。
            // 另外不能在 IRQ 模式里再交付（固件若嵌套开中断会造成风暴）。
            var cur: u32 = 0;
            _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cur);
            if ((cur & 0x80) == 0 and (cur & 0x1F) != 0x12) {
                enterIrq(m, engine, @truncate(address));
                return;
            }
        }
    }
    if (m.trace) {
        log.debug(@src(), "pc=0x{x:0>8} size={d}", .{ address, size });
    }
}

/// 手工模拟 ARM 的 IRQ 异常入口：保存现场 → 切 IRQ 模式/换栈 → PC = BootROM IRQ 桩。
/// 返回地址按 ARM 约定放 LR_irq = 中断点 + 4（桩用 `subs pc,lr,#4` 返回）。
fn enterIrq(m: *Machine, engine: ?*c.uc_engine, ret_addr: u32) void {
    var i: usize = 0;
    while (i < 13) : (i += 1) {
        var v: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0 + @as(c_int, @intCast(i)), &v);
        m.irq_saved_regs[i] = v;
    }
    _ = c.uc_reg_read(engine, c.UC_ARM_REG_SP, &m.irq_saved_regs[13]);
    _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &m.irq_saved_regs[14]);
    m.irq_saved_regs[15] = ret_addr;
    _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &m.irq_saved_cpsr);

    // 不用合成桩：MAUI 的 crt0 已把 flash 0x872548（0x20A8 字节）整段拷到
    // SRAM 0x70008000，其中 0x700096B0 就是**固件自己的 ARM 中断入口**
    // （push {r1} / mrs r1,spsr / tst r1,#0x80 / pop {r1} / subsne pc,lr,#4 …）。
    // 之前用合成桩盖掉它是错的（会执行到 0x1008E090 处非法指令）。
    m.irq_ret = ret_addr;
    m.irq_active = true;
    m.irq_count += 1;

    // IRQ 模式、ARM 态、I 置位（F 保持）；SPSR_irq = 旧 CPSR
    var cpsr: u32 = (m.irq_saved_cpsr & ~@as(u32, 0x3F)) | 0x12 | 0x80;
    cpsr &= ~@as(u32, 0x20);
    // 先切模式再写 SPSR：UC_ARM_REG_SPSR 写的是**当前模式**的 SPSR，
    // 顺序反了就会写到 SPSR_svc，异常返回时恢复出错误的 CPSR（实测踩过）
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_CPSR, &cpsr);
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_SPSR, &m.irq_saved_cpsr);
    if (m.irq_count == 1) {
        var cpsr_rb: u32 = 0;
        var spsr_rb: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr_rb);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_SPSR, &spsr_rb);
        log.info(@src(), "  [IRQ 诊断] 写入后回读 cpsr=0x{x:0>8} spsr=0x{x:0>8}（期望 spsr=0x{x:0>8}）", .{
            cpsr_rb, spsr_rb, m.irq_saved_cpsr,
        });
    }
    var sp: u32 = bootrom.irq_stack_top;
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_SP, &sp);
    var lr: u32 = ret_addr +% 4;
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_LR, &lr);
    var pc: u32 = bootrom.irq_entry;
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_PC, &pc);

    if (m.irq_count <= 8 or m.irq_count % 256 == 0) {
        log.info(@src(), "  [IRQ #{d}] 中断 {d} 交付: 中断点 pc=0x{x:0>8} → 桩 0x{x:0>8} (instrs={d})", .{
            m.irq_count, m.irq_pending, ret_addr, bootrom.irq_entry, m.instrs,
        });
    }
}

/// RAM 补丁区（0xF0700000+）执行钩子 = BootROM 服务的宿主侧实现。
/// veneer 表 101 个目标全部 bit0=1（Thumb），而 ARMv5TE 的 Thumb 没有
/// MRS/MSR——固件侧无法开中断，所以「OS 启动」必须在模拟器侧完成：
/// 清 CPSR.I + 返回 0，让 MAUI 的等待循环收到 tick 后继续走。
pub fn onRamPatchExec(engine: ?*c.uc_engine, address: u64, size: u32, user: ?*anyopaque) callconv(.c) void {
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    if (m.rampatch_calls < 8) {
        var r0: u32 = 0;
        var r1: u32 = 0;
        var lr: u32 = 0;
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R0, &r0);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_R1, &r1);
        _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
        log.info(@src(), "  [BootROM补丁] pc=0x{x:0>8} r0=0x{x:0>8} r1=0x{x:0>8} lr=0x{x:0>8} → 清 I 位返回 0", .{
            address, r0, r1, lr,
        });
    }
    m.rampatch_calls += 1;
    const zero: u32 = 0;
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_R0, &zero);
    var cpsr: u32 = 0;
    _ = c.uc_reg_read(engine, c.UC_ARM_REG_CPSR, &cpsr);
    cpsr &= ~@as(u32, 0x80); // 清 I 位：开 IRQ
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_CPSR, &cpsr);
    var lr: u32 = 0;
    _ = c.uc_reg_read(engine, c.UC_ARM_REG_LR, &lr);
    _ = c.uc_reg_write(engine, c.UC_ARM_REG_PC, &lr); // 返回调用者（lr 带 Thumb 位）
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

/// 关机 magic 变量（0xF03CFE24）的写入者监视
pub fn onMagicWrite(uc_engine: ?*c.uc_engine, typ: c.uc_mem_type, address: u64, size: c_int, value: i64, user: ?*anyopaque) callconv(.c) bool {
    _ = typ;
    _ = size;
    const m: *Machine = @ptrCast(@alignCast(user));
    var pc: u32 = 0;
    var lr: u32 = 0;
    _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_PC, &pc);
    _ = c.uc_reg_read(uc_engine, c.UC_ARM_REG_LR, &lr);
    log.info(@src(), "  [magic写] pc=0x{x:0>8} lr=0x{x:0>8} -> [0x{x:0>8}] = 0x{x:0>8} (instrs={d})", .{
        pc, lr, address, @as(u64, @bitCast(value)), m.instrs,
    });
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
