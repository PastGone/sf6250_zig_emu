//! Unicorn（QEMU 派生的 CPU 模拟器）的薄封装。
//!
//! 官方 `bindings/zig` 停留在 0.13（用了 0.15 起已移除的 `usingnamespace`），
//! 0.16 下编译不过，因此这里只对 C API 做最小封装：把 `uc_err` 映射成 Zig 错误，
//! 其余保持 Unicorn 的原样语义。

const std = @import("std");

/// C API 原始绑定（@cImport 翻译）。封装层内部使用；需要绕过封装直接调
/// C 时也可以从这里拿（例如 machine.zig 的 `uc.c.UC_ARM_REG_SP`）。
pub const c = @cImport({
    @cInclude("unicorn/unicorn.h");
});

pub const Error = error{
    NoMemory,
    Arch,
    Handle,
    Mode,
    Version,
    ReadUnmapped,
    WriteUnmapped,
    FetchUnmapped,
    Hook,
    InvalidInstruction,
    Map,
    WriteProtected,
    ReadProtected,
    FetchProtected,
    InvalidArgument,
    ReadUnaligned,
    WriteUnaligned,
    FetchUnaligned,
    Unknown,
};

fn check(err: c.uc_err) Error!void {
    return switch (err) {
        c.UC_ERR_OK => {},
        c.UC_ERR_NOMEM => Error.NoMemory,
        c.UC_ERR_ARCH => Error.Arch,
        c.UC_ERR_HANDLE => Error.Handle,
        c.UC_ERR_MODE => Error.Mode,
        c.UC_ERR_VERSION => Error.Version,
        c.UC_ERR_READ_UNMAPPED => Error.ReadUnmapped,
        c.UC_ERR_WRITE_UNMAPPED => Error.WriteUnmapped,
        c.UC_ERR_FETCH_UNMAPPED => Error.FetchUnmapped,
        c.UC_ERR_HOOK => Error.Hook,
        c.UC_ERR_INSN_INVALID => Error.InvalidInstruction,
        c.UC_ERR_MAP => Error.Map,
        c.UC_ERR_WRITE_PROT => Error.WriteProtected,
        c.UC_ERR_READ_PROT => Error.ReadProtected,
        c.UC_ERR_FETCH_PROT => Error.FetchProtected,
        c.UC_ERR_ARG => Error.InvalidArgument,
        c.UC_ERR_READ_UNALIGNED => Error.ReadUnaligned,
        c.UC_ERR_WRITE_UNALIGNED => Error.WriteUnaligned,
        c.UC_ERR_FETCH_UNALIGNED => Error.FetchUnaligned,
        else => Error.Unknown,
    };
}

pub const Perm = enum(u32) {
    read = c.UC_PROT_READ,
    write = c.UC_PROT_WRITE,
    exec = c.UC_PROT_EXEC,
    all = c.UC_PROT_ALL,

    pub fn combine(list: []const Perm) u32 {
        var v: u32 = 0;
        for (list) |p| v |= @intFromEnum(p);
        return v;
    }
};

pub const Engine = struct {
    handle: ?*c.uc_engine = null,

    pub fn open(arch: c.uc_arch, mode: c.uc_mode) Error!Engine {
        var h: ?*c.uc_engine = null;
        try check(c.uc_open(arch, mode, &h));
        return .{ .handle = h };
    }

    pub fn close(self: *const Engine) void {
        if (self.handle) |h| _ = c.uc_close(h);
    }

    pub fn memMap(self: *const Engine, address: u64, size: u64, perms: u32) Error!void {
        try check(c.uc_mem_map(self.handle, address, size, perms));
    }

    /// 把宿主机的一块内存直接挂进去（零拷贝，MMIO 之外的常规做法）
    pub fn memMapPtr(self: *const Engine, address: u64, size: u64, perms: u32, ptr: *anyopaque) Error!void {
        try check(c.uc_mem_map_ptr(self.handle, address, size, perms, ptr));
    }

    pub fn memWrite(self: *const Engine, address: u64, data: []const u8) Error!void {
        try check(c.uc_mem_write(self.handle, address, data.ptr, data.len));
    }

    pub fn memRead(self: *const Engine, address: u64, out: []u8) Error!void {
        try check(c.uc_mem_read(self.handle, address, out.ptr, out.len));
    }

    /// MMIO 区域：读写都回调到宿主机，用来实现外设寄存器
    pub fn mmioMap(
        self: *const Engine,
        address: u64,
        size: u64,
        read: c.uc_cb_mmio_read_t,
        read_ctx: ?*anyopaque,
        write: c.uc_cb_mmio_write_t,
        write_ctx: ?*anyopaque,
    ) Error!void {
        try check(c.uc_mmio_map(self.handle, address, size, read, read_ctx, write, write_ctx));
    }

    pub fn regWrite(self: *const Engine, reg: c_int, value: *const anyopaque) Error!void {
        try check(c.uc_reg_write(self.handle, reg, value));
    }

    pub fn regRead(self: *const Engine, reg: c_int, value: *anyopaque) Error!void {
        try check(c.uc_reg_read(self.handle, reg, value));
    }

    /// until == 0 表示一直跑到结束；count == 0 表示不限指令数
    pub fn emuStart(self: *const Engine, begin: u64, until: u64, timeout_us: u64, count: usize) Error!void {
        try check(c.uc_emu_start(self.handle, begin, until, timeout_us, count));
    }

    pub fn emuStop(self: *const Engine) Error!void {
        try check(c.uc_emu_stop(self.handle));
    }

    pub fn hookCode(self: *const Engine, hh: *c.uc_hook, cb: c.uc_cb_hookcode_t, ctx: ?*anyopaque) Error!void {
        try check(c.uc_hook_add(self.handle, hh, c.UC_HOOK_CODE, @ptrCast(@constCast(cb)), ctx, 1, 0));
    }

    /// 带地址范围的内存访问钩子（UC_HOOK_MEM_WRITE/READ 等）
    pub fn hookMem(self: *const Engine, hh: *c.uc_hook, typ: c_int, begin: u64, end: u64, cb: c.uc_cb_eventmem_t, ctx: ?*anyopaque) Error!void {
        try check(c.uc_hook_add(self.handle, hh, typ, @ptrCast(@constCast(cb)), ctx, begin, end));
    }

    /// 非法/未映射访问：返回 false 表示让 Unicorn 停下并报错
    pub fn hookMemInvalid(self: *const Engine, hh: *c.uc_hook, cb: c.uc_cb_eventmem_t, ctx: ?*anyopaque) Error!void {
        try check(c.uc_hook_add(self.handle, hh, c.UC_HOOK_MEM_INVALID, @ptrCast(@constCast(cb)), ctx, 1, 0));
    }

    /// 软件中断（SWI）：Nucleus/MAUI 的系统调用入口之一
    pub fn hookIntr(self: *const Engine, hh: *c.uc_hook, cb: c.uc_cb_hookintr_t, ctx: ?*anyopaque) Error!void {
        try check(c.uc_hook_add(self.handle, hh, c.UC_HOOK_INTR, @ptrCast(@constCast(cb)), ctx, 1, 0));
    }

    pub fn hookDel(self: *const Engine, hh: c.uc_hook) Error!void {
        try check(c.uc_hook_del(self.handle, hh));
    }

    pub fn strerror(err: Error) [:0]const u8 {
        const code: c.uc_err = switch (err) {
            Error.NoMemory => c.UC_ERR_NOMEM,
            Error.Arch => c.UC_ERR_ARCH,
            Error.Handle => c.UC_ERR_HANDLE,
            Error.Mode => c.UC_ERR_MODE,
            Error.Version => c.UC_ERR_VERSION,
            Error.ReadUnmapped => c.UC_ERR_READ_UNMAPPED,
            Error.WriteUnmapped => c.UC_ERR_WRITE_UNMAPPED,
            Error.FetchUnmapped => c.UC_ERR_FETCH_UNMAPPED,
            Error.Hook => c.UC_ERR_HOOK,
            Error.InvalidInstruction => c.UC_ERR_INSN_INVALID,
            Error.Map => c.UC_ERR_MAP,
            Error.WriteProtected => c.UC_ERR_WRITE_PROT,
            Error.ReadProtected => c.UC_ERR_READ_PROT,
            Error.FetchProtected => c.UC_ERR_FETCH_PROT,
            Error.InvalidArgument => c.UC_ERR_ARG,
            Error.ReadUnaligned => c.UC_ERR_READ_UNALIGNED,
            Error.WriteUnaligned => c.UC_ERR_WRITE_UNALIGNED,
            Error.FetchUnaligned => c.UC_ERR_FETCH_UNALIGNED,
            Error.Unknown => c.UC_ERR_MAP,
        };
        const msg = c.uc_strerror(code);
        return std.mem.span(msg);
    }
};
