//! 唯一职责：把 unicorn 的 C 头文件翻译成 Zig。
//!
//! include 路径由 build.zig 推导（UNICORN_PREFIX，或系统/ pip 安装的 libunicorn）。

pub const c = @cImport({
    @cInclude("unicorn/unicorn.h");
});
