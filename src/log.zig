//! 日志：基于 axe（https://github.com/Ratakor/axe）的实例与配置。
//!
//! 取代原先手写的 rxi-log 复刻版。`Axe(.{...})` 每个实例自带全局状态，
//! 因此整个项目共用这里导出的这一个实例。

const std = @import("std");

pub const log = @import("axe").Axe(.{
    // HH:MM:SS LEVEL file:line: message
    .format = "%t %l%L %m\n",
    .time_format = .{ .strftime = "%H:%M:%S" },
    .loc_format = " %f:%l:",
    .level_text = .{
        .err = "ERROR",
        .warn = "WARN",
        .info = "INFO",
        .debug = "DEBUG",
    },
    .color = .auto,
});

/// 这些别名让调用点保持 log.xxxAt(@src(), ...) 之外的简洁形式。
pub const info = log.infoAt;
pub const warn = log.warnAt;
pub const debug = log.debugAt;
pub const err = log.errAt;

/// `env` 用于读取 TZ / TZDIR（时间输出）与 NO_COLOR / CLICOLOR_FORCE。
pub fn init(io: std.Io, env: ?*const std.process.Environ.Map) !void {
    try log.init(io, null, env);
}

pub fn deinit() void {
    log.deinit();
}
