//! 模拟器子包根。
//!
//! - `unicorn.zig`：CPU（Unicorn）薄封装
//! - `machine.zig`：地址空间、装载与执行
//! - `display.zig`：LCD 窗口（SDL3）

pub const unicorn = @import("unicorn.zig");
pub const machine = @import("machine.zig");
pub const display = @import("display.zig");

pub const Machine = machine.Machine;
pub const Display = display.Display;
pub const map = machine.map;
