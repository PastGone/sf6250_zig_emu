//! LCD 显示：把固件写进 framebuffer 的像素搬到 SDL 窗口上。
//!
//! MT6250 的 LCD 控制器支持 RGB332/444/565/666/888，功能机上最常见的是
//! RGB565，且像素缓冲区在 RAM 里（控制器用 DMA 取）。这里先把 565 → XRGB8888
//! 的转换做好，framebuffer 地址待实测确认后再接上去。

const std = @import("std");
const log = @import("../log.zig");
const c = @import("c/sdl.zig").c;

pub const Display = struct {
    window: ?*c.SDL_Window = null,
    renderer: ?*c.SDL_Renderer = null,
    texture: ?*c.SDL_Texture = null,
    width: u32 = 0,
    height: u32 = 0,
    /// XRGB8888 中转缓冲（每像素 4 字节）
    pixels: []u32 = &.{},
    scale: u32 = 2,

    pub fn init(title: [:0]const u8, width: u32, height: u32, scale: u32) !Display {
        if (!c.SDL_Init(c.SDL_INIT_VIDEO)) return error.SdlInitFailed;

        var d: Display = .{ .width = width, .height = height, .scale = scale };
        errdefer d.deinit();

        d.window = c.SDL_CreateWindow(
            title,
            @intCast(width * scale),
            @intCast(height * scale),
            0,
        ) orelse return error.SdlWindowFailed;
        d.renderer = c.SDL_CreateRenderer(d.window, null) orelse return error.SdlRendererFailed;
        d.texture = c.SDL_CreateTexture(
            d.renderer,
            c.SDL_PIXELFORMAT_XRGB8888,
            c.SDL_TEXTUREACCESS_STREAMING,
            @intCast(width),
            @intCast(height),
        ) orelse return error.SdlTextureFailed;

        d.pixels = try std.heap.page_allocator.alloc(u32, @as(usize, width) * height);
        @memset(d.pixels, 0xff00_0000);

        return d;
    }

    pub fn deinit(self: *Display) void {
        if (self.pixels.len > 0) std.heap.page_allocator.free(self.pixels);
        if (self.texture) |t| c.SDL_DestroyTexture(t);
        if (self.renderer) |r| c.SDL_DestroyRenderer(r);
        if (self.window) |w| c.SDL_DestroyWindow(w);
        c.SDL_Quit();
        self.* = .{};
    }

    /// 把 RGB565 小端缓冲画出来（长度不足时按有效像素处理）
    pub fn present565(self: *Display, fb: []const u8) void {
        const n = @min(self.pixels.len, fb.len / 2);
        for (0..n) |i| {
            const v = std.mem.readInt(u16, fb[i * 2 ..][0..2], .little);
            const r = (v >> 11) & 0x1f;
            const g = (v >> 5) & 0x3f;
            const b = v & 0x1f;
            // 565 → 888：高位补齐，避免整体偏暗
            const r8 = (r << 3) | (r >> 2);
            const g8 = (g << 2) | (g >> 4);
            const b8 = (b << 3) | (b >> 2);
            self.pixels[i] = 0xff00_0000 | (@as(u32, r8) << 16) | (@as(u32, g8) << 8) | b8;
        }
        self.present();
    }

    pub fn present(self: *Display) void {
        if (self.texture == null or self.renderer == null) return;
        _ = c.SDL_UpdateTexture(self.texture, null, self.pixels.ptr, @intCast(self.width * 4));
        _ = c.SDL_RenderTexture(self.renderer, self.texture, null, null);
        _ = c.SDL_RenderPresent(self.renderer);
    }

    pub fn delay(_: *Display, ms: u32) void {
        c.SDL_Delay(ms);
    }

    /// 泵一次 SDL 事件；返回 false 表示用户要退出
    pub fn pump(self: *Display) bool {
        _ = self;
        var ev: c.SDL_Event = undefined;
        while (c.SDL_PollEvent(&ev)) {
            switch (ev.type) {
                c.SDL_EVENT_QUIT => return false,
                c.SDL_EVENT_KEY_DOWN => {
                    // 后面映射成 keypad 矩阵；先只记日志，确认事件链路通
                    log.debug(@src(), "sdl key down: scancode={d}", .{ev.key.scancode});
                },
                else => {},
            }
        }
        return true;
    }
};
