//! SDL3 的 C 绑定。
//!
//! SDL3 本身来自依赖 `castholm/SDL`（把 SDL3 C 源码移植到 Zig 构建系统），
//! 链接它的 artifact 之后 include 目录会随之传播。
//! `SDL_MAIN_HANDLED` 保留我们自己的 `main`（SDL3 默认会把它接管成 SDL_main）。

pub const c = @cImport({
    @cDefine("SDL_MAIN_HANDLED", "1");
    @cInclude("SDL3/SDL.h");
});
