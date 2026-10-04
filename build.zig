const std = @import("std");

// 本项目只产出一个可执行程序（sf6250_zig_emu），不对外提供 Zig 模块。
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 日志库 axe（https://github.com/Ratakor/axe），0.16 起支持。
    const axe = b.dependency("axe", .{
        .target = target,
        .optimize = optimize,
    }).module("axe");

    const exe = b.addExecutable(.{
        .name = "sf6250_zig_emu",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "axe", .module = axe },
            },
        }),
    });

    // `zig build` 会把产物安装到 prefix（默认 zig-out/）。
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // C 版的 xmake.lua 里 set_rundir(os.projectdir())：固件资源按项目根的相对
    // 路径存放（res/...），这里同样把运行目录钉在 build root，保证
    // `zig build run` 能解析默认镜像路径。
    run_cmd.setCwd(b.path("."));

    // 让 run 步骤依赖 install，这样会从安装目录而不是 cache 目录运行。
    run_cmd.step.dependOn(b.getInstallStep());

    // 允许 `zig build run -- arg1 arg2` 透传参数给程序。
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
