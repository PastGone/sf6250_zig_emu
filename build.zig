const std = @import("std");

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
            // SDL3 / unicorn 都是 C 库，需要 libc
            .link_libc = true,
            .imports = &.{
                .{ .name = "axe", .module = axe },
            },
        }),
    });

    // gcc16 的 crt1.o 带 .sframe 段，Zig 0.16 的自研链接器处理不了其中的
    // R_X86_64_PC64 重定位，回退到 lld 就能过去。
    exe.use_llvm = true;

    // SDL3：castholm/SDL 是官方 SDL3 C 源码的 zig 构建移植，纯 zig 编译，
    // 不用系统库。头文件目录显式加进来，@cImport("SDL3/SDL.h") 直接可用。
    const sdl_dep = b.dependency("sdl", .{ .target = target, .optimize = optimize });
    exe.root_module.addIncludePath(sdl_dep.path("include"));
    exe.root_module.linkLibrary(sdl_dep.artifact("SDL3"));

    // Unicorn：源码（build.zig.zon 里 hash 固定）直接用 zig cc 编进可执行文件，
    // 只编 ARM，不用 cmake。详见 buildUnicorn。
    buildUnicorn(b, exe, target);

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
    exe_tests.use_llvm = true; // 同上：绕开 .sframe 重定位
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}

/// 把 vendor/unicorn 的 C 源码直接编进可执行文件，等价于其 CMake 里
/// UNICORN_ARCH=arm 的三个目标（unicorn / unicorn-common / arm-softmmu）。
/// 文件清单与编译选项照抄 unicorn 2.1.4 的 CMakeLists.txt（注释里给行号）。
/// 源码不走 build.zig.zon 依赖：上游包自带的 build.zig 面向旧版 Zig，
/// b.dependency() 一编译它就报错；vendor 目录用 b.path() 引用即可。
fn buildUnicorn(b: *std.Build, exe: *std.Build.Step.Compile, target: std.Build.ResolvedTarget) void {
    const uc = b.path("vendor/unicorn");
    const m = exe.root_module;
    const is_windows = target.result.os.tag == .windows;

    // include 目录 = CMakeLists.txt:98-106（CMAKE_BINARY_DIR 上的 config-host.h
    // 换成预生成的 src/emu/uc_config/，按目标 OS 选 host 侧那份）。
    m.addIncludePath(b.path("src/emu/uc_config/common"));
    const host_cfg: []const u8 = if (is_windows)
        "src/emu/uc_config/windows"
    else
        "src/emu/uc_config/linux";
    m.addIncludePath(b.path(host_cfg));
    m.addIncludePath(uc.path(b, "glib_compat"));
    m.addIncludePath(uc.path(b, "qemu"));
    m.addIncludePath(uc.path(b, "qemu/include"));
    m.addIncludePath(uc.path(b, "include"));
    m.addIncludePath(uc.path(b, "qemu/tcg"));

    // TCG 宿主后端按宿主架构选（CMakeLists 里的 UNICORN_TARGET_ARCH）。
    switch (target.result.cpu.arch) {
        .x86_64 => m.addIncludePath(uc.path(b, "qemu/tcg/i386")),
        .aarch64 => m.addIncludePath(uc.path(b, "qemu/tcg/aarch64")),
        else => std.debug.panic("unicorn 构建暂不支持宿主架构 {s}", .{@tagName(target.result.cpu.arch)}),
    }

    // 全局编译选项：CMakeLists.txt:473-479（-D_GNU_SOURCE 等）+ 1275 行
    // -DUNICORN_HAS_ARM + x86_64 上的 -mcx16（128 位原子操作；CMAKE 里
    // UNICORN_CFLAGS=-m64 -mcx16，-m64 在 x86_64 下是默认值）。
    const is_x86_64 = target.result.cpu.arch == .x86_64;
    const global_flags: []const []const u8 = if (is_x86_64)
        &unicorn_global_flags_x86
    else
        &unicorn_global_flags;
    // ARM 组私有选项（CMakeLists.txt:595-599）：-DNEED_CPU_H 是 config-target.h
    // 的开关；-include arm.h 让 qemu/arm.h 把符号统一改名加 _arm 后缀；
    // -I target/arm 供 cpu.h / cpu-param.h 命中。-include 的文件必须能被 zig
    // 的 C 缓存清单按路径直接打开（不走 -I 搜索），所以用绝对路径。
    const arm_extra = [_][]const u8{
        "-DNEED_CPU_H",
        "-include",
        b.pathFromRoot("vendor/unicorn/qemu/arm.h"),
        "-I",
        b.pathFromRoot("vendor/unicorn/qemu/target/arm"),
    };
    const arm_flags = std.mem.concat(
        b.graph.arena,
        []const u8,
        &.{ global_flags, &arm_extra },
    ) catch @panic("out of memory");

    // unicorn 核心（CMakeLists.txt:1169 UNICORN_SRCS）
    m.addCSourceFiles(.{
        .root = uc,
        .files = &.{
            "uc.c",
            "qemu/softmmu/vl.c",
            "qemu/hw/core/cpu.c",
        },
        .flags = global_flags,
    });

    // 公共层（CMakeLists.txt:1177 UNICORN_COMMON_SRCS；平台相关的
    // oslib/qemu-thread 两个文件见下一个调用）
    m.addCSourceFiles(.{
        .root = uc,
        .files = &.{
            "list.c",
            "glib_compat/glib_compat.c",
            "glib_compat/gtestutils.c",
            "glib_compat/garray.c",
            "glib_compat/gtree.c",
            "glib_compat/grand.c",
            "glib_compat/glist.c",
            "glib_compat/gmem.c",
            "glib_compat/gpattern.c",
            "glib_compat/gslice.c",
            "qemu/util/bitmap.c",
            "qemu/util/bitops.c",
            "qemu/util/crc32c.c",
            "qemu/util/cutils.c",
            "qemu/util/getauxval.c",
            "qemu/util/guest-random.c",
            "qemu/util/host-utils.c",
            "qemu/util/osdep.c",
            "qemu/util/qdist.c",
            "qemu/util/qemu-timer.c",
            "qemu/util/qemu-timer-common.c",
            "qemu/util/range.c",
            "qemu/util/qht.c",
            "qemu/util/pagesize.c",
            "qemu/util/cacheinfo.c",
            "qemu/crypto/aes.c",
        },
        .flags = global_flags,
    });

    // 平台层（CMakeLists.txt:1177-1236 的 MSVC/POSIX 两分支）。注意 qemu 的
    // thread.h 在 __MINGW32__（含 zig 的 windows-gnu）下也走 POSIX/winpthreads，
    // win32 文件是纯 MSVC 路径；MSVC 独有的 setjmp-wrapper-win32.asm 是 MASM，
    // zig 路径用不到。
    const use_win32_thread = target.result.abi == .msvc;
    const platform_files: []const []const u8 = if (use_win32_thread)
        &.{ "qemu/util/oslib-win32.c", "qemu/util/qemu-thread-win32.c" }
    else
        &.{ "qemu/util/oslib-posix.c", "qemu/util/qemu-thread-posix.c" };
    m.addCSourceFiles(.{
        .root = uc,
        .files = platform_files,
        .flags = global_flags,
    });

    // ARM 目标（CMakeLists.txt:574 arm-softmmu = UNICORN_ARCH_COMMON 493 +
    // target/arm），私有选项见 arm_extra。
    m.addCSourceFiles(.{
        .root = uc,
        .files = &.{
            "qemu/exec.c",
            "qemu/exec-vary.c",
            "qemu/softmmu/cpus.c",
            "qemu/softmmu/ioport.c",
            "qemu/softmmu/memory.c",
            "qemu/softmmu/memory_mapping.c",
            "qemu/fpu/softfloat.c",
            "qemu/tcg/optimize.c",
            "qemu/tcg/tcg.c",
            "qemu/tcg/tcg-op.c",
            "qemu/tcg/tcg-op-gvec.c",
            "qemu/tcg/tcg-op-vec.c",
            "qemu/accel/tcg/cpu-exec.c",
            "qemu/accel/tcg/cpu-exec-common.c",
            "qemu/accel/tcg/cputlb.c",
            "qemu/accel/tcg/tcg-all.c",
            "qemu/accel/tcg/tcg-runtime.c",
            "qemu/accel/tcg/tcg-runtime-gvec.c",
            "qemu/accel/tcg/translate-all.c",
            "qemu/accel/tcg/translator.c",
            "qemu/softmmu/unicorn_vtlb.c",
            "qemu/target/arm/cpu.c",
            "qemu/target/arm/crypto_helper.c",
            "qemu/target/arm/debug_helper.c",
            "qemu/target/arm/helper.c",
            "qemu/target/arm/iwmmxt_helper.c",
            "qemu/target/arm/m_helper.c",
            "qemu/target/arm/neon_helper.c",
            "qemu/target/arm/op_helper.c",
            "qemu/target/arm/psci.c",
            "qemu/target/arm/tlb_helper.c",
            "qemu/target/arm/translate.c",
            "qemu/target/arm/vec_helper.c",
            "qemu/target/arm/vfp_helper.c",
            "qemu/target/arm/unicorn_arm.c",
        },
        .flags = arm_flags,
    });

    // CMakeLists 里 unicorn.pc 的 Libs.private：-lpthread -lm。POSIX 平台层
    // （含 windows-gnu 的 winpthreads）需要 pthread；libm 是 Linux 独有的拆分。
    if (!use_win32_thread) {
        m.linkSystemLibrary("pthread", .{});
    }
    if (!is_windows) {
        m.linkSystemLibrary("m", .{});
    }
}

const unicorn_global_flags = [_][]const u8{
    "-std=gnu11",
    "-D_GNU_SOURCE",
    "-D_FILE_OFFSET_BITS=64",
    "-D_LARGEFILE_SOURCE",
    "-DUNICORN_HAS_ARM",
    // zig 在 Debug 下给 C 源默认开 UBSan，QEMU 5 的老代码里有对 null 指针做
    // 偏移的良性 UB（gcc/clang 正常构建的 unicorn 同样带这些代码），关掉对齐。
    "-fno-sanitize=undefined",
};
const unicorn_global_flags_x86 = unicorn_global_flags ++ [_][]const u8{"-mcx16"};
