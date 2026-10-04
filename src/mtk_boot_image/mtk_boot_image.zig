//! MediaTek MT6250 (SF_BOOT) 闪存镜像解析器（子包根）。
//!
//! 说明哪些字段来自官方 U-Boot 的 `docs/mtk_image.h.txt`、哪些是本仓库按实测
//! 反推的（反推部分都标了 `推测`），避免把猜测当成规范。所有 on-flash 字段为小端。
//!
//! 本文件只做子包的公共 API 汇总，实现分散在同目录的各模块里：
//! - `bytes.zig`：小端读取、定长字符串、CRC32 等通用零件
//! - `boot_header.zig`：设备头（0x000）
//! - `brlyt.zig`：BootROM 布局头（0x200）
//! - `gfh.zig`：GFH 链式头及其各 body
//! - `image.zig`：镜像表与登记/扫描逻辑
//! - `parse.zig`：解析入口与文件加载
//! - `dump.zig`：结构打印

// 子模块只在内部按命名空间使用（例如 `brlyt.offset`），对外统一走下面的扁平再导出，
// 这样调用方的写法与拆分前完全一致。
const boot_header = @import("boot_header.zig");
const brlyt = @import("brlyt.zig");
const gfh = @import("gfh.zig");
const image = @import("image.zig");
const parse_mod = @import("parse.zig");

// 1. 设备头
pub const boot_name_emmc = boot_header.boot_name_emmc;
pub const boot_name_sf = boot_header.boot_name_sf;
pub const boot_name_sdmmc = boot_header.boot_name_sdmmc;
pub const GenBootHeader = boot_header.GenBootHeader;

// 2. BootROM 布局头
pub const brlyt_name = brlyt.brlyt_name;
pub const brlyt_magic = brlyt.brlyt_magic;
pub const brlyt_region_size = brlyt.brlyt_region_size;
pub const brlyt_max_regions = brlyt.brlyt_max_regions;
pub const brlyt_index_reserved = brlyt.brlyt_index_reserved;
pub const sram_window_base = brlyt.sram_window_base;
pub const sram_window_mask = brlyt.sram_window_mask;
pub const RegionKind = brlyt.RegionKind;
pub const BromLayoutRegion = brlyt.BromLayoutRegion;
pub const BromLayoutHeader = brlyt.BromLayoutHeader;
pub const BromLayout = brlyt.BromLayout;
pub const brlytRegionIndex = brlyt.brlytRegionIndex;
pub const brlytRegionFlash = brlyt.brlytRegionFlash;
pub const flash_type = brlyt.flash_type;
pub const flashTypeName = brlyt.flashTypeName;

// 3. GFH
pub const gfh_file_info_name = gfh.gfh_file_info_name;
pub const GfhCommonHeader = gfh.GfhCommonHeader;
pub const gfh_type = gfh.gfh_type;
pub const GfhBody = gfh.GfhBody;
pub const FileInfo = gfh.FileInfo;
pub const sig_type_none = gfh.sig_type_none;
pub const sig_type_sha256 = gfh.sig_type_sha256;
pub const file_type = gfh.file_type;
pub const fileTypeName = gfh.fileTypeName;
pub const gfhTypeName = gfh.gfhTypeName;

// 4. 解析结果
pub const image_max = image.image_max;
pub const gfh_max = image.gfh_max;
pub const GfhEntry = image.GfhEntry;
pub const Integrity = image.Integrity;
pub const Image = image.Image;
pub const ScanStats = image.ScanStats;
pub const TailInfo = image.TailInfo;
pub const BootImage = image.BootImage;
pub const find = image.find;
pub const payload = image.payload;

// 5. 对外接口
pub const ParseError = parse_mod.ParseError;
pub const loadFile = parse_mod.loadFile;
pub const parse = parse_mod.parse;
pub const dump = @import("dump.zig").dump;

pub const default_image =
    "res/AHONG50_11B_PCB01_gprs_MT6250_S00.D27D__11B_W11_32__V0010.bin";
