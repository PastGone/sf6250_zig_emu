//! MediaTek MT6250 (SF_BOOT) 闪存镜像解析器（子包根）。
//!
//! 说明哪些字段来自官方 U-Boot 的 `docs/mtk_image.h.txt`、哪些是本仓库按实测
//! 反推的（反推部分都标了 `推测`），避免把猜测当成规范。所有 on-flash 字段为小端。
//!
//! 本文件只做子包的公共 API 汇总，实现分散在同目录的各模块里：
//! - `format.zig`：**全部 on-flash 格式定义**。官方区（与 docs/mtk_image.h.txt
//!   1:1 的 extern 定义 + 编译期大小断言）→ 实测扩展区（本镜像观测反推，标
//!   *推测*）→ 解析函数区（拷贝到栈上官方结构再取字段）
//! - `bytes.zig`：小端读取、定长字符串、CRC32 等通用零件
//! - `image.zig`：解析结果数据结构与登记/扫描逻辑
//! - `parse.zig`：解析入口与文件加载
//! - `dump.zig`：结构打印

const fmt = @import("format.zig");
const image = @import("image.zig");
const parse_mod = @import("parse.zig");

// 1. 设备头
pub const GenBootHeader = fmt.GenBootHeader; // 官方 1:1 extern 定义
pub const BootHeader = fmt.BootHeader; // 解析值
pub const boot_name_emmc = fmt.boot_name_emmc;
pub const boot_name_sf = fmt.boot_name_sf;
pub const boot_name_sdmmc = fmt.boot_name_sdmmc;

// 2. BootROM 布局头
pub const BromLayoutHeader = fmt.BromLayoutHeader; // 官方 1:1 extern 定义
pub const BromLayout = fmt.BromLayout; // 解析值（含实测扩展槽位）
pub const BromLayoutRegion = fmt.BromLayoutRegion;
pub const RegionKind = fmt.RegionKind;
pub const BrlytImgType = fmt.BrlytImgType;
pub const brlyt_name = fmt.brlyt_name;
pub const brlyt_magic = fmt.brlyt_magic;
pub const brlyt_region_size = fmt.brlyt_region_size;
pub const brlyt_max_regions = fmt.brlyt_max_regions;
pub const brlyt_index_reserved = fmt.brlyt_index_reserved;
pub const sram_window_base = fmt.sram_window_base;
pub const sram_window_mask = fmt.sram_window_mask;
pub const brlytRegionIndex = fmt.brlytRegionIndex;
pub const brlytRegionFlash = fmt.brlytRegionFlash;
pub const flash_type = fmt.flash_type;
pub const flashTypeName = fmt.flashTypeName;

// 3. GFH
pub const GfhCommonHeader = fmt.GfhCommonHeader;
pub const GfhFileInfo = fmt.GfhFileInfo;
pub const GfhType = fmt.GfhType;
pub const GfhFlashType = fmt.GfhFlashType;
pub const GfhSigType = fmt.GfhSigType;
pub const GfhBody = fmt.GfhBody;
pub const gfh_file_info_name = fmt.gfh_file_info_name;
pub const gfh_type = fmt.gfh_type;
pub const sig_type_none = fmt.sig_type_none;
pub const sig_type_sha256 = fmt.sig_type_sha256;
pub const file_type = fmt.file_type;
pub const fileTypeName = fmt.fileTypeName;
pub const gfhTypeName = fmt.gfhTypeName;

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
