// fwextract：把 MT6250 固件按「加载视图」切成 IDA Pro 可直接分析的切片。
//
// 用法：
//
//	go run ./tools/fwextract -fw res/AHONG50_...bin -out ida
//
// 输出（-out 目录）：
//   - flash_16m.bin   整片 flash，IDA 里以基址 0x10000000 加载（XIP 视图）
//   - bl_sram.bin     第 2 阶段 Bootloader 载荷，基址 0x7000818c（SRAM 视图）
//   - maui_xip.bin    MAUI 主固件载荷，基址 0x10020300
//   - MANIFEST.md     每个切片的基址/入口/模式 + 已知地标（诊断中确认的函数）
//   - ida_load.py     IDAPython：在 IDB 里补建 SRAM 段、设入口与 Thumb 标志、打地标标签
//
// 切片规则与模拟器装载一致（src/mtk_boot_image/format.zig / image.zig）：
// 载荷 = 镜像区起点 + hdr_size；目标地址 = load_addr + hdr_size；
// 入口 = 目标地址 | jump_offset（bit0 = Thumb）。
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// 固件内已解析出的镜像区（本固件实测值；换固件需同步 mtk_boot_image 的解析结果）
type region struct {
	name     string // 人类可读名
	file     uint32 // 镜像区内文件偏移（区起点，含 GFH 头）
	hdrSize  uint32 // GFH 头链总长
	loadAddr uint32 // 声明的加载地址
	entry    uint32 // 入口（SRAM/flash 视图地址，含 Thumb 位）
	end      uint32 // 区终点（文件偏移）
}

var regions = []region{
	{"bl_sram", 0x800, 0x18c, 0x70008000, 0x7000818d, 0x2980},
	{"extbl_xip", 0x8000, 0x60, 0x10008000, 0x10008061, 0xe2a0},
	{"maui_xip", 0x20000, 0x300, 0x10020000, 0x10020301, 0x874eb0},
	{"maui_res", 0x8752b0, 0x38, 0x108752b0, 0, 0xdd89f8},
}

// 已知地标：诊断中确认过的函数/数据（详见 docs/mt6250-wiring.md）
type landmark struct {
	addr uint32
	name string
	desc string
}

var landmarks = []landmark{
	// ---- 第 2 阶段 BL（SRAM 视图）----
	{0x7000818c, "bl_entry", "BL 入口（Thumb）"},
	{0x700082ac, "xor_checksum", "XOR 校验：[base+0x20]=长度，对 0x400 字节异或"},
	{0x700082e0, "init_dispatch", "初始化分发：注册回调表 0x7000a114，arg1=镜像基址(r10)"},
	{0x70008bf8, "table_register", "注册助手：*0x7000a114 = r2"},
	{0x7000868e, "pll_lock_wait", "轮询 0xA0050318 bit1（PLL 锁定）"},
	{0x70008aac, "clk_switch_p1", "时钟切换握手：写 0x300F0000 等 bit7=1"},
	{0x70008ab6, "clk_switch_p2", "写 0x700F0000 等 bit7=0"},
	{0x70008fa8, "emi_calib", "EMI 校准例程：命令 0x11 → 0xA01800A0，读 A8/B8 测量值"},
	{0x70009688, "indirect_call_site", "blx [[0x7000a114]]——崩溃点（表内容错→跳 0）"},
	{0x70009b20, "ram_zero_loop", "ARM 清零循环 [r0, r1)，返回 r0=终点"},
	{0x700099c8, "ram_veneer", "RAM 蹦床：mov r7,lr；BSS 清理；bx r7（ARM 模式）"},
	// ---- 外设寄存器（分析时对照）----
	{0xA0010100, "emi_ctrl", "EMI 控制器配置（BL 写 0x8610/0x8049）"},
	{0xA0010320, "emi_ctrl_b", "EMI 控制器（BL 写 halfword 1）"},
	{0xA0050090, "clk_switch", "时钟切换命令/状态（三步握手）"},
	{0xA0050318, "pll_lock", "PLL 锁定状态 bit1"},
	{0xA01800A0, "bus_cmd", "总线命令：bit0=busy，写 0x11 清"},
	{0xA0730160, "acfg_gpio", "ACFG GPIO（数据手册已确认）"},
	// ---- 阶段 3/4 ----
	{0x10008061, "extbl_entry", "第 3 阶段 BL2 入口（Thumb，XIP）"},
	{0x10020301, "maui_entry", "第 4 阶段 MAUI 入口（Thumb，XIP）"},
}

func write(out string, data []byte) error {
	return os.WriteFile(out, data, 0o644)
}

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func main() {
	fwPath := flag.String("fw", "res/AHONG50_11B_PCB01_gprs_MT6250_S00.D27D__11B_W11_32__V0010.bin", "固件路径")
	outDir := flag.String("out", "ida", "输出目录")
	flag.Parse()

	fw, err := os.ReadFile(*fwPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read firmware: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("固件: %s (%d 字节)\n", *fwPath, len(fw))
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// 1. 整片 flash（XIP 视图）
	if err := write(filepath.Join(*outDir, "flash_16m.bin"), fw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// 2. 每个镜像区的载荷切片（基址 = load_addr + hdr_size）
	type slice struct {
		name   string
		base   uint32
		data   []byte
		r      region
	}
	var slices []slice
	for _, r := range regions {
		start := r.file + r.hdrSize
		if start < r.file || r.end > uint32(len(fw)) || start >= r.end {
			fmt.Fprintf(os.Stderr, "region %s 越界，跳过\n", r.name)
			continue
		}
		base := r.loadAddr + r.hdrSize
		data := fw[start:r.end]
		slices = append(slices, slice{r.name, base, data, r})
		if err := write(filepath.Join(*outDir, r.name+".bin"), data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("  %s.bin: 文件 0x%x..0x%x → 基址 0x%08x (%d 字节)\n",
			r.name, start, r.end, base, len(data))
	}

	// 3. IDAPython 脚本：在已加载 flash 的 IDB 里补段 + 入口 + 地标
	var py string
	py += "import idaapi, ida_segment, ida_bytes, ida_funcs, idc, ida_name\n\n"
	py += "# 前提：先把 flash_16m.bin 以 ARM Little-endian、基址 0x10000000 载入 IDB，再运行本脚本\n\n"
	for _, s := range slices {
		if s.name == "bl_sram" {
			// BL 的 SRAM 视图内容与 flash 视图相同，直接补一段并填字节
			py += fmt.Sprintf("if ida_segment.getseg(0x%08x) is None:\n", s.base)
			py += fmt.Sprintf("    ida_segment.add_segm(0, 0x%08x, 0x%08x, %q, \"CODE\")\n",
				s.base, s.base+uint32(len(s.data)), s.name)
			py += fmt.Sprintf("ida_bytes.put_bytes(0x%08x, bytes.fromhex(%q))\n",
				s.base, fmt.Sprintf("%x", s.data))
		}
	}
	py += "\n# 入口与 Thumb 标志（IDA 9: add_entry(ea, name, makecode)）\n"
	entryNames := map[string]string{
		"bl_sram":   "bl_entry",
		"extbl_xip": "extbl_entry",
		"maui_xip":  "maui_entry",
	}
	for _, r := range regions {
		if r.entry == 0 {
			continue
		}
		e := r.entry
		name := entryNames[r.name]
		if name == "" {
			name = fmt.Sprintf("entry_%x", e&^1)
		}
		py += fmt.Sprintf("ida_funcs.add_func(0x%08x)\n", e&^1)
		py += fmt.Sprintf("idc.add_entry(0x%08x, %q, True)\n", e&^1, name)
		py += fmt.Sprintf("idc.split_sreg_range(0x%08x, \"T\", %d, idc.SR_user)\n", e&^1, e&1)
	}
	py += "\n# 已知地标（命名 + 重复注释）\n"
	for _, l := range landmarks {
		py += fmt.Sprintf("ida_name.set_name(0x%08x, %q, ida_name.SN_NOWARN)\n", l.addr, l.name)
		py += fmt.Sprintf("idc.set_func_cmt(0x%08x, %q, 0) if ida_funcs.get_func(0x%08x) else None\n",
			l.addr, l.desc, l.addr)
	}
	py += "\nprint(\"fwextract: 段/入口/地标设置完成\")\n"
	if err := write(filepath.Join(*outDir, "ida_load.py"), []byte(py)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// 4. 地标标签也打在 BL SRAM 切片里？不需要——SRAM 段已在同一 IDB。

	// 5. MANIFEST.md
	mf := "# IDA 切片清单（由 tools/fwextract 生成）\n\n"
	mf += "## 加载步骤\n\n"
	mf += "1. IDA 打开 `flash_16m.bin`：Processor = ARM Little-endian，Loading offset = `0x10000000`，\n"
	mf += "   ROM start/address 同为 0x10000000；选项里把 Min EA/Max EA 覆盖为整个 16MB。\n"
	mf += "2. File → Script file… 运行 `ida_load.py`（补 BL 的 SRAM 段、设入口、打地标名）。\n"
	mf += "3. 入口处按 C 让 IDA 以 Thumb 反汇编（脚本已设 T 标志）。\n\n"
	mf += "## 切片\n\n"
	mf += "| 文件 | 基址 | 大小 | 入口 | 模式 | 说明 |\n|---|---|---|---|---|---|\n"
	mf += "| flash_16m.bin | 0x10000000 | 16M | — | ARM/Thumb 混合 | 整片 flash（XIP 视图） |\n"
	for _, s := range slices {
		mode := "Thumb"
		if s.r.entry != 0 && s.r.entry&1 == 0 {
			mode = "ARM"
		}
		entry := "—"
		if s.r.entry != 0 {
			entry = fmt.Sprintf("0x%08x", s.r.entry)
		}
		mf += fmt.Sprintf("| %s.bin | 0x%08x | %d | %s | %s | %s |\n",
			s.name, s.base, len(s.data), entry, mode, s.r.name)
	}
	mf += "\n## 已知地标\n\n"
	mf += "| 地址 | 名称 | 说明 |\n|---|---|---|\n"
	for _, l := range landmarks {
		mf += fmt.Sprintf("| 0x%08x | `%s` | %s |\n", l.addr, l.name, l.desc)
	}
	mf += "\n## 背景阅读\n\n- `docs/mt6250-wiring.md`：外设接线与启动链情报\n"
	mf += "- `docs/uboot/tools/mtk_image.h.txt`：官方镜像头定义\n"
	mf += "- 模拟器侧解析：`src/mtk_boot_image/format.zig`（切分规则同源）\n"
	if err := write(filepath.Join(*outDir, "MANIFEST.md"), []byte(mf)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("输出目录: %s\n", *outDir)
	_ = u32le
}
