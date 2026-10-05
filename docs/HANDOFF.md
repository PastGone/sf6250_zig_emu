# MT6250 模拟器接力文档（给下一个 AI / 开发者）

> 本文档写给**从零上下文接手**的 AI。读完本文 + `docs/mt6250-wiring.md` 即可继续开发。
> 所有结论都有实证（反编译/运行日志），标注「推测」的除外。

## 1. 项目是什么

MT6250（MTK 功能机 GSM/GPRS 基带 SoC，ARM7EJ-S ≈ ARMv5TE）的固件模拟器：

- **语言**：Zig 0.16（构建系统）+ Unicorn 2.1.4（CPU，源码 vendor 在 `vendor/unicorn/`，由 zig cc 直接编译，不用 cmake、不链系统库）+ SDL3（castholm/SDL 源码构建）
- **固件**：`res/AHONG50_...bin`（16MB NOR 整片 dump，已入库）
- **构建/运行**：`zig build run -- --lenient`（--lenient = 未映射读写自动映射 4KB 页放行）
- **测试**：`zig build test`
- **Windows 交叉编译**：`zig build -Dtarget=x86_64-gnu`（已验证）

## 2. 启动链模型（四阶段，全部有实证）

```
1. BootROM   片上 mask ROM（无固件）→ 模拟器扮演它：
             拷 BL 全镜像到 SRAM 0x70008000、设 SP/CPSR、
             r4 = BootROM 上下文指针（关键！见 §4）
2. ExtBL     SRAM 0x7000818c（镜像 0x800~0x2980）← 我们现在在这
3. BL2       XIP 0x10008061（镜像 0x8000 区）
4. MAUI      入口 0x10020301；⚠️ 运行时被重定位到外部 RAM 0x84Exxxxx（非 XIP）
```

BL 最终会**跳转到 0x0** 调用 BootROM 安装在低 RAM 的函数——这是正常流程，
不是崩溃（模拟器的 `until=0` 哨兵曾因此误拦，已改为 0xFFFFFFF0）。

## 3. 已实现（machine.zig）

- **外设接线**（读回有意义值/写日志）：UART1/2/3（0xA006/7/0080000，16550）、
  CLK/PLL 0xA0050000、EMI 总线命令 0xA0180000、LCM 0xA0450000、ACFG 0xA0730000
- **BootROM 上下文合成**（`setupBootromContext`）：
  - ctx = 0x70041000（地址必须 > 0x70040000：BL 的 BSS 清理范围止于此）
  - ctx+0x000：TLV 记录（首记录 0x6b422101+4，终止符 0x6820d104）
  - ctx+0x208：**BRLYT 表副本**（镜像 0x200~0x408）——BL 校验 strcmp+槽位扫描
  - ctx+0x8A8：模式标志 bit1（填 0 走默认路径）
  - ctx+0x8DC：服务表指针 → 0x70042000
- **服务表** 0x70042000：+0x00/+0x08/+0x18/+0x34 四个函数指针（**必须带 Thumb 位！**）
  → 服务桩 0x70042100（movs r0,#0; bx lr，返回 0）
- **EMI 重映射**：0xA01800A0 首次写入触发——0x0 从只读 NOR 视图切 8MB 可写 RAM，
  并在 0x0 安装 BootROM RAM 函数（ARM: mov r0,#0; bx lr）——BL 会跳到 0x0 调用它
- **SRAM 2MB**（0x70000000；run761 写 1MB，实测执行冲出 1MB 边界故扩到 2MB）
- **外部 RAM** 0x82000000+64MB（MAUI 重定位目标 0x84Exxxxx）
- **全镜像装载**：GFH 头链随载荷一起拷进 SRAM（BL 的记录查找器在头副本里按
  GFH type 找 FILE_INFO/ANTI_CLONE 记录——只拷载荷会读全零）

## 4. 当前卡点（接手后第一件事）

1 亿条预算下，BL 完成全部初始化（EMI/时钟/校准/服务分发/UART3 配置序列），
**已通过 0x7000825c 错误自旋**（BRLYT 校验放行），进入 **ExtBL 装载阶段**，
触碰两个未接线外设后停止：

- `0xA014xxxx`：写 0x800/0x10/0x14，读 0x04 —— 用途未知，待查（IDA）
- `0xA071xxxx`：读 0x50/0x54/0x00 —— ACFG 域（0xA073 = GPIO 已确认）

同时**性能不足**：3 个写监视钩子 + 2MB 映射拖慢速度，100M 条跑不完 550s。
优化方向：合并/裁剪监视范围（只保留 svc 表和必要段）、降低日志量。

## 5. 诊断工具箱（machine.zig 的 onCode/onMemInvalid 内，全部带开关）

| 工具 | 触发 | 用途 |
|---|---|---|
| PC 轨迹环 1024 条 | run 结束打印 `末尾轨迹` | 看停机/空转前执行序列 |
| 外设访问计数 | run 结束按次数排序 | 轮询目标自动浮到榜首 |
| 入口断点（0x700082e0 / 0x70009b20 / 0x7000844a） | 各自独立标志 | 抓参数现场 |
| 写监视（回调表 0x7000a114 / 低 RAM / 服务表+代码 / init 代码区） | guest 写入时 | 抓改写者 pc+lr |
| 阶段切换日志 | pc == 0x10008061 / 0x10020301 打 ★ | 确认进入下阶段 |
| 取指失败 INFO 日志 | fetch unmapped | 定位跳转指令 pc |
| 停止现场 | run 结束 | cpsr（含 T 位/mode）+ sp + 代码区内存 hex |

**方法论**（已验证有效，勿改）：遇到新卡点 → PC 轨迹定位循环/跳转 →
capstone 反汇编目标（注意 ARM/Thumb 模式，运行时内存可能 ≠ 静态镜像）→
确认轮询的寄存器/缺失的数据 → 接线或合成数据 → 重跑。

## 6. 已知地址速查（详见 docs/mt6250-wiring.md）

| 地址 | 含义 |
|---|---|
| 0x7000825c | BL 错误自旋（某初始化返回 -1 时 b . 等死）——已通过 |
| 0x70008266 | 读 [ctx+0x8A8] bit1 设模式标志；UART3/EMI 初始化 |
| 0x700082ac | XOR 校验（[base+0x20]=长度，校验 0x400 字节） |
| 0x700082e0 | init_dispatch：校验和+sl 存全局、注册服务表 |
| 0x70008bf8 | table_register：*0x7000a114 = r2 |
| 0x70008fa4 | EMI 校准（有限迭代，已跑通） |
| 0x70009b20 | ARM 清零循环 [r0, r1)，返回 r0=终点 |
| 0x700099c8 | RAM 蹦床（mov r7,lr；会清 r0-r3/r7） |
| 0x70009688 | 服务调用分发：服务表 +0x00/+0x08/+0x18/+0x34 依次调用 |
| 0x7000842c | BRLYT 校验+ExtBL 槽位扫描（index==2）→ 调 0x70008e78 装载器 |
| 0x7000a0e4 | 全局：init_dispatch 的 a2（= ctx 指针） |
| 0x7000a114 | 服务表指针槽（= [ctx+0x8DC]） |

## 7. 铁律（前一个 AI 用 761 轮补丁换来的教训 + 本轮验证）

1. **函数指针必须带 Thumb 位（bit0=1）**——否则 blx 切 ARM 模式执行 Thumb
   字节 → 条件跳过 → 滑进零区。已犯过两次（服务表、GFH 交接）
2. **不跳过任何初始化**——跳过的会在十万里之外爆炸（前 AI 的 761 轮补丁地狱）
3. **stub 必须有名字和依据**——每个接线的外设/合成的数据都要能回答
   「为什么是这个值」
4. **运行时内存 ≠ 静态镜像**——0x70009900~0x70009b40 是运行时写入的代码，
   静态反汇编不可信；断点时刻 dump 运行时内存再反汇编
5. **Zig 侧陷阱**：函数指针/内存写入的常量不要在多处硬编码（ctx 地址曾两处
   脱节）；C 回调不能传播错误（用 catch）；`until=0` 哨兵会拦截合法跳转

## 8. 工具链

- **IDA**：`tools/fwextract`（Go）切片固件 → `ida/`（flash_16m + bl_sram +
  extbl + maui 切片，基址/入口/Thumb 标志/18 个地标函数名全自动）。
  `ida/bl_sram.elf.i64` 已保存（ARM ELF 包装版，函数已命名：init_dispatch、
  xor_checksum、service_call_dispatch 等）
- **注意**：bl_sram.elf 的 IDA 地址 = 真实地址 − 0x7000818c；Thumb/ARM 混合
  区域 IDA 自动分析边界不可信，关键函数用 capstone 手动验证
- **文档**：`docs/mt6250-wiring.md`（外设接线+启动链+教训）、
  `docs/uboot/tools/mtk_image.h.txt`（官方镜像头定义）、
  `docs/markdown/`（数据手册文字提取，1.md=SoC 概述、2.md=寄存器位定义）

## 9. 下一步路线（优先级序）

1. **性能**：裁剪写监视（只留服务表/必要段）、或预算分段——让 100M 条能跑完
2. **接线 0xA014/0xA071**：IDA 查语义（可能是 DMA/NAND 控制器——ExtBL 装载
   用），接线后 BL 应继续走 ExtBL 装载
3. **跑到 ★ 进入 BL2**：ExtBL 装载完成 → BL 跳 0x10008061
4. **BL2 阶段**：重复同样的流程（它可能也需要 BootROM 服务——服务表已就位）
5. **MAUI + Nucleus**：定时器 tick + 中断控制器（手册有 IRQ_CLR/IRQMASK），
   RTOS 调度活起来后接 LCD（LCM 0xA0450000，320×240 RGB565）和 keypad

## 10. 提交纪律

每个里程碑一个 commit（当前 HEAD：`39a9e4f` 之后的 `078700a`），消息里写
「实测」段落——这是下一个人最宝贵的上下文。诊断工具的增删也要进 commit。
