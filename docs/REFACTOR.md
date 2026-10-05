# machine.zig 拆分方案（纯重构，不改任何行为）

现状：`src/emu/machine.zig` 731 行，混杂四种职责。本文是可直接执行的拆分说明。

## 现状结构（行号为拆分前 machine.zig 的实际行号）

| 行号 | 内容 |
|---|---|
| 1-10 | imports（std/log/mtk/uc/c） |
| 12-34 | `map` 地址空间常量 + `max_faults` |
| 35-41 | BootROM 常量（ctx/svc_table/svc_code） |
| 43-72 | 外设：`known_regions`/`regionName`/`uartIndex`/`RegionCtx` |
| 75-378 | `Machine` 结构（字段 75-149、init/deinit、mapSram 150、mapExternalRam 160、**setupBootromContext 175-219**、mapPeriphStubs 221、mapFlashWindow 236、loadBootloader 253、run 288、readPc 324、dumpExecHist 331、recordFault 347、reportFaults 362） |
| 380-482 | 外设读写：`uartPutc`/`periphRead`/`periphWrite`/`onMmioRead`/`onMmioWrite` |
| 484-624 | `onCode`（入口断点/阶段日志/r10 跟踪/越界与栈执行记录——最大的块） |
| 626-676 | 写监视回调：`onTblWrite`/`onSvcTableWrite`/`onLowRamWrite` |
| 678-731 | `onMemInvalid` |

## 目标布局

```
src/emu/
├── machine.zig   ~330 行  Machine 结构 + init/deinit + map* + loadBootloader + run
│                          + readPc/dumpExecHist/recordFault/reportFaults（后两个改 pub）
├── periph.zig    ~120 行  外设接线：known_regions/regionName/uartIndex/RegionCtx/
│                          uartPutc/periphRead/periphWrite/onMmioRead/onMmioWrite
├── diag.zig      ~260 行  诊断：onCode（断点/阶段日志/r10 跟踪）、三个写监视回调、
│                          onMemInvalid
├── bootrom.zig   ~80 行   BootROM 仿真：三个常量（ctx/svc_table/svc_code）、
│                          setupBootromContext、onBusCommand（EMI 重映射+RAM 函数安装，
│                          从 periphWrite 的 0xA01800A0 分支抽出）
├── unicorn.zig / display.zig / emu.zig   不动
```

## 操作步骤（自底向上删，行号不漂移）

1. **diag.zig（先建）**：拷 484-731 全部 + 头部：
   ```zig
   const std = @import("std");
   const log = @import("../log.zig");
   const c = @import("unicorn.zig").c;
   const Machine = @import("machine.zig").Machine;
   ```
   回调签名带 `callconv(.c)` 原样保留。
2. **periph.zig**：拷 43-72 + 380-482 + 头部（log/c/Machine）。
3. **bootrom.zig**：拷 35-41 的三个常量 + 175-219（setupBootromContext）+
   periphWrite 里 0xA01800A0 分支的 EMI 重映射块（约 440-460 行，抽成
   `pub fn onBusCommand(self: *Machine) void`）+ 头部（log/c/uc/map/Machine）。
4. **machine.zig 删**：上述已拷出的行；加三行 import；
   `regions: [2]RegionCtx` 改 `periph.RegionCtx`；
   `dumpExecHist`/`recordFault` 加 `pub`（diag 调用它们）；
   init 里的钩子注册改命名空间：`diag.onCode`、`diag.onTblWrite`、
   `diag.onSvcTableWrite`、`diag.onLowRamWrite`、`diag.onMemInvalid`、
   `periph.onMmioRead`、`periph.onMmioWrite`；
   loadBootloader 里 `setupBootromContext(img.data)` 改 `bootrom.setupBootromContext(self, img.data)`；
   periphWrite 的 0xA01800A0 分支改 `bootrom.onBusCommand(self); return;`
5. `zig fmt src/emu`。

## 循环引用说明

machine.zig ↔ diag/periph/bootrom 互相 import 是**合法的**（Zig 惰性解析，
只要没有 comptime 循环）。Machine 结构留在 machine.zig，其他文件以
`*Machine` 参数访问字段——Zig 结构体字段无私有性，直接可用。

## 验证（必须全做）

```sh
zig build && zig build test
./zig-out/bin/sf6250_zig_emu --lenient > /tmp/after.txt 2>&1
diff <(拆分前同命令输出) /tmp/after.txt   # 逐字节一致才算通过
```

时间戳每次不同，diff 前先 `sed 's/^[0-9:]* //'` 去掉时间戳。

## 拆分时顺手做（可选，同一 commit）

- `bp_logged`/`bp_bss`/`bp_brlyt` 三个一次性断点标志 → diag.zig 里改成
  小型断点表（`[_]struct { addr, flag }`），消除标志共用事故的复发风险
- 服务日志的硬编码地址 `0x7004_2100` → 引 bootrom 常量

## 其他已检查的问题（本次审查结论）

| 问题 | 结论 |
|---|---|
| build.zig 252 行 | 尚可，不拆 |
| unicorn.zig 187 行 | 尚可，不拆 |
| go.mod 在仓库根 | fwextract 用，保留 |
| 诊断一次性标志共用 | 拆分时顺手修（见上） |
| 运行性能（写监视钩子拖慢） | 已记 HANDOFF.md §4，独立任务勿混入重构 |
| 0xA014/0xA071 外设未接线 | 已记 HANDOFF.md §4，独立任务 |
