# SuperLamzu

[English](README.md) | 简体中文

基于 [hyperdrako](https://gitlab.jaceee.dev/open/hyperdrako) 的二次开发与 LAMZU 固件移植，提供 **SUPER 固件补丁构建器与命令行配置工具**。仅供学习与研究。

## 支持设备

| 鼠标 | 鼠标原厂输入版本 | 配套接收器及原厂输入版本 |
| --- | --- | --- |
| THORN V2 | `00.00.01.16` | H20 Receiver B，CPUAPP / CPURAD `0.0.1.16` |
| MAYA X V2 | `0.0.3.0` | LM20 三灯无屏接收器，`0.0.3.0` |

只适用于上述目标和固定原厂版本。两类接收器不能互刷，不支持 MAYA 与 H20 接收器混配。

当前源码可离线生成并检查两套配套候选。**最新候选尚未完成完整实机验收**，物理 FPS、功耗及端到端延迟收益没有完整实测结论。

## 安装与恢复原厂

仅使用仓库 [flasher/](flasher/) 中对应型号的 Windows x64 程序：

- THORN V2：[SuperLAMZU THORN V2](flasher/SuperLAMZU%20THORN%20V2-0.1.0-windows-x64.exe)
- MAYA X V2：[SuperLAMZU MAYA X V2](flasher/SuperLAMZU%20MAYA%20X%20V2-0.1.0-windows-x64.exe)

每个程序包含该型号鼠标与配套接收器的 SUPER / 原厂固件，无需 Python 或旁置 HEX。需要 Windows 10/11 x64 和 Microsoft Edge WebView2 Runtime。连接与操作步骤见[固件操作](docs/flashing.md)。

## 当前功能

- Downshift B、原厂传感器配方等价压缩。
- 原厂时序、37 个扩展 FPS 预设及自定义时序。
- 无线读取调相 LOCK、静止跟踪控制。
- thread / direct 运动路径、配套接收器 ABS 累计位移。
- stock / reduced 平滑、高级设置保存和版本迁移。
- 按需 SPI 配置快照、本地配置预设、原生参数设置。
- 保留原厂光学消抖、Speed Click、LOD、宏、配对和接收器三灯。

SUPER 在构建时移除 STATS / CHAN 遥测计数及专用钩子。功能机制和代码入口见[功能实现](docs/features.md)。

## 命令行配置

将 THORN V2 用 USB 连接并保持正常 APP 固件运行，安装 Python 3.10+ 后在项目目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m superlamzu cfg --help
.\.venv\Scripts\python.exe -m superlamzu cfg list
.\.venv\Scripts\python.exe -m superlamzu cfg info
.\.venv\Scripts\python.exe -m superlamzu cfg show
```

配置 CLI 当前仅支持 THORN V2 的有线 APP，不支持 MAYA X V2 或经接收器配置。配置命令和离线构建不会烧录固件。设置与保存示例见[使用说明](docs/usage.md)，双型号离线构建与专用刷机软件见[固件操作](docs/flashing.md)。

例如，将 CPI 档位设为三档：

```powershell
.\.venv\Scripts\python.exe -m superlamzu cfg dpi 800 1600 3200
```

## 风险与责任

刷写第三方固件可能导致设备无法启动、连接或输入异常、数据丢失，甚至无法通过 USB 恢复，并可能影响原厂保修。修改时序和无线行为也可能影响追踪、耗电及稳定性。请确认能够承担这些后果再操作。刷机软件不备份设备，也不自动回滚；“恢复原厂”是刷入内置原厂固件，不是恢复设备刷写前的精确状态。

本项目为独立研究项目，并非 LAMZU 官方产品，与 LAMZU 不存在开发、授权、认证或担保关系。LAMZU 不为本项目提供支持或担保；本项目的修改和使用后果不应归责于 LAMZU。项目按现状提供，使用者自行评估并承担操作风险；法律规定不能排除的责任不受本声明影响。

本项目拥有权利的代码采用 [MIT 许可证](LICENSE)，来源与范围见 [NOTICE.md](NOTICE.md)。
