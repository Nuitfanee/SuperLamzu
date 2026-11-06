# 固件操作

[返回项目首页](../README.md)

安装 SUPER 和恢复原厂统一使用仓库 [flasher/](../flasher/) 中的型号专用软件。操作会写入鼠标与配套接收器，请先阅读首页的风险说明。

## 选择软件

| 程序 | 配套设备 |
| --- | --- |
| [SuperLAMZU THORN V2](../flasher/SuperLAMZU%20THORN%20V2-0.1.0-windows-x64.exe) | THORN V2 + H20 Receiver B，原厂输入版本 `0.0.1.16` |
| [SuperLAMZU MAYA X V2](../flasher/SuperLAMZU%20MAYA%20X%20V2-0.1.0-windows-x64.exe) | MAYA X V2 + LM20 / Orbital 8K Receiver，原厂输入版本 `0.0.3.0` |
| [SuperLAMZU MAYA S V2](../flasher/SuperLAMZU%20MAYA%20S%20V2-0.1.0-windows-x64.exe) | MAYA S V2 + LM20 接收器，S原厂基底 SUPER `0.0.3.0` |

每个 EXE 都包含对应鼠标与接收器的 SUPER 和原厂固件，只处理自己的型号，没有任意固件加载器。运行需要 Windows 10/11 x64 和 Microsoft Edge WebView2 Runtime，无需 Python、Node.js 或旁置固件。

THORN 的 H20 接收器与 MAYA 的 LM20 接收器不能互刷，不支持混配。
MAYA S V2 的实现及配套接收器固件与 MAYA X V2 一致。

## 安装 SUPER

1. 关闭占用同一设备的厂商软件，结束对该设备的配置访问，插入对应接收器，用数据线连接鼠标。
2. 打开对应型号的 EXE，点击“安装 SUPER”进入确认页。
3. 核对鼠标、接收器的当前固件和目标固件，点击“确认并安装”，再在风险确认窗中确认。
4. 保持原设备、原 USB 接口连接，不要拔线、休眠、合盖或强制退出。程序依次处理接收器与鼠标，显示写入、完整读回和 APP 返回状态；双端通过后才完成。

程序不会因插入设备自动刷写。失败时按界面显示的失败阶段和下一步处理，可复制诊断；不要把单端完成当成双端完成。如果程序提供“只读检查设备返回”，该操作只检查设备返回，不重写固件。

当前候选已经过离线检查，尚未完成完整实机验收。开启 ABS 后，若鼠标单独重启而接收器保留旧累计基线，首份新报告可能产生一次指针跳变。

## 恢复原厂

在同一型号软件中点击“恢复原厂”，核对双端与目标固件后点击“确认并恢复”。连接条件与操作期间的注意事项同上。

**恢复原厂是刷入软件内置的对应原厂固件，不要求设备备份，也不等于恢复刷写前的精确状态。** 软件不提供实时固件备份、备份导出或自动回滚。原厂固件不能补回已经丢失的启动区、身份或配对数据；APP 与 Bootloader 均无法枚举时，不能保证通过 USB 恢复。

## 离线构建

以下命令仅生成与检查本地固件，不操作设备。构建结果用于源码研究；刷机软件使用自身内置的固定固件，不加载本地生成的 HEX。

```powershell
# THORN 鼠标与 H20 Receiver B 两核
python -B -m superlamzu patch SUPER --target all

# MAYA X V2 鼠标与 LM20 接收器
python -B -m MAYA_X_V2 build --profile SUPER
python -B -m MAYA_X_V2 verify --profile SUPER
```

THORN 输出位于 `build/`，MAYA 配套输出位于 `build/MAYA_X_V2/SUPER/`。每份 HEX 配同名 JSON；MAYA 另有配套清单。不要使用 `--skip-check` 生成交付候选，也不要用 `-O` 或 `PYTHONOPTIMIZE` 关闭检查断言。

```powershell
python -B -m unittest discover -s tests -v
```
