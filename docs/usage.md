# 使用说明

[返回项目首页](../README.md)

将 THORN V2 用 USB 连接并保持正常 APP 固件运行，先用 CLI 读取状态。当前配置 CLI 仅支持 THORN 有线 APP，不支持 MAYA X V2 或经接收器配置。设置命令会写设备配置，不会刷写固件；安装 SUPER 或恢复原厂统一使用 [flasher/](../flasher/) 中对应型号的软件，见[固件操作](flashing.md)。

以下 `python` 指已安装 [requirements.txt](../requirements.txt) 依赖的 Python；使用项目虚拟环境时可替换为 `.\.venv\Scripts\python.exe`。

```powershell
python -m superlamzu cfg --help
python -m superlamzu cfg list
python -m superlamzu cfg info
python -m superlamzu cfg show
```

## 应用与保存

高级设置的应用和保存不同：

| 操作 | 保存行为 |
| --- | --- |
| FPS、LOCK、tracking、path、ABS | 只修改运行期选择，需另行保存 |
| 应用 stock / reduced 平滑 | 同时保存设备当前全部高级选择 |
| `save-advanced` | 保存设备当前全部高级选择 |
| 原生 CPI、消抖、profile 等 | 沿原厂延迟保存路径 |

请求成功不等于传感器已完成应用。查看 requested / applied / pending 和新快照，确认完成后再进行体验测试。

## 命令行

下列读操作按需查看能力、时序和快照。`sensor-snapshot` 触发一次新的白名单 SPI 读取，不重放配方。

```powershell
python -m superlamzu cfg caps --json
python -m superlamzu cfg fps-list
python -m superlamzu cfg fps-status
python -m superlamzu cfg sensor-snapshot
```

`--profile` 等通用选项放在操作名之前。以下是独立的设置例子，请按需执行，不要整段当作初始化脚本。

```powershell
python -m superlamzu cfg fps-set 0
python -m superlamzu cfg fps-custom 47 1 1
python -m superlamzu cfg lock-set on 80
python -m superlamzu cfg lock-off
python -m superlamzu cfg tracking-set on
python -m superlamzu cfg path direct
python -m superlamzu cfg smoothing-set reduced
python -m superlamzu cfg save-advanced
python -m superlamzu cfg saved-advanced
```

FPS ID0 为原厂，ID1..37 为扩展预设，ID255 为自定义。自定义 U / slow / fast 均为 1..255，且 slow≥fast。LOCK lead 为 0..499µs，0 表示有效默认值 80µs；默认值和预设名称不代表实测最优。

启用 ABS 前，先安装对应的配套接收器固件：

```powershell
python -m superlamzu cfg abs on
python -m superlamzu cfg save-advanced
```

ABS 开启后，鼠标单独重启而接收器保留旧基线时，首份新累计报告可能产生一次位移跳变。有线 USB 报告仍使用原生增量格式。

原生四参数消抖按 `pre / post / plock / relock` 排列，每项 0..255ms。Speed Click 和左右主键继续使用原厂光学算法。

```powershell
python -m superlamzu cfg --profile 2 debounce-status
python -m superlamzu cfg --profile 2 set debounce 0 2 20 20
python -m superlamzu cfg dpi 800 1600 3200
python -m superlamzu cfg set lod 1.3
```

## 本地预设

预设保存设备当前值，属于当前目标，不能导入 hyperdrako 的原始设备预设。

```powershell
python -m superlamzu cfg preset save mine
python -m superlamzu cfg preset load mine --dry-run
python -m superlamzu cfg preset load mine --save
```

命名预设默认保存在本机 `.panel/presets/`，`SUPERLAMZU_PRESETS` 可指定其他目录。`preset load --dry-run` 只预览；`--save` 在应用后保存当前高级选择。FPS 的名义估算和寄存器读回不能当成物理测量。

无线测试时拔下鼠标本体 USB 线，保留接收器连接，并先完成设置。测量期间不要轮询配置、SPI 快照或稳定性查询，以免影响结果。
