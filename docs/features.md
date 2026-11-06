# 功能实现

[返回项目首页](../README.md)

固件补丁以固定版本的原厂 HEX 为输入，先核对地址、原像和内存边界，再生成稀疏 HEX。THORN 与 MAYA 使用独立目标适配，共用构建、协议和 Thumb 检查支撑。

| 功能 | 当前机制 | 代码入口 |
| --- | --- | --- |
| Downshift B、配方压缩 | 等价保留原配方的有序 SPI 行为；THORN 七套、MAYA 九套配方按各自地址适配 | [THORN Builder](../superlamzu/patch.py)、[MAYA Builder](../MAYA_X_V2/build.py) |
| FPS | ID0 原厂、ID1..37 扩展预设、ID255 自定义 U / slow / fast；原生 worker 应用并读回，分别报告请求、已应用和 pending | [扩展固件](../superlamzu/advanced.py)、[时序目录](../superlamzu/frame_timing.py) |
| LOCK、静止跟踪 | 调整 MCU 读取相对无线 slot 的相位；无线 1/2/4k 在适用条件下使用 1MHz plock，边缘条件保留 legacy；THORN 原生 FLL 引用管理，MAYA 保留原生 HFXO | [时钟](../superlamzu/native_clock.py)、[plock](../superlamzu/native_plock.py)、[接入](../superlamzu/native_timing.py) |
| 原厂光学点击 | 保留原生四参数、Speed Click、IR、采样、唤醒和报告链 | [光学接口](../superlamzu/optical.py)、[协议](../superlamzu/protocol.py) |
| 运动路径 | THORN 沿原生 done 线程和无线完成回调；MAYA 默认 direct，显式 thread 使用独立消费者，积压及完整回调在途时拒绝切换 | [THORN 运动](../superlamzu/motion.py)、[MAYA 运动](../MAYA_X_V2/motion.py) |
| ABS | 鼠标独立原子累计 u16 位移，配套接收器回绕差分；报告进入真实 USB 队列后提交基线；保留 relative 兼容 | [鼠标累计](../superlamzu/mouse_abs.py)、[接收器差分](../superlamzu/receiver_abs.py) |
| 平滑、保存 | stock 恢复当前配方原值，reduced 走 `0C:4D`；16B v5 高级记录兼容 v1..v5，不改变原生 profile、宏和配对格式 | [设置](../superlamzu/settings.py) |
| 按需快照 | 新 token 排队至原生 sensor worker，读取八个白名单寄存器，返回 24B 结果；不读取 motion burst | [固件快照](../superlamzu/advanced.py)、[主机校验](../superlamzu/cfg.py) |
| 接收器 SOF | THORN 使用软件捕获；MAYA 保留 USBHS 经 DPPI 到 TIMER20 CLEAR 的原生硬件链；保留三灯逻辑 | [THORN 接收器](../superlamzu/receiver.py)、[MAYA 接收器](../MAYA_X_V2/receiver.py) |
| 本地配置 | CLI 使用统一的设置类型、范围、能力和保存元数据，预设应用前验证并逐项读回；当前仅支持 THORN 有线 APP | [CLI](../superlamzu/cfg.py)、[元数据](../superlamzu/config_registry.py) |

SUPER 编译移除 STATS / CHAN 遥测计数及专用热路径钩子，保留按需配置读回。原厂五档 LOD、六字节 motion burst、高 CPI 差异、光学消抖和原生 ripple 保持。

LOCK 不控制传感器曝光，也不代表 USB 锁相。寄存器读回和离线指令检查不能代替物理 FPS、功耗或延迟测量。ABS 的鼠标独立重启跳变限制见[使用说明](usage.md)。
