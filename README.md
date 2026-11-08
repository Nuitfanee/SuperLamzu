# SuperLamzu

English | [简体中文](README.zh-CN.md)

Mouse web driver URL/鼠标网页驱动地址: [superlamzu.wtf](https://superlamzu.wtf)

A LAMZU firmware port and derivative of [hyperdrako](https://gitlab.jaceee.dev/open/hyperdrako), providing a **SUPER firmware patch builder and command-line configuration tools**. For learning and research only.

## Supported Devices

| Mouse | Stock mouse firmware | Paired receiver and stock firmware |
| --- | --- | --- |
| THORN V2 | `00.00.01.16` | H20 Receiver B, CPUAPP / CPURAD `0.0.1.16` |
| MAYA X V2 | `0.0.3.0` | LM20 receiver with three LEDs and no display, `0.0.3.0` |
| MAYA S V2 | `0.0.3.0` | LM20 receiver, same as MAYA X V2 |

Only the listed hardware and stock firmware versions are supported. Receiver firmware is not interchangeable. MAYA paired with an H20 receiver is not supported.

The MAYA S V2 S-stock-based SUPER is version `0.0.3.0`; its implementation and paired receiver firmware match MAYA X V2. The source can build and check THORN V2 and MAYA X V2 candidates offline. **The latest candidates have not completed full hardware acceptance testing.** Physical sensor FPS, power consumption, and end-to-end latency improvements have not been fully measured.

## Install SUPER or Restore Stock

Use only the matching Windows x64 application in [flasher/](flasher/):

- THORN V2: [SuperLAMZU THORN V2](flasher/SuperLAMZU%20THORN%20V2-0.1.0-windows-x64.exe)
- MAYA X V2: [SuperLAMZU MAYA X V2](flasher/SuperLAMZU%20MAYA%20X%20V2-0.1.0-windows-x64.exe)
- MAYA S V2: [SuperLAMZU MAYA S V2](flasher/SuperLAMZU%20MAYA%20S%20V2-0.1.0-windows-x64.exe)

Each application includes SUPER and stock firmware for its mouse and paired receiver. Python and separate HEX files are not required. Windows 10/11 x64 and the Microsoft Edge WebView2 Runtime are required. See the [flashing and recovery guide (Chinese)](docs/flashing.md) for connection and operating instructions.

## Features

- Downshift B and behavior-preserving compression of stock sensor recipes.
- Stock timing, 37 additional FPS presets, and custom timing.
- LOCK wireless sensor-read phase adjustment and idle tracking control.
- Thread / direct motion paths and ABS cumulative motion with a paired receiver.
- Stock / reduced smoothing, advanced settings persistence, and saved-record migration.
- On-demand SPI configuration snapshots, local configuration presets, and native parameter settings.
- Preserves stock optical debounce, Speed Click, LOD, macros, pairing, and the receiver's three LEDs.

SUPER removes STATS / CHAN telemetry counters and their dedicated hooks at build time. See [feature implementation (Chinese)](docs/features.md) for mechanisms and source entry points.

## Command-Line Configuration

With THORN V2 connected by USB and running its normal APP firmware, install Python 3.10+ and run these commands from the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m superlamzu cfg --help
.\.venv\Scripts\python.exe -m superlamzu cfg list
.\.venv\Scripts\python.exe -m superlamzu cfg info
.\.venv\Scripts\python.exe -m superlamzu cfg show
```

The configuration CLI currently supports THORN V2 through its wired APP only; it does not configure MAYA X V2 or devices through a receiver. Configuration commands and offline builds do not flash firmware. See the [usage guide (Chinese)](docs/usage.md) for settings and saving, or the [firmware guide (Chinese)](docs/flashing.md) for both models' offline builds and dedicated flashing applications.

For example, set three CPI stages:

```powershell
.\.venv\Scripts\python.exe -m superlamzu cfg dpi 800 1600 3200
```

## Risks and Disclaimer

Flashing third-party firmware can make a device unbootable, cause connection or input problems, or result in data loss. USB recovery may become impossible, and the manufacturer's warranty may be affected. Changes to timing and wireless behavior may also affect tracking, power consumption, and stability. Proceed only if you accept these risks. The flasher does not back up your device or roll back automatically. "Restore stock" writes the bundled stock firmware; it does not restore the device's exact previous state.

This is an independent research project, not an official LAMZU product. It is not developed, authorized, certified, or warranted by LAMZU. LAMZU does not provide support or warranties for this project and should not be held responsible for its modifications or their use. The project is provided as is; users must assess and accept the risks of operating it. This disclaimer does not exclude liability that cannot legally be excluded.

Code owned by this project is available under the [MIT License](LICENSE). See [NOTICE.md (Chinese)](NOTICE.md) for attribution and scope.
