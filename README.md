[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](#) [![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](#)

# 🖧 IP Discovery Monitor

**Real-time network device scanner with GUI**
Built with Python + PyQt6 + PyShark — powerful, multilingual, and user-friendly.

## 📸 Screenshots

![IP Discovery Monitor Screenshot](https://i.imgur.com/gNr23tD.png)

## 🌟 Features

* 🔍 **Discover devices** on your local network in real-time
* 📶 **Live packet capture** via `pyshark`
* 📊 **Traffic chart** (if `pyqtgraph` is installed)
* 🗂 **Sortable table** with IP, MAC, Hostname, and First Seen time
* 📁 **Save scan reports** to `.txt`
* 🌐 **Multi-language support**: English, Italiano, Français, Español, Deutsch
* 🕵️ Smart filtering:

  * All private IPs
  * Devices in a specific subnet (CIDR)

## 📦 Requirements

* Python 3.9+
* OS: Windows / Linux / macOS
* Recommended dependencies:

  * `pyshark`
  * `pyqt6`
  * `psutil`
  * `pyqtgraph` (optional, for traffic graph)

Install required dependencies:

```bash
pip install pyshark pyqt6 psutil
```

Optional (for graph):

```bash
pip install pyqtgraph
```

## 🚀 How to Run

```bash
python ip_discovery_monitor.pyw
```

To bundle as a standalone app (e.g., with PyInstaller):

```bash
pyinstaller --noconfirm --onefile --windowed ip_discovery_monitor.pyw
```

## 🌍 Languages

| Code | Language |
| ---- | -------- |
| en   | English  |
| it   | Italiano |
| fr   | Français |
| es   | Español  |
| de   | Deutsch  |

