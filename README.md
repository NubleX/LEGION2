# Legion2 (Community Fork)

**NOTICE:** This is a community-maintained fork of the original Legion project. The official GoVanguard repo is archived and no longer maintained. This fork includes updates and critical fixes for modern systems.

---


## About

Legion, a fork of SECFORCE's Sparta, is an open-source, extensible, and semi-automated network penetration testing framework that assists with discovery, reconnaissance, and exploitation.

## Current Fork Status

**Fixes implemented:**

* Crash from SQLAlchemy tuple index issue resolved with `getSafeHostField()`
* PyQt6 repaint and QPainter errors fixed
* Re-enabled proper host sorting and scanning stability

**Issues still under investigation:**

* Incomplete IP parsing in some auxiliary modules
* Some auxiliary tools like `selenium` remain optional

---

## Installation (Traditional)

This fork targets **Debian-based systems** (Debian 12, Ubuntu 20.04+, Kali, Parrot).

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/legion.git
cd legion
```

### 2. Install Dependencies

```bash
sudo apt update && sudo apt install -y \
  python3-pyqt5 python3-pyqt5.qtsvg \
  python3-sqlalchemy python3-lxml python3-psutil \
  nmap git net-tools
```

### (Optional) Selenium Support

```bash
sudo pip install selenium
```

Or install via `pipx`:

```bash
pipx install legion --include-deps
pipx inject legion selenium
```

### 3. Run as Root

Legion requires root access due to raw socket operations:

```bash
sudo python3 legion.py
```

---

## Features

* Automatic recon and scanning with `nmap`, `whatweb`, `nikto`, Vulners, Hydra, SMBenum, `dirbuster`, `sslyzer`, and more.
* Graphical interface (PyQt6) with context menus and panels.
* Modular framework — drop in your own tools.
* Scan CIDRs, hostnames, IP lists, and vhosts.
* IPS evasion via staged scanning.
* CPE/CVE detection and Exploit-DB integration.
* Real-time project autosave.

## Notable Changes from Original

* Python 3.8+ support (no Python 2.7)
* PyQt6 upgraded GUI (better rendering and performance)
* Rewritten scheduling and reliability
* Docker support for platform independence

## Docker Support (Optional)

Docker support is provided but not prioritized in this fork. You can still try the legacy `runIt.sh` method from the `docker` folder.

---

## Development & Config

To run tests:

```bash
python -m unittest
```

To edit Legion's scan scheduling behavior:

```bash
sudoedit /root/.local/share/legion/legion.conf
```

---

## License

Legion is licensed under the **GNU GPLv3**. See the [LICENSE](https://github.com/GoVanguard/legion/blob/master/LICENSE) file for more.

## Credits

* GoVanguard — initial Python 3+ refactor
* SECFORCE — original Sparta framework
* Community contributors (2024–2025) — current maintenance
* Thanks to developers behind nmap, PyQt, SQLAlchemy, and other essential tools

---

**Want to contribute?** Submit bug reports, feature requests, or pull requests. Help us keep Legion alive and effective!
