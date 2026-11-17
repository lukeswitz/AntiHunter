<p align="center">
  <img src="https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO/blob/main/TopREADMElogo.png?raw=true" alt="AntiHunter logo" width="320" />
</p>

<div align="center">

[![Stable](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?filter=!*-beta*&label=stable&color=2ea44f)](https://github.com/lukeswitz/AntiHunter/releases/latest)
[![Beta](https://img.shields.io/github/v/tag/lukeswitz/AntiHunter?filter=*-beta*&label=beta&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![C5](https://img.shields.io/github/v/tag/lukeswitz/AntiHunter?filter=*-c5exp*&label=c5&color=purple)](https://github.com/lukeswitz/AntiHunter/releases)
[![AntiHunter Discord](https://img.shields.io/badge/AntiHunter-Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/AYFzUurfmh)</br>
[![Code Quality](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml)
[![PlatformIO CI](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml)
[![CodeQL](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql)

</div>

<div align="center">

  <a href="https://github.com/lukeswitz/AntiHunter/wiki"><img src="docs/img/wiki-button.png" alt="AntiHunter Wiki" width="320" /></a>


<a href="https://lectronz.com/stores/antihunter">
  <img alt="I sell on Lectronz" src="https://lectronz.com/static/badges/i-sell-on-lectronz-medium.png" />
</a>

</div>


<div align="center">
  
## What is AntiHunter?

***Hunt the hunters:*** _AntiHunter is a compact digital and physical tripwire. It provides detection, defense and awareness for the devices on your airwaves._

Leave one in a home, a vehicle, along a fence line, or at a site with no signal. It watches every wireless device and the activity around it, flags what doesn’t belong, and sends the alert over its own long-range mesh radio or Wi-Fi. 

**No internet or subscription required, open source. Defensive by design.** 

---

[Wiki](https://github.com/lukeswitz/AntiHunter/wiki) · [Web flasher](https://lukeswitz.github.io/AntiHunter/) · [Assembly manual](https://github.com/lukeswitz/AntiHunter/blob/main/hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf) · [Case STLs](https://github.com/lukeswitz/AntiHunter/tree/main/hw/Prototype_STL_Files) · [Operator's Guide (PDF)](docs/AntiHunter-Operators-Guide.pdf) · [Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO) · [Store](https://lectronz.com/stores/antihunter) · [Website](https://rootdowndigital.com/antihunter) · [Legal](docs/legal-disclaimer.md)


</div>

<p align="center">
  <img width="320" alt="Three AntiHunter nodes on tripods" src="docs/img/ah-hero.png" />
</p>

<p align="center"><i>Featured in Seeed Studio's <a href="https://www.seeedstudio.com/blog/2026/01/29/best-xiao-projects/">Best 20 XIAO Projects in 2025</a>.</i></p>

---

## What it does

- **[Scan your watchlist](https://github.com/lukeswitz/AntiHunter/wiki/Target-scan)** - Alerts the moment a MAC, vendor, or network name on your list shows up.
- **[Know who belongs](https://github.com/lukeswitz/AntiHunter/wiki/Baseline-anomaly)** - Learns a site, then flags new, returning, and moving devices.
- **[Catch Wi-Fi attacks](https://github.com/lukeswitz/AntiHunter/wiki/Sentinel)** - Spots death floods, fake access points, handshake capture & more.
- **[Track drones](https://github.com/lukeswitz/AntiHunter/wiki/Drone-Remote-ID)** - Reads each drone's ID, position, altitude, and speed, and its pilot's position if the drone sends it.
- **[Unmask rotating MACs](https://github.com/lukeswitz/AntiHunter/wiki/Randomized-MAC-tracer)** - Links a phone's changing addresses back to one device.
- **[Guard the node](https://github.com/lukeswitz/AntiHunter/wiki/Vibration-and-tamper)** - Feels anyone moving it and can respond with a scan, a recording, or a wipe. With the Beta firmware, senses people moving nearby, even [through a wall](https://github.com/lukeswitz/AntiHunter/wiki/CSI-motion).
- **[Run a fleet](https://github.com/lukeswitz/AntiHunter/wiki/How-to-run-several-nodes)** - Start and stop scans on every node from any one of them, split one scan across the mesh, and locate a device with three GPS nodes.



<p align="center">
  <img width="640" alt="Device discovery results" src="https://www.rootdowndigital.com/assets/img/ah-movement.webp" />
</p>


### **The [wiki](https://github.com/lukeswitz/AntiHunter/wiki) covers everything, start there:**

- [Choose your hardware](https://github.com/lukeswitz/AntiHunter/wiki/Choose-your-hardware)
- [Flash a node](https://github.com/lukeswitz/AntiHunter/wiki/Flash-a-node)
- [First setup](https://github.com/lukeswitz/AntiHunter/wiki/First-setup)
- [Field exercises](https://github.com/lukeswitz/AntiHunter/wiki#field-exercises)
- [Troubleshooting](https://github.com/lukeswitz/AntiHunter/wiki/Troubleshooting)

---

### Contributing

We welcome your ideas! Ask questions and share builds in [Discussions](https://github.com/lukeswitz/AntiHunter/discussions) or on [Discord](https://discord.gg/AYFzUurfmh). Report bugs in [Issues](https://github.com/lukeswitz/AntiHunter/issues). Pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

### Acknowledgments

Hardware design by @TheRealSirHaXalot.

This project includes code from [opendroneid-core-c](https://github.com/opendroneid/opendroneid-core-c), licensed under the Apache License 2.0. Copyright © Intel Corporation and OpenDroneID contributors.

### License

Firmware: [GNU Affero General Public License v3.0](LICENSE). Hardware and documentation: as stated in their files.

## Legal disclaimer

> [!IMPORTANT]
> AntiHunter is for lawful, authorized defensive use only, on infrastructure, networks, devices, radio spectrum, and datasets that you own or have written permission to assess. The [full disclaimer](docs/legal-disclaimer.md) covers radio and interception law, privacy, drone Remote ID, computer misuse, export rules, hardware risk, and the warranty limitations. Boards, kits, and assembled units are used entirely at your own risk, including failure, fire, property damage, and injury, and the seller is not liable for them beyond the written warranty on the product listing. Buying a unit or flashing the firmware is acceptance of those terms. If you do not agree, do not buy, build, flash, assemble, deploy, or operate AntiHunter.
