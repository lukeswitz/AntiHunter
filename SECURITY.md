# Security Policy

AntiHunter DIGI node firmware runs on nodes controlled by one operator over a private mesh, with no internet connection. The Full build also runs a Wi-Fi access point for its web UI. Headless runs none. Report issues that are exploitable within the trust model below.

## Supported Versions

| Version branch    | Supported? | Notes                                                    |
| ----------------- | ---------- | -------------------------------------------------------- |
| `main`            | Yes        | Actively developed; security fixes land here first       |
| Release tags      | Partial    | Snapshots only; update to latest `main`                  |
| Modified builds   | No         | Out of scope unless reproducible on unmodified firmware  |

## Trust model

Three boundaries define the scope:

- **The encrypted mesh channel is the authentication boundary.** Operators configure their own encrypted Meshtastic channel and disable the public channel before deployment. [Radio Setup](README.md#radio-setup) has the steps. Meshtastic does not decode or deliver text to a node on a channel it holds no key for. A party that can send a command to a deployed node therefore already holds the operator's channel key, and the project treats that party as an authorized operator. The node accepts commands from keyed channel members by design. That is not an authentication flaw.
- **Physical and wired access implies device control.** The USB serial console, the mesh UART (Serial1), and the on-board microSD all require physical possession of the node. Reaching them means opening the enclosure, and for the SD card, also removing a brass standoff. Anyone with that access already controls the device. Behavior that only opening the case or touching those interfaces can reach is not a vulnerability in this model.
- **The default public channel is pre-deployment only.** A node still on the public channel is unconfigured. Securing the channel is the first deployment step. Findings that assume an unconfigured node must say so.

## Scope

**In scope:** issues that a party can reach **without** the operator's encrypted-channel key and **without** physical access to the node. Physical access means an opened enclosure, USB or UART, or the SD card.

- Memory-safety or remote-code-execution in the firmware's parsing of radio traffic the sensor receives: malformed 802.11 frames, BLE advertisements, or drone RID frames handled by the scan and detection paths.
- The Full build's HTTP interface on its Wi-Fi AP, and its authentication, where reachable over Wi-Fi without the mesh channel key.
- Cryptographic weaknesses that let a party **without** the channel key or erase PSK forge, recover, or replay erase/tamper authorization.
- Secrets (keys, PSK, location) leaked in telemetry or logs readable without the channel key.

**Out of scope:**

- Anything that requires the operator's configured encrypted channel key. Delivering a mesh command requires the key. Keyed channel members are trusted operators, so mesh command dispatch, configuration, and erase from a keyed member are the accepted design, not findings.
- Anything that requires physical access to the node: opening the enclosure, the USB serial console, the mesh UART (Serial1), the microSD behind its internal brass standoff, JTAG/SWD, or any hardware modification.
- A node left on the default public channel. Securing the channel is step one of deployment, and findings must hold on a properly configured node.
- Social engineering and phishing.
- Denial-of-service or resource-exhaustion attacks.
- Findings in third-party libraries such as ESP-IDF, the Arduino core, NimBLE, and ArduinoJson. Report those upstream.
- Vulnerabilities in forked or modified firmware diverging from upstream `main`.

A report that depends on the channel key, on physical/USB/UART/SD access, or on a node left on the public channel is a configuration or trust-model matter, not a vulnerability. We may handle it as a hardening change without an advisory.

## Reporting

1. Open a private advisory at the repository's [Security Advisories](https://github.com/lukeswitz/AntiHunter/security/advisories) page with subject `AHFW SECURITY REPORT`.
2. Include a description, the impact within the trust model above, reproduction steps, the commit hash or version tested, and the hardware configuration. For any mesh finding, say whether it holds **without** the operator's channel key.
3. We acknowledge reports within 3 business days and triage them within 7 business days.
4. Do not disclose publicly until we confirm a fix or agree on a disclosure date with you. The minimum is 30 days.

## Coordinated disclosure & safe harbor

- Acting in good faith within this policy will not lead to legal action.
- Do not access, modify, or destroy data you do not own. If you encounter data owned by others, stop and notify us.
- Use your own test devices and isolated test networks.
- Give reasonable time to remediate before public disclosure.

## Credit

We credit researchers who responsibly disclose in-scope issues, subject to your consent and the severity of the finding.
