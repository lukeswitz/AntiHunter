# Security Policy

AntiHunter DIGI node firmware is operator-controlled firmware for a private, operator-run mesh. The device operates as a standalone Wi-Fi access point without internet connectivity. We welcome responsible disclosure of issues that are exploitable within the trust model below.

## Supported Versions

| Version branch    | Supported? | Notes                                                    |
| ----------------- | ---------- | -------------------------------------------------------- |
| `main`            | ✅         | Actively developed; security fixes land here first       |
| Release tags      | ⚠️         | Snapshots only; update to latest `main`                  |
| Modified builds   | ❌         | Out of scope unless reproducible on unmodified firmware  |

## Trust model

The scope below follows directly from how AntiHunter is deployed. Three boundaries define it:

- **The encrypted mesh channel is the authentication boundary.** Operators configure their own encrypted Meshtastic channel and disable the public channel before deployment (see [Radio Setup](README.md#radio-setup)). Meshtastic does not decode or deliver text to a node on a channel it holds no key for. A party that can send a command to a deployed node therefore already holds the operator's channel key, and is treated as an authorized operator. Commands accepted from a keyed channel member are by design, not an authentication flaw.
- **Physical and wired access implies device control.** The USB serial console, the mesh UART (Serial1), and the on-board microSD all require physical possession of the node — opening the enclosure, and in the SD's case removing a brass standoff to reach the card. Anyone with that access already controls the device; behavior reachable only by opening the case or touching those interfaces is not a vulnerability in this model.
- **The default public channel is pre-deployment only.** A node still on the public channel is unconfigured. Securing the channel is the first deployment step; findings that assume an unconfigured node must say so.

## Scope

**In scope** — reachable by a party that does **not** hold the operator's encrypted-channel key and does **not** have physical access to the node (no opened enclosure, no USB/UART, no SD):

- Memory-safety or remote-code-execution in the firmware's parsing of radio traffic the sensor ingests by design — malformed 802.11 Wi-Fi frames, BLE advertisements, or drone RID frames handled by the scan/detection paths. This is the device's real unauthenticated attack surface: it listens to hostile RF.
- The on-device HTTP interface on the node's Wi-Fi AP, and its authentication, where reachable over Wi-Fi without the mesh channel key.
- Cryptographic weaknesses that let a party **without** the channel key or erase PSK forge, recover, or replay erase/tamper authorization.
- Secrets (keys, PSK, location) leaked in telemetry or logs readable without the channel key.

**Out of scope:**

- Anything that requires the operator's configured encrypted channel key. Delivery of a mesh command presupposes the key; keyed channel members are trusted operators, so mesh command dispatch, configuration, and erase from a keyed member are the accepted design, not findings.
- Anything that requires physical access to the node: opening the enclosure, the USB serial console, the mesh UART (Serial1), the microSD (behind an internal brass standoff), JTAG/SWD, or any hardware modification.
- A node left on the default public channel — securing the channel is step one of deployment; findings must hold on a properly configured node.
- Social engineering and phishing.
- Denial-of-service or resource-exhaustion attacks.
- Findings in third-party libraries (ESP-IDF, Arduino core, NimBLE, ArduinoJson) — report to upstream.
- Vulnerabilities in forked or modified firmware diverging from upstream `main`.

A report that depends on the channel key, on physical/USB/UART/SD access, or on a node left on the public channel is a configuration or trust-model matter, not a vulnerability, and may be addressed as a hardening change without an advisory.

## Reporting

1. Open a private advisory at the repository's [Security Advisories](https://github.com/lukeswitz/AntiHunter/security/advisories) page with subject `AHFW SECURITY REPORT`.
2. Include: description, impact within the trust model above, reproduction steps, commit hash/version tested, hardware configuration, and — for any mesh finding — whether it holds **without** the operator's channel key.
3. Response: acknowledgment within 3 business days, triage within 7 business days.
4. Do not publicly disclose until a fix is confirmed or a disclosure date is mutually agreed (minimum 30 days).

## Coordinated disclosure & safe harbor

- Acting in good faith within this policy will not lead to legal action.
- Do not access, modify, or destroy data you do not own. If you encounter data owned by others, stop and notify us.
- Use your own test devices and isolated test networks.
- Give reasonable time to remediate before public disclosure.

## Credit

We credit researchers who responsibly disclose in-scope issues, subject to your consent and the severity of the finding.
