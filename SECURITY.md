# Security Policy

AntiHunter DIGI node firmware is currently in **beta** and has not completed formal security testing. The device operates as a standalone WiFi access point without internet connectivity. We welcome responsible disclosure of security vulnerabilities.

## Supported Versions

| Version branch    | Supported? | Notes                                                    |
| ----------------- | ---------- | -------------------------------------------------------- |
| `main`            | ✅         | Actively developed; security fixes land here first       |
| Release tags      | ⚠️         | Beta snapshots only; update to latest `main`             |
| Modified builds   | ❌         | Out of scope unless reproducible on unmodified firmware  |

## Reporting a Vulnerability

1. **Open a private advisory** at the repository's [Security Advisories](https://github.com/lukeswitz/Antihunter/security/advisories) page or message `@lukeswitz` with subject `AHFW SECURITY REPORT`.
2. Include: vulnerability description, impact assessment, reproduction steps, commit hash/version tested, hardware configuration.
3. For encrypted communication, request PGP key via GitHub message.
4. Response timeline: acknowledgment within **3 business days**, triage within **7 business days**.
5. **Do not publicly disclose** until we confirm a fix or mutually agree on disclosure date (minimum 30 days).

### What to Include

- Concise description of the issue and potential impact (e.g., unauthorized device control, data disclosure, secure erase bypass).
- Steps to reproduce or proof of concept.
- Commit hash or release tag tested.
- Hardware configuration (ESP32 variant, SD card, sensors).
- Mesh radio hardware if testing mesh protocol vulnerabilities.
- Any temporary mitigations observed.

## Scope

**In scope:**

- Firmware code in this repository (`*.cpp`, `*.h` files, `platformio.ini`).
- HTTP API endpoints.
- Configuration file parsing and validation (`config.json` on SD card).
- Mesh UART protocol security (Serial1 at 115200 baud).
- Mesh command injection and authentication bypass.
- Mesh message spoofing or replay attacks.
- Compatibility testing with non-standard mesh radios (e.g., older T114 versions, third-party UART devices).
- Secure erase and tamper detection mechanisms.
- SD card data storage security.

**Out of scope:**

- Social engineering, phishing, or physical attacks not involving documented interfaces.
- Findings in third‑party libraries (ESP-IDF, Arduino core, NimBLE, ArduinoJson) - report to upstream projects.
- Denial-of-service or resource exhaustion attacks.
- Issues requiring physical hardware modification beyond connecting to documented UART pins.
- JTAG/SWD debug interface exploitation.
- Vulnerabilities in forked or modified versions diverging from upstream `main`.

If your research affects an upstream dependency, please disclose directly to that project. We appreciate a heads-up so we can track the fix.

## Coordinated Disclosure & Safe Harbor

- Acting in good faith within this policy will not lead to legal action. This includes testing, reporting, and discussing vulnerabilities privately.
- Avoid accessing, modifying, or destroying user data. If you encounter data owned by others, stop testing immediately and notify us.
- Limit automated scanning to minimum necessary for verification. Avoid resource exhaustion that could damage SD cards or flash memory.
- Testing mesh protocol security with various UART devices is permitted and encouraged.
- Give us reasonable time to remediate (minimum 30 days unless otherwise agreed) before public disclosure.

## Testing Guidelines

**Device Access:**
- Connect to device AP (default gateway: `192.168.4.1`)
- HTTP API: `http://192.168.4.1`
- USB serial console: 115200 baud
- Mesh UART (Serial1): 115200 baud on GPIO pins (physical access required)

**Mesh Protocol Testing:**
- Test with standard T114 mesh radios
- Test with older/legacy mesh radio firmware versions
- Test with non-standard UART devices to evaluate command injection
- Test mesh message authentication and validation
- Test replay attack resistance

**Safe Harbor:**
- Use your own test devices only.
- Avoid data destruction beyond demonstrating vulnerability.
- Stop testing if you encounter data owned by others.
- Do not bypass tamper detection unless specifically testing that feature.
- When testing mesh protocols, use isolated test networks.

## Credit & Recognition

We acknowledge security researchers who responsibly disclose issues, subject to your consent and severity of the finding. Let us know if you'd like credit in release notes or advisories.

## Need Help?

- For policy clarifications, contact via repository owner's GitHub [profile](https://github.com/lukeswitz) or open a draft advisory.
- For operational questions, consult firmware documentation first.
- For incidents involving deployed devices, also notify your organization's security contacts - this is open-source firmware and you remain responsible for your device security posture.

Thank you for helping keep AntiHunter firmware secure for all users.
