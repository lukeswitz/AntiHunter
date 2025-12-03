# Security Policy

AntiHunter DIGI node firmware is currently in **beta** and has not completed formal security testing. The device operates as a standalone WiFi access point without internet connectivity. We welcome responsible disclosure of security vulnerabilities.

## Supported Versions

| Version        | Supported? | Notes                                                    |
| -------------- | ---------- | -------------------------------------------------------- |
| `main`         | ✅         | Actively developed; security fixes land here first       |
| Release tags   | ⚠️         | Beta snapshots only; update to latest `main`             |
| Modified builds| ❌         | Out of scope unless reproducible on unmodified firmware  |

## Reporting a Vulnerability

1. **Open a private advisory** at the repository's [Security Advisories](https://github.com/lukeswitz/antihunter/security/advisories) page or message `@lukeswitz` with subject `AHFW SECURITY`
2. Include: vulnerability description, impact assessment, reproduction steps, commit hash/version tested, hardware configuration
3. For encrypted communication, request PGP key via GitHub message
4. Response timeline: acknowledgment within 3 business days, triage within 7 business days
5. **Do not publicly disclose** until we confirm a fix or mutually agree on disclosure date (minimum 30 days)

## Scope

### In Scope

**Authentication & Access Control:**
- WiFi AP password bypass 
- Unauthorized access to web interface or API endpoints
- Configuration tampering without authentication
- Session hijacking or fixation

**Data Exfiltration & Privacy:**
- Unauthorized access to scan results (MAC addresses, GPS coordinates, device names)
- SD card data extraction via API endpoints
- WebSocket terminal data leakage to unauthorized clients
- GPS coordinates disclosed in unintended contexts
- Scan logs accessible without proper authorization

**Injection & Command Execution:**
- Command injection via mesh UART protocol
- HTTP parameter injection in API endpoints
- Configuration file injection (config.json manipulation)
- Node ID validation bypass leading to command execution

**Mesh Protocol Security:**
- Spoofing or impersonation of mesh nodes
- Triangulation data manipulation via mesh
- Unauthorized scan control via mesh commands
- Mesh message replay attacks

**Secure Erase & Tamper Detection:**
- Bypass of secure erase functionality
- Tamper detection evasion
- Data recovery after secure wipe
- Accelerometer-based detection circumvention

**API Security:**
- Missing authentication on sensitive endpoints
- Parameter validation failures
- Rate limiting bypass
- CORS policy violations allowing unauthorized access

### Out of Scope

**Network & Physical Attacks:**
- Denial of Service (DoS) or resource exhaustion attacks
- RF jamming or physical interference
- Attacks requiring physical hardware modification
- JTAG/SWD debug interface exploitation
- Social engineering or phishing

**Third-Party & Dependencies:**
- Vulnerabilities in upstream libraries (ESP-IDF, Arduino core, NimBLE, ArduinoJson) - report to upstream projects
- Issues in OpenDroneID library - report to maintainers
- Hardware vulnerabilities in ESP32 chipset

**Low-Impact Findings:**
- Clickjacking on non-sensitive pages
- Self-XSS requiring extensive user interaction
- Missing security headers without demonstrable impact
- Verbose error messages without sensitive data disclosure
- Outdated libraries without proven exploitability
- Missing best practices (e.g., CSP headers) without attack vector

**Testing Restrictions:**
- Attacks requiring root access to connected computers
- Browser vulnerabilities unrelated to device code
- Attacks requiring device firmware modification beyond documented upload procedures
- Testing on production deployments without owner permission

## Testing Guidelines

**Access Requirements:**
- Connect to device AP 
- HTTP API: `http://192.168.4.1`
- WebSocket terminal: `ws://192.168.4.1/terminal`
- USB serial
- Mesh UART: 115200 baud (requires physical GPIO access)

**Safe Harbor:**
- Use ypur own test devices only
- Avoid data destruction beyond demonstrating vulnerability
- Stop testing if you encounter data owned by others
- Give us 30+ days before public disclosure

## Examples of Valid Reports

- Unauthorized access to scan results without authentication
- Command injection via mesh protocol allowing device takeover
- GPS coordinate leakage to unauthorized AP clients
- Bypass of secure erase allowing data recovery
- Authentication bypass on configuration endpoints
- MAC address enumeration without authorization
- Mesh node spoofing enabling false data injection

## Recognition

We acknowledge security researchers who responsibly disclose vulnerabilities. Let us know if you'd like credit in release notes or advisories.

## Questions

Contact via repository owner's GitHub profile or open a draft advisory for policy clarification. For operational questions, consult firmware documentation first.

Thank you for helping secure AntiHunter firmware.
