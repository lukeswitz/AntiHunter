# Contributing to AntiHunter

Open issues with the [templates](https://github.com/lukeswitz/AntiHunter/issues/new/choose). Ask questions in [Discussions](https://github.com/lukeswitz/AntiHunter/discussions). Before a pull request, sign the [CLA](CLA.md) by adding your name to its Signatories table.

## Development Setup

### Prerequisites
- PlatformIO IDE or PlatformIO Core. It installs the ESP32 toolchain on the first build
- Supported [hardware](README.md#hardware)
- cppcheck 2.20 for `make lint`, the version CI uses. CI builds it from source; see `.github/workflows/lint.yml`

### Building from Source
```bash
git clone https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full
pio run -e AntiHunter-headless
```

### Code Style

- Match the indentation and naming of the file you edit
- Test on hardware before submitting

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit with clear messages
4. Test on hardware
5. Push to your fork and open a pull request

### Pull Request Guidelines

- Describe what the PR does and why
- Reference related issues
- Include testing details and the hardware used
- Code must compile without warnings
- Run `make lint` and `make test-ble`. CI runs both and fails on any finding
- One feature or fix per PR

### Reporting Issues
- Use the bug report template
- Include serial output when relevant
- Give the hardware configuration
- List the steps to reproduce

### Code of Conduct
- Be respectful and constructive
