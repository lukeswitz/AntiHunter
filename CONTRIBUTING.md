# Contributing to AntiHunter

Open issues with the [templates](https://github.com/lukeswitz/AntiHunter/issues/new/choose) and ask questions in [Discussions](https://github.com/lukeswitz/AntiHunter/discussions). Before you open a pull request, sign the [CLA](CLA.md) by adding your name to its Signatories table.

## Development Setup

### Prerequisites

- PlatformIO IDE or PlatformIO Core. It installs the ESP32 toolchain on the first build.
- Supported [hardware](README.md#hardware).
- cppcheck 2.20 for `make lint`. This is the version CI uses. CI builds it from source. See `.github/workflows/lint.yml`.

### Building from Source

```bash
git clone https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full
pio run -e AntiHunter-headless
```

### Code Style

- Match the indentation and naming of the file you edit.
- Test on hardware before you submit.

### Submitting Changes

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit with clear messages.
4. Test on hardware.
5. Push to your fork and open a pull request.

### Pull Request Guidelines

- Describe what the PR does and why.
- Reference related issues.
- Include testing details and the hardware you used.
- Make the code compile without warnings.
- Run `make lint` and `make test-ble`. CI runs both and fails on any finding.
- Keep to one feature or fix per PR.

### Reporting Issues

Use the bug report template, and include:

- Serial output, when relevant.
- Your hardware configuration.
- The steps to reproduce the problem.

### Code of Conduct

Be respectful and constructive.
