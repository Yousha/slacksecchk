# SlackSecChk

SlackSecChk is a C-based security-audit utility for Slackware Linux. It checks a selected set of system files and configuration settings against security-hardening recommendations.

[![Compile and Test](https://github.com/Yousha/slacksecchk/actions/workflows/action.yml/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/action.yml) [![Dependabot Updates](https://github.com/Yousha/slacksecchk/actions/workflows/dependabot/dependabot-updates/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/dependabot/dependabot-updates) [![CodeQL](https://github.com/Yousha/slacksecchk/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/github-code-scanning/codeql)

> **Scope:** This project is an audit helper, not a complete CIS benchmark or NSA/DISA STIG compliance scanner. Its checks are selective and may require review for the target Slackware release and local system policy. A passing result does not certify compliance.

## Features

- Checks permissions on selected system files and directories.
- Reviews selected password and account-policy settings.
- Checks selected services, packages, logging, SSH, firewall, and kernel settings.
- Uses Slackware package records and `/etc/rc.d` service scripts where applicable.
- Organizes Slackware-specific checks into focused C modules for packages, services, boot, kernel, accounts, filesystems, networking, logging, and miscellaneous controls.

## Requirements

- Slackware Linux (the checks are intended for Slackware; other distributions are not currently supported).
- GCC and GNU Make to build from source.
- Root privileges are recommended when running the audit so checks can read protected system files and inspect system state.

## Screenshots

![SlackSecChk screenshot](resources/images/screenshots/1.png)

## Build

Clone the repository:

```bash
git clone https://github.com/Yousha/slacksecchk.git
cd slacksecchk
```

Build the executable:

```bash
make
```

The executable is created at `artifacts/slacksecchk`.

Useful Make targets:

| Command | Description |
| --- | --- |
| `make` | Build the optimized executable. |
| `make debug` | Clean and build with debug symbols. |
| `make clean` | Remove generated build files. |
| `make test` | Build and run fixture-based unit tests plus the isolated smoke test. |
| `make checksums` | Generate a fresh `Checksums.sha256` manifest for the working tree. |
| `sudo make install` | Install to `/usr/local/bin/slacksecchk` (requires root privileges). |
| `sudo make uninstall` | Remove the installed executable (requires root privileges). |

## Usage

Run the executable from the repository:

```bash
sudo ./artifacts/slacksecchk
```

Or, after installation:

```bash
sudo slacksecchk
```

The program prints the result of each configured check. Output labels have the following meaning:

- **PASSED**: The check's configured condition was met.
- **FAILED**: The check reported a condition that needs review.
- **Notice/Error**: The check could not fully verify the condition or the required configuration was unavailable.

These labels describe the current implementation; they should not be interpreted as proof of overall system security or benchmark compliance.

## Checksums

The checksum manifest is generated from the current working tree. After running `make checksums`, verify it from the repository root with:

```bash
sha256sum -c Checksums.sha256
```

Regenerate the manifest after changing project files.

## Testing

Build and run the smoke tests with:

```bash
make test
```

The source is organized by audit domain: classic CIS/DISA/NSA checks remain in `rules.c`, while Slackware-specific checks are separated into focused `rules_*.c` modules. Shared parsing helpers live in `audit_utils.c`.

The test suite includes fixture-based unit tests for exact mount-option matching, strict integer parsing, shadow password-field parsing, and exact kernel-module matching. Tests use real temporary streams and no mocks or external services. The smoke test sets `SLACKSECCHK_TEST_MODE=1` so recursive filesystem scans are skipped on the CI host. Run the complete suite with `make test`.

## CI

GitHub Actions runs on pushes and pull requests targeting `main`. The workflow checks out the repository, lints YAML files, builds with GCC on Ubuntu, and runs the smoke tests.

This CI job validates the build and basic execution path on Ubuntu; it does not replace testing on supported Slackware releases.

## Contributing

Contributions are welcome. Please create a feature branch, include tests for behavior changes, and open a pull request.

## License

This project is licensed under the GPL-3.0. See [LICENSE](LICENSE) for details.

## Contact

For questions or feedback, please use the [GitHub issues](https://github.com/Yousha/slacksecchk/issues) page.
