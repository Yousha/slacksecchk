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
- Parses selected security configuration directives exactly and treats incomplete or overlong records as unverifiable.
- Reviews effective OpenSSH daemon settings and additional kernel attack-surface sysctls when exposed by the running kernel.
- Bounds external audit commands with a 30-second default timeout and terminates their process groups when they exceed it.
- Assigns stable rule IDs and records structured findings with status, severity, category, evidence, remediation, and reference fields.

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

## Command-line options

| Option | Description |
| --- | --- |
| `-h`, `--help` | Display command-line help and exit. |
| `-V`, `--version` | Display the application version and exit. |
| `--color=auto` | Enable colors only when standard output is a suitable terminal. |
| `--color=always` | Force ANSI colors, including when output is redirected. |
| `--color=never`, `--no-color` | Disable ANSI colors. |
| `--format=text` | Human-readable output (default). |
| `--format=json` | Emit a JSON report with summary counters and structured findings. |

Automatic color detection also respects `NO_COLOR` and `TERM=dumb`. Unknown options print usage information and return exit code `2`.

## Machine-readable output

Use \`--format=json\` to emit a single JSON summary document instead of terminal text:

\`\`\`bash
sudo slacksecchk --format=json
\`\`\`

The schema-v2 document includes `schema_version`, `tool`, `version`, overall `status`, summary counters (`passed`, `failed`, `unverified`), and a `findings` array. Each finding contains `rule_id`, `title`, `description`, `severity`, `category`, `status`, `evidence`, `remediation`, and `references`. Rule IDs are stable identifiers assigned by the audit entry point. Existing rule output is currently adapted into this model; evidence is retained from the emitted result line, while remediation and references are empty until a rule supplies explicit metadata. Status values are `PASS`, `FAIL`, `WARN`, `INFO`, `NOT_APPLICABLE`, and `ERROR`. In JSON mode, exit codes are `0` when no failed or unverified findings exist, `1` when at least one finding failed, and `2` when findings are unverified but none failed. Invalid command-line options also return `2` and write the error to stderr.

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

The fixture-based unit suite covers structured finding validation, stable rule IDs, status counters, JSON finding serialization, executable-file detection, exact mount-option matching, strict integer parsing, shadow password-field parsing, exact kernel-module matching, bounded configuration-line reading, exact bootloader directives, `hosts.deny` parsing, and shell-free process execution, plus exact key/value matching for generated configuration output. Process tests use real binaries and verify exit statuses, missing commands, literal shell metacharacters, output truncation, and timeout termination. Timeout tests use real sleeping processes and verify the timeout result for both execution and capture APIs. Configuration-value tests cover case-insensitive keys, whitespace, exact values, missing keys, and duplicate-key ambiguity. Tests follow Arrange-Act-Assert structure and use no mocks or external services. Overlong configuration records and command output are not treated as complete results. The smoke test sets `SLACKSECCHK_TEST_MODE=1` so recursive filesystem scans are skipped on the CI host.

## CI

GitHub Actions runs on pushes and pull requests targeting `main`. The workflow checks out the repository, lints YAML files, builds with GCC on Ubuntu, and runs the test suite.

This CI job validates the build and basic execution path on Ubuntu; it does not replace testing on supported Slackware releases.

## Contributing

Contributions are welcome. Please create a feature branch, include tests for behavior changes, and open a pull request.

## License

This project is licensed under the GPL-3.0. See [LICENSE](LICENSE) for details.

## Contact

For questions or feedback, please use the [GitHub issues](https://github.com/Yousha/slacksecchk/issues) page.
