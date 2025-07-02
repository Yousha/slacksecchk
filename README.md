# SlackSecChk

A C tool to audit Slackware Linux(>=14) security against CIS, NSA, and DISA benchmarks

[![Compile and Test](https://github.com/Yousha/slacksecchk/actions/workflows/action.yml/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/action.yml) [![Dependabot Updates](https://github.com/Yousha/slacksecchk/actions/workflows/dependabot/dependabot-updates/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/dependabot/dependabot-updates) [![CodeQL](https://github.com/Yousha/slacksecchk/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/github-code-scanning/codeql)

## Features

* **File permissions**: Checks critical file permissions (e.g., `/etc/passwd`, `/etc/shadow`).
* **Password policy**: Verifies password quality settings.
* **Service management**: Ensures unnecessary services are disabled using Slackware's SysV Init scripts.
* **Package auditing**: Identifies and warns about unnecessary packages installed on system using `/var/log/packages`.
* **SSH configuration**: Validates secure SSH settings.
* **Firewall rules**: Checks for active firewall configurations.
* **Logging**: Ensures logging services (e.g., `syslog`) are running and properly configured.
* **Customizable**: Easily extendable with additional CIS rules.
* **etc...**

## Overview

The **SlackSecChk** is a security auditing tool designed to verify system configurations against CIS benchmarks, some NSA, and some DISA STIG rules. It helps identify potential vulnerabilities and ensures that your Slackware Linux system adheres to best practices for security hardening.
This tool is specifically tailored for **Slackware Linux**, leveraging its unique package management system (`slackpkg`) and SysV Init scripts.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Yousha/slacksecchk.git
   cd slacksecchk
   ```

2. Compile the program:

`make clean`: Removes all compiled files for a fresh build.
`make` or `make debug`: Compiles the program without errors or warnings.
`make install`: Installs the tool system-wide for easy access.
`make uninstall`: Removes the tool from system.

## Usage

Run with following command:

```bash
chmod +x ./slacksecchk
./slacksecchk
```

Or if installed as system-wide:

```bash
sudo slacksecchk
```

The tool will output detailed information about each security check, including:

* **OK**: Indicates the check passed successfully.
* **Warning**: Indicates a potential issue that needs attention.
* **Error**: Indicates a critical issue or inability to perform a check.

Example output:

```shell
slacksecchk: Verifying system security...
CIS: OK: /etc/passwd permissions are correctly set.
CIS: Warning: Unnecessary service 'telnet' is enabled.
CIS: OK: No unnecessary packages found.
CIS Check complete.
```

## Testing

A simple test script to verify functionality of tool:

```bash
./test.sh
```

Or:

```bash
make test
```

## Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository.

2. Create a new branch for your feature or fix:

```bash
git checkout -b feature-name
```

3. Commit your changes:

```bash
git commit -m "Add feature or fix"
```

4. Push to your fork:

```bash
git push origin feature-name
```

5. Open a pull request on GitHub.

## License

This project is licensed under the **GPL-3.0**. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, please use [issues](https://github.com/yousha/slacksecchk/issues) section.
