# SlackSecChk

A C tool to audit Slackware Linux(>=14) security against CIS, NSA, and DISA benchmarks.

[![Compile and Test](https://github.com/Yousha/slacksecchk/actions/workflows/action.yml/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/action.yml) [![Dependabot Updates](https://github.com/Yousha/slacksecchk/actions/workflows/dependabot/dependabot-updates/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/dependabot/dependabot-updates) [![CodeQL](https://github.com/Yousha/slacksecchk/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/Yousha/slacksecchk/actions/workflows/github-code-scanning/codeql)

## Features

* Checks critical files permissions.
* Verifies password quality settings.
* Ensures unnecessary services are disabled using Slackware's SysV Init scripts.
* Identifies and warns about unnecessary packages installed on system using `/var/log/packages`.
* Validates secure SSH settings.
* Checks for active firewall configurations.
* Ensures logging services (e.g., `syslog`) are running and properly configured.
* Easily extendable with additional CIS rules.

## Overview

The **SlackSecChk** is a security auditing tool designed to verify system configurations against CIS standards, some NSA, and some DISA STIG rules. It helps identify potential vulnerabilities and ensures that your Slackware Linux system adheres to best practices for security hardening.
This tool is specifically tailored for **Slackware Linux**, leveraging its unique package management system (`slackpkg`) and SysV Init scripts.

## Screenshots

![Screenshot](resources/images/screenshots/1.png)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Yousha/slacksecchk.git
   cd slacksecchk
   ```

2. Compile the program:

* `make clean`: Removes all compiled files for a fresh build.
* `make` or `make debug`: Compiles program without errors or warnings.
* `make install`: Installs tool system-wide for easy access.
* _`make uninstall`: Removes tool from system._

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

* **OK**: Indicates that check passed successfully.
* **Warning**: Indicates a potential issue that needs attention.
* **Error**: Indicates a critical issue or inability to perform a check.

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

1. Commit your changes:

```bash
git commit -m "Add feature or fix"
```

1. Push to your fork:

```bash
git push origin feature-name
```

1. Open a pull request on GitHub.

## License

This project is licensed under the **GPL-3.0**. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, please use [issues](https://github.com/yousha/slacksecchk/issues) section.
