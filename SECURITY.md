# Security Policy

## Reporting a Vulnerability

The security of [SQLite3MultipleCiphers](https://utelle.github.io/SQLite3MultipleCiphers/) is taken seriously.

If you believe you have discovered a security vulnerability in this project, please report it using [GitHub's private vulnerability reporting](https://github.com/utelle/SQLite3MultipleCiphers/security/advisories/new) feature. Please **do not create a public issue** for _security-related reports_.

### What to Include

To help with triage and analysis, please include as much information as possible:

- A clear description of the issue
- Steps to reproduce the problem
- Affected versions
- Potential security impact
- Any proof-of-concept code, test case, or example database (if applicable)

### Response Policy

Reports are reviewed on a best-effort basis.

While reasonable effort will be made to assess and address valid security issues in a timely manner, no specific response time or remediation schedule can be guaranteed.

## Scope

[SQLite3MultipleCiphers}(https://utelle.github.io/SQLite3MultipleCiphers/) extends [SQLite](https://sqlite.org) with database encryption capabilities.

Security reports should focus on vulnerabilities introduced by this project, particularly in relation to its cryptographic functionality.

### In Scope

The following types of issues are generally considered in scope:

- Weaknesses or flaws in encryption implementations
- Cryptographic design or implementation issues
- Key derivation or key management problems
- Authentication or integrity protection failures
- Sensitive information leakage caused by this project
- Vulnerabilities introduced by modifications or extensions to SQLite

### Out of Scope

The following types of issues are generally considered out of scope:

- Vulnerabilities in upstream SQLite that are not introduced or modified by this project
- Issues that require an attacker to execute arbitrary SQL statements within a target application
- Application-level misuse, insecure configuration, or incorrect integration of SQLite3MultipleCiphers
- General SQLite behavior unrelated to the encryption features provided by this project

## Upstream SQLite Vulnerabilities

[SQLite3MultipleCiphers](https://utelle.github.io/SQLite3MultipleCiphers/) is built on top of [SQLite](https://sqlite.org).

Security issues originating from SQLite itself should generally be reported to the SQLite project unless there is clear evidence that SQLite3MultipleCiphers introduces, modifies, or significantly amplifies the vulnerability.

For background on _SQLite CVEs_ and their applicability, see: [https://sqlite.org/cves.html](https://sqlite.org/cves.html).

Reports should clearly explain how a given [SQLite](https://sqlite.org) issue affects [SQLite3MultipleCiphers](https://utelle.github.io/SQLite3MultipleCiphers/), particularly with respect to its _encryption-related_ functionality.

Reports that merely reference a published [SQLite CVE](https://sqlite.org/cves.html) without demonstrating relevance to this project are generally considered out of scope.

## Supported Versions

Security fixes are generally applied only to the most recent release and the current development branch.

Older versions may not receive security updates.

## Coordinated Disclosure

Please do not publicly disclose security vulnerabilities before they have been reviewed and addressed.

Responsible disclosure helps protect users and ensures that fixes can be prepared before details are made public.

Thank you for helping improve the security of [SQLite3MultipleCiphers](https://utelle.github.io/SQLite3MultipleCiphers/).
