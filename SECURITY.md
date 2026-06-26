# Security Policy

## Status

Omega is **pre-alpha**. Do not use it in production. APIs,
storage formats, and on-disk layouts will change without notice.

## Supported versions

Only the latest tagged release receives security fixes during the
pre-1.0 phase. Older tags are explicitly unsupported.

| Version | Supported |
| ------- | --------- |
| latest  | yes       |
| older   | no        |

After 1.0 this policy will be revised to cover at least the two most
recent minor versions.

## Reporting a vulnerability

**Do not file a public GitHub issue for security reports.**

Instead, use one of the following private channels:

1. GitHub private vulnerability reporting:
   <https://github.com/kanywst/omega/security/advisories/new>
2. Email the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md).

Please include:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal proof of concept.
- Affected versions, commits, or configurations.
- Any suggested mitigation or patch.

## Response timeline

| Stage                    | Target           |
| ------------------------ | ---------------- |
| Acknowledgement          | within 3 days    |
| Initial triage           | within 7 days    |
| Fix or mitigation plan   | within 30 days   |
| Public disclosure        | coordinated      |

We follow coordinated disclosure. Reporters are credited in the
advisory unless they request anonymity.

## Scope

In scope:

- The `omega` binary and all code under this repository.
- Default configurations shipped in `examples/` and `charts/`.

Out of scope (report to upstream instead):

- Vulnerabilities in third-party dependencies (file with the upstream
  project; we will pick up fixed versions).
- Issues in the user's own deployment configuration that are not caused
  by an Omega default.
