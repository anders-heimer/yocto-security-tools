<!-- SPDX-License-Identifier: MIT -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-25

### Added

- **cve-metadata-extractor**: Find fix commits from Debian tracker, OSV, CVEList V5, and Ubuntu
- **cve-corrector**: Automate CVE backporting to Yocto recipes via devtool
- **cve-agent**: AI-assisted conflict resolution for CVE backports
- Plugin system for custom CVE sources and AI backends (`extra/` directory)
- XDG Base Directory compliant data/cache storage
- GitHub Actions CI (lint, type check, tests across Python 3.9–3.12)
- Pre-commit hooks (ruff, mypy)

[1.0.0]: https://github.com/Ericsson/yocto-security-tools/releases/tag/v1.0.0
