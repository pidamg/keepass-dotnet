# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-29

### Changed

- Established the current public API as the compatibility baseline for the stable release.

## [0.1.0-beta.1] - 2026-07-28

### Added

- Added English and French project documentation focused on package consumers.
- Added support for KeePass XML v2 key files, including key-hash validation.

### Changed

- Made `KdbxVersion` relational operators consistent when either operand is `null`.

### Fixed

- Fixed XML key-file detection when the file contains a UTF-8 byte order mark.

## [0.1.0-alpha.3] - 2026-07-28

### Added

- Added an original KDBX package icon and complete English NuGet metadata.
- Added automatic GitHub Releases with changelog notes and NuGet package artifacts.

## [0.1.0-alpha.2] - 2026-07-28

### Added

- Added CI validation of the packed `.nupkg` through the public integration test suite.
- Blocked package publication until the packed artifact passes its integration tests.

## [0.1.0-alpha.1] - 2026-07-28

### Added

- Initial preview release of the `Pidamg.KeePass.Kdbx` package.
- Added support for reading, creating, and writing KDBX 3.x and 4.x databases.
- Added AES, ChaCha20, and Twofish content ciphers.
- Added AES-KDF, Argon2d, and Argon2id key derivation.
- Added password and key-file authentication.
- Added entries, groups, metadata, attachments, custom icons, Auto-Type, search, history, and
  recycle-bin operations.
- Added synchronous and asynchronous file APIs.
- Added XML IntelliSense documentation and public API compatibility validation.
- Added unit and public integration test suites.

[Unreleased]: https://github.com/pidamg/keepass-dotnet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pidamg/keepass-dotnet/compare/v0.1.0-beta.1...v0.1.0
[0.1.0-beta.1]: https://github.com/pidamg/keepass-dotnet/compare/v0.1.0-alpha.3...v0.1.0-beta.1
[0.1.0-alpha.3]: https://github.com/pidamg/keepass-dotnet/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/pidamg/keepass-dotnet/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/pidamg/keepass-dotnet/releases/tag/v0.1.0-alpha.1
