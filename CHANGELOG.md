# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [1.0.2] - 2026-07-31

### Added
- `AUTH LOGIN` support on IMAP, POP3, ManageSieve and SMTP submission (#3).

### Changed
- `LOGIN` is now part of the default `capabilities.<protocol>.sasl` set.

### Fixed

## [1.0.1] - 2026-07-30

### Added
- `server.host_down_min_clients`: number of distinct client addresses a
  failure streak must span before client-attributable failures can mark a destination
  down.
- `GET /destinations` now also reports `failure_sources` and `host_level_failure`.

### Changed

### Fixed
- The circuit breaker no longer marks a destination down because a backend rejects
  the connections of a single banned client (#2).

## [1.0.0] - 2026-06-08

### Added
- Initial release of the migration proxy: pre-auth routing and socket bridging
  for SMTP, submission, LMTP, IMAP, POP3, ManageSieve and HTTP/HTTPS.

### Changed

### Fixed
