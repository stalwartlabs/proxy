# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [1.0.5] - 2026-10-25

### Added

### Changed
- Replaced `base64` with `encodify`.
- An HTTP route's `fallback` is now honoured: unmatched or unmapped requests on that route go to the fallback destination instead of `routing.default_destination`. A `fallback` naming an undeclared destination, or one that does not declare the `http` protocol, is rejected at startup.
- A login held by `POST /connections/delay` now resolves its destination when the hold ends instead of before it.
- `PUT /mappings`, `DELETE /mappings` and `POST /cache/invalidate?identifier=` end the login delay of that identifier; `POST /mappings/reload` and `POST /cache/invalidate` without an identifier end every login delay. Held logins proceed at once to the newly mapped destination.
- Calling `POST /connections/delay` again for an identifier also moves the hold deadline of logins already waiting (still capped at 120 seconds per login).

### Fixed
- The sample configuration written by `install.sh` and `resources/config.sample.toml` named an undeclared HTTP route fallback (`default`) and failed startup validation.
- `resources/config.stalwart-upgrade.toml` now documents the WebUI OAuth client identifiers (`https://<host>/admin/oauth-client.json`, `https://<host>/account/oauth-client.json`) and pins `/admin`, `/account`, `/api/auth/**` to the new deployment.
- The `POST /config/reload` response no longer claims that cache capacity and TTLs require a restart; a reload rebuilds the router and its cache.
- `POST /connections/delay` with a `seconds` value too large to represent now returns `400` instead of panicking.

## [1.0.4] - 2026-09-10

### Added

### Changed
- HTTP and JMAP connections are pinned to the account that authenticated them.
- HTTP and JMAP routing identifiers are split on `routing.master_user_separators`.
- A backend authentication failure now counts towards `listener.max_auth_attempts`.

### Fixed
- A backend authentication failure no longer leaves the client bridged to the backend unparsed.
- `POST /connections/kick` now covers HTTP and JMAP sessions, including upgraded WebSocket bridges.
- `POST /connections/delay` now covers HTTP and JMAP logins.
- A rejected SASL response is no longer re-parsed as a command, which charged two authentication failures for one client mistake and could drop a command pipelined behind it.
- An empty routing identifier is no longer treated as an account, so it is neither registered nor used to pin an HTTP connection.
- A backend leg rejected at authentication is now closed with the protocol's logout command instead of having its socket dropped.

## [1.0.3] - 2026-08-30

### Added

### Changed

### Fixed
- IMAP authentication is no longer replayed with an inline initial response to backends that do not advertise `SASL-IR` (#4).

## [1.0.2] - 2026-07-31

### Added
- `AUTH LOGIN` support on IMAP, POP3, ManageSieve and SMTP submission (#3).

### Changed
- `LOGIN` is now part of the default `capabilities.<protocol>.sasl` set.

### Fixed

## [1.0.1] - 2026-07-30

### Added
- `server.host_down_min_clients`: number of distinct client addresses a failure streak must span before client-attributable failures can mark a destination down.
- `GET /destinations` now also reports `failure_sources` and `host_level_failure`.

### Changed

### Fixed
- The circuit breaker no longer marks a destination down because a backend rejects the connections of a single banned client (#2).

## [1.0.0] - 2026-06-08

### Added
- Initial release of the migration proxy: pre-auth routing and socket bridging for SMTP, submission, LMTP, IMAP, POP3, ManageSieve and HTTP/HTTPS.

### Changed

### Fixed
