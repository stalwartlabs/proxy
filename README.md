<p align="center">
    <a href="https://stalw.art">
    <img src="./img/logo-red.svg" height="150">
    </a>
</p>

<h3 align="center">
  Multi-protocol e-mail migration proxy for Stalwart
</h3>

<br>

<p align="center">
  <a href="https://github.com/stalwartlabs/proxy/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/stalwartlabs/proxy/ci.yml?style=flat-square" alt="continuous integration"></a>
  &nbsp;
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg?label=license&style=flat-square" alt="License: AGPL v3"></a>
  &nbsp;
  <a href="https://stalw.art/docs/install/get-started"><img src="https://img.shields.io/badge/read_the-docs-red?style=flat-square" alt="Documentation"></a>
</p>
<p align="center">
  <a href="https://mastodon.social/@stalwartlabs"><img src="https://img.shields.io/mastodon/follow/109929667531941122?style=flat-square&logo=mastodon&color=%236364ff&label=Follow%20on%20Mastodon" alt="Mastodon"></a>
  &nbsp;
  <a href="https://twitter.com/stalwartlabs"><img src="https://img.shields.io/twitter/follow/stalwartlabs?style=flat-square&logo=x&label=Follow%20on%20Twitter" alt="Twitter"></a>
</p>
<p align="center">
  <a href="https://discord.com/servers/stalwart-923615863037390889"><img src="https://img.shields.io/discord/923615863037390889?label=Join%20Discord&logo=discord&style=flat-square" alt="Discord"></a>
  &nbsp;
  <a href="https://www.reddit.com/r/stalwartlabs/"><img src="https://img.shields.io/reddit/subreddit-subscribers/stalwartlabs?label=Join%20%2Fr%2Fstalwartlabs&logo=reddit&style=flat-square" alt="Reddit"></a>
</p>

## Features

The migration proxy sits in front of one or more mail backends and decides, on a per-account basis, which backend a given connection belongs to. It terminates IMAP, POP3, ManageSieve, SMTP submission, SMTP/LMTP and HTTP (JMAP) sessions, identifies the account behind each connection from the credentials the client already presents, looks up the destination that account is assigned to, replays the authentication to that backend, and bridges the session. Because the routing decision is made from the existing credentials, no client reconfiguration is required: users keep the same server name, ports and passwords while the proxy routes them to the correct system.

It is built for three scenarios: migrating from legacy servers (Dovecot, Cyrus and other IMAP/POP3/SMTP servers) onto Stalwart one mailbox at a time, migrating between Stalwart versions by running an old and a new deployment side by side, and acting as a cache-locality router in front of a Stalwart cluster so each account is consistently pinned to the same node.

- **Multi-protocol.** Proxies IMAP, POP3, ManageSieve, SMTP submission, SMTP/LMTP pass-through and HTTP/JMAP, including JMAP-over-WebSocket.
- **Per-account routing.** Resolves each account to a backend through a mapping store backed by a flat file, Redis or a SQL database (PostgreSQL, MySQL or SQLite), with an in-memory cache and a configurable default destination for unmapped accounts.
- **Credential-aware.** Extracts the routing identifier from SASL `PLAIN`, `OAUTHBEARER` and `XOAUTH2` exchanges, from HTTP Basic and Bearer authentication, and from JWT and Stalwart access-token claims, then replays authentication to the backend without ever persisting passwords.
- **Backend-friendly forwarding.** Conveys the real client identity using the PROXY protocol for modern backends, or the `XCLIENT` and IMAP `ID` extensions for Dovecot and Postfix, with `Forwarded` and `X-Forwarded-For` headers for HTTP.
- **Flexible TLS.** Terminates inbound TLS with SNI-based certificate selection, and reaches backends over implicit TLS, STARTTLS or plaintext, with platform, pinned-certificate or mutual-TLS verification on the backend leg.
- **Resilient.** Per-destination health gating with a circuit breaker, connection retries, idle timeouts and graceful draining on shutdown.
- **Operable at runtime.** An authenticated HTTP management API exposes statistics, mapping management, cache invalidation, connection control and configuration reload without a restart.

## Installing

The proxy is distributed as a single self-contained binary and as a multi-architecture container image (`amd64`, `arm64`, `armv7` and `armv6`), in both glibc and Alpine/musl variants.

The container image is published to the GitHub Container Registry and Docker Hub. Mount a configuration directory at `/etc/proxy` and run:

```bash
docker run -d --name proxy \
  -v /srv/proxy:/etc/proxy \
  -p 993:993 -p 143:143 -p 995:995 \
  -p 587:587 -p 465:465 -p 4190:4190 -p 443:443 \
  ghcr.io/stalwartlabs/proxy:latest
```

To install directly on a host, the install script provisions the binary, a service account, a service unit and sample configuration files:

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/stalwartlabs/proxy/main/install.sh | sudo sh
```

The service is installed but not started, because the sample configuration must first be edited for the local destinations, listeners and TLS certificates. Full instructions are in the [documentation](https://stalw.art/docs/migration/proxy).

## Documentation

All documentation is available at [stalw.art/docs/migration/proxy](https://stalw.art/docs/migration/proxy).

## Support

If you are having problems running Stalwart, found a bug, or just have a question, please head to the [Stalwart Support Portal](https://support.stalw.art) at [support.stalw.art](https://support.stalw.art). 
Additionally, you may purchase an [Enterprise License](https://stalw.art/enterprise) to obtain priority support from Stalwart Labs LLC, including response-time commitments and a private Priority Support area on the portal.

## License

This project is dual-licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0; as published by the Free Software Foundation) and the **Stalwart Enterprise License v2 (SELv2)**:

- The [GNU Affero General Public License v3.0](./LICENSES/AGPL-3.0-only.txt) is a free software license that ensures your freedom to use, modify, and distribute the software, with the condition that any modified versions of the software must also be distributed under the same license. 
- The [Stalwart Enterprise License v2 (SELv2)](./LICENSES/LicenseRef-SEL.txt) is a proprietary license designed for commercial use. It offers additional features and greater flexibility for businesses that do not wish to comply with the AGPL-3.0 license requirements. 

Each file in this project contains a license notice at the top, indicating the applicable license(s). The license notice follows the [REUSE guidelines](https://reuse.software/) to ensure clarity and consistency. The full text of each license is available in the [LICENSES](./LICENSES/) directory.

## Copyright

Copyright (C) 2020, Stalwart Labs LLC
