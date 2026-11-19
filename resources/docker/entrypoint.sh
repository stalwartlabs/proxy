#!/bin/sh
#
# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
#

set -eu

readonly PROXY_BIN="/usr/local/bin/proxy"
readonly INIT_CONFIG_EXISTS=3

if [ "$#" -eq 1 ] && [ ! -e "$1" ]; then
    case "$1" in
        config.toml | */config.toml)
            status=0
            "$PROXY_BIN" init "$(dirname "$1")" --admin-bind "${PROXY_ADMIN_BIND:-0.0.0.0:9443}" || status=$?
            if [ "$status" -ne 0 ] && [ "$status" -ne "$INIT_CONFIG_EXISTS" ]; then
                exit "$status"
            fi
            echo "Read the token with: docker exec <container> cat $(dirname "$1")/admin-token"
            echo "Publish the admin port on a trusted address only, e.g. -p 127.0.0.1:9443:9443."
            echo "The admin binds ${PROXY_ADMIN_BIND:-0.0.0.0:9443} inside the container: reachable from every container on"
            echo "the same Docker network, and on every host interface with --network host."
            ;;
    esac
fi

exec "$PROXY_BIN" "$@"
