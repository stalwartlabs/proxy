/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::{AsyncBuilder, AsyncRunner};
use testcontainers::{ContainerAsync, GenericBuildableImage, GenericImage, ImageExt};
use tokio::net::TcpStream;

pub const MASTER_USER: &str = "admin";
pub const MASTER_PASSWORD: &str = "MasterPass#2026";

const DOCKERFILE: &str = r#"FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections \
 && echo "postfix postfix/mailname string legacy.test" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      postfix postfix-pcre \
      dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
      dovecot-managesieved dovecot-sieve \
      openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY users /etc/dovecot/users
COPY master-users /etc/dovecot/master-users
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 143 993 110 995 587 465 4190 25
ENTRYPOINT ["/entrypoint.sh"]
"#;

const DOVECOT_CONF: &str = r#"protocols = imap pop3 sieve lmtp
listen = *

ssl = yes
ssl_cert = </etc/dovecot/ssl/dovecot.crt
ssl_key = </etc/dovecot/ssl/dovecot.key
ssl_min_protocol = TLSv1.2

disable_plaintext_auth = no
auth_mechanisms = plain login
auth_master_user_separator = %

login_trusted_networks = 0.0.0.0/0

mail_location = maildir:/var/vmail/%u/Maildir
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
last_valid_uid = 5000

namespace inbox {
  inbox = yes
}

passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/users
}
passdb {
  driver = passwd-file
  master = yes
  args = scheme=PLAIN username_format=%u /etc/dovecot/master-users
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/vmail/%u
}

service imap-login {
  service_count = 0
  process_min_avail = 2
  client_limit = 256
}
service pop3-login {
  service_count = 0
  process_min_avail = 2
  client_limit = 256
}
service imap {
  process_limit = 256
}
service pop3 {
  process_limit = 256
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}

protocol lmtp {
  mail_plugins = $mail_plugins sieve
}

protocol imap {
  mail_plugins = $mail_plugins
  mail_max_userip_connections = 0
}

protocol pop3 {
  mail_max_userip_connections = 0
}

plugin {
  sieve = file:~/sieve;active=~/.dovecot.sieve
}

log_path = /dev/stderr
info_log_path = /dev/stderr
"#;

const USERS: &str = "alice@legacy.test:{PLAIN}AlicePass#2026:5000:5000::/var/vmail/alice@legacy.test::\nbob@legacy.test:{PLAIN}BobPass#2026:5000:5000::/var/vmail/bob@legacy.test::\n";

const MASTER_USERS: &str = "admin:{PLAIN}MasterPass#2026\n";

const ENTRYPOINT: &str = r#"#!/bin/sh
set -e

mkdir -p /etc/dovecot/ssl
if [ ! -f /etc/dovecot/ssl/dovecot.crt ]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/dovecot/ssl/dovecot.key \
    -out /etc/dovecot/ssl/dovecot.crt \
    -subj "/CN=legacy.test" >/dev/null 2>&1
  chmod 600 /etc/dovecot/ssl/dovecot.key
fi

getent group vmail >/dev/null 2>&1 || groupadd -g 5000 vmail
getent passwd vmail >/dev/null 2>&1 || useradd -u 5000 -g 5000 -d /var/vmail -s /usr/sbin/nologin vmail
mkdir -p /var/vmail/alice@legacy.test /var/vmail/bob@legacy.test
chown -R vmail:vmail /var/vmail

postconf -e "maillog_file=/dev/stdout"
postconf -e "myhostname=legacy.test"
postconf -e "mydestination="
postconf -e "smtpd_sasl_type=dovecot"
postconf -e "smtpd_sasl_path=private/auth"
postconf -e "smtpd_sasl_auth_enable=yes"
postconf -e "broken_sasl_auth_clients=yes"
postconf -e "smtpd_tls_cert_file=/etc/dovecot/ssl/dovecot.crt"
postconf -e "smtpd_tls_key_file=/etc/dovecot/ssl/dovecot.key"
postconf -e "smtpd_tls_security_level=may"
postconf -e "smtpd_authorized_xclient_hosts=0.0.0.0/0"
postconf -e "virtual_mailbox_domains=legacy.test"
postconf -e "virtual_mailbox_base=/var/vmail"
postconf -e "virtual_transport=lmtp:unix:private/dovecot-lmtp"
postconf -e "virtual_mailbox_maps=inline:{alice@legacy.test=alice@legacy.test/,bob@legacy.test=bob@legacy.test/}"
postconf -e "virtual_minimum_uid=5000"
postconf -e "virtual_uid_maps=static:5000"
postconf -e "virtual_gid_maps=static:5000"

postconf -M submission/inet="submission inet n - y - - smtpd"
postconf -P "submission/inet/syslog_name=postfix/submission"
postconf -P "submission/inet/smtpd_tls_security_level=may"
postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
postconf -P "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
postconf -P "submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject"
postconf -P "submission/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"

postconf -M smtps/inet="smtps inet n - y - - smtpd"
postconf -P "smtps/inet/syslog_name=postfix/smtps"
postconf -P "smtps/inet/smtpd_tls_wrappermode=yes"
postconf -P "smtps/inet/smtpd_sasl_auth_enable=yes"
postconf -P "smtps/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
postconf -P "smtps/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject"
postconf -P "smtps/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"

chown root:dovecot /etc/dovecot/users /etc/dovecot/master-users
chmod 640 /etc/dovecot/users /etc/dovecot/master-users

dovecot
postfix check || true
postfix start

echo "LEGACY-MAIL READY"

exec sleep infinity
"#;

pub struct Legacy {
    _container: ContainerAsync<GenericImage>,
    pub host: String,
    pub imap: u16,
    pub imaps: u16,
    pub pop3: u16,
    pub pop3s: u16,
    pub submission: u16,
    pub smtps: u16,
    pub sieve: u16,
}

impl Legacy {
    pub async fn start() -> Legacy {
        let image: GenericImage = GenericBuildableImage::new("proxy-legacymail", "test")
            .with_dockerfile_string(DOCKERFILE.to_string())
            .with_data(DOVECOT_CONF.as_bytes().to_vec(), "dovecot.conf")
            .with_data(USERS.as_bytes().to_vec(), "users")
            .with_data(MASTER_USERS.as_bytes().to_vec(), "master-users")
            .with_data(ENTRYPOINT.as_bytes().to_vec(), "entrypoint.sh")
            .build_image()
            .await
            .expect("build legacy image");

        let container = image
            .with_exposed_port(143u16.tcp())
            .with_exposed_port(993u16.tcp())
            .with_exposed_port(110u16.tcp())
            .with_exposed_port(995u16.tcp())
            .with_exposed_port(587u16.tcp())
            .with_exposed_port(465u16.tcp())
            .with_exposed_port(4190u16.tcp())
            .with_exposed_port(25u16.tcp())
            .with_wait_for(WaitFor::message_on_stdout("LEGACY-MAIL READY"))
            .with_startup_timeout(Duration::from_secs(240))
            .start()
            .await
            .expect("start legacy container");

        let host = container.get_host().await.expect("legacy host").to_string();
        let map = |p: u16| {
            let container = &container;
            async move {
                container
                    .get_host_port_ipv4(p.tcp())
                    .await
                    .unwrap_or_else(|e| panic!("legacy port {p}: {e}"))
            }
        };
        let legacy = Legacy {
            imap: map(143).await,
            imaps: map(993).await,
            pop3: map(110).await,
            pop3s: map(995).await,
            submission: map(587).await,
            smtps: map(465).await,
            sieve: map(4190).await,
            host,
            _container: container,
        };
        wait_port(&legacy.host, legacy.imap).await;
        wait_port(&legacy.host, legacy.submission).await;
        wait_port(&legacy.host, legacy.sieve).await;
        legacy
    }
}

async fn wait_port(host: &str, port: u16) {
    for _ in 0..200 {
        if TcpStream::connect((host, port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("legacy backend port {host}:{port} never came up");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn legacy_boots_and_serves_all_protocols() {
        let legacy = Legacy::start().await;

        let mut imap = TcpStream::connect((legacy.host.as_str(), legacy.imap))
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = imap.read(&mut buf).await.unwrap();
        assert!(
            buf[..n].windows(4).any(|w| w == b"* OK"),
            "imap greeting: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
        imap.write_all(b"a1 LOGIN alice@legacy.test AlicePass#2026\r\n")
            .await
            .unwrap();
        let n = imap.read(&mut buf).await.unwrap();
        assert!(
            buf[..n].windows(5).any(|w| w == b"a1 OK"),
            "imap login: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );

        let mut sieve = TcpStream::connect((legacy.host.as_str(), legacy.sieve))
            .await
            .unwrap();
        let mut caps = Vec::new();
        let mut scratch = [0u8; 1024];
        loop {
            let n = sieve.read(&mut scratch).await.unwrap();
            if n == 0 {
                break;
            }
            caps.extend_from_slice(&scratch[..n]);
            if caps.windows(4).any(|w| w == b"OK\r\n") {
                break;
            }
        }
        assert!(
            caps.windows(7).any(|w| w == b"XCLIENT"),
            "managesieve advertises XCLIENT: {:?}",
            String::from_utf8_lossy(&caps)
        );
    }
}
