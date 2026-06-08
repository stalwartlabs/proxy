/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::{DestProtocol, DestinationConfig, Forwarding};
use crate::error::{ProxyError, Result};
use crate::net::BoxedStream;
use crate::outbound;
use crate::proto::common::advertises_token;

const CLIENT_TRANSPORT_TLS: &str = "TLS";
const CLIENT_TRANSPORT_INSECURE: &str = "insecure";

pub struct ForwardInfo {
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub client_tls: bool,
    pub helo: Option<String>,
    pub session: String,
    pub ttl: u32,
}

impl ForwardInfo {
    pub fn new(
        peer: SocketAddr,
        local: SocketAddr,
        client_tls: bool,
        helo: Option<String>,
        inbound_ttl: u32,
    ) -> Self {
        ForwardInfo {
            peer,
            local,
            client_tls,
            helo,
            session: new_session_id(),
            ttl: inbound_ttl.saturating_sub(1),
        }
    }

    fn transport(&self) -> &'static str {
        if self.client_tls {
            CLIENT_TRANSPORT_TLS
        } else {
            CLIENT_TRANSPORT_INSECURE
        }
    }
}

fn new_session_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("P{n:x}")
}

pub fn guard_loop(
    self_binds: &ahash::AHashSet<SocketAddr>,
    dest: &DestinationConfig,
    ep: &DestProtocol,
    forwarding: Forwarding,
    inbound_ttl: u32,
) -> Result<()> {
    if let Ok(ip) = dest.host.parse::<IpAddr>()
        && self_binds.contains(&SocketAddr::new(ip, ep.port))
    {
        return Err(ProxyError::backend(
            "proxying loop: destination is one of our own listeners",
        ));
    }
    if forwarding == Forwarding::Xclient && inbound_ttl <= 1 {
        return Err(ProxyError::backend(
            "proxying loop: forwarded TTL exhausted",
        ));
    }
    Ok(())
}

fn addr_for_smtp(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("IPV6:{v6}"),
    }
}

pub fn imap_id_fields(fwd: &ForwardInfo) -> String {
    format!(
        "(\"x-originating-ip\" \"{}\" \"x-originating-port\" \"{}\" \
         \"x-connected-ip\" \"{}\" \"x-connected-port\" \"{}\" \
         \"x-proxy-ttl\" \"{}\" \"x-session-id\" \"{}\" \
         \"x-client-transport\" \"{}\")",
        fwd.peer.ip(),
        fwd.peer.port(),
        fwd.local.ip(),
        fwd.local.port(),
        fwd.ttl,
        fwd.session,
        fwd.transport(),
    )
}

fn xclient_pairs(fwd: &ForwardInfo, smtp: bool) -> Vec<(&'static str, String)> {
    let (addr, destaddr) = if smtp {
        (addr_for_smtp(fwd.peer.ip()), addr_for_smtp(fwd.local.ip()))
    } else {
        (fwd.peer.ip().to_string(), fwd.local.ip().to_string())
    };
    let mut pairs = vec![
        ("ADDR", addr),
        ("PORT", fwd.peer.port().to_string()),
        ("DESTADDR", destaddr),
        ("DESTPORT", fwd.local.port().to_string()),
        ("SESSION", fwd.session.clone()),
        ("TTL", fwd.ttl.to_string()),
        ("CLIENT-TRANSPORT", fwd.transport().to_string()),
    ];
    if smtp {
        if let Some(helo) = &fwd.helo
            && !helo.is_empty()
            && crate::token::valid_routing_identifier(helo)
        {
            pairs.push(("HELO", helo.clone()));
        }
        pairs.push(("PROTO", "ESMTP".to_string()));
    }
    pairs
}

fn join_pairs(pairs: &[(&'static str, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn xclient_params(fwd: &ForwardInfo, smtp: bool) -> String {
    join_pairs(&xclient_pairs(fwd, smtp))
}

pub fn xclient_params_advertised(fwd: &ForwardInfo, advertised: &[String]) -> String {
    let pairs: Vec<(&'static str, String)> = xclient_pairs(fwd, true)
        .into_iter()
        .filter(|(k, _)| advertised.iter().any(|a| a.eq_ignore_ascii_case(k)))
        .collect();
    join_pairs(&pairs)
}

pub async fn send_imap_id(
    backend: &mut BoxedStream,
    residual: &mut Vec<u8>,
    banner: &[u8],
    fwd: &ForwardInfo,
    max: usize,
) -> Result<()> {
    if !advertises_token(banner, "ID") {
        return Ok(());
    }
    let cmd = format!("F1 ID {}\r\n", imap_id_fields(fwd));
    outbound::write_all(backend, cmd.as_bytes()).await?;
    for _ in 0..16 {
        let line = outbound::read_line(backend, residual, max).await?;
        if line
            .trim_ascii_start()
            .to_ascii_uppercase()
            .starts_with(b"F1 ")
        {
            return Ok(());
        }
    }
    Err(ProxyError::backend("backend ID reply was not tagged"))
}

pub async fn send_pop3_xclient(
    backend: &mut BoxedStream,
    residual: &mut Vec<u8>,
    advertised: bool,
    fwd: &ForwardInfo,
    max: usize,
) -> Result<()> {
    if !advertised {
        return Ok(());
    }
    let cmd = format!("XCLIENT {}\r\n", xclient_params(fwd, false));
    outbound::write_all(backend, cmd.as_bytes()).await?;
    let resp = outbound::read_line(backend, residual, max).await?;
    if !resp.starts_with(b"+OK") {
        return Err(ProxyError::backend("backend rejected XCLIENT"));
    }
    Ok(())
}

pub async fn send_managesieve_xclient(
    backend: &mut BoxedStream,
    residual: &mut Vec<u8>,
    advertised: bool,
    fwd: &ForwardInfo,
    max: usize,
) -> Result<()> {
    if !advertised {
        return Ok(());
    }
    let cmd = format!("XCLIENT {}\r\n", xclient_params(fwd, false));
    outbound::write_all(backend, cmd.as_bytes()).await?;
    let resp = outbound::read_line(backend, residual, max).await?;
    if !resp.to_ascii_uppercase().starts_with(b"OK") {
        return Err(ProxyError::backend("backend rejected XCLIENT"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd() -> ForwardInfo {
        ForwardInfo {
            peer: "203.0.113.5:40000".parse().unwrap(),
            local: "192.0.2.10:993".parse().unwrap(),
            client_tls: true,
            helo: Some("client.example".into()),
            session: "Pdead".into(),
            ttl: 6,
        }
    }

    #[test]
    fn imap_id_has_core_fields() {
        let s = imap_id_fields(&fwd());
        assert!(s.contains("\"x-originating-ip\" \"203.0.113.5\""));
        assert!(s.contains("\"x-proxy-ttl\" \"6\""));
        assert!(s.contains("\"x-client-transport\" \"TLS\""));
        assert!(s.starts_with('(') && s.ends_with(')'));
    }

    #[test]
    fn xclient_pop3_omits_login_and_helo() {
        let s = xclient_params(&fwd(), false);
        assert!(s.contains("ADDR=203.0.113.5 PORT=40000"));
        assert!(s.contains("CLIENT-TRANSPORT=TLS"));
        assert!(!s.contains("LOGIN="));
        assert!(!s.contains("HELO="));
    }

    #[test]
    fn xclient_smtp_includes_helo_proto_and_v6_prefix_but_never_login() {
        let mut f = fwd();
        f.peer = "[2001:db8::5]:40000".parse().unwrap();
        let s = xclient_params(&f, true);
        assert!(s.contains("ADDR=IPV6:2001:db8::5"));
        assert!(s.contains("HELO=client.example"));
        assert!(s.contains("PROTO=ESMTP"));
        assert!(
            !s.contains("LOGIN="),
            "LOGIN must not be forwarded: the proxy replays AUTH; XCLIENT LOGIN would pre-authenticate the backend"
        );
    }

    #[test]
    fn xclient_advertised_filters_unsupported_attributes() {
        let advertised: Vec<String> = ["ADDR", "PORT", "HELO", "PROTO", "DESTADDR", "DESTPORT"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let s = xclient_params_advertised(&fwd(), &advertised);
        assert!(s.contains("ADDR=203.0.113.5"));
        assert!(s.contains("PROTO=ESMTP"));
        assert!(!s.contains("SESSION="), "Postfix rejects SESSION: {s}");
        assert!(!s.contains("TTL="), "Postfix rejects TTL: {s}");
        assert!(
            !s.contains("CLIENT-TRANSPORT="),
            "Postfix rejects CLIENT-TRANSPORT: {s}"
        );
    }

    #[test]
    fn guard_loop_rejects_self_and_exhausted_ttl() {
        use crate::config::{DestProtocol, TlsMode};
        use ahash::AHashSet;

        let mut binds = AHashSet::new();
        binds.insert("127.0.0.1:993".parse().unwrap());

        let mut dest: DestinationConfig = toml::from_str("host = \"127.0.0.1\"").expect("dest");
        let ep = DestProtocol {
            port: 993,
            tls: TlsMode::Implicit,
            forwarding: None,
        };
        assert!(guard_loop(&binds, &dest, &ep, Forwarding::Proxy, 7).is_err());

        let ep2 = DestProtocol {
            port: 143,
            tls: TlsMode::Implicit,
            forwarding: None,
        };
        assert!(guard_loop(&binds, &dest, &ep2, Forwarding::Proxy, 7).is_ok());

        dest.host = "10.0.0.9".to_string();
        assert!(guard_loop(&binds, &dest, &ep2, Forwarding::Xclient, 1).is_err());
        assert!(guard_loop(&binds, &dest, &ep2, Forwarding::Proxy, 1).is_ok());
    }

    #[test]
    fn ttl_decrements_on_construction() {
        let f = ForwardInfo::new(
            "203.0.113.5:40000".parse().unwrap(),
            "192.0.2.10:993".parse().unwrap(),
            false,
            None,
            7,
        );
        assert_eq!(f.ttl, 6);
        assert_eq!(f.transport(), "insecure");
    }
}
