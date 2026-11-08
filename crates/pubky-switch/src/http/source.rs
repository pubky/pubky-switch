//! Network sources (Switch wire 7.2, 9.4).
//!
//! Before a request verifies, the service trusts nothing it claims, so it limits it only by
//! its network source: an IPv4 address, or an IPv6 /64, an IPv4 address mapped into IPv6
//! counting as the IPv4 address. Behind a reverse proxy the source is the address the proxy
//! reports, and only proxies the operator names are believed.

use std::net::{IpAddr, Ipv4Addr};

use axum::http::HeaderMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The network source of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetworkSource {
    /// An IPv4 address.
    V4(Ipv4Addr),
    /// An IPv6 /64: the first 64 bits of the address.
    V6([u8; 8]),
}

impl NetworkSource {
    /// The source of `ip`.
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::V4(v4),
                None => {
                    let octets = v6.octets();
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&octets[..8]);
                    Self::V6(prefix)
                }
            },
        }
    }
}

/// Reverse proxies whose report of the client's address the service believes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// The proxies' addresses or networks, such as `10.0.0.0/8`. Empty: no proxy is
    /// believed, and the source is the connection's peer.
    pub trusted: Vec<IpNet>,
    /// The header the proxies append the client's address to.
    pub header: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            trusted: Vec::new(),
            header: "x-forwarded-for".into(),
        }
    }
}

impl ProxyConfig {
    fn trusts(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// The client's address: the connection's `peer`, or, when the peer is a trusted proxy,
    /// the address in the proxies' header nearest the service that isn't a trusted proxy.
    /// A header that doesn't parse leaves the peer as the client, so a proxy that sends
    /// garbage is limited as one client rather than believed.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.trusts(peer) {
            return peer;
        }
        let mut hops = Vec::new();
        for value in headers.get_all(self.header.as_str()) {
            let Ok(text) = value.to_str() else {
                return peer;
            };
            for hop in text.split(',') {
                match hop.trim().parse::<IpAddr>() {
                    Ok(ip) => hops.push(ip),
                    Err(_) => return peer,
                }
            }
        }
        hops.iter()
            .rev()
            .find(|ip| !self.trusts(**ip))
            .or(hops.first())
            .copied()
            .unwrap_or(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::Ipv6Addr;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(
                "x-forwarded-for",
                HeaderValue::from_str(value).expect("value"),
            );
        }
        map
    }

    fn proxies(nets: &[&str]) -> ProxyConfig {
        ProxyConfig {
            trusted: nets.iter().map(|net| net.parse().expect("net")).collect(),
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn test_network_source_ipv4_and_ipv6_prefix() {
        assert_eq!(
            NetworkSource::of(ip("203.0.113.7")),
            NetworkSource::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
        let a = NetworkSource::of(ip("2001:db8:1:2:aaaa::1"));
        let b = NetworkSource::of(ip("2001:db8:1:2:bbbb::9"));
        let c = NetworkSource::of(ip("2001:db8:1:3::1"));
        assert_eq!(a, b, "one /64 is one source");
        assert_ne!(a, c);
    }

    #[test]
    fn test_network_source_mapped_ipv4_is_ipv4() {
        let mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 4).to_ipv6_mapped());
        assert_eq!(
            NetworkSource::of(mapped),
            NetworkSource::of(ip("198.51.100.4"))
        );
        // An IPv4-compatible address isn't mapped: it is an IPv6 /64.
        let compatible = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc633, 0x6404));
        assert!(matches!(
            NetworkSource::of(compatible),
            NetworkSource::V6(_)
        ));
    }

    #[test]
    fn test_client_ip_without_trusted_proxies_is_the_peer() {
        let config = ProxyConfig::default();
        let forged = headers(&["192.0.2.1"]);
        assert_eq!(
            config.client_ip(ip("203.0.113.9"), &forged),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn test_client_ip_behind_trusted_proxies() {
        let config = proxies(&["10.0.0.0/8"]);
        // The client prepended a forged hop; the proxy appended the real one.
        let chain = headers(&["192.0.2.1, 203.0.113.5"]);
        assert_eq!(config.client_ip(ip("10.1.2.3"), &chain), ip("203.0.113.5"));
        // Two proxies of ours, the second header line appended by the inner one.
        let chain = headers(&["192.0.2.1, 203.0.113.5", "10.9.9.9"]);
        assert_eq!(config.client_ip(ip("10.1.2.3"), &chain), ip("203.0.113.5"));
        // A peer that isn't trusted isn't believed.
        assert_eq!(
            config.client_ip(ip("198.51.100.1"), &chain),
            ip("198.51.100.1")
        );
        // A mapped IPv4 peer counts as the IPv4 address.
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 1, 2, 3).to_ipv6_mapped());
        assert_eq!(
            config.client_ip(mapped, &headers(&["203.0.113.5"])),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn test_client_ip_bad_or_missing_header_is_the_peer() {
        let config = proxies(&["10.0.0.0/8"]);
        assert_eq!(
            config.client_ip(ip("10.1.2.3"), &HeaderMap::new()),
            ip("10.1.2.3")
        );
        assert_eq!(
            config.client_ip(ip("10.1.2.3"), &headers(&["203.0.113.5, not-an-ip"])),
            ip("10.1.2.3")
        );
        // Every hop a trusted proxy: the first one is the client.
        assert_eq!(
            config.client_ip(ip("10.1.2.3"), &headers(&["10.0.0.1, 10.0.0.2"])),
            ip("10.0.0.1")
        );
    }
}
