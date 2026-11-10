//! The address classifier for connections to URLs someone else chose (Switch wire 7.1, 8.2;
//! Switch spec 6.1, 9): push relay URLs, and switch origins read from an `identity.json`.
//!
//! An address is usable only if it is globally reachable per the IANA IPv4 and IPv6
//! special-purpose address registries. Addresses that embed an IPv4 address (IPv4-mapped,
//! NAT64 at the well-known prefix, 6to4) are judged by the address they embed; the forms
//! that hide one (IPv4-compatible, Teredo) are refused. The check runs after DNS resolution
//! and on every connection, and the connection goes to the address checked, so DNS
//! rebinding can't move it. Resolving and connecting are the caller's; this module only
//! judges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result, invalid};

/// Whether an address is usable, or the special-purpose block that refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    /// Globally reachable.
    Public,
    /// In a special-purpose block that isn't globally reachable, or multicast; the name of
    /// the block.
    Special(&'static str),
}

impl AddressClass {
    /// Whether the address may be connected to.
    pub fn is_public(self) -> bool {
        self == AddressClass::Public
    }
}

fn v4_in(ip: Ipv4Addr, base: [u8; 4], len: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(base)) & mask)
}

fn v6_in(ip: Ipv6Addr, base: [u16; 8], len: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
    (u128::from(ip) & mask) == (u128::from(Ipv6Addr::from(base)) & mask)
}

/// The IPv4 blocks that aren't globally reachable (Switch wire 8.2), with multicast and the
/// deprecated 6to4 relay anycast block.
const V4_SPECIAL: &[([u8; 4], u32, &str)] = &[
    ([0, 0, 0, 0], 8, "this network"),
    ([10, 0, 0, 0], 8, "private"),
    ([100, 64, 0, 0], 10, "shared address space"),
    ([127, 0, 0, 0], 8, "loopback"),
    ([169, 254, 0, 0], 16, "link-local"),
    ([172, 16, 0, 0], 12, "private"),
    ([192, 0, 2, 0], 24, "documentation (TEST-NET-1)"),
    ([192, 88, 99, 0], 24, "deprecated 6to4 relay anycast"),
    ([192, 168, 0, 0], 16, "private"),
    ([198, 18, 0, 0], 15, "benchmarking"),
    ([198, 51, 100, 0], 24, "documentation (TEST-NET-2)"),
    ([203, 0, 113, 0], 24, "documentation (TEST-NET-3)"),
    ([224, 0, 0, 0], 4, "multicast"),
    ([240, 0, 0, 0], 4, "reserved"),
];

/// Classify an IPv4 address (Switch wire 8.2).
pub fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    // 192.0.0.0/24, IETF protocol assignments, except the anycast addresses .9 and .10.
    if v4_in(ip, [192, 0, 0, 0], 24) && !matches!(ip.octets()[3], 9 | 10) {
        return AddressClass::Special("IETF protocol assignments");
    }
    if ip == Ipv4Addr::BROADCAST {
        return AddressClass::Special("limited broadcast");
    }
    V4_SPECIAL
        .iter()
        .find(|(base, len, _)| v4_in(ip, *base, *len))
        .map_or(AddressClass::Public, |(_, _, name)| {
            AddressClass::Special(name)
        })
}

/// The IPv6 blocks that aren't globally reachable (Switch wire 8.2), with multicast and the
/// deprecated site-local block. Checked after the blocks that embed an IPv4 address and the
/// globally reachable blocks inside `2001::/23`.
const V6_SPECIAL: &[([u16; 8], u32, &str)] = &[
    (
        [0, 0, 0, 0, 0, 0, 0, 0],
        96,
        "IPv4-compatible, loopback or unspecified",
    ),
    (
        [0x64, 0xff9b, 1, 0, 0, 0, 0, 0],
        48,
        "local-use IPv4/IPv6 translation",
    ),
    ([0x100, 0, 0, 0, 0, 0, 0, 0], 64, "discard-only"),
    ([0x100, 0, 0, 1, 0, 0, 0, 0], 64, "dummy prefix"),
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 32, "Teredo"),
    (
        [0x2001, 0, 0, 0, 0, 0, 0, 0],
        23,
        "IETF protocol assignments",
    ),
    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32, "documentation"),
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20, "documentation"),
    ([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16, "segment routing SIDs"),
    ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7, "unique-local"),
    ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, "link-local"),
    ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10, "site-local"),
    ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8, "multicast"),
];

/// The globally reachable blocks inside `2001::/23`.
const V6_GLOBAL_IN_2001: &[([u16; 8], u32)] = &[
    ([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
    ([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
    ([0x2001, 1, 0, 0, 0, 0, 0, 3], 128),
    ([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
    ([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
    ([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
    ([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
];

/// Classify an IPv6 address, judging those that embed an IPv4 address by it (Switch wire
/// 8.2).
pub fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let bits = u128::from(ip);
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return classify_v4(mapped);
    }
    if v6_in(ip, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        return classify_v4(Ipv4Addr::from((bits & 0xffff_ffff) as u32));
    }
    // 6to4: the IPv4 address in bits 16 to 47.
    if v6_in(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16) {
        return classify_v4(Ipv4Addr::from(((bits >> 80) & 0xffff_ffff) as u32));
    }
    if V6_GLOBAL_IN_2001
        .iter()
        .any(|(base, len)| v6_in(ip, *base, *len))
    {
        return AddressClass::Public;
    }
    V6_SPECIAL
        .iter()
        .find(|(base, len, _)| v6_in(ip, *base, *len))
        .map_or(AddressClass::Public, |(_, _, name)| {
            AddressClass::Special(name)
        })
}

/// Classify an address (Switch wire 8.2).
pub fn classify(ip: &IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(*v4),
        IpAddr::V6(v6) => classify_v6(*v6),
    }
}

/// Whether an address is globally reachable.
pub fn is_public(ip: &IpAddr) -> bool {
    classify(ip).is_public()
}

/// What a URL is checked for: its port policy and whether it may carry a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UrlUse {
    /// A push relay URL (Switch wire 8.1): HTTPS on port 443 only; a path is allowed.
    Relay,
    /// A switch origin (Switch wire 7.1): `https://host[:port]`, with no path, query or
    /// fragment; port 443, or one of `extra_ports` where the caller's operator allows it.
    SwitchOrigin {
        /// The ports other than 443 the caller allows.
        extra_ports: Vec<u16>,
    },
}

/// A URL that passed the syntax, scheme and port checks. A host name's addresses are still
/// to be checked after resolution, with [`check_addresses`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedUrl {
    /// The host: a domain name in lower case, or an address literal in its canonical text,
    /// without brackets.
    pub host: String,
    /// The port: 443 unless the URL names another the policy allows.
    pub port: u16,
}

/// Check a URL's syntax, scheme and port for `use_`, and an address literal host.
///
/// The host must be spelled so that every URL parser reads it as the same host: a
/// dotted-quad IPv4 address, a bracketed IPv6 address without a zone, or a domain name (see
/// `is_domain_name`). Any other spelling is refused rather than read the way one parser
/// would, since the client connects to the host its HTTP library parses.
///
/// # Errors
///
/// [`Error::Invalid`] for another scheme, user info, a host in another spelling, a path on
/// a switch origin, a port the policy doesn't allow, or an address literal that isn't
/// public.
pub fn check_url(url: &str, use_: &UrlUse) -> Result<CheckedUrl> {
    let Some(rest) = url.strip_prefix("https://") else {
        return invalid("Switch wire 7.1: HTTPS URLs only");
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return invalid("Switch wire 7.1: the URL's authority has no host or carries user info");
    }
    if matches!(use_, UrlUse::SwitchOrigin { .. }) && !tail.is_empty() {
        return invalid("Switch wire 7.1: a switch origin has no path, query or fragment");
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, after)) = bracketed.split_once(']') else {
            return invalid("Switch wire 7.1: an unclosed IPv6 literal");
        };
        let port = match after {
            "" => None,
            other => match other.strip_prefix(':') {
                Some(port) => Some(port),
                None => return invalid("Switch wire 7.1: the URL's port"),
            },
        };
        (host, port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => 443,
        Some(text) => match text.parse::<u16>() {
            Ok(port) if port != 0 && !text.starts_with('0') => port,
            _ => return invalid("Switch wire 7.1: the URL's port"),
        },
    };
    let allowed = match use_ {
        UrlUse::Relay => port == 443,
        UrlUse::SwitchOrigin { extra_ports } => port == 443 || extra_ports.contains(&port),
    };
    if !allowed {
        return invalid(format!("Switch wire 7.1: port {port} isn't allowed here"));
    }
    let host = if authority.starts_with('[') {
        let Ok(ip) = host.parse::<Ipv6Addr>() else {
            return invalid("Switch wire 7.1: a bracketed host that isn't an IPv6 address");
        };
        check_addresses(&[IpAddr::V6(ip)])?;
        ip.to_string()
    } else if let Ok(ip) = host.parse::<Ipv4Addr>() {
        check_addresses(&[IpAddr::V4(ip)])?;
        ip.to_string()
    } else if is_domain_name(host) {
        host.to_ascii_lowercase()
    } else {
        return invalid(
            "Switch wire 7.1: the host isn't a dotted-quad IPv4 address, a bracketed IPv6 \
             address or a domain name",
        );
    };
    Ok(CheckedUrl { host, port })
}

/// Whether `host` is a domain name in the one spelling every URL parser reads alike: labels
/// of ASCII letters, digits and hyphens, 1 to 63 bytes each, not starting or ending with a
/// hyphen, at most 253 bytes in all, no empty label (so no trailing dot), and a last label
/// that starts with a letter.
///
/// A URL parser reads a host whose last label is a number, such as `127.1`, `2130706433`,
/// `0x7f000001` or `127.0.0.1.`, as an IPv4 address, which the client would then connect to
/// without resolving it, so without the address check (Switch wire 7.1, 8.2). Escapes,
/// other characters and non-ASCII names, which a URL parser maps to other hosts, are
/// refused for the same reason.
fn is_domain_name(host: &str) -> bool {
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    host.len() <= 253
        && host.split('.').all(label_ok)
        && host
            .rsplit('.')
            .next()
            .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// Check every address a host resolves to (Switch wire 8.2).
///
/// One address that isn't public refuses the host, so a name that resolves to a public and
/// a private address can't be used to reach the private one. The caller then connects to an
/// address it checked here.
///
/// # Errors
///
/// [`Error::Invalid`] if the list is empty or any address isn't public.
pub fn check_addresses(addresses: &[IpAddr]) -> Result<()> {
    if addresses.is_empty() {
        return invalid("Switch wire 8.2: the host doesn't resolve");
    }
    for ip in addresses {
        if let AddressClass::Special(block) = classify(ip) {
            return Err(Error::Invalid(format!(
                "Switch wire 8.2: {ip} isn't a public address ({block})"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn test_classify_refuses_special_purpose_addresses() {
        for text in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::7f00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::1",
        ] {
            assert!(!is_public(&ip(text)), "{text}");
        }
    }

    #[test]
    fn test_classify_takes_public_addresses() {
        for text in [
            "1.1.1.1",
            "192.0.0.9",
            "192.0.0.10",
            "8.8.8.8",
            "2606:4700::1111",
            "2001:1::1",
            "2001:3::1",
            "2001:20::1",
            "::ffff:1.1.1.1",
            "64:ff9b::101:101",
            "2002:101:101::1",
        ] {
            assert!(is_public(&ip(text)), "{text}");
        }
    }

    #[test]
    fn test_check_url_ports_and_paths() {
        let relay = check_url("https://push.example/v1/hook", &UrlUse::Relay).unwrap();
        assert_eq!((relay.host.as_str(), relay.port), ("push.example", 443));
        assert!(check_url("https://push.example:8443/hook", &UrlUse::Relay).is_err());
        assert!(check_url("http://push.example", &UrlUse::Relay).is_err());
        assert!(check_url("https://user@push.example", &UrlUse::Relay).is_err());
        assert!(check_url("https://10.0.0.1/hook", &UrlUse::Relay).is_err());
        let origin = UrlUse::SwitchOrigin {
            extra_ports: vec![8443],
        };
        assert!(check_url("https://switch.example", &origin).is_ok());
        assert_eq!(
            check_url("https://switch.example:8443", &origin)
                .unwrap()
                .port,
            8443
        );
        assert!(check_url("https://switch.example/", &origin).is_err());
        assert!(check_url("https://switch.example:9000", &origin).is_err());
        assert!(check_url("https://[::1]", &origin).is_err());
        assert!(check_url("https://[2606:4700::1111]:08443", &origin).is_err());
    }

    #[test]
    fn test_check_url_refuses_hosts_a_url_parser_reads_as_another_address() {
        let origin = UrlUse::SwitchOrigin {
            extra_ports: Vec::new(),
        };
        for url in [
            // Short, integer, hex and octal IPv4 forms, which a URL parser reads as
            // 127.0.0.1 or 10.0.0.1.
            "https://127.1",
            "https://127.0.1",
            "https://2130706433",
            "https://0x7f000001",
            "https://0x7f.0.0.1",
            "https://0177.0.0.1",
            "https://010.0.0.1",
            "https://127.000.0.1",
            // Trailing dots, empty labels and escapes.
            "https://127.0.0.1.",
            "https://localhost.",
            "https://example.com.",
            "https://.example.com",
            "https://inbox..example",
            "https://127%2E0%2E0%2E1",
            "https://inbox.example\\.evil",
            // A last label that is a number, or not a name at all.
            "https://inbox.123",
            "https://inbox.0x7f",
            "https://-inbox.example",
            "https://inbox-.example",
            "https://inbox_1.example",
            "https://xn--nxa\u{3b1}.example",
            "https://inbox\u{3002}example",
            // IPv6: loopback, mapped loopback in either spelling, zone IDs, non-addresses.
            "https://[::1]",
            "https://[0:0:0:0:0:0:0:1]",
            "https://[::ffff:127.0.0.1]",
            "https://[::FFFF:7F00:1]",
            "https://[fe80::1%25eth0]",
            "https://[fe80::1%eth0]",
            "https://[inbox.example]",
            "https://[1.1.1.1]",
        ] {
            assert!(check_url(url, &origin).is_err(), "{url}");
        }
        assert!(check_url("https://", &origin).is_err());
        let long = format!("https://{}.example", "a".repeat(64));
        assert!(check_url(&long, &origin).is_err());
    }

    #[test]
    fn test_check_url_normalizes_hosts_it_takes() {
        let origin = UrlUse::SwitchOrigin {
            extra_ports: Vec::new(),
        };
        for (url, host) in [
            ("https://Inbox.EXAMPLE", "inbox.example"),
            ("https://inbox-1.example", "inbox-1.example"),
            ("https://1.1.1.1", "1.1.1.1"),
            ("https://[2606:4700:0:0:0:0:0:1111]", "2606:4700::1111"),
            ("https://[2606:4700::1111]", "2606:4700::1111"),
            ("https://[2606:4700::ABCD]:443", "2606:4700::abcd"),
            ("https://[::ffff:1.1.1.1]", "::ffff:1.1.1.1"),
            ("https://xn--nxasmq6b.example", "xn--nxasmq6b.example"),
        ] {
            assert_eq!(check_url(url, &origin).unwrap().host, host, "{url}");
        }
    }

    #[test]
    fn test_check_addresses_refuses_any_private_address() {
        assert!(check_addresses(&[]).is_err());
        assert!(check_addresses(&[ip("1.1.1.1"), ip("10.0.0.1")]).is_err());
        assert!(check_addresses(&[ip("1.1.1.1"), ip("8.8.8.8")]).is_ok());
    }
}
