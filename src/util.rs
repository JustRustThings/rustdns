use std::fmt::Write;
use std::net::IpAddr;
use std::net::IpAddr::V4;
use std::net::IpAddr::V6;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

#[cfg(test)]
use pretty_assertions::assert_eq;

use crate::ParseError;

/// Returns the reverse DNS name for this IP address. Suitable for use with
/// [`Type::PTR`] records. See [rfc1035] and [rfc3596] for IPv4 and IPv6 respectively.
///
/// # Example
///
/// ```rust
/// use rustdns::util::reverse;
///
/// let ip4 = "127.0.0.1".parse().unwrap();
/// let ip6 = "2001:db8::567:89ab".parse().unwrap();
///
/// assert_eq!(reverse(ip4), "1.0.0.127.in-addr.arpa.");
/// assert_eq!(reverse(ip6), "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.");
/// ```
///
/// [`Type::PTR`]: crate::Type::PTR
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.5
/// [rfc3596]: https://datatracker.ietf.org/doc/html/rfc3596#section-2.5
pub fn reverse(ip: IpAddr) -> String {
    match ip {
        V4(ipv4) => {
            let octets = ipv4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        V6(ipv6) => {
            let mut result = String::new();
            for o in ipv6.octets().iter().rev() {
                write!(
                    result,
                    "{:x}.{:x}.",
                    o & 0b0000_1111,
                    (o & 0b1111_0000) >> 4
                )
                .unwrap(); // Impossible for write! to fail when appending to a string.
            }
            result.push_str("ip6.arpa.");
            result
        }
    }
}

/// Parses a reverse DNS name and returns the described IP address.
/// Suitable for use with answers to [`Type::PTR`] questions.
/// See [rfc1035] and [rfc3596] for IPv4 and IPv6 respectively.
///
/// # Example
///
/// ```rust
/// # use std::net::IpAddr;
/// # use std::str::FromStr;
/// use rustdns::util::parse_arpa_name;
///
/// let reverse_ip4 = "1.0.0.127.in-addr.arpa.";
/// let reverse_ip6 = "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
///
/// assert_eq!(parse_arpa_name(reverse_ip4).unwrap(), IpAddr::from_str("127.0.0.1").unwrap());
/// assert_eq!(parse_arpa_name(reverse_ip6).unwrap(), IpAddr::from_str("2001:db8::567:89ab").unwrap());
/// ```
///
/// [`Type::PTR`]: crate::Type::PTR
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.5
/// [rfc3596]: https://datatracker.ietf.org/doc/html/rfc3596#section-2.5
pub fn parse_arpa_name(arpa_name: &str) -> Result<IpAddr, ParseError> {
    if let Some(rev_ipv4_str) = arpa_name.strip_suffix(".in-addr.arpa.") {
        let ipv4_str = rev_ipv4_str
            .rsplit('.')
            .fold(String::new(), |s, b| s + "." + b)
            .trim_start_matches('.')
            .to_string();
        match ipv4_str.parse::<Ipv4Addr>() {
            Ok(ipv4) => Ok(ipv4.into()),
            Err(_) => Err(ParseError::InvalidArpaName(arpa_name.to_string()))
        }
    } else if let Some(rev_ipv6_str) = arpa_name.strip_suffix(".ip6.arpa.") {
        let ipv6_chars = rev_ipv6_str
            .rsplit('.')
            .collect::<Vec<&str>>();
        if ipv6_chars.len() != 32 || ipv6_chars.iter().any(|c| c.is_empty()) {
            return Err(ParseError::InvalidArpaName(arpa_name.to_string()));
        }
        let ipv6_str = ipv6_chars
            .chunks(4)
            .fold(String::new(), |s, b| s + ":" + b[0] + b[1] + b[2] + b[3])
            .trim_start_matches(':')
            .to_string();
        match ipv6_str.parse::<Ipv6Addr>() {
            Ok(ipv6) => Ok(ipv6.into()),
            Err(_) => Err(ParseError::InvalidArpaName(arpa_name.to_string()))
        }
    } else {
        Err(ParseError::InvalidArpaName(arpa_name.to_string()))
    }
}

#[test]
fn test_reverse() {
    let tests: Vec<(IpAddr, &str)> = vec![
        ("127.0.0.1".parse().unwrap(), "1.0.0.127.in-addr.arpa."),
        ("8.8.4.4".parse().unwrap(), "4.4.8.8.in-addr.arpa."),
        (
            "2001:db8::567:89ab".parse().unwrap(),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ),
    ];

    for test in tests {
        assert_eq!(reverse(test.0), test.1);
    }
}

#[test]
fn test_parse_arpa_name() {
    let tests: Vec<(IpAddr, &str)> = vec![
        ("127.0.0.1".parse().unwrap(), "1.0.0.127.in-addr.arpa."),
        ("8.8.4.4".parse().unwrap(), "4.4.8.8.in-addr.arpa."),
        (
            "2001:db8::567:89ab".parse().unwrap(),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ),
    ];

    for test in tests {
        assert_eq!(test.0, parse_arpa_name(test.1).unwrap());
    }
}

#[test]
fn test_parse_invalid_arpa_name() {
    // invalid ip addresses
    let tests = vec![
        "4.3.2.1.out-addr.arpa.",
        "5.4.3.2.1.in-addr.arpa.",
        "80:4.3.2.1.in-addr.arpa.",
        "4.3.2.1.ip6.arpa.",
        "hello.3.2.1.in-addr.arpa.",
        "f.b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        "X.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ".a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        "b. .9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        "80:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        "b:.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ":b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        "999.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    ];

    for test in tests {
        let parsed = parse_arpa_name(test);
        assert!(parsed.is_err(), "{} was parsed to {:?}", test, parsed);
    }
}

/// IpAddr -> reverse() -> parse_arpa_name() -> same IpAddr
#[test]
fn test_reverse_then_parse_arpa_name() {
    let tests: Vec<IpAddr> = vec![
        "127.0.0.1".parse().unwrap(),
        "8.8.4.4".parse().unwrap(),
        "2001:db8::567:89ab".parse().unwrap(),
        "::1".parse().unwrap(),
    ];

    for test in tests {
        assert_eq!(test, parse_arpa_name(&reverse(test)).unwrap());
    }
}
