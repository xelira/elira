//! PROXY protocol, versions 1 and 2.
//!
//! The header arrives before TLS and before HTTP, so it is read from the bare
//! socket and the exact number of header bytes is then consumed. Peeking first
//! means a connection without the header is closed instead of having its first
//! HTTP bytes eaten.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

/// Reads the client address from the header and consumes it.
///
/// Returns `None` when the header is missing or malformed; the caller must
/// then close the connection, because an enabled PROXY protocol is required.
pub async fn read_peer(stream: &mut TcpStream) -> Option<SocketAddr> {
    let mut peeked = [0u8; 512];
    let read = stream.peek(&mut peeked).await.ok()?;
    let head = &peeked[..read];

    if head.starts_with(b"PROXY ") {
        let end = head.windows(2).position(|window| window == b"\r\n")?;
        let line = std::str::from_utf8(&head[..end]).ok()?;
        let peer = parse_v1(line)?;

        let mut discard = vec![0u8; end + 2];
        stream.read_exact(&mut discard).await.ok()?;
        return Some(peer);
    }

    if head.starts_with(&SIGNATURE) {
        if head.len() < 16 {
            return None;
        }

        let length = u16::from_be_bytes([head[14], head[15]]) as usize;
        let total = 16 + length;
        if head.len() < total {
            return None;
        }

        let peer = parse_v2(&head[..total])?;

        let mut discard = vec![0u8; total];
        stream.read_exact(&mut discard).await.ok()?;
        return Some(peer);
    }

    None
}

fn parse_v1(line: &str) -> Option<SocketAddr> {
    let mut parts = line.split(' ');
    if parts.next()? != "PROXY" {
        return None;
    }

    match parts.next()? {
        "TCP4" => {
            let source: Ipv4Addr = parts.next()?.parse().ok()?;
            parts.next()?; // destination
            let port: u16 = parts.next()?.parse().ok()?;
            Some(SocketAddr::new(IpAddr::V4(source), port))
        }
        "TCP6" => {
            let source: Ipv6Addr = parts.next()?.parse().ok()?;
            parts.next()?;
            let port: u16 = parts.next()?.parse().ok()?;
            Some(SocketAddr::new(IpAddr::V6(source), port))
        }
        // `UNKNOWN` is valid and carries no addresses; the socket peer wins.
        _ => None,
    }
}

fn parse_v2(head: &[u8]) -> Option<SocketAddr> {
    let command = head[12];
    // 0x21 is PROXY; 0x20 is LOCAL, which means "use the socket address".
    if command != 0x21 {
        return None;
    }

    let family = head[13];
    match family {
        // TCP over IPv4: src addr, dst addr, src port, dst port.
        0x11 => {
            let source = Ipv4Addr::new(head[16], head[17], head[18], head[19]);
            let port = u16::from_be_bytes([head[24], head[25]]);
            Some(SocketAddr::new(IpAddr::V4(source), port))
        }
        // TCP over IPv6: 16-byte addresses, then the ports.
        0x21 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&head[16..32]);
            let source = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([head[48], head[49]]);
            Some(SocketAddr::new(IpAddr::V6(source), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v1_ipv4() {
        let peer = parse_v1("PROXY TCP4 203.0.113.7 10.0.0.1 5555 443").expect("valid");
        assert_eq!(peer, "203.0.113.7:5555".parse().expect("addr"));
    }

    #[test]
    fn rejects_v1_unknown() {
        assert!(parse_v1("PROXY UNKNOWN").is_none());
    }

    #[test]
    fn parses_v2_ipv4() {
        let mut head = [0u8; 28];
        head[..12].copy_from_slice(&SIGNATURE);
        head[12] = 0x21;
        head[13] = 0x11;
        head[14] = 0;
        head[15] = 12;
        head[16..20].copy_from_slice(&[203, 0, 113, 7]);
        head[20..24].copy_from_slice(&[10, 0, 0, 1]);
        head[24..26].copy_from_slice(&0x15b3u16.to_be_bytes()); // 5555
        head[26..28].copy_from_slice(&0x01bbu16.to_be_bytes()); // 443

        let peer = parse_v2(&head).expect("valid");
        assert_eq!(peer, "203.0.113.7:5555".parse().expect("addr"));
    }

    #[test]
    fn rejects_v2_local_command() {
        let mut head = [0u8; 16];
        head[..12].copy_from_slice(&SIGNATURE);
        head[12] = 0x20;
        head[13] = 0x11;
        head[14] = 0;
        head[15] = 0;
        assert!(parse_v2(&head).is_none());
    }
}
