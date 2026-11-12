use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

pub async fn read_peer(stream: &mut TcpStream) -> Option<SocketAddr> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut peeked = [0u8; 512];
        let read = stream.peek(&mut peeked).await.ok()?;
        let head = &peeked[..read];

        if head.starts_with(b"PROXY ") {
            if let Some(end) = head.windows(2).position(|window| window == b"\r\n") {
                let line = std::str::from_utf8(&head[..end]).ok()?;
                let peer = parse_v1(line)?;
                let mut discard = vec![0u8; end + 2];
                stream.read_exact(&mut discard).await.ok()?;
                return Some(peer);
            }
            if read >= 512 {
                return None;
            }
        } else if head.starts_with(&SIGNATURE) {
            if head.len() >= 16 {
                let length = u16::from_be_bytes([head[14], head[15]]) as usize;
                let total = 16usize.checked_add(length)?;
                if head.len() >= total {
                    let peer = parse_v2(&head[..total])?;
                    let mut discard = vec![0u8; total];
                    stream.read_exact(&mut discard).await.ok()?;
                    return Some(peer);
                }
                if total > 512 {
                    return None;
                }
            }
        } else {
            let partial =
                !head.is_empty() && (b"PROXY ".starts_with(head) || SIGNATURE.starts_with(head));
            if !partial {
                return None;
            }
        }

        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn parse_v1(line: &str) -> Option<SocketAddr> {
    let mut parts = line.split(' ');
    if parts.next()? != "PROXY" {
        return None;
    }

    match parts.next()? {
        "TCP4" => {
            let source: Ipv4Addr = parts.next()?.parse().ok()?;
            parts.next()?;
            let port: u16 = parts.next()?.parse().ok()?;
            Some(SocketAddr::new(IpAddr::V4(source), port))
        }
        "TCP6" => {
            let source: Ipv6Addr = parts.next()?.parse().ok()?;
            parts.next()?;
            let port: u16 = parts.next()?.parse().ok()?;
            Some(SocketAddr::new(IpAddr::V6(source), port))
        }

        _ => None,
    }
}

fn parse_v2(head: &[u8]) -> Option<SocketAddr> {
    if head.len() < 16 {
        return None;
    }
    let command = head[12];

    if command != 0x21 {
        return None;
    }

    let family = head[13];
    match family {
        0x11 => {
            if head.len() < 28 {
                return None;
            }
            let source = Ipv4Addr::new(head[16], head[17], head[18], head[19]);
            let port = u16::from_be_bytes([head[24], head[25]]);
            Some(SocketAddr::new(IpAddr::V4(source), port))
        }

        0x21 => {
            if head.len() < 52 {
                return None;
            }
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
        head[24..26].copy_from_slice(&0x15b3u16.to_be_bytes());
        head[26..28].copy_from_slice(&0x01bbu16.to_be_bytes());

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

#[cfg(test)]
mod short_tests {
    use super::*;

    #[test]
    fn rejects_short_proxy_v2_payloads() {
        let mut head = [0u8; 16];
        head[..12].copy_from_slice(&SIGNATURE);
        head[12] = 0x21;
        head[13] = 0x21;
        head[14] = 0;
        head[15] = 0;
        assert!(parse_v2(&head).is_none());
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn reads_a_proxy_header_split_across_segments() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let addr = listener.local_addr().expect("addr");
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            stream
                .write_all(b"PROXY TCP4 203.0.113.7 ")
                .await
                .expect("part");
            tokio::time::sleep(Duration::from_millis(20)).await;
            stream
                .write_all(b"10.0.0.1 5555 443\r\n")
                .await
                .expect("rest");
            stream
        });
        let (mut server, _) = listener.accept().await.expect("accept");
        let peer = read_peer(&mut server).await.expect("proxy peer");
        assert_eq!(peer, "203.0.113.7:5555".parse().expect("addr"));
        let _client = client.await.expect("client task");
    }
}
