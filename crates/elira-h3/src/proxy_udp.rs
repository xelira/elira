use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

pub type Clients = Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>;

pub struct ProxyUdpSocket {
    fd: Arc<AsyncFd<std::net::UdpSocket>>,
    clients: Clients,
}

impl ProxyUdpSocket {
    pub fn new(socket: std::net::UdpSocket) -> io::Result<(Arc<Self>, Clients)> {
        socket.set_nonblocking(true)?;
        #[allow(deprecated)]
        let fd = Arc::new(AsyncFd::new(socket)?);
        let clients = Arc::new(Mutex::new(HashMap::new()));
        Ok((
            Arc::new(Self {
                fd,
                clients: clients.clone(),
            }),
            clients,
        ))
    }
}

impl fmt::Debug for ProxyUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyUdpSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ProxyUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller {
            fd: self.fd.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        match self.fd.try_io(Interest::WRITABLE, |socket| {
            socket.send_to(transmit.contents, transmit.destination)
        }) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(err) => Err(err),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(meta) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };

        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            };

            let result = guard.try_io(|socket| socket.get_ref().recv_from(&mut buf[..]));
            let (read, transport) = match result {
                Ok(Ok(received)) => received,
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            };

            let mut clients = self
                .clients
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match strip_header(&mut buf[..read], transport, &mut clients) {
                Some(len) => {
                    *meta = RecvMeta {
                        addr: transport,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }

                None => continue,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.fd.get_ref().local_addr()
    }
}

struct Poller {
    fd: Arc<AsyncFd<std::net::UdpSocket>>,
}

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyUdpPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.fd.poll_write_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

fn strip_header(
    buf: &mut [u8],
    transport: SocketAddr,
    clients: &mut HashMap<SocketAddr, SocketAddr>,
) -> Option<usize> {
    const MAX_CLIENTS: usize = 4096;
    let len = buf.len();
    if len < 16 || buf[..12] != SIGNATURE {
        return Some(len);
    }

    let version = buf[12] >> 4;
    if version != 2 {
        return None;
    }

    let command = buf[12] & 0x0f;
    let family = buf[13];
    let header_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = 16usize.checked_add(header_len)?;
    if len < total {
        return None;
    }

    if command == 1 {
        let source = match family {
            0x11 | 0x12 => {
                if header_len < 12 {
                    return None;
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[16..20]);
                let port = u16::from_be_bytes([buf[24], buf[25]]);
                SocketAddr::from((ip, port))
            }

            0x21 | 0x22 => {
                if header_len < 36 {
                    return None;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[16..32]);
                let port = u16::from_be_bytes([buf[48], buf[49]]);
                SocketAddr::from((ip, port))
            }
            _ => return None,
        };
        if !clients.contains_key(&transport) && clients.len() >= MAX_CLIENTS {
            return None;
        }
        clients.insert(transport, source);
    }

    buf.copy_within(total..len, 0);
    Some(len - total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v2_header(family: u8, command: u8, body: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&SIGNATURE);
        header.push(0x20 | command);
        header.push(family);
        header.extend_from_slice(&(body.len() as u16).to_be_bytes());
        header.extend_from_slice(body);
        header
    }

    fn ipv4_body(source: SocketAddr, target: SocketAddr) -> Vec<u8> {
        let mut body = Vec::new();
        for address in [source, target] {
            match address.ip() {
                IpAddr::V4(ip) => body.extend_from_slice(&ip.octets()),
                IpAddr::V6(_) => unreachable!(),
            }
        }
        body.extend_from_slice(&source.port().to_be_bytes());
        body.extend_from_slice(&target.port().to_be_bytes());
        body
    }

    #[test]
    fn strips_an_ipv4_header_and_remembers_the_client() {
        let transport: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let client: SocketAddr = "203.0.113.7:4242".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let body = ipv4_body(client, target);
        let mut datagram = v2_header(0x12, 1, &body);
        datagram.extend_from_slice(b"quic");

        let mut clients = HashMap::new();
        let len = strip_header(&mut datagram, transport, &mut clients).expect("valid header");
        assert_eq!(&datagram[..len], b"quic");
        assert_eq!(clients.get(&transport), Some(&client));
    }

    #[test]
    fn strips_a_local_header_without_a_client() {
        let transport: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut datagram = v2_header(0x00, 0, &[]);
        datagram.extend_from_slice(b"quic");

        let mut clients = HashMap::new();
        let len = strip_header(&mut datagram, transport, &mut clients).expect("valid header");
        assert_eq!(&datagram[..len], b"quic");
        assert!(clients.is_empty());
    }

    #[test]
    fn leaves_plain_quic_alone() {
        let transport: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut datagram = b"quic bytes".to_vec();
        let mut clients = HashMap::new();
        assert_eq!(
            strip_header(&mut datagram, transport, &mut clients),
            Some(datagram.len())
        );
        assert_eq!(&datagram, b"quic bytes");
    }

    #[test]
    fn rejects_a_truncated_header() {
        let transport: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut datagram = v2_header(0x12, 1, &[0u8; 4]);
        let mut clients = HashMap::new();
        assert!(strip_header(&mut datagram, transport, &mut clients).is_none());
    }

    #[tokio::test]
    async fn socket_strips_a_header_before_quinn_sees_it() {
        use std::io::IoSliceMut;
        use std::net::UdpSocket;

        let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
        let server_addr = server.local_addr().expect("addr");
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
        let client_addr = client.local_addr().expect("client addr");

        let (socket, clients) = ProxyUdpSocket::new(server).expect("wrap socket");
        let target: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let body = ipv4_body(client_addr, target);
        let mut datagram = v2_header(0x12, 1, &body);
        datagram.extend_from_slice(b"quic");

        client
            .send_to(&datagram, server_addr)
            .expect("send proxy datagram");

        let mut buf = [0u8; 64];
        let mut meta = [RecvMeta::default()];
        let read = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await
        .expect("recv");

        assert_eq!(read, 1);
        assert_eq!(&buf[..meta[0].len], b"quic");
        assert_eq!(
            clients.lock().expect("clients").get(&client_addr).copied(),
            Some(client_addr)
        );
    }

    #[test]
    fn parses_an_ipv6_source() {
        let transport: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let client: SocketAddr = (Ipv6Addr::LOCALHOST, 4242).into();
        let target: SocketAddr = (Ipv6Addr::LOCALHOST, 443).into();
        let mut body = Vec::new();
        body.extend_from_slice(
            &client
                .ip()
                .to_string()
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        body.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        body.extend_from_slice(&client.port().to_be_bytes());
        body.extend_from_slice(&target.port().to_be_bytes());
        let mut datagram = v2_header(0x22, 1, &body);
        datagram.extend_from_slice(b"quic");

        let mut clients = HashMap::new();
        let len = strip_header(&mut datagram, transport, &mut clients).expect("valid header");
        assert_eq!(&datagram[..len], b"quic");
        assert_eq!(clients.get(&transport), Some(&client));
        assert_eq!(client.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(Ipv4Addr::UNSPECIFIED.to_string(), "0.0.0.0");
    }
}
