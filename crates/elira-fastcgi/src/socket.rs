use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf as TcpReadHalf, OwnedWriteHalf as TcpWriteHalf};
use tokio::net::unix::{OwnedReadHalf as UnixReadHalf, OwnedWriteHalf as UnixWriteHalf};
use tokio::net::{TcpStream, UnixStream};

use crate::{Error, Target};

#[derive(Debug)]
pub(crate) enum Socket {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Socket {
    pub(crate) async fn connect(target: &Target) -> Result<Self, Error> {
        match target {
            Target::Tcp(address) => TcpStream::connect(address)
                .await
                .map(Self::Tcp)
                .map_err(|source| connect_error(target, source)),
            Target::TcpName(name) => {
                let address = tokio::net::lookup_host(name)
                    .await
                    .map_err(|source| connect_error(target, source))?
                    .next()
                    .ok_or_else(|| {
                        connect_error(
                            target,
                            io::Error::new(io::ErrorKind::NotFound, "host has no addresses"),
                        )
                    })?;
                TcpStream::connect(address)
                    .await
                    .map(Self::Tcp)
                    .map_err(|source| connect_error(target, source))
            }
            Target::Unix(path) => UnixStream::connect(path)
                .await
                .map(Self::Unix)
                .map_err(|source| connect_error(target, source)),
        }
    }

    pub(crate) fn is_alive(&mut self) -> bool {
        let mut byte = [0u8; 1];
        let result = match self {
            Self::Tcp(stream) => stream.try_read(&mut byte),
            Self::Unix(stream) => stream.try_read(&mut byte),
        };

        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,

            Ok(_) | Err(_) => false,
        }
    }

    pub(crate) fn into_split(self) -> (SocketRead, SocketWrite) {
        match self {
            Self::Tcp(stream) => {
                let (reader, writer) = stream.into_split();
                (SocketRead::Tcp(reader), SocketWrite::Tcp(writer))
            }
            Self::Unix(stream) => {
                let (reader, writer) = stream.into_split();
                (SocketRead::Unix(reader), SocketWrite::Unix(writer))
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum SocketRead {
    Tcp(TcpReadHalf),
    Unix(UnixReadHalf),
}

#[derive(Debug)]
pub(crate) enum SocketWrite {
    Tcp(TcpWriteHalf),
    Unix(UnixWriteHalf),
}

pub(crate) fn reunite(reader: SocketRead, writer: SocketWrite) -> Option<Socket> {
    match (reader, writer) {
        (SocketRead::Tcp(reader), SocketWrite::Tcp(writer)) => {
            reader.reunite(writer).ok().map(Socket::Tcp)
        }
        (SocketRead::Unix(reader), SocketWrite::Unix(writer)) => {
            reader.reunite(writer).ok().map(Socket::Unix)
        }
        _ => None,
    }
}

fn connect_error(target: &Target, source: io::Error) -> Error {
    Error::Connect {
        target: target.to_string(),
        source,
    }
}

impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            Self::Unix(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

impl AsyncRead for SocketRead {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for SocketWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            Self::Unix(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}
