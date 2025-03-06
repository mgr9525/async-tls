use crate::common::tls_state::TlsState;
use crate::server;

use futures_io::{AsyncRead, AsyncWrite};
use rustls::{ServerConfig, ServerConnection};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub struct Acceptor<'a, IO> {
    io: &'a mut IO,
    acceptor: rustls::server::Acceptor,
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> Acceptor<'a, IO> {
    pub fn new(io: &'a mut IO) -> Acceptor<'a, IO> {
        Acceptor {
            io,
            acceptor: rustls::server::Acceptor::default(),
        }
    }

    pub fn read_tls(&mut self) -> ReadTls<'_, IO> {
        ReadTls {
            io: &mut self.io,
            acceptor: &mut self.acceptor,
        }
    }

    pub fn accept(&mut self) -> Accepted<'_> {
        Accepted {
            acceptor: &mut self.acceptor,
        }
    }
    /* pub fn accept(&mut self) -> Poll<io::Result<rustls::server::Accepted>> {
        match self.acceptor.accept() {
            Ok(Some(accepted)) => Poll::Ready(Ok(accepted)),
            Ok(None) => Poll::Pending,
            Err((err, alert)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("accepted err{}", err),
            ))),
        }
    } */

    // pub(crate) fn read_tls_inner(&mut self, rd: &mut crate::rusttls::StdReader<'_>) -> io::Result<usize> {
}

pub struct Accepted<'a> {
    acceptor: &'a mut rustls::server::Acceptor,
}

impl<'a> Future for Accepted<'a> {
    type Output = io::Result<rustls::server::Accepted>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.acceptor.accept() {
            Ok(Some(accepted)) => Poll::Ready(Ok(accepted)),
            Ok(None) => Poll::Pending,
            Err((err, alert)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("accepted err{}", err),
            ))),
        }
    }
}
pub struct ReadTls<'a, IO> {
    io: &'a mut IO,
    acceptor: &'a mut rustls::server::Acceptor,
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> Future for ReadTls<'a, IO> {
    type Output = io::Result<usize>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut rd = crate::rusttls::StdReader::new(this.io, cx);
        match this.acceptor.read_tls(&mut rd) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        }
    }
}

/// The TLS accepting part. The acceptor drives
/// the server side of the TLS handshake process. It works
/// on any asynchronous stream.
///
/// It provides a simple interface (`accept`), returning a future
/// that will resolve when the handshake process completed. On
/// success, it will hand you an async `TLSStream`.
///
/// ## Example
///
/// See /examples/server for an example.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl TlsAcceptor {
    pub fn new(inner: ServerConfig) -> TlsAcceptor {
        TlsAcceptor {
            inner: Arc::new(inner),
        }
    }
    /// Accept a client connections. `stream` can be any type implementing `AsyncRead` and `AsyncWrite`,
    /// such as TcpStreams or Unix domain sockets.
    ///
    /// Otherwise, it will return a `Accept` Future, representing the Acceptance part of a
    /// Tls handshake. It will resolve when the handshake is over.
    #[inline]
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with(stream, |_| ())
    }

    // Currently private, as exposing ServerConnections exposes rusttls
    fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ServerConnection),
    {
        let mut conn = match ServerConnection::new(self.inner.clone()) {
            Ok(conn) => conn,
            Err(_) => {
                return Accept(server::MidHandshake::End);
            }
        };

        f(&mut conn);

        Accept(server::MidHandshake::Handshaking(server::TlsStream {
            conn,
            io: stream,
            state: TlsState::Stream,
        }))
    }
}

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(server::MidHandshake<IO>);
impl<IO: AsyncRead + AsyncWrite + Unpin> Accept<IO> {
    pub fn from_srvconn(conn: ServerConnection, stream: IO) -> Self {
        Self(server::MidHandshake::Handshaking(server::TlsStream {
            conn,
            io: stream,
            state: TlsState::Stream,
        }))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> TlsAcceptor {
        TlsAcceptor { inner }
    }
}

impl From<ServerConfig> for TlsAcceptor {
    fn from(inner: ServerConfig) -> TlsAcceptor {
        TlsAcceptor {
            inner: Arc::new(inner),
        }
    }
}
