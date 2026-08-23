//! A TLS-terminating [`axum::serve::Listener`] for the optional HTTPS web UI.
//!
//! Handshakes run in a [`JoinSet`] rather than inline, so one client that opens
//! a socket and then says nothing cannot stall every other connection. The
//! `TcpListener` is owned by this struct, which means aborting the serving task
//! (how [`crate::listeners`] moves a listener to a new port) releases the port
//! immediately instead of leaking it to a detached loop.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use axum::serve::Listener;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// A client that has not finished the handshake by now is not worth waiting for.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on handshakes in flight; past this we stop accepting TCP until
/// some of them resolve, which applies back-pressure instead of eating memory.
const MAX_PENDING_HANDSHAKES: usize = 256;

pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
    local: SocketAddr,
    pending: JoinSet<Option<(TlsStream<TcpStream>, SocketAddr)>>,
}

impl TlsListener {
    pub fn new(inner: TcpListener, acceptor: TlsAcceptor) -> io::Result<Self> {
        let local = inner.local_addr()?;
        Ok(TlsListener {
            inner,
            acceptor,
            local,
            pending: JoinSet::new(),
        })
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                // Only take new connections while there is handshake headroom.
                result = self.inner.accept(), if self.pending.len() < MAX_PENDING_HANDSHAKES => {
                    match result {
                        Ok((stream, peer)) => {
                            let acceptor = self.acceptor.clone();
                            self.pending.spawn(async move {
                                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                                    Ok(Ok(tls)) => Some((tls, peer)),
                                    Ok(Err(e)) => {
                                        tracing::debug!("TLS handshake with {peer} failed: {e}");
                                        None
                                    }
                                    Err(_) => {
                                        tracing::debug!("TLS handshake with {peer} timed out");
                                        None
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            // Mirrors axum's own behaviour for a TcpListener: log
                            // and pause briefly rather than spin on a hard error.
                            tracing::warn!("HTTPS accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                Some(joined) = self.pending.join_next(), if !self.pending.is_empty() => {
                    match joined {
                        Ok(Some(conn)) => return conn,
                        // A failed or timed-out handshake: nothing to serve.
                        Ok(None) => {}
                        Err(e) if e.is_panic() => tracing::error!("TLS handshake task panicked: {e}"),
                        Err(_) => {}
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}
