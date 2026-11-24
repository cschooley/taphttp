//! Which upstream address an exchange actually went to (`TrafficEntry::peer`,
//! #24). The connector records the TCP peer the moment it connects, so the
//! address is known even when TLS or the response fails afterwards.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use hyper::Uri;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Where [`RecordPeer`] writes the address it connected to. `None` until a
/// connection is made.
#[derive(Clone, Default)]
pub struct PeerSlot(Arc<Mutex<Option<SocketAddr>>>);

impl PeerSlot {
    pub fn get(&self) -> Option<SocketAddr> {
        *self.0.lock().unwrap()
    }
}

/// A connector wrapper that records each connection's remote address in its
/// [`PeerSlot`]. Use one per request (a fresh client), so the slot holds that
/// request's connection.
#[derive(Clone)]
pub struct RecordPeer<C> {
    inner: C,
    slot: PeerSlot,
}

impl<C> RecordPeer<C> {
    pub fn new(inner: C) -> (Self, PeerSlot) {
        let slot = PeerSlot::default();
        (
            Self {
                inner,
                slot: slot.clone(),
            },
            slot,
        )
    }
}

impl<C> tower::Service<Uri> for RecordPeer<C>
where
    C: tower::Service<Uri, Response = TokioIo<TcpStream>>,
    C::Future: Send + 'static,
{
    type Response = TokioIo<TcpStream>;
    type Error = C::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connecting = self.inner.call(uri);
        let slot = self.slot.clone();
        Box::pin(async move {
            let io = connecting.await?;
            if let Ok(addr) = io.inner().peer_addr() {
                *slot.0.lock().unwrap() = Some(addr);
            }
            Ok(io)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_util::client::legacy::connect::HttpConnector;
    use tower::ServiceExt;

    #[tokio::test]
    async fn records_the_address_it_connected_to() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connector, slot) = RecordPeer::new(HttpConnector::new());
        assert_eq!(slot.get(), None);
        let uri: Uri = format!("http://{addr}/").parse().unwrap();
        connector.oneshot(uri).await.unwrap();
        assert_eq!(slot.get(), Some(addr));
    }

    #[tokio::test]
    async fn records_nothing_when_the_connection_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (connector, slot) = RecordPeer::new(HttpConnector::new());
        let uri: Uri = format!("http://{addr}/").parse().unwrap();
        assert!(connector.oneshot(uri).await.is_err());
        assert_eq!(slot.get(), None);
    }
}
