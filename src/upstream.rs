//! Sending a request upstream, shared by the proxy, replay and send: the
//! host is resolved once, the connection goes only to the addresses that
//! were checked (so a name can't answer differently the second time), and
//! the address actually connected to is recorded.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use crate::peer::{PeerSlot, RecordPeer};

/// Every address `uri`'s host resolves to, on its port.
pub async fn resolve(uri: &hyper::Uri) -> std::io::Result<Vec<SocketAddr>> {
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    resolve_host(uri.host().unwrap_or_default(), port).await
}

/// Every address `host` (a name, or an IP literal, bracketed or not)
/// resolves to, on `port`.
pub async fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    #[cfg(test)]
    if let Some(ips) = TEST_DNS.lock().unwrap().get(host) {
        return Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::other(format!("{host} has no addresses")));
    }
    Ok(addrs)
}

/// Whether connecting to `target` would reach one of `own` (taphttp's
/// bound listeners). A listener on `0.0.0.0` / `::` is reached through any
/// address of this host, which `is_local` decides.
pub fn is_own_target(
    target: SocketAddr,
    own: &[SocketAddr],
    is_local: impl Fn(IpAddr) -> bool,
) -> bool {
    let t = target.ip().to_canonical();
    own.iter().any(|o| {
        let l = o.ip().to_canonical();
        o.port() == target.port()
            && (t == l
                || (l.is_unspecified() && (t.is_unspecified() || is_local(t)))
                || (t.is_unspecified() && is_local(l)))
    })
}

/// Whether `ip` is an address of this host: loopback, unspecified (which
/// connects locally), or one a socket can bind to.
pub fn is_local_ip(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback()
        || ip.is_unspecified()
        || std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// A resolver that answers with addresses already looked up and checked.
#[derive(Clone)]
struct Pinned(Arc<Vec<SocketAddr>>);

impl tower::Service<Name> for Pinned {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<std::io::Result<Self::Response>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Name) -> Self::Future {
        std::future::ready(Ok(Vec::clone(&self.0).into_iter()))
    }
}

/// Upstream TLS: the webpki roots, built once.
fn tls_config() -> rustls::ClientConfig {
    static ROOTS: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    let roots = ROOTS
        .get_or_init(|| {
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(store)
        })
        .clone();
    #[cfg(test)]
    let roots = {
        let mut with_test = (*roots).clone();
        for c in TEST_ROOTS.lock().unwrap().iter() {
            with_test.add(c.clone()).unwrap();
        }
        Arc::new(with_test)
    };
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Names tests resolve themselves (e.g. one that "rebinds" between lookups).
#[cfg(test)]
pub static TEST_DNS: std::sync::Mutex<std::collections::BTreeMap<String, Vec<IpAddr>>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Extra upstream roots for tests that need a TLS upstream taphttp trusts.
#[cfg(test)]
pub static TEST_ROOTS: std::sync::Mutex<Vec<rustls::pki_types::CertificateDer<'static>>> =
    std::sync::Mutex::new(Vec::new());

/// Send `req` (`http` or `https`) over a fresh connection to one of
/// `addrs`, which must be non-empty. The slot says which address it
/// connected to, if any; it is set even when TLS or the response fails.
pub async fn request(
    req: Request<Full<Bytes>>,
    addrs: Vec<SocketAddr>,
) -> (
    Result<Response<Incoming>, hyper_util::client::legacy::Error>,
    PeerSlot,
) {
    let mut http = HttpConnector::new_with_resolver(Pinned(Arc::new(addrs)));
    http.enforce_http(false);
    let (http, peer) = RecordPeer::new(http);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config())
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    (client.request(req).await, peer)
}

/// `e: its source: …`, since hyper's top-level messages are vague
/// ("client error (Connect)").
pub fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut next = e.source();
    while let Some(cause) = next {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        next = cause.source();
    }
    out
}
