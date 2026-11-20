use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::ca::Ca;
use crate::cli::StartArgs;
use crate::intercept::{self, Decision, InterceptEvent, RequestEvent, ResponseEvent};
use crate::storage::{Headers, Store, TrafficEntry};
use taphttp_types::{encode_body, header_value_to_string};

#[derive(Clone)]
struct ProxyConfig {
    filter_host: Option<String>,
    intercept_socket: Option<PathBuf>,
}

pub async fn run(args: StartArgs, data_dir: PathBuf) -> Result<()> {
    let ca = Arc::new(Ca::load_or_create(&data_dir)?);
    let store = Store::new(&data_dir, args.log_file.as_deref(), args.sqlite)?;
    let addr: SocketAddr = args.listen.parse().context("invalid listen address")?;
    let listener = TcpListener::bind(addr).await.context("binding listener")?;

    // Optionally serve the lever API alongside the proxy, sharing the same
    // live Store so its /feed carries real traffic as it is recorded.
    if let Some(api_listen) = &args.api_listen {
        let api_addr: SocketAddr = api_listen.parse().context("invalid api-listen address")?;
        let token = crate::api::generate_token();
        let token_path = crate::api::write_token_file(&data_dir, &token)?;
        eprintln!("lever API token: {token}");
        eprintln!("  (also written to {}, mode 0600)", token_path.display());
        let state = Arc::new(crate::api::ApiState {
            store: store.clone(),
            log_path: args.log_file.clone(),
            token,
        });
        tokio::spawn(async move {
            if let Err(e) = crate::api::serve(state, api_addr).await {
                tracing::error!("lever API exited: {e}");
            }
        });
    }

    serve(listener, ca, store, args.filter_host, args.intercept_socket).await
}

pub async fn serve(
    listener: TcpListener,
    ca: Arc<Ca>,
    store: Arc<Store>,
    filter_host: Option<String>,
    intercept_socket: Option<PathBuf>,
) -> Result<()> {
    let addr = listener.local_addr()?;
    let config = Arc::new(ProxyConfig { filter_host, intercept_socket });
    tracing::info!("taphttp listening on {}", addr);
    eprintln!("taphttp listening on {addr}");
    eprintln!("Configure your HTTP client to use proxy http://{addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let ca = ca.clone();
        let store = store.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, ca, store, config).await {
                tracing::debug!("connection error from {peer}: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<()> {
    let io = hyper_util::rt::TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let ca = ca.clone();
                let store = store.clone();
                let config = config.clone();
                async move { dispatch(req, peer, ca, store, config).await }
            }),
        )
        .with_upgrades()
        .await
        .context("serving http1 connection")
}

async fn dispatch(
    req: Request<Incoming>,
    _peer: SocketAddr,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    if req.method() == hyper::Method::CONNECT {
        handle_connect(req, ca, store, config).await
    } else {
        handle_http(req, store, config).await
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let host_port = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&host_port)
        .to_string();

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = mitm_tls(upgraded, host, host_port, ca, store, config).await {
                    tracing::debug!("mitm error: {e}");
                }
            }
            Err(e) => tracing::debug!("upgrade error: {e}"),
        }
    });

    Ok(Response::new(Full::new(Bytes::new())))
}

async fn mitm_tls(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    host_port: String,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<()> {
    let server_cfg = ca
        .server_config_for(&host)
        .await
        .context("getting server config")?;

    let acceptor = TlsAcceptor::from(server_cfg);
    let tls_stream = acceptor
        .accept(hyper_util::rt::TokioIo::new(upgraded))
        .await
        .context("TLS accept")?;

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let host_clone = host.clone();
    let host_port_clone = host_port.clone();

    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |mut req: Request<Incoming>| {
                let host = host_clone.clone();
                let host_port = host_port_clone.clone();
                let store = store.clone();
                let config = config.clone();
                async move {
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/");
                    let full_url = format!("https://{host_port}{path}");
                    *req.uri_mut() = full_url.parse()?;
                    forward_https(req, host, store, config).await
                }
            }),
        )
        .await
        .context("serving mitm https")
}

async fn forward_https(
    req: Request<Incoming>,
    host: String,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    if let Some(f) = &config.filter_host {
        if !host.contains(f.as_str()) {
            return passthrough_https(req).await;
        }
    }

    let id = Uuid::new_v4().to_string();
    let mut method = req.method().to_string();
    let mut url = req.uri().to_string();
    let mut req_headers = collect_headers(req.headers());

    let (_, body) = req.into_parts();
    let mut req_body_bytes = body.collect().await?.to_bytes();

    // --- intercept request ---
    if let Some(socket) = &config.intercept_socket {
        let event = InterceptEvent::Request(RequestEvent {
            id: id.clone(),
            method: method.clone(),
            url: url.clone(),
            headers: intercept_header_map(&req_headers),
            body: maybe_utf8(&req_body_bytes),
        });
        match intercept::pause(socket, &event).await {
            Ok(Decision::Forward(mods)) => {
                apply_request_mods(
                    &mut method,
                    &mut url,
                    &mut req_headers,
                    &mut req_body_bytes,
                    mods,
                );
            }
            Ok(Decision::Drop(d)) => return make_drop_response(d.status.unwrap_or(403), d.body),
            Err(e) => {
                tracing::warn!("intercept error on request: {e}");
                return make_drop_response(502, Some("intercept unavailable".into()));
            }
        }
    }

    let start = Instant::now();
    let upstream_req =
        build_upstream_request(&method, &url, &req_headers, req_body_bytes.clone())?;
    let res = send_https(upstream_req).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    let (mut status, mut res_headers, mut res_body_bytes) = match res {
        Ok(r) => {
            let s = r.status().as_u16();
            let h = collect_headers(r.headers());
            let b = r.into_body().collect().await?.to_bytes();
            (Some(s), h, b)
        }
        Err(e) => {
            tracing::debug!("upstream error: {e}");
            (None, Headers::new(), Bytes::new())
        }
    };

    // --- intercept response ---
    if let Some(socket) = &config.intercept_socket {
        if let Some(s) = status {
            let event = InterceptEvent::Response(ResponseEvent {
                id: Uuid::new_v4().to_string(),
                request_id: id.clone(),
                status: s,
                headers: intercept_header_map(&res_headers),
                body: maybe_utf8(&res_body_bytes),
            });
            match intercept::pause(socket, &event).await {
                Ok(Decision::Forward(mods)) => {
                    apply_response_mods(&mut status, &mut res_headers, &mut res_body_bytes, mods);
                }
                Ok(Decision::Drop(d)) => {
                    return make_drop_response(d.status.unwrap_or(502), d.body);
                }
                Err(e) => {
                    tracing::warn!("intercept error on response: {e}");
                    return make_drop_response(502, Some("intercept unavailable".into()));
                }
            }
        }
    }

    let (req_body, req_body_encoding) = encode_body(&req_body_bytes);
    let (res_body, res_body_encoding) = encode_body(&res_body_bytes);
    let entry = TrafficEntry {
        id,
        ts: Utc::now(),
        host: host.clone(),
        method,
        url,
        req_headers,
        req_body,
        req_body_encoding,
        status,
        res_headers,
        res_body,
        res_body_encoding,
        duration_ms: Some(duration_ms),
        replay_of: None,
    };

    tracing::info!(
        "{} {} {} {}ms",
        entry.method,
        entry.url,
        entry.status.map(|s| s.to_string()).unwrap_or_else(|| "ERR".to_string()),
        duration_ms
    );

    store.record(entry);

    let status = status.unwrap_or(502);
    Ok(Response::builder()
        .status(status)
        .body(Full::new(res_body_bytes))
        .unwrap())
}

async fn passthrough_https(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let url = req.uri().to_string();
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let upstream = rebuild_request(&parts, body_bytes, &url)?;
    let res = send_https(upstream).await?;
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await?.to_bytes();
    let mut builder = Response::builder().status(status);
    for (k, v) in &headers {
        builder = builder.header(k, v);
    }
    Ok(builder.body(Full::new(body)).unwrap())
}

async fn send_https(req: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build::<_, Full<Bytes>>(https);
    client.request(req).await.context("https upstream request")
}

async fn handle_http(
    req: Request<Incoming>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let host = req.uri().host().unwrap_or("").to_string();

    if let Some(f) = &config.filter_host {
        if !host.contains(f.as_str()) {
            return forward_http_raw(req).await;
        }
    }

    let id = Uuid::new_v4().to_string();
    let mut method = req.method().to_string();
    let mut url = req.uri().to_string();
    let mut req_headers = collect_headers(req.headers());

    let (_, body) = req.into_parts();
    let mut req_body_bytes = body.collect().await?.to_bytes();

    // --- intercept request ---
    if let Some(socket) = &config.intercept_socket {
        let event = InterceptEvent::Request(RequestEvent {
            id: id.clone(),
            method: method.clone(),
            url: url.clone(),
            headers: intercept_header_map(&req_headers),
            body: maybe_utf8(&req_body_bytes),
        });
        match intercept::pause(socket, &event).await {
            Ok(Decision::Forward(mods)) => {
                apply_request_mods(
                    &mut method,
                    &mut url,
                    &mut req_headers,
                    &mut req_body_bytes,
                    mods,
                );
            }
            Ok(Decision::Drop(d)) => return make_drop_response(d.status.unwrap_or(403), d.body),
            Err(e) => {
                tracing::warn!("intercept error on request: {e}");
                return make_drop_response(502, Some("intercept unavailable".into()));
            }
        }
    }

    let start = Instant::now();
    let upstream_req =
        build_upstream_request(&method, &url, &req_headers, req_body_bytes.clone())?;
    let res = forward_http_request(upstream_req).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    let (mut status, mut res_headers, mut res_body_bytes) = match res {
        Ok(r) => {
            let s = r.status().as_u16();
            let h = collect_headers(r.headers());
            let b = r.into_body().collect().await?.to_bytes();
            (Some(s), h, b)
        }
        Err(e) => {
            tracing::debug!("http upstream error: {e}");
            (None, Headers::new(), Bytes::new())
        }
    };

    // --- intercept response ---
    if let Some(socket) = &config.intercept_socket {
        if let Some(s) = status {
            let event = InterceptEvent::Response(ResponseEvent {
                id: Uuid::new_v4().to_string(),
                request_id: id.clone(),
                status: s,
                headers: intercept_header_map(&res_headers),
                body: maybe_utf8(&res_body_bytes),
            });
            match intercept::pause(socket, &event).await {
                Ok(Decision::Forward(mods)) => {
                    apply_response_mods(&mut status, &mut res_headers, &mut res_body_bytes, mods);
                }
                Ok(Decision::Drop(d)) => {
                    return make_drop_response(d.status.unwrap_or(502), d.body);
                }
                Err(e) => {
                    tracing::warn!("intercept error on response: {e}");
                    return make_drop_response(502, Some("intercept unavailable".into()));
                }
            }
        }
    }

    let (req_body, req_body_encoding) = encode_body(&req_body_bytes);
    let (res_body, res_body_encoding) = encode_body(&res_body_bytes);
    let entry = TrafficEntry {
        id,
        ts: Utc::now(),
        host: host.clone(),
        method,
        url,
        req_headers,
        req_body,
        req_body_encoding,
        status,
        res_headers,
        res_body,
        res_body_encoding,
        duration_ms: Some(duration_ms),
        replay_of: None,
    };

    tracing::info!(
        "{} {} {} {}ms",
        entry.method,
        entry.url,
        entry.status.map(|s| s.to_string()).unwrap_or_else(|| "ERR".to_string()),
        duration_ms
    );

    store.record(entry);

    let status = status.unwrap_or(502);
    Ok(Response::builder()
        .status(status)
        .body(Full::new(res_body_bytes))
        .unwrap())
}

async fn forward_http_raw(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let url = req.uri().to_string();
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let upstream = rebuild_request(&parts, body_bytes, &url)?;
    let res = forward_http_request(upstream).await?;
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await?.to_bytes();
    let mut builder = Response::builder().status(status);
    for (k, v) in &headers {
        builder = builder.header(k, v);
    }
    Ok(builder.body(Full::new(body)).unwrap())
}

async fn forward_http_request(req: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build::<_, Full<Bytes>>(connector);
    client.request(req).await.context("http upstream request")
}

fn build_upstream_request(
    method: &str,
    url: &str,
    headers: &Headers,
    body: Bytes,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(url.parse::<hyper::Uri>()?);
    // `header` appends, so repeated headers go upstream as captured.
    for (k, v) in headers.iter() {
        if !k.eq_ignore_ascii_case("host") && !k.eq_ignore_ascii_case("proxy-connection") {
            builder = builder.header(k, v);
        }
    }
    Ok(builder.body(Full::new(body))?)
}

fn rebuild_request(
    parts: &hyper::http::request::Parts,
    body: Bytes,
    url: &str,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(url.parse::<hyper::Uri>()?);
    for (k, v) in &parts.headers {
        if k != hyper::header::HOST && k != "proxy-connection" {
            builder = builder.header(k, v);
        }
    }
    Ok(builder.body(Full::new(body))?)
}

fn apply_request_mods(
    method: &mut String,
    url: &mut String,
    headers: &mut Headers,
    body_bytes: &mut Bytes,
    mods: crate::intercept::ForwardDecision,
) {
    if let Some(m) = mods.method { *method = m; }
    if let Some(u) = mods.url { *url = u; }
    if let Some(h) = mods.headers { *headers = h.into_iter().collect(); }
    if let Some(b) = mods.body { *body_bytes = Bytes::from(b.into_bytes()); }
}

fn apply_response_mods(
    status: &mut Option<u16>,
    headers: &mut Headers,
    body_bytes: &mut Bytes,
    mods: crate::intercept::ForwardDecision,
) {
    if let Some(s) = mods.status { *status = Some(s); }
    if let Some(h) = mods.headers { *headers = h.into_iter().collect(); }
    if let Some(b) = mods.body { *body_bytes = Bytes::from(b.into_bytes()); }
}

fn make_drop_response(status: u16, body: Option<String>) -> Result<Response<Full<Bytes>>> {
    let body_bytes = body
        .map(|b| Bytes::from(b.into_bytes()))
        .unwrap_or_default();
    Ok(Response::builder()
        .status(status)
        .body(Full::new(body_bytes))
        .unwrap())
}

/// Every header in wire order, repeated names included. Values that are not
/// valid UTF-8 are kept lossily rather than dropped.
pub(crate) fn collect_headers(headers: &hyper::HeaderMap) -> Headers {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), header_value_to_string(v.as_bytes())))
        .collect()
}

/// The intercept-socket protocol still carries headers as a `{name: value}`
/// map. Repeated names are joined with ", " (RFC 9110 field combining) so a
/// hook sees every value; Set-Cookie is joined too, which is lossy only if
/// the hook writes the map back.
fn intercept_header_map(headers: &Headers) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for (k, v) in headers.iter() {
        map.entry(k.to_string())
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(v);
            })
            .or_insert_with(|| v.to_string());
    }
    map
}

/// Body as text for the intercept-socket protocol, which is string-only.
/// The traffic log uses `encode_body` instead, which is byte-exact.
fn maybe_utf8(b: &Bytes) -> Option<String> {
    if b.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(b).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;
    use crate::storage::{Store, TrafficEntry};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream, UnixListener};

    // --- unit tests ---

    #[test]
    fn maybe_utf8_empty_is_none() {
        assert_eq!(maybe_utf8(&Bytes::new()), None);
    }

    #[test]
    fn maybe_utf8_valid_string() {
        assert_eq!(
            maybe_utf8(&Bytes::from("hello")),
            Some("hello".to_string())
        );
    }

    #[test]
    fn maybe_utf8_invalid_bytes_returns_lossy_string() {
        let result = maybe_utf8(&Bytes::from(vec![0xFF, 0xFE, 0x00]));
        assert!(result.is_some());
    }

    #[test]
    fn collect_headers_basic() {
        let mut map = hyper::HeaderMap::new();
        map.insert(
            hyper::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        map.insert(hyper::header::ACCEPT, "*/*".parse().unwrap());
        let collected = collect_headers(&map);
        assert_eq!(collected.get("content-type"), Some("application/json"));
        assert_eq!(collected.get("accept"), Some("*/*"));
    }

    #[test]
    fn collect_headers_keeps_repeated_values_in_order() {
        let mut map = hyper::HeaderMap::new();
        map.append(hyper::header::SET_COOKIE, "a=1".parse().unwrap());
        map.append(hyper::header::SET_COOKIE, "b=2".parse().unwrap());
        let collected = collect_headers(&map);
        assert_eq!(collected.get_all("set-cookie").collect::<Vec<_>>(), ["a=1", "b=2"]);
    }

    #[test]
    fn collect_headers_keeps_non_utf8_values() {
        let mut map = hyper::HeaderMap::new();
        map.insert("x-odd", hyper::header::HeaderValue::from_bytes(b"caf\xe9").unwrap());
        let v = collect_headers(&map).get("x-odd").unwrap().to_string();
        assert!(v.starts_with("caf") && v.len() > 3, "got {v:?}");
    }

    #[test]
    fn build_upstream_request_sends_repeated_headers() {
        let h: Headers = [("x-multi", "one"), ("host", "h"), ("x-multi", "two")].into_iter().collect();
        let req = build_upstream_request("GET", "http://h/", &h, Bytes::new()).unwrap();
        let vals: Vec<_> = req.headers().get_all("x-multi").iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(vals, ["one", "two"]);
        assert!(!req.headers().contains_key("host"));
    }

    #[test]
    fn intercept_header_map_joins_repeated_values() {
        let h: Headers = [("a", "1"), ("b", "x"), ("a", "2")].into_iter().collect();
        let m = intercept_header_map(&h);
        assert_eq!(m["a"], "1, 2");
        assert_eq!(m["b"], "x");
    }

    #[test]
    fn rebuild_request_strips_proxy_connection_header() {
        let original = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("proxy-connection", "keep-alive")
            .header("accept", "*/*")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (parts, body) = original.into_parts();
        let rebuilt = rebuild_request(&parts, Bytes::new(), "http://example.com/").unwrap();
        assert!(!rebuilt.headers().contains_key("proxy-connection"));
        assert!(rebuilt.headers().contains_key("accept"));
        drop(body);
    }

    // --- integration test helpers ---

    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(|_req: Request<Incoming>| async move {
                                Ok::<_, anyhow::Error>(Response::new(Full::new(Bytes::from(
                                    "echo-ok",
                                ))))
                            }),
                        )
                        .await
                        .ok();
                });
            }
        });
        port
    }

    /// Start a mock Unix socket interceptor that replies with the given decisions in order,
    /// one per connection (one connection per intercepted event).
    async fn start_mock_interceptor(socket_path: PathBuf, decisions: Vec<&'static str>) {
        let listener = UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            for decision in decisions {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (reader, mut writer) = tokio::io::split(stream);
                    let mut reader = BufReader::new(reader);
                    let mut _line = String::new();
                    reader.read_line(&mut _line).await.ok();
                    writer.write_all(decision.as_bytes()).await.ok();
                    writer.write_all(b"\n").await.ok();
                });
            }
        });
    }

    async fn send_http_through_proxy(proxy_port: u16, echo_port: u16, path: &str) -> String {
        let target_url = format!("http://127.0.0.1:{echo_port}{path}");
        let raw = format!(
            "GET {target_url} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\nConnection: close\r\n\r\n"
        );
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn start_proxy(
        data_dir: &std::path::Path,
        log_file: &std::path::Path,
        intercept_socket: Option<PathBuf>,
    ) -> u16 {
        let ca = Arc::new(Ca::load_or_create(data_dir).unwrap());
        let store = Store::new(data_dir, Some(log_file), false).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy_listener.local_addr().unwrap().port();
        tokio::spawn(serve(proxy_listener, ca, store, None, intercept_socket));
        tokio::time::sleep(Duration::from_millis(20)).await;
        port
    }

    // --- proxy integration tests (no intercept) ---

    #[tokio::test]
    async fn http_proxy_records_request_in_log() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let proxy_port = start_proxy(dir.path(), &log_file, None).await;

        let response = send_http_through_proxy(proxy_port, echo_port, "/probe").await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200, got: {response}"
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        let content = std::fs::read_to_string(&log_file).expect("traffic.jsonl should exist");
        let entry: TrafficEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.status, Some(200));
        assert!(entry.url.contains("/probe"), "url was: {}", entry.url);
        assert!(entry.duration_ms.is_some());
    }

    /// Upstream that answers with two Set-Cookie headers, a header value that
    /// is not valid UTF-8, and a binary body; it echoes nothing. Raw TCP so
    /// the bytes on the wire are exactly what the test says.
    async fn start_awkward_upstream() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let mut res: Vec<u8> = b"HTTP/1.1 200 OK\r\n\
                set-cookie: session=abc; Secure; HttpOnly\r\n\
                set-cookie: theme=dark; SameSite=Lax\r\n\
                x-odd: caf\xe9\r\n\
                content-length: 6\r\n\
                connection: close\r\n\r\n"
                .to_vec();
            res.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x00, 0xff]);
            stream.write_all(&res).await.ok();
        });
        port
    }

    #[tokio::test]
    async fn proxy_log_keeps_repeated_headers_odd_values_and_binary_bodies() {
        let up = start_awkward_upstream().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let proxy_port = start_proxy(dir.path(), &log_file, None).await;

        let req_body: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0xfe];
        let mut raw = format!(
            "POST http://127.0.0.1:{up}/bin HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\n\
             x-multi: one\r\nx-multi: two\r\ncontent-length: {}\r\nConnection: close\r\n\r\n",
            req_body.len()
        )
        .into_bytes();
        raw.extend_from_slice(req_body);
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
        stream.write_all(&raw).await.unwrap();
        let mut sink = Vec::new();
        stream.read_to_end(&mut sink).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let line = std::fs::read_to_string(&log_file).unwrap();
        let entry: TrafficEntry = serde_json::from_str(line.lines().next().unwrap()).unwrap();

        assert_eq!(
            entry.res_headers.get_all("set-cookie").collect::<Vec<_>>(),
            ["session=abc; Secure; HttpOnly", "theme=dark; SameSite=Lax"],
            "every Set-Cookie must be logged, in order"
        );
        assert_eq!(entry.req_headers.get_all("x-multi").collect::<Vec<_>>(), ["one", "two"]);
        let odd = entry.res_headers.get("x-odd").unwrap();
        assert!(odd.starts_with("caf") && odd.len() > 3, "non-UTF-8 value kept, got {odd:?}");
        assert_eq!(entry.req_body_bytes().unwrap().as_deref(), Some(req_body));
        assert_eq!(
            entry.res_body_bytes().unwrap().as_deref(),
            Some(&[0x89, b'P', b'N', b'G', 0x00, 0xff][..]),
            "binary response body must be byte-exact"
        );
    }

    #[tokio::test]
    async fn http_proxy_filter_host_skips_unmatched() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");

        let ca = Arc::new(Ca::load_or_create(dir.path()).unwrap());
        let store = Store::new(dir.path(), Some(&log_file), false).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        tokio::spawn(serve(
            proxy_listener,
            ca,
            store,
            Some("only-this-host.example".to_string()),
            None,
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;

        send_http_through_proxy(proxy_port, echo_port, "/nolog").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !log_file.exists(),
            "log file should not exist when filter doesn't match"
        );
    }

    // --- intercept integration tests ---

    #[tokio::test]
    async fn intercept_request_drop_returns_configured_status() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        // Decision: drop the request before it reaches the server
        start_mock_interceptor(socket_path.clone(), vec![r#"{"action":"drop","status":403}"#])
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/secret").await;

        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 from drop, got: {response}"
        );
        // Nothing should reach the echo server, so no 200 log entry
        tokio::time::sleep(Duration::from_millis(50)).await;
        if log_file.exists() {
            let content = std::fs::read_to_string(&log_file).unwrap();
            let entry: TrafficEntry =
                serde_json::from_str(content.lines().next().unwrap()).unwrap();
            // If logged, status must NOT be 200 (request was dropped before upstream)
            assert_ne!(entry.status, Some(200));
        }
    }

    #[tokio::test]
    async fn intercept_response_drop_returns_configured_status() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        // Two events: forward the request, drop the response
        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward"}"#,
                r#"{"action":"drop","status":502,"body":"blocked"}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/anything").await;

        assert!(
            response.starts_with("HTTP/1.1 502"),
            "expected 502 from dropped response, got: {response}"
        );
        assert!(response.ends_with("blocked"), "expected body 'blocked'");
    }

    #[tokio::test]
    async fn intercept_request_forward_reaches_upstream() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        // Forward request, forward response
        start_mock_interceptor(
            socket_path.clone(),
            vec![r#"{"action":"forward"}"#, r#"{"action":"forward"}"#],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/pass").await;

        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200, got: {response}"
        );
    }

    #[tokio::test]
    async fn intercept_response_body_modification_reaches_client() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward"}"#,
                r#"{"action":"forward","body":"injected-body"}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/modify").await;

        assert!(
            response.contains("injected-body"),
            "expected injected body in response, got: {response}"
        );
    }
}
