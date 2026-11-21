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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::ca::Ca;
use crate::cli::StartArgs;
use crate::deploy::{self, Cidr, Exposure, ProxyCredentials};
use crate::intercept::{self, Decision, InterceptEvent, RequestEvent, ResponseEvent};
use crate::storage::{Headers, Store, TrafficEntry};
use taphttp_types::{encode_body, header_value_to_string};

/// How the proxy listener behaves. `Default` is today's local proxy: no
/// filter, no intercept, no access control, no expiry, plaintext.
#[derive(Default)]
pub struct ProxyConfig {
    pub filter_host: Option<String>,
    pub intercept_socket: Option<PathBuf>,
    /// Source-IP allowlist; empty allows everyone.
    pub allow_clients: Vec<Cidr>,
    /// When set, every client must present one of these (Basic), and the
    /// username becomes each exchange's verified `source`.
    pub credentials: Option<ProxyCredentials>,
    /// After this, requests are refused (and `run` exits).
    pub expires: Option<chrono::DateTime<Utc>>,
    /// TLS on the proxy listener itself (an HTTPS proxy), so proxy
    /// credentials aren't cleartext on the network.
    pub tls: Option<Arc<rustls::ServerConfig>>,
}

impl ProxyConfig {
    fn expired(&self) -> bool {
        self.expires.is_some_and(|t| Utc::now() >= t)
    }
}

/// The sqlite database to record into, if any: with `--sqlite`, or with
/// `--api-listen`, which serves history from it. `--db` only says where, so
/// it can be set as an environment default (as the Docker image does).
fn sqlite_path(args: &StartArgs, data_dir: &std::path::Path) -> Option<PathBuf> {
    let wanted = args.sqlite || args.api_listen.is_some();
    wanted.then(|| args.db.clone().unwrap_or_else(|| data_dir.join("traffic.db")))
}

/// SANs for taphttp's own listener certs: every `--tls-name`, plus each
/// listener's IP when it's a specific address (not 0.0.0.0 / ::).
fn tls_names(names: &[String], listeners: &[Option<SocketAddr>]) -> Result<Vec<String>> {
    let mut out: Vec<String> = names.to_vec();
    for addr in listeners.iter().flatten() {
        if !addr.ip().is_unspecified() {
            out.push(addr.ip().to_string());
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        anyhow::bail!(
            "TLS on a wildcard address needs the name clients will connect to: pass \
             --tls-name <host-or-ip> (repeatable)"
        );
    }
    Ok(out)
}

pub async fn run(args: StartArgs, data_dir: PathBuf) -> Result<()> {
    // Decide what may be exposed before binding anything.
    let addr: SocketAddr = args.listen.parse().context("invalid listen address")?;
    let api_addr: Option<SocketAddr> = args
        .api_listen
        .as_deref()
        .map(|a| a.parse().context("invalid api-listen address"))
        .transpose()?;
    let credentials =
        ProxyCredentials::load(args.proxy_auth_file.as_deref(), std::env::var("TAPHTTP_PROXY_AUTH").ok())?;
    let allow_clients = args
        .allow_client
        .iter()
        .map(|c| c.parse())
        .collect::<Result<Vec<Cidr>>>()?;
    let expires = args
        .expires
        .as_deref()
        .map(|e| deploy::parse_expires(e, Utc::now()))
        .transpose()?;
    let exposure = Exposure {
        proxy: Some(addr),
        proxy_tls: args.proxy_tls,
        proxy_auth: credentials.is_some(),
        allow_open_proxy: args.allow_open_proxy,
        api: api_addr,
        api_tls: args.api_tls,
        api_allow_plaintext: args.api_allow_plaintext,
    };
    deploy::check_exposure(&exposure)?;
    let names = if args.proxy_tls || args.api_tls {
        tls_names(&args.tls_name, &[args.proxy_tls.then_some(addr), api_addr.filter(|_| args.api_tls)])?
    } else {
        Vec::new()
    };

    let ca = Arc::new(Ca::load_or_create(&data_dir)?);
    let listener_tls = if names.is_empty() { None } else { Some(ca.listener_tls_config(&names)?) };

    let info = deploy::BannerInfo {
        exposure,
        allow_clients: allow_clients.clone(),
        proxy_users: credentials.as_ref().map_or(0, |c| c.len()),
        expires,
        ca_fingerprint: ca.fingerprint_sha256(),
    };
    let banner = deploy::banner(&info);
    eprintln!("{banner}");
    if !names.is_empty() {
        eprintln!("  TLS names: {}", names.join(", "));
    }
    tracing::info!("{}", banner.replace('\n', " |"));

    if let Some(at) = expires {
        tokio::spawn(async move {
            let wait = (at - Utc::now()).to_std().unwrap_or_default();
            tokio::time::sleep(wait).await;
            eprintln!("taphttp: deployment expired at {}; exiting", at.to_rfc3339());
            tracing::warn!("deployment expired at {}; exiting", at.to_rfc3339());
            std::process::exit(0);
        });
    }

    let db = sqlite_path(&args, &data_dir);
    if let Some(db) = &db {
        eprintln!("recording to sqlite at {}", db.display());
    }
    let store = Store::new(args.log_file.as_deref(), db.as_deref())?;
    let listener = TcpListener::bind(addr).await.context("binding listener")?;

    // Optionally serve the lever API alongside the proxy, sharing the same
    // live Store so its /feed carries real traffic as it is recorded.
    if let Some(api_addr) = api_addr {
        let token = match &args.api_token_file {
            // From a file: print only where it is, so it stays out of logs.
            Some(path) => {
                let token = crate::api::load_or_create_token_file(path)?;
                eprintln!("lever API token: in {}", path.display());
                token
            }
            None => {
                let token = crate::api::generate_token();
                let token_path = crate::api::write_token_file(&data_dir, &token)?;
                eprintln!("lever API token: {token}");
                eprintln!("  (also written to {}, mode 0600)", token_path.display());
                token
            }
        };
        let state = Arc::new(crate::api::ApiState { store: store.clone(), token });
        let api_tls = if args.api_tls { listener_tls.clone() } else { None };
        tokio::spawn(async move {
            if let Err(e) = crate::api::serve(state, api_addr, api_tls).await {
                tracing::error!("lever API exited: {e}");
            }
        });
    }

    let config = ProxyConfig {
        filter_host: args.filter_host,
        intercept_socket: args.intercept_socket,
        allow_clients,
        credentials,
        expires,
        tls: if args.proxy_tls { listener_tls } else { None },
    };
    serve(listener, ca, store, config).await
}

pub async fn serve(listener: TcpListener, ca: Arc<Ca>, store: Arc<Store>, config: ProxyConfig) -> Result<()> {
    let addr = listener.local_addr()?;
    let scheme = if config.tls.is_some() { "https" } else { "http" };
    let acceptor = config.tls.clone().map(TlsAcceptor::from);
    let config = Arc::new(config);
    tracing::info!("taphttp listening on {}", addr);
    eprintln!("taphttp listening on {addr}");
    eprintln!("Configure your HTTP client to use proxy {scheme}://{addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        if !deploy::client_allowed(&config.allow_clients, peer.ip()) {
            // Close without a byte: a stranger learns nothing.
            tracing::warn!("refused proxy client {peer}: not in --allow-client");
            drop(stream);
            continue;
        }
        let ca = ca.clone();
        let store = store.clone();
        let config = config.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let result = match acceptor {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls) => handle_connection(tls, ca, store, config).await,
                    Err(e) => Err(anyhow::Error::from(e).context("proxy listener TLS handshake")),
                },
                None => handle_connection(stream, ca, store, config).await,
            };
            if let Err(e) = result {
                tracing::debug!("connection error from {peer}: {e:#}");
            }
        });
    }
}

async fn handle_connection<IO>(stream: IO, ca: Arc<Ca>, store: Arc<Store>, config: Arc<ProxyConfig>) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = hyper_util::rt::TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let ca = ca.clone();
                let store = store.clone();
                let config = config.clone();
                async move { dispatch(req, ca, store, config).await }
            }),
        )
        .with_upgrades()
        .await
        .context("serving http1 connection")
}

async fn dispatch(
    req: Request<Incoming>,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    if config.expired() {
        return make_drop_response(503, Some("taphttp: this deployment has expired".into()));
    }
    // For HTTPS this is the CONNECT, which is where clients send proxy auth;
    // the source then applies to every request in that tunnel.
    let header = req.headers().get(hyper::header::PROXY_AUTHORIZATION).map(|v| v.as_bytes());
    let source = match deploy::authorize(header, config.credentials.as_ref()) {
        Ok(source) => source,
        Err(deploy::AuthRequired) => return proxy_auth_required(),
    };
    if req.method() == hyper::Method::CONNECT {
        handle_connect(req, source, ca, store, config).await
    } else {
        handle_http(req, source, store, config).await
    }
}

fn proxy_auth_required() -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(407)
        .header(hyper::header::PROXY_AUTHENTICATE, r#"Basic realm="taphttp""#)
        .body(Full::new(Bytes::from_static(b"proxy authentication required")))?)
}

async fn handle_connect(
    req: Request<Incoming>,
    source: Option<String>,
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
                if let Err(e) = mitm_tls(upgraded, host, host_port, source, ca, store, config).await {
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
    source: Option<String>,
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
                let source = source.clone();
                let store = store.clone();
                let config = config.clone();
                async move {
                    // An open tunnel doesn't outlive the deployment.
                    if config.expired() {
                        return make_drop_response(503, Some("taphttp: this deployment has expired".into()));
                    }
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/");
                    let full_url = format!("https://{host_port}{path}");
                    *req.uri_mut() = full_url.parse()?;
                    forward_https(req, host, source, store, config).await
                }
            }),
        )
        .await
        .context("serving mitm https")
}

async fn forward_https(
    req: Request<Incoming>,
    host: String,
    source: Option<String>,
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
    // Proxy credentials are ours: never logged, never shown to an intercept
    // hook, never sent upstream.
    req_headers.remove("proxy-authorization");

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

    let (mut status, mut res_headers, mut res_raw_headers, mut res_body_bytes) = match res {
        Ok(r) => {
            let s = r.status().as_u16();
            let h = collect_headers(r.headers());
            let raw = r.headers().clone();
            let b = r.into_body().collect().await?.to_bytes();
            (Some(s), h, raw, b)
        }
        Err(e) => {
            tracing::debug!("upstream error: {e}");
            (None, Headers::new(), hyper::HeaderMap::new(), Bytes::new())
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
                    apply_response_mods(
                        &mut status,
                        &mut res_headers,
                        &mut res_raw_headers,
                        &mut res_body_bytes,
                        mods,
                    );
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
        source: source.clone(),
    };

    tracing::info!(
        "{} {} {} {}ms",
        entry.method,
        entry.url,
        entry.status.map(|s| s.to_string()).unwrap_or_else(|| "ERR".to_string()),
        duration_ms
    );

    store.record(entry);

    match status {
        Some(s) => client_response(s, &res_raw_headers, res_body_bytes),
        None => make_drop_response(502, None),
    }
}

async fn passthrough_https(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let url = req.uri().to_string();
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let upstream = rebuild_request(&parts, body_bytes, &url)?;
    let res = send_https(upstream).await?;
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await?.to_bytes();
    client_response(status, &headers, body)
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
    source: Option<String>,
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
    // Proxy credentials are ours: never logged, never shown to an intercept
    // hook, never sent upstream.
    req_headers.remove("proxy-authorization");

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

    let (mut status, mut res_headers, mut res_raw_headers, mut res_body_bytes) = match res {
        Ok(r) => {
            let s = r.status().as_u16();
            let h = collect_headers(r.headers());
            let raw = r.headers().clone();
            let b = r.into_body().collect().await?.to_bytes();
            (Some(s), h, raw, b)
        }
        Err(e) => {
            tracing::debug!("http upstream error: {e}");
            (None, Headers::new(), hyper::HeaderMap::new(), Bytes::new())
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
                    apply_response_mods(
                        &mut status,
                        &mut res_headers,
                        &mut res_raw_headers,
                        &mut res_body_bytes,
                        mods,
                    );
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
        source: source.clone(),
    };

    tracing::info!(
        "{} {} {} {}ms",
        entry.method,
        entry.url,
        entry.status.map(|s| s.to_string()).unwrap_or_else(|| "ERR".to_string()),
        duration_ms
    );

    store.record(entry);

    match status {
        Some(s) => client_response(s, &res_raw_headers, res_body_bytes),
        None => make_drop_response(502, None),
    }
}

async fn forward_http_raw(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let url = req.uri().to_string();
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let upstream = rebuild_request(&parts, body_bytes, &url)?;
    let res = forward_http_request(upstream).await?;
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await?.to_bytes();
    client_response(status, &headers, body)
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
        if !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("proxy-connection")
            && !k.eq_ignore_ascii_case("proxy-authorization")
        {
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
        if k != hyper::header::HOST && k != "proxy-connection" && k != hyper::header::PROXY_AUTHORIZATION {
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
    raw_headers: &mut hyper::HeaderMap,
    body_bytes: &mut Bytes,
    mods: crate::intercept::ForwardDecision,
) {
    if let Some(s) = mods.status { *status = Some(s); }
    if let Some(h) = mods.headers {
        *headers = h.into_iter().collect();
        *raw_headers = to_header_map(headers);
    }
    if let Some(b) = mods.body { *body_bytes = Bytes::from(b.into_bytes()); }
}

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1),
/// plus content-length, which hyper recomputes from the buffered body.
const NOT_FORWARDED: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The response the proxy sends back to its client: upstream's status and
/// headers (every repeated one, raw bytes) minus hop-by-hop and framing
/// headers, since the body has been buffered and is re-framed here.
fn client_response(status: u16, headers: &hyper::HeaderMap, body: Bytes) -> Result<Response<Full<Bytes>>> {
    // Headers named in Connection are hop-by-hop too.
    let named: Vec<String> = headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        let name = k.as_str();
        if NOT_FORWARDED.contains(&name) || name == "content-length" || named.iter().any(|n| n == name) {
            continue;
        }
        builder = builder.header(k, v);
    }
    Ok(builder.body(Full::new(body))?)
}

/// Build a sendable header map from string headers (an intercept hook's
/// override). Names or values hyper can't send are skipped, not fatal.
fn to_header_map(headers: &Headers) -> hyper::HeaderMap {
    let mut map = hyper::HeaderMap::new();
    for (k, v) in headers.iter() {
        let (Ok(name), Ok(value)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) else {
            tracing::debug!("skipping unsendable header {k:?}");
            continue;
        };
        map.append(name, value);
    }
    map
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

    fn start_args(sqlite: bool, db: Option<&str>, api: bool) -> StartArgs {
        StartArgs {
            listen: "127.0.0.1:0".into(),
            log_file: None,
            sqlite,
            db: db.map(PathBuf::from),
            filter_host: None,
            intercept_socket: None,
            api_listen: api.then(|| "127.0.0.1:0".into()),
            api_token_file: None,
            proxy_auth_file: None,
            allow_client: vec![],
            proxy_tls: false,
            api_tls: false,
            tls_name: vec![],
            allow_open_proxy: false,
            api_allow_plaintext: false,
            expires: None,
        }
    }

    #[test]
    fn sqlite_path_is_on_when_asked_for_or_when_the_api_needs_it() {
        let dd = std::path::Path::new("/dd");
        assert_eq!(sqlite_path(&start_args(false, None, false), dd), None);
        assert_eq!(sqlite_path(&start_args(true, None, false), dd), Some(PathBuf::from("/dd/traffic.db")));
        assert_eq!(sqlite_path(&start_args(false, None, true), dd), Some(PathBuf::from("/dd/traffic.db")));
        assert_eq!(sqlite_path(&start_args(false, Some("/data/t.db"), false), dd), None, "--db alone only sets the location");
        assert_eq!(sqlite_path(&start_args(true, Some("/data/t.db"), false), dd), Some(PathBuf::from("/data/t.db")));
        assert_eq!(sqlite_path(&start_args(true, Some("/data/t.db"), true), dd), Some(PathBuf::from("/data/t.db")));
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
        start_proxy_with(data_dir, log_file, ProxyConfig { intercept_socket, ..Default::default() }).await
    }

    async fn start_proxy_with(data_dir: &std::path::Path, log_file: &std::path::Path, config: ProxyConfig) -> u16 {
        // `main` does this; tests that do TLS need it too.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = Arc::new(Ca::load_or_create(data_dir).unwrap());
        let store = Store::new(Some(log_file), None).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy_listener.local_addr().unwrap().port();
        tokio::spawn(serve(proxy_listener, ca, store, config));
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

    /// Upstream that answers with a chunked body, two Set-Cookies and hop-by-hop
    /// headers, as a browser-facing app server would.
    async fn start_cookie_upstream() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let res = "HTTP/1.1 200 OK\r\n\
                content-type: text/html; charset=utf-8\r\n\
                set-cookie: session=abc; Secure; HttpOnly\r\n\
                set-cookie: theme=dark\r\n\
                keep-alive: timeout=5\r\n\
                transfer-encoding: chunked\r\n\
                connection: close\r\n\r\n\
                5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
            stream.write_all(res.as_bytes()).await.ok();
        });
        port
    }

    /// Send a GET through the proxy and parse the response with hyper, so
    /// framing errors (e.g. a stale transfer-encoding) fail the test.
    async fn get_through_proxy(proxy_port: u16, target: &str) -> (hyper::http::response::Parts, Bytes) {
        let stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        let req = Request::get(target)
            .header("host", "upstream")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = sender.send_request(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let body = tokio::time::timeout(Duration::from_secs(5), body.collect())
            .await
            .expect("body must be framed so the client can finish reading it")
            .unwrap()
            .to_bytes();
        (parts, body)
    }

    #[tokio::test]
    async fn http_proxy_forwards_response_headers_to_client() {
        let up = start_cookie_upstream().await;
        let dir = TempDir::new().unwrap();
        let proxy_port = start_proxy(dir.path(), &dir.path().join("t.jsonl"), None).await;

        let (parts, body) = get_through_proxy(proxy_port, &format!("http://127.0.0.1:{up}/")).await;

        assert_eq!(parts.status, 200);
        let cookies: Vec<_> = parts.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(cookies, ["session=abc; Secure; HttpOnly", "theme=dark"], "browser must get every Set-Cookie");
        assert_eq!(parts.headers["content-type"], "text/html; charset=utf-8");
        assert!(!parts.headers.contains_key("keep-alive"), "hop-by-hop headers are not forwarded");
        assert!(!parts.headers.contains_key("transfer-encoding"), "body is re-framed by the proxy");
        assert_eq!(body, "hello world");
    }

    #[tokio::test]
    async fn intercept_response_header_override_reaches_client() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");
        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward"}"#,
                r#"{"action":"forward","headers":{"x-injected":"yes"}}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let proxy_port = start_proxy(dir.path(), &dir.path().join("t.jsonl"), Some(socket_path)).await;

        let (parts, body) = get_through_proxy(proxy_port, &format!("http://127.0.0.1:{echo_port}/")).await;
        assert_eq!(parts.headers["x-injected"], "yes");
        assert_eq!(body, "echo-ok");
    }

    #[test]
    fn client_response_drops_hop_by_hop_and_length_headers() {
        let h: Headers = [
            ("connection", "keep-alive, x-private"),
            ("x-private", "1"),
            ("keep-alive", "timeout=5"),
            ("Transfer-Encoding", "chunked"),
            ("content-length", "999"),
            ("upgrade", "h2c"),
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
            ("content-encoding", "gzip"),
        ]
        .into_iter()
        .collect();
        let res = client_response(200, &to_header_map(&h), Bytes::from_static(b"abc")).unwrap();
        let names: Vec<_> = res.headers().keys().map(|k| k.as_str()).collect();
        assert_eq!(names, ["set-cookie", "content-encoding"]);
        assert_eq!(res.headers().get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn to_header_map_skips_headers_hyper_rejects() {
        // An intercept hook can send any string; a name with a space can't
        // go on the wire and must not fail the whole response.
        let h: Headers = [("bad name", "x"), ("ok", "1"), ("ok", "2")].into_iter().collect();
        let map = to_header_map(&h);
        assert_eq!(map.get_all("ok").iter().count(), 2);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn client_response_forwards_raw_non_utf8_value_bytes() {
        let mut map = hyper::HeaderMap::new();
        map.insert("x-odd", hyper::header::HeaderValue::from_bytes(b"caf\xe9").unwrap());
        let res = client_response(200, &map, Bytes::new()).unwrap();
        assert_eq!(res.headers()["x-odd"].as_bytes(), b"caf\xe9");
    }

    // --- access control, attribution, expiry, TLS listener (#8, #9) ---

    type SeenHeaders = Arc<tokio::sync::Mutex<Vec<hyper::HeaderMap>>>;

    /// Upstream that remembers every request's headers and answers 200 "ok".
    async fn start_header_capture_upstream() -> (u16, SeenHeaders) {
        let seen: SeenHeaders = Default::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let s = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let s = s.clone();
                tokio::spawn(async move {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(move |req: Request<Incoming>| {
                                let s = s.clone();
                                async move {
                                    s.lock().await.push(req.headers().clone());
                                    Ok::<_, anyhow::Error>(Response::new(Full::new(Bytes::from("ok"))))
                                }
                            }),
                        )
                        .await
                        .ok();
                });
            }
        });
        (port, seen)
    }

    /// `Basic <base64(user:pass)>`, encoded test-side.
    fn basic_header(userpass: &str) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in userpass.as_bytes().chunks(3) {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
        }
        format!("Basic {out}")
    }

    /// One request through the proxy over an already-connected stream.
    async fn request_over<IO>(io: IO, req: Request<Full<Bytes>>) -> (hyper::http::response::Parts, Bytes)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io)).await.unwrap();
        tokio::spawn(conn);
        let res = sender.send_request(req).await.unwrap();
        let (parts, body) = res.into_parts();
        (parts, body.collect().await.unwrap().to_bytes())
    }

    fn proxied_get(target: &str, auth: Option<&str>) -> Request<Full<Bytes>> {
        let mut b = Request::get(target).header("host", "upstream");
        if let Some(a) = auth {
            b = b.header("proxy-authorization", basic_header(a));
        }
        b.body(Full::new(Bytes::new())).unwrap()
    }

    fn creds(text: &str) -> Option<ProxyCredentials> {
        Some(ProxyCredentials::parse(text).unwrap())
    }

    fn logged(log: &std::path::Path) -> Vec<TrafficEntry> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn proxy_auth_required_when_credentials_configured() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig { credentials: creds("agent.T-3:s3cret"), ..Default::default() },
        )
        .await;
        let target = format!("http://127.0.0.1:{up}/x");
        let connect = || TcpStream::connect(format!("127.0.0.1:{port}"));

        for bad in [None, Some("agent.T-3:wrong"), Some("someone:s3cret")] {
            let (parts, _) = request_over(connect().await.unwrap(), proxied_get(&target, bad)).await;
            assert_eq!(parts.status, 407, "{bad:?}");
            assert_eq!(parts.headers["proxy-authenticate"], r#"Basic realm="taphttp""#);
        }
        assert!(seen.lock().await.is_empty(), "rejected requests never reach upstream");

        let (parts, body) = request_over(connect().await.unwrap(), proxied_get(&target, Some("agent.T-3:s3cret"))).await;
        assert_eq!(parts.status, 200);
        assert_eq!(body, "ok");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 1, "only the authenticated request is logged");
        assert_eq!(entries[0].source.as_deref(), Some("agent.T-3"), "verified identity recorded");
    }

    #[tokio::test]
    async fn proxy_authorization_never_reaches_upstream_or_the_log() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        // No credentials configured: the username is a self-reported label.
        let port = start_proxy(dir.path(), &log, None).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let (parts, _) =
            request_over(stream, proxied_get(&format!("http://127.0.0.1:{up}/"), Some("agent.T-3:not-a-secret"))).await;
        assert_eq!(parts.status, 200);

        let upstream = seen.lock().await;
        assert!(!upstream[0].contains_key("proxy-authorization"), "credentials must not leak to the target");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let raw = std::fs::read_to_string(&log).unwrap();
        assert!(!raw.to_ascii_lowercase().contains("proxy-authorization"), "{raw}");
        assert!(!raw.contains("not-a-secret") && !raw.contains(&basic_header("agent.T-3:not-a-secret")[6..]));
        let entries = logged(&log);
        assert_eq!(entries[0].source.as_deref(), Some("agent.T-3"));
    }

    #[tokio::test]
    async fn intercept_hook_cannot_send_proxy_authorization_upstream() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");
        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward","headers":{"proxy-authorization":"Basic eDp5","x-kept":"1"}}"#,
                r#"{"action":"forward"}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let port = start_proxy(dir.path(), &dir.path().join("t.jsonl"), Some(socket_path)).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        request_over(stream, proxied_get(&format!("http://127.0.0.1:{up}/"), None)).await;
        let upstream = seen.lock().await;
        assert_eq!(upstream[0]["x-kept"], "1", "the hook's other headers apply");
        assert!(!upstream[0].contains_key("proxy-authorization"));
    }

    #[tokio::test]
    async fn untagged_traffic_has_no_source() {
        let (up, _) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy(dir.path(), &log, None).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        request_over(stream, proxied_get(&format!("http://127.0.0.1:{up}/"), None)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(logged(&log)[0].source, None);
    }

    /// Open a CONNECT tunnel through the proxy, then TLS to taphttp's MITM
    /// cert for `host` (trusting the CA in `dir`). Returns the CONNECT status
    /// and, if it was 200, the TLS stream.
    async fn connect_tunnel(
        proxy_port: u16,
        authority: &str,
        auth: Option<&str>,
        dir: &std::path::Path,
    ) -> (u16, Option<tokio_rustls::client::TlsStream<TcpStream>>) {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
        let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(a) = auth {
            head.push_str(&format!("Proxy-Authorization: {}\r\n", basic_header(a)));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            buf.push(byte[0]);
        }
        let status: u16 = String::from_utf8_lossy(&buf)[9..12].parse().unwrap();
        if status != 200 {
            return (status, None);
        }
        let host = authority.rsplit_once(':').unwrap().0.to_string();
        let tls = tls_connector(dir)
            .connect(rustls::pki_types::ServerName::try_from(host).unwrap(), stream)
            .await
            .unwrap();
        (status, Some(tls))
    }

    /// A TLS client that trusts only taphttp's CA in `dir`.
    fn tls_connector(dir: &std::path::Path) -> tokio_rustls::TlsConnector {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = std::fs::read_to_string(dir.join("ca.crt")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
    }

    #[tokio::test]
    async fn connect_is_authenticated_and_its_source_covers_the_tunnel() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig { credentials: creds("agent.T-3:s3cret"), ..Default::default() },
        )
        .await;
        // Nothing listens on :9 upstream, so the exchange records as a 502;
        // what matters is the auth decision and the recorded source.
        let authority = "localhost:9";
        assert_eq!(connect_tunnel(port, authority, None, dir.path()).await.0, 407);
        assert_eq!(connect_tunnel(port, authority, Some("agent.T-3:nope"), dir.path()).await.0, 407);

        let (status, tls) = connect_tunnel(port, authority, Some("agent.T-3:s3cret"), dir.path()).await;
        assert_eq!(status, 200);
        let req = Request::get("/inside").header("host", "localhost").body(Full::new(Bytes::new())).unwrap();
        let (parts, _) = request_over(tls.unwrap(), req).await;
        assert_eq!(parts.status, 502);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].url.ends_with("/inside"));
        assert_eq!(entries[0].source.as_deref(), Some("agent.T-3"));
    }

    #[tokio::test]
    async fn client_outside_allowlist_is_disconnected() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let allow = vec!["10.0.0.0/8".parse().unwrap()];
        let port = start_proxy_with(dir.path(), &log, ProxyConfig { allow_clients: allow, ..Default::default() }).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let req = format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n");
        let _ = stream.write_all(req.as_bytes()).await;
        let mut buf = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await.unwrap().unwrap_or(0);
        assert_eq!(n, 0, "closed without a response");
        assert!(seen.lock().await.is_empty());

        // 127.0.0.1 allowed: works.
        let ok = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig { allow_clients: vec!["127.0.0.0/8".parse().unwrap()], ..Default::default() },
        )
        .await;
        let stream = TcpStream::connect(format!("127.0.0.1:{ok}")).await.unwrap();
        assert_eq!(request_over(stream, proxied_get(&format!("http://127.0.0.1:{up}/"), None)).await.0.status, 200);
    }

    #[tokio::test]
    async fn requests_after_expiry_are_refused() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let expires = Some(Utc::now() - chrono::Duration::seconds(1));
        let port = start_proxy_with(dir.path(), &log, ProxyConfig { expires, ..Default::default() }).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let (parts, body) = request_over(stream, proxied_get(&format!("http://127.0.0.1:{up}/"), None)).await;
        assert_eq!(parts.status, 503);
        assert!(String::from_utf8_lossy(&body).contains("expired"));
        assert!(seen.lock().await.is_empty());
        assert_eq!(connect_tunnel(port, "localhost:9", None, dir.path()).await.0, 503);
    }

    #[tokio::test]
    async fn tls_proxy_listener_serves_trusting_clients_and_rejects_plaintext() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let tls = Some(ca.listener_tls_config(&["127.0.0.1".into()]).unwrap());
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig { tls, credentials: creds("you:pw"), ..Default::default() },
        )
        .await;

        let tcp = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let stream = tls_connector(dir.path()).connect(name, tcp).await.expect("listener cert chains to ca.crt");
        let (parts, body) = request_over(stream, proxied_get(&format!("http://127.0.0.1:{up}/"), Some("you:pw"))).await;
        assert_eq!((parts.status.as_u16(), body.as_ref()), (200, &b"ok"[..]));
        assert_eq!(seen.lock().await.len(), 1);

        // A plaintext client gets no HTTP response from a TLS listener.
        let mut plain = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        plain.write_all(format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut buf)).await;
        assert!(!String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
        assert_eq!(seen.lock().await.len(), 1, "plaintext request never forwarded");
    }

    #[test]
    fn tls_names_include_specific_listener_ips_and_require_one_for_wildcards() {
        let a: SocketAddr = "10.0.0.5:8443".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        assert_eq!(tls_names(&[], &[Some(a)]).unwrap(), ["10.0.0.5"]);
        assert_eq!(tls_names(&["proxy.lan".into()], &[Some(any), Some(a)]).unwrap(), ["10.0.0.5", "proxy.lan"]);
        let err = tls_names(&[], &[Some(any), None]).unwrap_err().to_string();
        assert!(err.contains("--tls-name"), "{err}");
    }

    #[tokio::test]
    async fn http_proxy_filter_host_skips_unmatched() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");

        let ca = Arc::new(Ca::load_or_create(dir.path()).unwrap());
        let store = Store::new(Some(&log_file), None).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let config = ProxyConfig { filter_host: Some("only-this-host.example".to_string()), ..Default::default() };
        tokio::spawn(serve(proxy_listener, ca, store, config));
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
