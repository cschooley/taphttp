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
use crate::storage::{Store, TrafficEntry};

pub async fn run(args: StartArgs, data_dir: PathBuf) -> Result<()> {
    let ca = Arc::new(Ca::load_or_create(&data_dir)?);
    let store = Store::new(&data_dir, args.sqlite)?;
    let addr: SocketAddr = args.listen.parse().context("invalid listen address")?;
    let listener = TcpListener::bind(addr).await.context("binding listener")?;
    tracing::info!("taphttp listening on {}", addr);
    eprintln!("taphttp listening on {addr}");
    eprintln!("Configure your HTTP client to use proxy http://{addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let ca = ca.clone();
        let store = store.clone();
        let filter_host = args.filter_host.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, ca, store, filter_host).await {
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
    filter_host: Option<String>,
) -> Result<()> {
    let io = hyper_util::rt::TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let ca = ca.clone();
                let store = store.clone();
                let filter_host = filter_host.clone();
                async move { dispatch(req, peer, ca, store, filter_host).await }
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
    filter_host: Option<String>,
) -> Result<Response<Full<Bytes>>> {
    if req.method() == hyper::Method::CONNECT {
        handle_connect(req, ca, store, filter_host).await
    } else {
        handle_http(req, store, filter_host).await
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<Ca>,
    store: Arc<Store>,
    filter_host: Option<String>,
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
                if let Err(e) = mitm_tls(upgraded, host, host_port, ca, store, filter_host).await {
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
    filter_host: Option<String>,
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
                let filter_host = filter_host.clone();
                async move {
                    // Reconstruct the full URL
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/");
                    let full_url = format!("https://{host_port}{path}");
                    *req.uri_mut() = full_url.parse()?;
                    forward_https(req, host, store, filter_host).await
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
    filter_host: Option<String>,
) -> Result<Response<Full<Bytes>>> {
    if let Some(f) = &filter_host {
        if !host.contains(f.as_str()) {
            return passthrough_https(req).await;
        }
    }

    let method = req.method().to_string();
    let url = req.uri().to_string();
    let req_headers = collect_headers(req.headers());

    let (parts, body) = req.into_parts();
    let req_body_bytes = body.collect().await?.to_bytes();
    let req_body_str = maybe_utf8(&req_body_bytes);

    let start = Instant::now();

    let upstream_req = rebuild_request(&parts, req_body_bytes.clone(), &url)?;
    let res = send_https(upstream_req).await;

    let duration_ms = start.elapsed().as_millis() as u64;

    let (status, res_headers, res_body_bytes) = match res {
        Ok(r) => {
            let status = r.status().as_u16();
            let headers = collect_headers(r.headers());
            let body = r.into_body().collect().await?.to_bytes();
            (Some(status), headers, body)
        }
        Err(e) => {
            tracing::debug!("upstream error: {e}");
            (None, HashMap::new(), Bytes::new())
        }
    };

    let entry = TrafficEntry {
        id: Uuid::new_v4().to_string(),
        ts: Utc::now(),
        host: host.clone(),
        method,
        url,
        req_headers,
        req_body: req_body_str,
        status,
        res_headers,
        res_body: maybe_utf8(&res_body_bytes),
        duration_ms: Some(duration_ms),
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
    Ok(client.request(req).await.context("https upstream request")?)
}

async fn handle_http(
    req: Request<Incoming>,
    store: Arc<Store>,
    filter_host: Option<String>,
) -> Result<Response<Full<Bytes>>> {
    let host = req
        .uri()
        .host()
        .unwrap_or("")
        .to_string();

    if let Some(f) = &filter_host {
        if !host.contains(f.as_str()) {
            return forward_http_raw(req).await;
        }
    }

    let method = req.method().to_string();
    let url = req.uri().to_string();
    let req_headers = collect_headers(req.headers());
    let (parts, body) = req.into_parts();
    let req_body_bytes = body.collect().await?.to_bytes();
    let req_body_str = maybe_utf8(&req_body_bytes);

    let start = Instant::now();
    let upstream_req = rebuild_request(&parts, req_body_bytes, &url)?;
    let res = forward_http_request(upstream_req).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    let (status, res_headers, res_body_bytes) = match res {
        Ok(r) => {
            let status = r.status().as_u16();
            let headers = collect_headers(r.headers());
            let body = r.into_body().collect().await?.to_bytes();
            (Some(status), headers, body)
        }
        Err(e) => {
            tracing::debug!("http upstream error: {e}");
            (None, HashMap::new(), Bytes::new())
        }
    };

    let entry = TrafficEntry {
        id: Uuid::new_v4().to_string(),
        ts: Utc::now(),
        host: host.clone(),
        method,
        url,
        req_headers,
        req_body: req_body_str,
        status,
        res_headers,
        res_body: maybe_utf8(&res_body_bytes),
        duration_ms: Some(duration_ms),
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
    Ok(client.request(req).await.context("http upstream request")?)
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

fn collect_headers(headers: &hyper::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

fn maybe_utf8(b: &Bytes) -> Option<String> {
    if b.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(b).into_owned())
    }
}
