use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use std::path::PathBuf;
use crate::cli::ReplayArgs;
use crate::storage;

pub async fn run(args: ReplayArgs, data_dir: PathBuf) -> Result<()> {
    let mut entry = storage::load_entry(&data_dir, &args.id)?;

    if let Some(method) = args.method {
        entry.method = method.to_uppercase();
    }

    for kv in &args.headers {
        let (k, v) = kv.split_once(':').context("header must be key:value")?;
        entry.req_headers.insert(k.trim().to_string(), v.trim().to_string());
    }

    if let Some(body) = args.body {
        entry.req_body = Some(body);
    }

    let method = hyper::Method::from_bytes(entry.method.as_bytes())
        .context("invalid method")?;

    let uri: hyper::Uri = entry.url.parse().context("invalid url")?;

    let body_bytes = entry
        .req_body
        .map(|b| Bytes::from(b.into_bytes()))
        .unwrap_or_default();

    let mut builder = Request::builder()
        .method(method)
        .uri(uri.clone());

    for (k, v) in &entry.req_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    let req = builder
        .body(Full::new(body_bytes))
        .context("building request")?;

    eprintln!("Replaying {} {}", entry.method, entry.url);

    let scheme = uri.scheme_str().unwrap_or("http");

    let res = if scheme == "https" {
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
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
        client.request(req).await.context("sending request")?
    } else {
        let http = hyper_util::client::legacy::connect::HttpConnector::new();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(http);
        client.request(req).await.context("sending request")?
    };

    let status = res.status();
    eprintln!("Status: {}", status);

    for (k, v) in res.headers() {
        eprintln!("{}: {}", k, v.to_str().unwrap_or("?"));
    }
    eprintln!();

    let body = res.into_body().collect().await?.to_bytes();
    println!("{}", String::from_utf8_lossy(&body));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ReplayArgs;
    use crate::storage::{JsonLinesBackend, TrafficEntry};
    use bytes::Bytes;
    use chrono::Utc;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    async fn start_capture_server(hit: Arc<AtomicBool>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let hit = hit.clone();
                tokio::spawn(async move {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(move |_req: Request<Incoming>| {
                                hit.store(true, Ordering::SeqCst);
                                async move {
                                    Ok::<_, anyhow::Error>(Response::new(Full::new(
                                        Bytes::from("replayed"),
                                    )))
                                }
                            }),
                        )
                        .await
                        .ok();
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn replay_sends_request_to_upstream() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;

        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_path_buf();

        let entry = TrafficEntry {
            id: "replay-test-id".to_string(),
            ts: Utc::now(),
            host: format!("127.0.0.1:{port}"),
            method: "GET".to_string(),
            url: format!("http://127.0.0.1:{port}/check"),
            req_headers: HashMap::new(),
            req_body: None,
            status: Some(200),
            res_headers: HashMap::new(),
            res_body: None,
            duration_ms: Some(5),
        };

        JsonLinesBackend::new(&data_dir.join("traffic.jsonl")).append(&entry).unwrap();

        let args = ReplayArgs {
            id: "replay-test-id".to_string(),
            method: None,
            headers: vec![],
            body: None,
        };

        run(args, data_dir).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(hit.load(Ordering::SeqCst), "capture server should have been hit by replay");
    }

    #[tokio::test]
    async fn replay_applies_method_and_header_overrides() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;

        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_path_buf();

        let entry = TrafficEntry {
            id: "override-id".to_string(),
            ts: Utc::now(),
            host: format!("127.0.0.1:{port}"),
            method: "GET".to_string(),
            url: format!("http://127.0.0.1:{port}/"),
            req_headers: HashMap::new(),
            req_body: None,
            status: Some(200),
            res_headers: HashMap::new(),
            res_body: None,
            duration_ms: None,
        };

        JsonLinesBackend::new(&data_dir.join("traffic.jsonl")).append(&entry).unwrap();

        let args = ReplayArgs {
            id: "override-id".to_string(),
            method: Some("POST".to_string()),
            headers: vec!["x-test:yes".to_string()],
            body: Some("new body".to_string()),
        };

        run(args, data_dir).await.unwrap();
        assert!(hit.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn replay_errors_on_missing_id() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_path_buf();
        JsonLinesBackend::new(&data_dir.join("traffic.jsonl"))
            .append(&TrafficEntry {
                id: "some-id".to_string(),
                ts: Utc::now(),
                host: "x".to_string(),
                method: "GET".to_string(),
                url: "http://x/".to_string(),
                req_headers: HashMap::new(),
                req_body: None,
                status: None,
                res_headers: HashMap::new(),
                res_body: None,
                duration_ms: None,
            })
            .unwrap();

        let args = ReplayArgs {
            id: "does-not-exist".to_string(),
            method: None,
            headers: vec![],
            body: None,
        };

        let result = run(args, data_dir).await;
        assert!(result.is_err(), "should error when ID not found");
    }
}
