use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

use crate::cli::ReplayArgs;
use crate::storage::{self, Store, TrafficEntry};

/// Modifications applied to a captured request before replaying it.
#[derive(Debug, Default, Clone)]
pub struct ReplayMods {
    /// Override the HTTP method.
    pub method: Option<String>,
    /// Headers to insert or overwrite (applied over the captured headers).
    pub headers: Vec<(String, String)>,
    /// Override the request body.
    pub body: Option<String>,
}

/// Replay `original` (with `mods` applied) against its upstream, record the
/// result as a new [`TrafficEntry`] linked back via `replay_of`, and return
/// that entry. Recording it into `store` means the replay shows up in the
/// traffic log and on the live `/feed` like any other exchange — which is
/// what downstream tools need for evidence and retest.
pub async fn replay_entry(
    store: &Store,
    mut original: TrafficEntry,
    mods: &ReplayMods,
) -> Result<TrafficEntry> {
    let original_id = original.id.clone();

    if let Some(method) = &mods.method {
        original.method = method.to_uppercase();
    }
    for (k, v) in &mods.headers {
        original.req_headers.insert(k.clone(), v.clone());
    }
    if let Some(body) = &mods.body {
        original.req_body = Some(body.clone());
    }

    let (status, res_headers, res_body, duration_ms) = send_request(
        &original.method,
        &original.url,
        &original.req_headers,
        original.req_body.as_deref(),
    )
    .await?;

    let replay = TrafficEntry {
        id: Uuid::new_v4().to_string(),
        ts: Utc::now(),
        host: original.host.clone(),
        method: original.method.clone(),
        url: original.url.clone(),
        req_headers: original.req_headers.clone(),
        req_body: original.req_body.clone(),
        status: Some(status),
        res_headers,
        res_body,
        duration_ms: Some(duration_ms),
        replay_of: Some(original_id),
    };

    store.record(replay.clone());
    Ok(replay)
}

/// Send one request and return `(status, response headers, response body,
/// elapsed ms)`. Shared by the CLI and the lever API's replay path.
async fn send_request(
    method: &str,
    url: &str,
    req_headers: &HashMap<String, String>,
    req_body: Option<&str>,
) -> Result<(u16, HashMap<String, String>, Option<String>, u64)> {
    let method = hyper::Method::from_bytes(method.as_bytes()).context("invalid method")?;
    let uri: hyper::Uri = url.parse().context("invalid url")?;
    let body_bytes = req_body
        .map(|b| Bytes::from(b.to_owned().into_bytes()))
        .unwrap_or_default();

    let mut builder = Request::builder().method(method).uri(uri.clone());
    for (k, v) in req_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = builder.body(Full::new(body_bytes)).context("building request")?;

    let scheme = uri.scheme_str().unwrap_or("http");
    let start = Instant::now();
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

    let status = res.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in res.headers() {
        headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
    }
    let body = res.into_body().collect().await?.to_bytes();
    let duration_ms = start.elapsed().as_millis() as u64;
    let res_body = if body.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&body).into_owned())
    };
    Ok((status, headers, res_body, duration_ms))
}

pub async fn run(args: ReplayArgs, data_dir: PathBuf) -> Result<()> {
    let original = storage::load_entry(&data_dir, &args.id)?;

    let mut mods = ReplayMods {
        method: args.method,
        body: args.body,
        headers: Vec::new(),
    };
    for kv in &args.headers {
        let (k, v) = kv.split_once(':').context("header must be key:value")?;
        mods.headers.push((k.trim().to_string(), v.trim().to_string()));
    }

    eprintln!("Replaying {} {}", original.method, original.url);

    // Record the replay into the same JSON-lines log the original came from.
    let store = Store::new(&data_dir, Some(&data_dir.join("traffic.jsonl")), false)?;
    let replay = replay_entry(&store, original, &mods).await?;

    // Human-readable summary to stderr; the recorded JSON line (emitted by the
    // store) is the structured stdout output, consistent with `start`.
    eprintln!("Status: {}", replay.status.unwrap_or(0));
    for (k, v) in &replay.res_headers {
        eprintln!("{k}: {v}");
    }
    eprintln!(
        "Recorded replay {} (replay_of {})",
        replay.id,
        replay.replay_of.as_deref().unwrap_or("?")
    );
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

    fn upstream_entry(id: &str, port: u16, method: &str) -> TrafficEntry {
        TrafficEntry {
            id: id.to_string(),
            ts: Utc::now(),
            host: format!("127.0.0.1:{port}"),
            method: method.to_string(),
            url: format!("http://127.0.0.1:{port}/check"),
            req_headers: HashMap::new(),
            req_body: None,
            status: Some(200),
            res_headers: HashMap::new(),
            res_body: None,
            duration_ms: Some(5),
            replay_of: None,
        }
    }

    #[tokio::test]
    async fn replay_entry_records_linked_response() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(dir.path(), Some(&log), false).unwrap();

        let replay = replay_entry(&store, upstream_entry("orig-1", port, "GET"), &ReplayMods::default())
            .await
            .unwrap();

        // The returned entry is a distinct, linked exchange with the captured response.
        assert_ne!(replay.id, "orig-1", "replay gets its own id");
        assert_eq!(replay.replay_of.as_deref(), Some("orig-1"));
        assert_eq!(replay.status, Some(200));
        assert_eq!(replay.res_body.as_deref(), Some("replayed"));

        // And it was persisted to the log, linked to the original.
        let logged = storage::load_entries(&log).unwrap();
        assert!(
            logged.iter().any(|e| e.replay_of.as_deref() == Some("orig-1") && e.id == replay.id),
            "replay must be recorded in the traffic log"
        );
    }

    #[tokio::test]
    async fn replay_entry_applies_method_override() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let store = Store::new(dir.path(), Some(&dir.path().join("traffic.jsonl")), false).unwrap();

        let mods = ReplayMods { method: Some("post".to_string()), ..Default::default() };
        let replay = replay_entry(&store, upstream_entry("orig-2", port, "GET"), &mods)
            .await
            .unwrap();

        assert_eq!(replay.method, "POST", "method override is applied and upcased");
        assert!(hit.load(Ordering::SeqCst));
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
            replay_of: None,
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
            replay_of: None,
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
                replay_of: None,
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
