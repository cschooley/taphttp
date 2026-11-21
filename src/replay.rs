use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

use crate::cli::ReplayArgs;
use crate::storage::{self, Headers, Store, TrafficEntry};

/// Modifications applied to a captured request before replaying it.
#[derive(Debug, Default, Clone)]
pub struct ReplayMods {
    /// Override the HTTP method.
    pub method: Option<String>,
    /// Headers to set over the captured ones. Each replaces every captured
    /// value for that name (so one override wins over repeated headers).
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
        original.req_headers.set(k.clone(), v.clone());
    }
    if let Some(body) = &mods.body {
        original.set_req_body(body.as_bytes());
    }
    // Byte-exact: a base64-stored body goes out as the original bytes.
    let req_body = original
        .req_body_bytes()
        .with_context(|| format!("decoding stored request body of {original_id}"))?
        .unwrap_or_default();

    let (status, res_headers, res_body, duration_ms) = send_request(
        &original.method,
        &original.url,
        &original.req_headers,
        req_body,
    )
    .await?;

    let mut replay = TrafficEntry {
        id: Uuid::new_v4().to_string(),
        ts: Utc::now(),
        res_headers,
        status: Some(status),
        duration_ms: Some(duration_ms),
        replay_of: Some(original_id),
        ..original
    };
    replay.set_res_body(&res_body);

    store.record(replay.clone());
    Ok(replay)
}

/// Send one request and return `(status, response headers, response body,
/// elapsed ms)`. Shared by the CLI and the lever API's replay path.
async fn send_request(
    method: &str,
    url: &str,
    req_headers: &Headers,
    req_body: Vec<u8>,
) -> Result<(u16, Headers, Bytes, u64)> {
    let method = hyper::Method::from_bytes(method.as_bytes()).context("invalid method")?;
    let uri: hyper::Uri = url.parse().context("invalid url")?;

    let mut builder = Request::builder().method(method).uri(uri.clone());
    // `header` appends, so repeated headers are sent as captured.
    for (k, v) in req_headers.iter() {
        builder = builder.header(k, v);
    }
    let req = builder.body(Full::new(Bytes::from(req_body))).context("building request")?;

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
    let headers = crate::proxy::collect_headers(res.headers());
    let body = res.into_body().collect().await?.to_bytes();
    let duration_ms = start.elapsed().as_millis() as u64;
    Ok((status, headers, body, duration_ms))
}

pub async fn run(args: ReplayArgs, data_dir: PathBuf) -> Result<()> {
    let log_path = args
        .log_file
        .clone()
        .unwrap_or_else(|| data_dir.join("traffic.jsonl"));
    if !log_path.exists() {
        anyhow::bail!(
            "no traffic log at {}. `taphttp start` only writes a file when given \
             --log-file <PATH>; pass the same path here with `taphttp replay --log-file <PATH> <ID>`",
            log_path.display()
        );
    }
    let original = storage::load_entry(&log_path, &args.id)?;

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
    let store = Store::new(Some(&log_path), None)?;
    let replay = replay_entry(&store, original, &mods).await?;

    // Human-readable summary to stderr; the recorded JSON line (emitted by the
    // store) is the structured stdout output, consistent with `start`.
    eprintln!("Status: {}", replay.status.unwrap_or(0));
    for (k, v) in replay.res_headers.iter() {
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
            req_headers: Headers::new(),
            req_body: None,
            req_body_encoding: Default::default(),
            status: Some(200),
            res_headers: Headers::new(),
            res_body: None,
            res_body_encoding: Default::default(),
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
        let store = Store::new(Some(&log), None).unwrap();

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

    /// What the recording upstream saw: every request header in order, and
    /// the raw body bytes.
    type Seen = Arc<tokio::sync::Mutex<Option<(Vec<(String, Vec<u8>)>, Vec<u8>)>>>;

    /// Upstream that records the request it receives and answers with two
    /// Set-Cookie headers and a binary body.
    async fn start_recording_server(seen: Seen) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    service_fn(move |req: Request<Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let headers = req
                                .headers()
                                .iter()
                                .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
                                .collect();
                            let body = req.into_body().collect().await?.to_bytes().to_vec();
                            *seen.lock().await = Some((headers, body));
                            Ok::<_, anyhow::Error>(
                                Response::builder()
                                    .header("set-cookie", "s=1; Secure")
                                    .header("set-cookie", "t=2; HttpOnly")
                                    .body(Full::new(Bytes::from_static(&[0xde, 0xad, 0x00, 0xff])))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .ok();
        });
        port
    }

    fn values<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Vec<&'a [u8]> {
        headers.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_slice()).collect()
    }

    #[tokio::test]
    async fn replay_sends_repeated_headers_and_binary_body_byte_exact() {
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(Some(&log), None).unwrap();

        let body: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe];
        let mut original = upstream_entry("bin-1", port, "POST");
        original.req_headers.append("x-multi", "one");
        original.req_headers.append("x-multi", "two");
        original.set_req_body(body);
        // Go through the log as the CLI would, so base64 is decoded from disk.
        JsonLinesBackend::new(&log).append(&original).unwrap();
        let original = storage::load_entry(&log, "bin-1").unwrap();
        assert_eq!(original.req_body_encoding, taphttp_types::BodyEncoding::Base64);

        let replay = replay_entry(&store, original, &ReplayMods::default()).await.unwrap();

        let (headers, got_body) = seen.lock().await.clone().unwrap();
        assert_eq!(values(&headers, "x-multi"), [b"one", b"two"], "repeated headers sent as captured");
        assert_eq!(got_body, body, "base64 body decoded before sending");

        // The recorded replay keeps both Set-Cookies and the binary response.
        let logged = storage::load_entry(&log, &replay.id).unwrap();
        assert_eq!(
            logged.res_headers.get_all("set-cookie").collect::<Vec<_>>(),
            ["s=1; Secure", "t=2; HttpOnly"]
        );
        assert_eq!(logged.res_body_bytes().unwrap().as_deref(), Some(&[0xde, 0xad, 0x00, 0xff][..]));
        assert_eq!(logged.req_body_bytes().unwrap().as_deref(), Some(body));
    }

    #[tokio::test]
    async fn replay_header_override_replaces_every_value_for_that_name() {
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let store = Store::new(None, None).unwrap();

        let mut original = upstream_entry("ovr-1", port, "GET");
        original.req_headers.append("cookie", "a=1");
        original.req_headers.append("cookie", "b=2");
        original.req_headers.append("x-keep", "yes");
        let mods = ReplayMods {
            headers: vec![("Cookie".into(), "c=3".into())],
            ..Default::default()
        };
        replay_entry(&store, original, &mods).await.unwrap();

        let (headers, _) = seen.lock().await.clone().unwrap();
        assert_eq!(values(&headers, "cookie"), [b"c=3"]);
        assert_eq!(values(&headers, "x-keep"), [b"yes"]);
    }

    #[tokio::test]
    async fn replay_entry_applies_method_override() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let store = Store::new(Some(&dir.path().join("traffic.jsonl")), None).unwrap();

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
            req_headers: Headers::new(),
            req_body: None,
            req_body_encoding: Default::default(),
            status: Some(200),
            res_headers: Headers::new(),
            res_body: None,
            res_body_encoding: Default::default(),
            duration_ms: Some(5),
            replay_of: None,
        };

        JsonLinesBackend::new(&data_dir.join("traffic.jsonl")).append(&entry).unwrap();

        let args = ReplayArgs {
            id: "replay-test-id".to_string(),
            log_file: None,
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
            req_headers: Headers::new(),
            req_body: None,
            req_body_encoding: Default::default(),
            status: Some(200),
            res_headers: Headers::new(),
            res_body: None,
            res_body_encoding: Default::default(),
            duration_ms: None,
            replay_of: None,
        };

        JsonLinesBackend::new(&data_dir.join("traffic.jsonl")).append(&entry).unwrap();

        let args = ReplayArgs {
            id: "override-id".to_string(),
            log_file: None,
            method: Some("POST".to_string()),
            headers: vec!["x-test:yes".to_string()],
            body: Some("new body".to_string()),
        };

        run(args, data_dir).await.unwrap();
        assert!(hit.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn replay_reads_and_records_to_explicit_log_file() {
        // Issue #2: under stdout-first logging the log lives wherever
        // `start --log-file` put it, not in the data dir.
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let data_dir = TempDir::new().unwrap();
        let elsewhere = TempDir::new().unwrap();
        let log = elsewhere.path().join("capture.jsonl");
        JsonLinesBackend::new(&log).append(&upstream_entry("custom-log-id", port, "GET")).unwrap();

        let args = ReplayArgs {
            id: "custom-log-id".to_string(),
            log_file: Some(log.clone()),
            method: None,
            headers: vec![],
            body: None,
        };
        run(args, data_dir.path().to_path_buf()).await.unwrap();

        assert!(hit.load(Ordering::SeqCst), "replay should reach upstream");
        let logged = storage::load_entries(&log).unwrap();
        assert!(
            logged.iter().any(|e| e.replay_of.as_deref() == Some("custom-log-id")),
            "replay must be recorded in the log it was read from"
        );
        assert!(
            !data_dir.path().join("traffic.jsonl").exists(),
            "nothing should be written to the data-dir default"
        );
    }

    #[tokio::test]
    async fn replay_missing_log_file_error_names_the_path_and_the_fix() {
        let data_dir = TempDir::new().unwrap();
        let args = ReplayArgs {
            id: "x".to_string(),
            log_file: None,
            method: None,
            headers: vec![],
            body: None,
        };
        let err = format!("{:#}", run(args, data_dir.path().to_path_buf()).await.unwrap_err());
        assert!(err.contains("traffic.jsonl"), "error should name the path: {err}");
        assert!(err.contains("--log-file"), "error should point at --log-file: {err}");
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
                req_headers: Headers::new(),
                req_body: None,
                req_body_encoding: Default::default(),
                status: None,
                res_headers: Headers::new(),
                res_body: None,
                res_body_encoding: Default::default(),
                duration_ms: None,
                replay_of: None,
            })
            .unwrap();

        let args = ReplayArgs {
            id: "does-not-exist".to_string(),
            log_file: None,
            method: None,
            headers: vec![],
            body: None,
        };

        let result = run(args, data_dir).await;
        assert!(result.is_err(), "should error when ID not found");
    }
}
