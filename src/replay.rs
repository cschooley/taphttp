use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

use crate::cli::ReplayArgs;
use crate::storage::{self, Headers, Origin, Store, TrafficEntry};
pub use crate::upstream::is_own_target;
use crate::upstream::{error_chain, is_local_ip, resolve};

/// Limits on [`ReplayMods::meta`]: it is attribution, not a payload.
pub const MAX_META_KEYS: usize = 16;
pub const MAX_META_KEY_LEN: usize = 64;
pub const MAX_META_VALUE_LEN: usize = 1024;

/// Modifications applied to a captured request before replaying it.
#[derive(Debug, Default, Clone)]
pub struct ReplayMods {
    /// Override the HTTP method.
    pub method: Option<String>,
    /// Replace the captured request headers entirely: this list, in order,
    /// repeats kept. Applied before `headers`.
    pub req_headers: Option<Headers>,
    /// Headers to set over the captured ones (or over `req_headers`). Each
    /// replaces every value for that name.
    pub headers: Vec<(String, String)>,
    /// Override the request body, byte-exact.
    pub body: Option<Vec<u8>>,
    /// Attribution recorded on the replay's entry and never sent upstream.
    pub meta: BTreeMap<String, String>,
}

/// A new request for `POST /send`: not a replay of anything captured.
#[derive(Debug, Default, Clone)]
pub struct SendSpec {
    pub method: String,
    /// An absolute `http` or `https` URL.
    pub url: String,
    /// The whole header list, in order. `None`: [`default_headers`]. A
    /// `host` header is added from the URL unless the list has one.
    pub req_headers: Option<Headers>,
    pub body: Vec<u8>,
    /// Attribution recorded on the entry and never sent upstream.
    pub meta: BTreeMap<String, String>,
}

/// The `user-agent` a [`SendSpec`] without headers goes out with.
pub const USER_AGENT: &str = concat!("taphttp/", env!("CARGO_PKG_VERSION"));

/// Why a replay or send produced no complete response.
#[derive(Debug)]
pub enum ReplayError {
    /// The request couldn't be built (bad method, URL, header, meta).
    /// Nothing was sent and nothing was recorded.
    Invalid(anyhow::Error),
    /// The request was attempted and failed: the upstream couldn't be
    /// reached or the response broke off. Recorded as this entry, whose
    /// `error` says why.
    Failed(Box<TrafficEntry>),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "invalid request: {e:#}"),
            Self::Failed(entry) => write!(
                f,
                "request failed: {} (recorded as {})",
                entry.error.as_deref().unwrap_or("unknown error"),
                entry.id
            ),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Check `meta` against the limits above.
pub fn validate_meta(meta: &BTreeMap<String, String>) -> Result<()> {
    if meta.len() > MAX_META_KEYS {
        bail!("meta has {} keys; at most {MAX_META_KEYS}", meta.len());
    }
    for (k, v) in meta {
        if k.is_empty() || k.len() > MAX_META_KEY_LEN {
            bail!("meta key {k:?}: must be 1 to {MAX_META_KEY_LEN} bytes");
        }
        if v.len() > MAX_META_VALUE_LEN {
            bail!("meta value for {k:?}: at most {MAX_META_VALUE_LEN} bytes");
        }
    }
    Ok(())
}

/// Replay `original` (with `mods` applied) against its upstream, record the
/// result as a new [`TrafficEntry`] linked back via `replay_of`, and return
/// that entry. Recording it into `store` means the replay shows up in the
/// traffic log and on the live `/feed` like any other exchange, which is
/// what downstream tools need for evidence and retest.
///
/// An attempt that fails is recorded too (with `error` set) and returned as
/// [`ReplayError::Failed`]: the history has no gaps. A request that can't
/// be built is [`ReplayError::Invalid`] and is neither sent nor recorded.
pub async fn replay_entry(
    store: &Store,
    original: TrafficEntry,
    mods: &ReplayMods,
) -> Result<TrafficEntry, ReplayError> {
    replay_entry_refusing(store, original, mods, &[]).await
}

/// [`replay_entry`], refusing (as [`ReplayError::Invalid`]) a target that
/// resolves to one of `own`, taphttp's listeners.
pub async fn replay_entry_refusing(
    store: &Store,
    mut original: TrafficEntry,
    mods: &ReplayMods,
    own: &[SocketAddr],
) -> Result<TrafficEntry, ReplayError> {
    let original_id = original.id.clone();
    validate_meta(&mods.meta).map_err(ReplayError::Invalid)?;

    if let Some(method) = &mods.method {
        original.method = method.to_uppercase();
    }
    if let Some(headers) = &mods.req_headers {
        original.req_headers = headers.clone();
    }
    for (k, v) in &mods.headers {
        original.req_headers.set(k.clone(), v.clone());
    }
    if let Some(body) = &mods.body {
        original.set_req_body(body);
    }
    // Byte-exact: a base64-stored body goes out as the original bytes.
    let req_body = original
        .req_body_bytes()
        .with_context(|| format!("decoding stored request body of {original_id}"))
        .map_err(ReplayError::Invalid)?
        .unwrap_or_default();

    let template = TrafficEntry {
        replay_of: Some(original_id),
        // A replay is sent by whoever ran `replay` / POST /replay, not by
        // the original's client, so it carries no source.
        source: None,
        meta: mods.meta.clone(),
        origin: Origin::Replay,
        ..original
    };
    exchange(store, template, req_body, own).await
}

/// Send a new request (`POST /send`), record it with `origin: send`, and
/// return the entry. Outcomes are as for [`replay_entry`]; a target that
/// resolves to one of `own` is [`ReplayError::Invalid`].
pub async fn send_new(
    store: &Store,
    spec: &SendSpec,
    own: &[SocketAddr],
) -> Result<TrafficEntry, ReplayError> {
    validate_meta(&spec.meta).map_err(ReplayError::Invalid)?;
    let uri = target_uri(&spec.url).map_err(ReplayError::Invalid)?;
    let host = uri.host().unwrap_or_default().to_string();
    let given = spec.req_headers.clone().unwrap_or_else(default_headers);
    let req_headers = if given.get("host").is_some() {
        given
    } else {
        let mut with_host = Headers::new();
        with_host.append("host", host_header(&uri));
        for (k, v) in given.iter() {
            with_host.append(k, v);
        }
        with_host
    };
    let mut template = TrafficEntry {
        id: String::new(),
        ts: taphttp_types::Timestamp::now(),
        host,
        method: spec.method.clone(),
        url: spec.url.clone(),
        req_headers,
        req_body: None,
        req_body_encoding: Default::default(),
        status: None,
        res_headers: Headers::new(),
        res_body: None,
        res_body_encoding: Default::default(),
        duration_ms: None,
        replay_of: None,
        source: None,
        meta: spec.meta.clone(),
        error: None,
        origin: Origin::Send,
        peer: None,
        refused: false,
    };
    template.set_req_body(&spec.body);
    exchange(store, template, spec.body.clone(), own).await
}

/// What a [`SendSpec`] without `req_headers` sends, besides `host`.
pub fn default_headers() -> Headers {
    let mut h = Headers::new();
    h.append("user-agent", USER_AGENT);
    h
}

/// `host[:port]` from the URL, without any userinfo.
fn host_header(uri: &hyper::Uri) -> String {
    let host = uri.host().unwrap_or_default();
    match uri.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Send `template`'s request, then record it completed with the response:
/// the one path behind replay and send.
async fn exchange(
    store: &Store,
    template: TrafficEntry,
    req_body: Vec<u8>,
    own: &[SocketAddr],
) -> Result<TrafficEntry, ReplayError> {
    let req = build_request(
        &template.method,
        &template.url,
        &template.req_headers,
        req_body,
    )
    .map_err(ReplayError::Invalid)?;
    // Record what goes on the wire: hyper groups a repeated header name at
    // its first position, so an interleaved list is sent grouped.
    let sent_headers = crate::proxy::collect_headers(req.headers());

    let start = Instant::now();
    let outcome = match resolve(req.uri()).await {
        Ok(addrs) => {
            if let Some(a) = addrs.iter().find(|a| is_own_target(**a, own, is_local_ip)) {
                return Err(ReplayError::Invalid(anyhow::anyhow!(
                    "{} resolves to {a}, one of taphttp's own listeners; refusing to send to itself",
                    template.url
                )));
            }
            // Connect only to the addresses just checked, so a name can't
            // resolve elsewhere the second time (DNS rebinding).
            send(req, addrs).await
        }
        Err(e) => Outcome {
            error: Some(format!("resolving host: {e}")),
            ..Default::default()
        },
    };
    let duration_ms = start.elapsed().as_millis() as u64;

    let mut entry = TrafficEntry {
        id: Uuid::new_v4().to_string(),
        ts: taphttp_types::Timestamp::now(),
        req_headers: sent_headers,
        status: outcome.status,
        res_headers: outcome.headers,
        duration_ms: Some(duration_ms),
        error: outcome.error,
        // Where this attempt went; a replay's original may have gone elsewhere.
        peer: outcome.peer,
        refused: false,
        ..template
    };
    entry.set_res_body(&outcome.body);

    store.record(entry.clone());
    if entry.error.is_some() {
        return Err(ReplayError::Failed(Box::new(entry)));
    }
    Ok(entry)
}

/// Parse a URL to send to: absolute `http` or `https`, with a host.
fn target_uri(url: &str) -> Result<hyper::Uri> {
    let uri: hyper::Uri = url
        .parse()
        .with_context(|| format!("invalid url {url:?}"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.host().is_none() {
        bail!("url {url:?}: need an absolute http or https URL");
    }
    Ok(uri)
}

/// Build the request, or say why it can't be sent. Only `http(s)` URLs
/// with a host are replayable.
fn build_request(
    method: &str,
    url: &str,
    req_headers: &Headers,
    req_body: Vec<u8>,
) -> Result<Request<Full<Bytes>>> {
    let method = hyper::Method::from_bytes(method.as_bytes())
        .with_context(|| format!("invalid method {method:?}"))?;
    let uri = target_uri(url)?;

    let mut builder = Request::builder().method(method).uri(uri);
    // `header` appends, so repeated headers are all sent.
    for (k, v) in req_headers.iter() {
        builder = builder.header(k, v);
    }
    builder
        .body(Full::new(Bytes::from(req_body)))
        .context("invalid request header")
}

/// What came back from one attempt. `error` is set when it didn't complete;
/// `status` and `headers` are kept if the response head arrived.
#[derive(Default)]
struct Outcome {
    status: Option<u16>,
    headers: Headers,
    body: Bytes,
    error: Option<String>,
    /// The address connected to, if a connection was made.
    peer: Option<SocketAddr>,
}

/// Send one request, connecting only to `addrs`. Shared by the CLI and the
/// lever API's replay and send paths.
async fn send(req: Request<Full<Bytes>>, addrs: Vec<SocketAddr>) -> Outcome {
    let (res, peer) = crate::upstream::request(req, addrs).await;
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            return Outcome {
                error: Some(format!("sending request: {}", error_chain(&e))),
                peer: peer.get(),
                ..Default::default()
            }
        }
    };

    let status = Some(res.status().as_u16());
    let headers = crate::proxy::collect_headers(res.headers());
    match res.into_body().collect().await {
        Ok(body) => Outcome {
            status,
            headers,
            body: body.to_bytes(),
            error: None,
            peer: peer.get(),
        },
        Err(e) => Outcome {
            status,
            headers,
            body: Bytes::new(),
            error: Some(format!("reading response body: {}", error_chain(&e))),
            peer: peer.get(),
        },
    }
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
        body: args.body.map(String::into_bytes),
        ..Default::default()
    };
    for kv in &args.headers {
        let (k, v) = kv.split_once(':').context("header must be key:value")?;
        mods.headers
            .push((k.trim().to_string(), v.trim().to_string()));
    }

    eprintln!("Replaying {} {}", original.method, original.url);

    // Record the replay into the same JSON-lines log the original came from.
    let store = Store::new(Some(&log_path), None)?;
    let replay = replay_entry(&store, original, &mods).await?;
    // (A failed attempt is recorded before the error propagates; its
    // message names the recorded id.)

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
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::collections::BTreeMap;
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
                                    Ok::<_, anyhow::Error>(Response::new(Full::new(Bytes::from(
                                        "replayed",
                                    ))))
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
            ts: taphttp_types::Timestamp::now(),
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
            source: None,
            meta: Default::default(),
            error: None,
            origin: crate::storage::Origin::Proxy,
            peer: None,
            refused: false,
        }
    }

    #[tokio::test]
    async fn replay_entry_records_linked_response() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(Some(&log), None).unwrap();

        let replay = replay_entry(
            &store,
            upstream_entry("orig-1", port, "GET"),
            &ReplayMods::default(),
        )
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
            logged
                .iter()
                .any(|e| e.replay_of.as_deref() == Some("orig-1") && e.id == replay.id),
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
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
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
        headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_slice())
            .collect()
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
        assert_eq!(
            original.req_body_encoding,
            taphttp_types::BodyEncoding::Base64
        );

        let replay = replay_entry(&store, original, &ReplayMods::default())
            .await
            .unwrap();

        let (headers, got_body) = seen.lock().await.clone().unwrap();
        assert_eq!(
            values(&headers, "x-multi"),
            [b"one", b"two"],
            "repeated headers sent as captured"
        );
        assert_eq!(got_body, body, "base64 body decoded before sending");

        // The recorded replay keeps both Set-Cookies and the binary response.
        let logged = storage::load_entry(&log, &replay.id).unwrap();
        assert_eq!(
            logged.res_headers.get_all("set-cookie").collect::<Vec<_>>(),
            ["s=1; Secure", "t=2; HttpOnly"]
        );
        assert_eq!(
            logged.res_body_bytes().unwrap().as_deref(),
            Some(&[0xde, 0xad, 0x00, 0xff][..])
        );
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

    fn mods_with_headers(pairs: &[(&str, &str)]) -> ReplayMods {
        ReplayMods {
            req_headers: Some(pairs.iter().copied().collect()),
            ..Default::default()
        }
    }

    /// The request headers the upstream saw whose name starts with `x-`.
    fn x_headers(headers: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
        headers
            .iter()
            .filter(|(k, _)| k.starts_with("x-"))
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect()
    }

    #[tokio::test]
    async fn req_headers_replace_the_captured_list_with_repeats_in_order() {
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let store = Store::new(None, None).unwrap();
        let mut original = upstream_entry("rh-1", port, "GET");
        original.req_headers.append("x-captured", "gone");
        original.req_headers.append("cookie", "old=1");

        let mods = mods_with_headers(&[
            ("x-z", "first"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
            ("x-a", "last"),
        ]);
        let replay = replay_entry(&store, original, &mods).await.unwrap();

        let (headers, _) = seen.lock().await.clone().unwrap();
        assert!(values(&headers, "x-captured").is_empty(), "removed");
        assert_eq!(values(&headers, "cookie"), [b"a=1", b"b=2"]);
        let order: Vec<&str> = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .filter(|k| ["x-z", "cookie", "x-a"].contains(k))
            .collect();
        assert_eq!(order, ["x-z", "cookie", "cookie", "x-a"]);
        assert_eq!(
            replay.req_headers.iter().collect::<Vec<_>>(),
            [
                ("x-z", "first"),
                ("cookie", "a=1"),
                ("cookie", "b=2"),
                ("x-a", "last")
            ]
        );
    }

    #[tokio::test]
    async fn recorded_req_headers_are_what_went_on_the_wire() {
        // hyper's HeaderMap groups a repeated name at its first position, so
        // an interleaved list goes out grouped. The record must say so.
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let store = Store::new(None, None).unwrap();
        let mods = mods_with_headers(&[("x-b", "1"), ("x-a", "2"), ("x-b", "3")]);
        let replay = replay_entry(&store, upstream_entry("rh-2", port, "GET"), &mods)
            .await
            .unwrap();

        let (headers, _) = seen.lock().await.clone().unwrap();
        assert_eq!(
            x_headers(&headers),
            [("x-b", &b"1"[..]), ("x-b", &b"3"[..]), ("x-a", &b"2"[..])]
        );
        assert_eq!(
            replay.req_headers.iter().collect::<Vec<_>>(),
            [("x-b", "1"), ("x-b", "3"), ("x-a", "2")]
        );
    }

    #[tokio::test]
    async fn header_map_is_applied_over_req_headers() {
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let store = Store::new(None, None).unwrap();
        let mut mods = mods_with_headers(&[("cookie", "a=1"), ("cookie", "b=2"), ("x-k", "v")]);
        mods.headers = vec![("Cookie".into(), "c=3".into())];
        replay_entry(&store, upstream_entry("rh-3", port, "GET"), &mods)
            .await
            .unwrap();
        let (headers, _) = seen.lock().await.clone().unwrap();
        assert_eq!(values(&headers, "cookie"), [b"c=3"]);
        assert_eq!(values(&headers, "x-k"), [b"v"]);
    }

    #[tokio::test]
    async fn binary_body_override_is_sent_and_recorded_byte_exact() {
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let store = Store::new(None, None).unwrap();
        let body = vec![0x00, 0xff, 0x1f, 0x8b, 0x80];
        let mods = ReplayMods {
            body: Some(body.clone()),
            ..Default::default()
        };
        let replay = replay_entry(&store, upstream_entry("bb-1", port, "POST"), &mods)
            .await
            .unwrap();
        assert_eq!(seen.lock().await.clone().unwrap().1, body);
        assert_eq!(
            replay.req_body_encoding,
            taphttp_types::BodyEncoding::Base64
        );
        assert_eq!(replay.req_body_bytes().unwrap(), Some(body));
    }

    // --- POST /send ---

    fn sent_headers(seen: &(Vec<(String, Vec<u8>)>, Vec<u8>)) -> Vec<(String, String)> {
        seen.0
            .iter()
            .map(|(k, v)| (k.clone(), String::from_utf8_lossy(v).into_owned()))
            .collect()
    }

    fn log_store(dir: &TempDir) -> (Arc<Store>, std::path::PathBuf) {
        let log = dir.path().join("traffic.jsonl");
        (Store::new(Some(&log), None).unwrap(), log)
    }

    #[tokio::test]
    async fn send_records_a_new_request_with_default_headers() {
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let dir = TempDir::new().unwrap();
        let (store, log) = log_store(&dir);
        let spec = SendSpec {
            method: "POST".into(),
            url: format!("http://127.0.0.1:{port}/new?x=1"),
            body: vec![0, 0xff, 7],
            meta: agent_meta(),
            ..Default::default()
        };
        let entry = send_new(&store, &spec, &[]).await.unwrap();

        let seen = seen.lock().await.clone().unwrap();
        assert_eq!(
            sent_headers(&seen)[..2],
            [
                ("host".to_string(), format!("127.0.0.1:{port}")),
                ("user-agent".to_string(), USER_AGENT.to_string()),
            ]
        );
        assert_eq!(seen.1, [0, 0xff, 7], "body byte-exact");
        assert!(USER_AGENT.starts_with("taphttp/"));

        assert_eq!(entry.origin, Origin::Send);
        assert_eq!(entry.replay_of, None);
        assert_eq!(entry.source, None);
        assert_eq!(entry.meta, agent_meta());
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.url, spec.url);
        assert_eq!(entry.host, "127.0.0.1");
        assert_eq!(entry.status, Some(200));
        assert_eq!(entry.req_body_bytes().unwrap(), Some(vec![0, 0xff, 7]));
        let to: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert_eq!(entry.peer, Some(to), "the address it connected to");
        assert_eq!(entry.req_headers.get("user-agent"), Some(USER_AGENT));
        let logged = storage::load_entries(&log).unwrap();
        assert_eq!(logged, [entry], "recorded once, as returned");
        assert!(
            !String::from_utf8_lossy(&seen.0.concat_bytes()).contains("T-3-meta-marker"),
            "meta never goes upstream"
        );
    }

    trait ConcatBytes {
        fn concat_bytes(&self) -> Vec<u8>;
    }
    impl ConcatBytes for Vec<(String, Vec<u8>)> {
        fn concat_bytes(&self) -> Vec<u8> {
            self.iter()
                .flat_map(|(k, v)| k.bytes().chain(v.iter().copied()))
                .collect()
        }
    }

    #[tokio::test]
    async fn send_adds_host_from_the_url_unless_given() {
        let store = Store::new(None, None).unwrap();
        let headers = |pairs: &[(&str, &str)]| {
            let mut h = Headers::new();
            for (k, v) in pairs {
                h.append(*k, *v);
            }
            h
        };

        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let spec = SendSpec {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{port}/"),
            req_headers: Some(headers(&[("accept", "*/*")])),
            ..Default::default()
        };
        send_new(&store, &spec, &[]).await.unwrap();
        let got = sent_headers(&seen.lock().await.clone().unwrap());
        assert_eq!(
            got,
            [
                ("host".to_string(), format!("127.0.0.1:{port}")),
                ("accept".to_string(), "*/*".to_string()),
            ],
            "no user-agent when the list is given"
        );

        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let spec = SendSpec {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{port}/"),
            req_headers: Some(headers(&[("x-a", "1"), ("Host", "virtual.example")])),
            ..Default::default()
        };
        send_new(&store, &spec, &[]).await.unwrap();
        let got = sent_headers(&seen.lock().await.clone().unwrap());
        assert_eq!(
            got,
            [
                ("x-a".to_string(), "1".to_string()),
                ("host".to_string(), "virtual.example".to_string()),
            ],
            "a given host is kept, once, where it was"
        );
    }

    #[tokio::test]
    async fn failed_send_is_recorded_with_its_error() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);
        let dir = TempDir::new().unwrap();
        let (store, log) = log_store(&dir);
        let spec = SendSpec {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{port}/"),
            meta: agent_meta(),
            ..Default::default()
        };
        let Err(ReplayError::Failed(entry)) = send_new(&store, &spec, &[]).await else {
            panic!("expected Failed");
        };
        assert_eq!(entry.origin, Origin::Send);
        assert_eq!(entry.status, None);
        assert!(
            entry.error.as_deref().unwrap().contains("onnect"),
            "{entry:?}"
        );
        assert_eq!(entry.meta, agent_meta());
        assert_eq!(storage::load_entries(&log).unwrap(), [*entry]);
    }

    #[tokio::test]
    async fn send_to_an_unresolvable_host_is_recorded_as_failed() {
        let dir = TempDir::new().unwrap();
        let (store, log) = log_store(&dir);
        let spec = SendSpec {
            method: "GET".into(),
            url: "http://no-such-host.invalid/".into(),
            ..Default::default()
        };
        let Err(ReplayError::Failed(entry)) = send_new(&store, &spec, &[]).await else {
            panic!("expected Failed");
        };
        assert!(
            entry
                .error
                .as_deref()
                .unwrap()
                .starts_with("resolving host"),
            "{entry:?}"
        );
        assert_eq!(entry.peer, None);
        assert_eq!(storage::load_entries(&log).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_send_is_neither_sent_nor_recorded() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let (store, log) = log_store(&dir);
        let ok = format!("http://127.0.0.1:{port}/");
        let mut bad_header = Headers::new();
        bad_header.append("bad header", "v");
        let cases = [
            (
                "GET",
                format!("ftp://127.0.0.1:{port}/"),
                None,
                BTreeMap::new(),
            ),
            ("GET", "/relative".to_string(), None, BTreeMap::new()),
            ("GET", "not a url".to_string(), None, BTreeMap::new()),
            ("BAD METHOD", ok.clone(), None, BTreeMap::new()),
            ("GET", ok.clone(), Some(bad_header), BTreeMap::new()),
            (
                "GET",
                ok.clone(),
                None,
                BTreeMap::from([(String::new(), "v".to_string())]),
            ),
        ];
        for (method, url, req_headers, meta) in cases {
            let spec = SendSpec {
                method: method.into(),
                url: url.clone(),
                req_headers,
                meta,
                ..Default::default()
            };
            let r = send_new(&store, &spec, &[]).await;
            assert!(
                matches!(r, Err(ReplayError::Invalid(_))),
                "{method} {url}: {r:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!hit.load(Ordering::SeqCst), "nothing sent");
        assert!(storage::load_entries(&log).unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn send_and_replay_refuse_taphttps_own_listeners() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let (store, log) = log_store(&dir);
        let own: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let any: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        for (url, own) in [
            (format!("http://127.0.0.1:{port}/"), own),
            (format!("http://localhost:{port}/"), own),
            (format!("http://127.0.0.1:{port}/"), any),
            (format!("https://127.0.0.1:{port}/"), own),
        ] {
            let spec = SendSpec {
                method: "GET".into(),
                url: url.clone(),
                ..Default::default()
            };
            let Err(ReplayError::Invalid(e)) = send_new(&store, &spec, &[own]).await else {
                panic!("{url} via {own}: expected Invalid");
            };
            assert!(e.to_string().contains("own listeners"), "{e}");
        }
        let r = replay_entry_refusing(
            &store,
            upstream_entry("self-1", port, "GET"),
            &ReplayMods::default(),
            &[own],
        )
        .await;
        assert!(matches!(r, Err(ReplayError::Invalid(_))), "{r:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!hit.load(Ordering::SeqCst), "never sent");
        assert!(storage::load_entries(&log).unwrap_or_default().is_empty());

        // Another port on the same host is fine.
        let other: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let spec = SendSpec {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{port}/"),
            ..Default::default()
        };
        send_new(&store, &spec, &[other]).await.unwrap();
        assert!(hit.load(Ordering::SeqCst));
    }

    /// The address checked against `own` is the one connected to: a name is
    /// never resolved a second time (DNS rebinding).
    #[tokio::test]
    async fn send_connects_only_to_the_checked_addresses() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let req = build_request(
            "GET",
            &format!("http://never-resolved.invalid:{port}/"),
            &Headers::new(),
            vec![],
        )
        .unwrap();
        let pinned = vec![SocketAddr::from(([127, 0, 0, 1], port))];
        let outcome = send(req, pinned).await;
        assert_eq!(outcome.error, None);
        assert_eq!(outcome.status, Some(200));
        assert!(hit.load(Ordering::SeqCst));
    }

    #[test]
    fn errors_read_for_send_as_well_as_replay() {
        let invalid = ReplayError::Invalid(anyhow::anyhow!("bad url"));
        assert_eq!(invalid.to_string(), "invalid request: bad url");
        let mut e = upstream_entry("f-1", 1, "GET");
        e.error = Some("connect refused".into());
        let failed = ReplayError::Failed(Box::new(e));
        assert_eq!(
            failed.to_string(),
            "request failed: connect refused (recorded as f-1)"
        );
    }

    #[test]
    fn own_target_matching() {
        let a = |s: &str| -> SocketAddr { s.parse().unwrap() };
        let lan: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        let local = move |ip: std::net::IpAddr| ip.to_canonical().is_loopback() || ip == lan;
        let own = |t: &str, o: &[&str]| {
            let o: Vec<SocketAddr> = o.iter().map(|s| a(s)).collect();
            is_own_target(a(t), &o, local)
        };
        assert!(own("127.0.0.1:8081", &["127.0.0.1:8080", "127.0.0.1:8081"]));
        assert!(!own("127.0.0.1:9", &["127.0.0.1:8081"]), "other port");
        assert!(!own("127.0.0.1:8081", &[]));
        // A wildcard listener is reached through any local address...
        assert!(own("10.1.2.3:8080", &["0.0.0.0:8080"]));
        assert!(own("127.0.0.1:8080", &["[::]:8080"]));
        // ...but not through another host's.
        assert!(!own("10.9.9.9:8080", &["0.0.0.0:8080"]));
        // A loopback listener isn't reachable through the LAN address.
        assert!(!own("10.1.2.3:8081", &["127.0.0.1:8081"]));
        // Connecting to 0.0.0.0 reaches this host.
        assert!(own("0.0.0.0:8081", &["127.0.0.1:8081"]));
        assert!(own("0.0.0.0:8080", &["0.0.0.0:8080"]));
        // IPv4-mapped IPv6 is the same address.
        assert!(own("[::ffff:127.0.0.1]:8081", &["127.0.0.1:8081"]));
        assert!(own("[::1]:8081", &["[::1]:8081"]));
    }

    #[test]
    fn local_ips_are_recognised() {
        assert!(is_local_ip("127.0.0.1".parse().unwrap()));
        assert!(is_local_ip("0.0.0.0".parse().unwrap()));
        // TEST-NET-3: never assigned to a host.
        assert!(!is_local_ip("203.0.113.9".parse().unwrap()));
    }

    /// A TLS server with a self-signed cert: nothing in webpki-roots
    /// trusts it, so an https replay must fail on the certificate.
    #[tokio::test]
    async fn https_replay_connects_and_verifies_the_certificate() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handshook = Arc::new(AtomicBool::new(false));
        let seen = handshook.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            seen.store(true, Ordering::SeqCst);
            let _ = acceptor.accept(stream).await;
        });

        let store = Store::new(None, None).unwrap();
        let mut original = upstream_entry("tls-1", port, "GET");
        original.url = format!("https://127.0.0.1:{port}/");
        let Err(ReplayError::Failed(entry)) =
            replay_entry(&store, original, &ReplayMods::default()).await
        else {
            panic!("expected Failed");
        };
        assert!(
            handshook.load(Ordering::SeqCst),
            "connected to the upstream"
        );
        let error = entry.error.unwrap();
        assert!(
            error.to_lowercase().contains("certificate"),
            "TLS was attempted and the cert checked: {error}"
        );
        let to: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert_eq!(
            entry.peer,
            Some(to),
            "connected, so known despite TLS failing"
        );
    }

    fn agent_meta() -> BTreeMap<String, String> {
        [
            ("actor", "agent"),
            ("task_id", "T-3-meta-marker"),
            ("audit_id", "audit-meta-marker"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[tokio::test]
    async fn meta_is_recorded_and_never_sent_upstream() {
        let seen: Seen = Default::default();
        let port = start_recording_server(seen.clone()).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(Some(&log), None).unwrap();
        let mods = ReplayMods {
            meta: agent_meta(),
            ..Default::default()
        };
        let replay = replay_entry(&store, upstream_entry("mt-1", port, "POST"), &mods)
            .await
            .unwrap();

        let (headers, body) = seen.lock().await.clone().unwrap();
        let mut sent = body;
        for (k, v) in &headers {
            sent.extend_from_slice(k.as_bytes());
            sent.extend_from_slice(v);
        }
        let sent = String::from_utf8_lossy(&sent);
        for needle in ["meta-marker", "audit", "task_id", "actor", "agent"] {
            assert!(!sent.contains(needle), "{needle} reached upstream: {sent}");
        }
        assert_eq!(replay.meta, agent_meta());
        assert_eq!(
            storage::load_entry(&log, &replay.id).unwrap().meta,
            agent_meta()
        );
    }

    #[tokio::test]
    async fn a_replay_does_not_inherit_the_originals_meta_or_error() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit).await;
        let store = Store::new(None, None).unwrap();
        let mut original = upstream_entry("inh-1", port, "GET");
        original.meta = agent_meta();
        original.error = Some("old failure".into());
        // Replaying a sent request is still a replay.
        original.origin = crate::storage::Origin::Send;
        original.peer = Some("192.0.2.1:9".parse().unwrap());
        let replay = replay_entry(&store, original, &ReplayMods::default())
            .await
            .unwrap();
        assert!(replay.meta.is_empty());
        assert_eq!(replay.error, None);
        assert_eq!(replay.origin, crate::storage::Origin::Replay);
        let to: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert_eq!(
            replay.peer,
            Some(to),
            "where the replay went, not the original"
        );
    }

    #[test]
    fn meta_limits_are_enforced() {
        let many: BTreeMap<String, String> = (0..=MAX_META_KEYS)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert!(validate_meta(&many).is_err());
        let at_limit: BTreeMap<String, String> = (0..MAX_META_KEYS)
            .map(|i| (format!("k{i}"), "v".repeat(MAX_META_VALUE_LEN)))
            .collect();
        assert!(validate_meta(&at_limit).is_ok());
        let long_key = BTreeMap::from([("k".repeat(MAX_META_KEY_LEN + 1), "v".to_string())]);
        assert!(validate_meta(&long_key).is_err());
        let empty_key = BTreeMap::from([(String::new(), "v".to_string())]);
        assert!(validate_meta(&empty_key).is_err());
        let long_value = BTreeMap::from([("k".to_string(), "v".repeat(MAX_META_VALUE_LEN + 1))]);
        assert!(validate_meta(&long_value).is_err());
        assert!(validate_meta(&agent_meta()).is_ok());
    }

    /// A port nothing listens on.
    async fn dead_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn failed_replay_is_recorded_exactly_once_with_its_error() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(Some(&log), None).unwrap();
        let mods = ReplayMods {
            meta: agent_meta(),
            ..Default::default()
        };
        let port = dead_port().await;
        let err = replay_entry(&store, upstream_entry("fail-1", port, "GET"), &mods)
            .await
            .unwrap_err();

        let ReplayError::Failed(entry) = err else {
            panic!("expected a recorded failure, got {err}");
        };
        assert_eq!(entry.replay_of.as_deref(), Some("fail-1"));
        assert_eq!(entry.status, None);
        assert!(entry.res_headers.is_empty() && entry.res_body.is_none());
        let error = entry.error.as_deref().unwrap();
        assert!(error.contains("connect"), "{error}");
        assert_eq!(entry.peer, None, "never connected");
        assert_eq!(entry.meta, agent_meta());
        let logged = storage::load_entries(&log).unwrap();
        assert_eq!(logged.len(), 1, "exactly one recorded exchange");
        assert_eq!(logged[0], *entry);
    }

    /// Upstream that sends a 200 head promising 100 bytes, sends 5, and hangs up.
    async fn start_truncating_server() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\nx-up: yes\r\n\r\nhello")
                .await
                .unwrap();
        });
        port
    }

    #[tokio::test]
    async fn response_that_breaks_off_keeps_its_status_and_records_the_error() {
        let port = start_truncating_server().await;
        let store = Store::new(None, None).unwrap();
        let err = replay_entry(
            &store,
            upstream_entry("cut-1", port, "GET"),
            &ReplayMods::default(),
        )
        .await
        .unwrap_err();
        let ReplayError::Failed(entry) = err else {
            panic!("expected a recorded failure, got {err}");
        };
        assert_eq!(entry.status, Some(200));
        assert_eq!(entry.res_headers.get("x-up"), Some("yes"));
        let error = entry.error.as_deref().unwrap();
        assert!(error.contains("response body"), "{error}");
        assert!(entry.peer.is_some(), "the head arrived, so it connected");
    }

    #[tokio::test]
    async fn invalid_replay_is_rejected_unsent_and_unrecorded() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(Some(&log), None).unwrap();

        let bad_header = mods_with_headers(&[("bad header", "v")]);
        let bad_value = mods_with_headers(&[("x-ok", "line\nbreak")]);
        let bad_method = ReplayMods {
            method: Some("GE T".into()),
            ..Default::default()
        };
        let bad_meta = ReplayMods {
            meta: BTreeMap::from([(String::new(), "v".to_string())]),
            ..Default::default()
        };
        for mods in [bad_header, bad_value, bad_method, bad_meta] {
            let err = replay_entry(&store, upstream_entry("inv-1", port, "GET"), &mods)
                .await
                .unwrap_err();
            assert!(matches!(err, ReplayError::Invalid(_)), "{err}");
        }
        for url in ["/relative", "ftp://127.0.0.1/x"] {
            let mut e = upstream_entry("inv-2", port, "GET");
            e.url = url.into();
            let err = replay_entry(&store, e, &ReplayMods::default())
                .await
                .unwrap_err();
            assert!(matches!(err, ReplayError::Invalid(_)), "{url}: {err}");
        }

        assert!(!hit.load(Ordering::SeqCst), "nothing was sent");
        assert!(!log.exists() || storage::load_entries(&log).unwrap().is_empty());
    }

    #[tokio::test]
    async fn cli_replay_failure_is_recorded_and_names_the_entry() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let port = dead_port().await;
        JsonLinesBackend::new(&log)
            .append(&upstream_entry("cli-fail", port, "GET"))
            .unwrap();
        let args = ReplayArgs {
            id: "cli-fail".to_string(),
            log_file: Some(log.clone()),
            method: None,
            headers: vec![],
            body: None,
        };
        let err = format!(
            "{:#}",
            run(args, dir.path().to_path_buf()).await.unwrap_err()
        );
        let logged = storage::load_entries(&log).unwrap();
        assert_eq!(logged.len(), 2, "original plus the failed attempt");
        let failed = &logged[1];
        assert_eq!(failed.replay_of.as_deref(), Some("cli-fail"));
        assert!(failed.error.is_some());
        assert!(err.contains(&failed.id), "error names the record: {err}");
    }

    #[tokio::test]
    async fn replay_entry_applies_method_override() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;
        let dir = TempDir::new().unwrap();
        let store = Store::new(Some(&dir.path().join("traffic.jsonl")), None).unwrap();

        let mods = ReplayMods {
            method: Some("post".to_string()),
            ..Default::default()
        };
        let replay = replay_entry(&store, upstream_entry("orig-2", port, "GET"), &mods)
            .await
            .unwrap();

        assert_eq!(
            replay.method, "POST",
            "method override is applied and upcased"
        );
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
            ts: taphttp_types::Timestamp::now(),
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
            source: None,
            meta: Default::default(),
            error: None,
            origin: crate::storage::Origin::Proxy,
            peer: None,
            refused: false,
        };

        JsonLinesBackend::new(&data_dir.join("traffic.jsonl"))
            .append(&entry)
            .unwrap();

        let args = ReplayArgs {
            id: "replay-test-id".to_string(),
            log_file: None,
            method: None,
            headers: vec![],
            body: None,
        };

        run(args, data_dir).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            hit.load(Ordering::SeqCst),
            "capture server should have been hit by replay"
        );
    }

    #[tokio::test]
    async fn replay_applies_method_and_header_overrides() {
        let hit = Arc::new(AtomicBool::new(false));
        let port = start_capture_server(hit.clone()).await;

        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_path_buf();

        let entry = TrafficEntry {
            id: "override-id".to_string(),
            ts: taphttp_types::Timestamp::now(),
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
            source: None,
            meta: Default::default(),
            error: None,
            origin: crate::storage::Origin::Proxy,
            peer: None,
            refused: false,
        };

        JsonLinesBackend::new(&data_dir.join("traffic.jsonl"))
            .append(&entry)
            .unwrap();

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
        JsonLinesBackend::new(&log)
            .append(&upstream_entry("custom-log-id", port, "GET"))
            .unwrap();

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
            logged
                .iter()
                .any(|e| e.replay_of.as_deref() == Some("custom-log-id")),
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
        let err = format!(
            "{:#}",
            run(args, data_dir.path().to_path_buf()).await.unwrap_err()
        );
        assert!(
            err.contains("traffic.jsonl"),
            "error should name the path: {err}"
        );
        assert!(
            err.contains("--log-file"),
            "error should point at --log-file: {err}"
        );
    }

    #[tokio::test]
    async fn replay_errors_on_missing_id() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_path_buf();
        JsonLinesBackend::new(&data_dir.join("traffic.jsonl"))
            .append(&TrafficEntry {
                id: "some-id".to_string(),
                ts: taphttp_types::Timestamp::now(),
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
                source: None,
                meta: Default::default(),
                error: None,
                origin: crate::storage::Origin::Proxy,
                peer: None,
                refused: false,
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
