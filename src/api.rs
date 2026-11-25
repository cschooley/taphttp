//! The lever API: a small HTTP/WebSocket surface over the store that the
//! SPA and the MCP server both consume. It owns no logic of its own — every
//! endpoint delegates to the same store levers (`query_entries`, `subscribe`)
//! the CLI and the future in-process MCP handler use.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as PathParam, Query, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::ca::CaCert;
use crate::deploy::DeploymentInfo;
use crate::history::{HistoryError, HistoryQuery};
use crate::replay::{replay_entry_refusing, send_new, ReplayError, ReplayMods, SendSpec};
use crate::storage::{Headers, SqliteBackend, Store, TrafficEntry, SCHEMA_VERSION};
use taphttp_types::{decode_body, BodyEncoding};

/// Shared state for the lever API handlers.
pub struct ApiState {
    /// Live-feed source and, via its sqlite backend, the history every
    /// read endpoint serves. `start --api-listen` always records to sqlite.
    pub store: Arc<Store>,
    /// Secret required on every request. The traffic this API exposes and
    /// (soon) replays includes captured credentials, so the surface is
    /// authenticated even on loopback.
    pub token: String,
    /// What `GET /info` reports.
    pub info: DeploymentInfo,
    /// What `GET /ca.pem` and `GET /ca.der` serve: the public certificate
    /// only. The key never reaches the API.
    pub ca_cert: CaCert,
    /// taphttp's own bound listeners (proxy and API). `/send` and `/replay`
    /// refuse targets that resolve to one of them.
    pub own: Vec<std::net::SocketAddr>,
    /// `POST /send` is on unless `start --api-no-send`.
    pub send_enabled: bool,
    /// Proxy credentials issued with `POST /clients`, shared with the proxy,
    /// which enforces them.
    pub clients: Arc<crate::clients::Registry>,
}

/// Generate a fresh random API token (122 bits from a v4 UUID).
pub fn generate_token() -> String {
    Uuid::new_v4().simple().to_string()
}

/// Persist the token to `<data_dir>/api-token` with owner-only permissions,
/// so sibling tools (the MCP server, scripts) on the same machine can read it.
pub fn write_token_file(data_dir: &Path, token: &str) -> Result<PathBuf> {
    let path = data_dir.join("api-token");
    std::fs::write(&path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// Use the token in `path`, or create one there. If the file exists its
/// contents (trimmed) are the token, so a token kept on a volume survives
/// restarts. Otherwise a fresh token is written with mode 0600, created that
/// way so it is never readable by others, even briefly.
pub fn load_or_create_token_file(path: &Path) -> Result<String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            let token = generate_token();
            f.write_all(token.as_bytes())
                .with_context(|| format!("writing API token to {}", path.display()))?;
            Ok(token)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let token = std::fs::read_to_string(path)
                .with_context(|| format!("reading API token from {}", path.display()))?
                .trim()
                .to_string();
            if token.is_empty() {
                bail!(
                    "API token file {} is empty; delete it to have a token generated, or write one into it",
                    path.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)?.permissions().mode();
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        "API token file {} is readable by group/others (mode {:o}); run `chmod 600` on it",
                        path.display(),
                        mode & 0o777
                    );
                }
            }
            Ok(token)
        }
        Err(e) => Err(e).with_context(|| {
            format!(
                "creating API token file {} (is its directory writable?)",
                path.display()
            )
        }),
    }
}

/// Build the router. Kept separate from [`serve`] so tests can drive it
/// without binding a socket.
pub fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/schema", get(schema))
        .route("/info", get(info))
        .route("/ca.pem", get(ca_pem))
        .route("/ca.der", get(ca_der))
        .route("/exchanges", get(exchanges))
        .route("/exchanges/{id}", get(exchange))
        .route("/exchanges/{id}/messages", get(exchange_messages))
        .route("/feed", get(feed))
        .route("/replay", post(replay))
        .route("/send", post(send))
        .route(
            "/clients",
            post(issue_client)
                .get(list_clients)
                .delete(revoke_all_clients),
        )
        .route("/clients/{id}", axum::routing::delete(revoke_client))
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state)
}

/// Reject any request that does not carry the API token. The token may arrive
/// as `Authorization: Bearer <token>` (HTTP clients, the MCP server) or as a
/// `?token=<token>` query parameter — the fallback for browsers, which cannot
/// set headers on a WebSocket handshake, so the SPA's `/feed` uses it.
async fn require_token(State(state): State<Arc<ApiState>>, req: Request, next: Next) -> Response {
    let authorized = {
        let from_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let from_query = req.uri().query().and_then(token_from_query);
        from_header
            .or(from_query)
            .is_some_and(|t| constant_time_eq(t, &state.token))
    };
    if authorized {
        next.run(req).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

/// Pull `token` out of a `&`-separated query string, if present.
fn token_from_query(query: &str) -> Option<&str> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
}

/// Constant-time comparison so token validation does not leak the secret
/// through response timing. Length is not secret; a length mismatch returns
/// early.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Serve the lever API on `listener` until the process exits, over TLS
/// when `tls` is given.
pub async fn serve(
    state: Arc<ApiState>,
    listener: tokio::net::TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let bound = listener.local_addr()?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!("lever API listening on {scheme}://{bound}");
    eprintln!("lever API listening on {scheme}://{bound}");
    match tls {
        None => axum::serve(listener, router(state)).await?,
        Some(cfg) => serve_tls(listener, router(state), cfg).await?,
    }
    Ok(())
}

/// Accept TLS connections and serve `app` on each (HTTP/1.1, with upgrades
/// so the `/feed` WebSocket works).
async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: Router,
    cfg: Arc<rustls::ServerConfig>,
) -> Result<()> {
    use tower::ServiceExt;
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!("lever API TLS handshake from {peer}: {e}");
                    return;
                }
            };
            let svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    app.clone().oneshot(req)
                });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .with_upgrades()
                .await
            {
                tracing::debug!("lever API connection from {peer}: {e}");
            }
        });
    }
}

/// `GET /schema` — the schema contract the SPA and MCP pin against.
async fn schema() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "schema_version": SCHEMA_VERSION }))
}

/// `GET /info` — this deployment's version, listeners, auth mode, expiry,
/// CA public details and history backends. No secrets and no paths.
async fn info(State(state): State<Arc<ApiState>>) -> Json<DeploymentInfo> {
    Json(state.info.clone())
}

/// `GET /ca.pem` — the CA certificate to install, the one whose pin `/info`
/// reports as `ca.sha256`.
async fn ca_pem(State(state): State<Arc<ApiState>>) -> Response {
    download(
        crate::ca::PEM_CONTENT_TYPE,
        crate::ca::PEM_FILENAME,
        state.ca_cert.pem.clone().into_bytes(),
    )
}

/// `GET /ca.der` — the same certificate as DER (Android, some Windows
/// dialogs).
async fn ca_der(State(state): State<Arc<ApiState>>) -> Response {
    download(
        crate::ca::DER_CONTENT_TYPE,
        crate::ca::DER_FILENAME,
        state.ca_cert.der.clone(),
    )
}

fn download(content_type: &'static str, filename: &'static str, body: Vec<u8>) -> Response {
    (
        [
            (axum::http::header::CONTENT_TYPE, content_type.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

fn no_history() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "no sqlite history configured",
    )
        .into_response()
}

fn db_error(e: impl std::fmt::Display) -> Response {
    tracing::warn!("lever API history error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("history error: {e}"),
    )
        .into_response()
}

/// `GET /exchanges` — history, newest first. Filters: `host`, `method`,
/// `status`, `q` (URL or host text), `since` / `until` (RFC 3339),
/// `replay_of` (an exchange's replays). Paging:
/// `limit` (default 100, max 500) and `before=<id>` (the last id of the
/// previous page). An unknown `before` id is a 404.
async fn exchanges(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<HistoryQuery>,
) -> Response {
    let Some(history) = state.store.history() else {
        return no_history();
    };
    match history.query(&query) {
        Ok(entries) => Json(entries).into_response(),
        Err(HistoryError::UnknownCursor(id)) => (
            StatusCode::NOT_FOUND,
            format!("unknown cursor: no exchange with id {id}"),
        )
            .into_response(),
        Err(HistoryError::Db(e)) => db_error(e),
    }
}

/// `GET /exchanges/{id}` — a single exchange by id (indexed), or 404.
#[derive(Deserialize)]
struct MessagesParams {
    /// Only messages after this `seq`.
    after: Option<u64>,
    limit: Option<usize>,
}

/// `GET /exchanges/{id}/messages` — the WebSocket messages or SSE events
/// recorded on an exchange, in order, paged by `?after=<seq>&limit=N`
/// (default 100, at most 1000). 404 if there is no such exchange.
async fn exchange_messages(
    State(state): State<Arc<ApiState>>,
    PathParam(id): PathParam<String>,
    Query(p): Query<MessagesParams>,
) -> Response {
    let Some(history) = state.store.history() else {
        return no_history();
    };
    let limit = p.limit.unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return (StatusCode::BAD_REQUEST, "limit must be 1 to 1000").into_response();
    }
    match history.get(&id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no exchange with id {id}")).into_response()
        }
        Err(e) => return db_error(e),
    }
    match history.messages(&id, p.after, limit) {
        Ok(messages) => Json(messages).into_response(),
        Err(e) => db_error(e),
    }
}

async fn exchange(
    State(state): State<Arc<ApiState>>,
    PathParam(id): PathParam<String>,
) -> Response {
    let Some(history) = state.store.history() else {
        return no_history();
    };
    match history.get(&id) {
        Ok(Some(entry)) => Json(entry).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, format!("no exchange with id {id}")).into_response(),
        Err(e) => db_error(e),
    }
}

/// Body of a `POST /replay` request: which captured exchange to replay, and
/// optional modifications to apply before sending.
#[derive(Debug, Deserialize)]
struct ReplayRequest {
    id: String,
    #[serde(default)]
    method: Option<String>,
    /// The whole request header list, `[[name, value], ...]`: replaces the
    /// captured headers, in order, repeats kept.
    #[serde(default)]
    req_headers: Option<Headers>,
    /// Headers set over the captured ones (or over `req_headers`), one
    /// value per name. Kept for clients from before `req_headers`.
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    /// How `body` encodes the bytes: `"utf8"` (default, also `null`) or
    /// `"base64"`.
    #[serde(default)]
    body_encoding: Option<BodyEncoding>,
    /// Attribution stored on the recorded replay, never sent upstream.
    #[serde(default)]
    meta: BTreeMap<String, String>,
}

/// `POST /replay` — replay a captured exchange by id, record the result as a
/// new exchange linked via `replay_of`, and return that recorded entry.
/// A failed attempt is recorded too and returned with 502 (its `error`
/// says why); a request that can't be built is 400 and isn't recorded.
async fn replay(State(state): State<Arc<ApiState>>, Json(req): Json<ReplayRequest>) -> Response {
    let Some(history) = state.store.history() else {
        return no_history();
    };
    let original = match history.get(&req.id) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                format!("no exchange with id {}", req.id),
            )
                .into_response()
        }
        Err(e) => return db_error(e),
    };

    let body = match decode_body(req.body.as_deref(), req.body_encoding.unwrap_or_default()) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("body: {e}")).into_response(),
    };
    let mods = ReplayMods {
        method: req.method,
        req_headers: req.req_headers,
        headers: req.headers.into_iter().collect(),
        body,
        meta: req.meta,
    };
    outcome(replay_entry_refusing(&state.store, original, &mods, &state.own).await)
}

/// 200 with the recorded entry, 502 with the recorded failed attempt, or
/// 400 when nothing was sent.
/// `POST /clients` — issue a proxy credential with its allowlist, rate,
/// budget and meta. 201 with the credential; the password is shown only
/// here.
async fn issue_client(State(state): State<Arc<ApiState>>, body: axum::body::Bytes) -> Response {
    let issued = crate::clients::parse_spec(&body).and_then(|spec| state.clients.issue(spec));
    match issued {
        Ok(issued) => (StatusCode::CREATED, Json(issued)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e:#}")).into_response(),
    }
}

/// `GET /clients` — every issued credential with its counts.
async fn list_clients(State(state): State<Arc<ApiState>>) -> Response {
    Json(state.clients.list()).into_response()
}

/// `DELETE /clients/{id}` — revoke one credential; its open connections
/// close.
async fn revoke_client(
    State(state): State<Arc<ApiState>>,
    PathParam(id): PathParam<String>,
) -> Response {
    if state.clients.revoke(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "no such client").into_response()
    }
}

/// `DELETE /clients` — revoke every credential at once (an e-stop).
async fn revoke_all_clients(State(state): State<Arc<ApiState>>) -> Response {
    let n = state.clients.revoke_all();
    Json(serde_json::json!({ "revoked": n })).into_response()
}

fn outcome(r: Result<TrafficEntry, ReplayError>) -> Response {
    match r {
        Ok(entry) => Json(entry).into_response(),
        Err(ReplayError::Failed(entry)) => (StatusCode::BAD_GATEWAY, Json(*entry)).into_response(),
        Err(e @ ReplayError::Invalid(_)) => {
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
        }
    }
}

/// Body of a `POST /send` request: a new request, not a replay.
#[derive(Debug, Deserialize)]
struct SendRequest {
    /// Default `GET`.
    #[serde(default)]
    method: Option<String>,
    url: String,
    /// The whole request header list, `[[name, value], ...]`. Absent: a
    /// `user-agent` naming taphttp. `host` is added from the URL unless
    /// the list has one.
    #[serde(default)]
    req_headers: Option<Headers>,
    #[serde(default)]
    body: Option<String>,
    /// `"utf8"` (default, also `null`) or `"base64"`.
    #[serde(default)]
    body_encoding: Option<BodyEncoding>,
    /// Attribution stored on the recorded entry, never sent upstream.
    #[serde(default)]
    meta: BTreeMap<String, String>,
}

/// `POST /send` — send a new request to any http(s) URL through taphttp,
/// record it with `origin: "send"`, and return the recorded entry. Same
/// outcomes as `/replay`. Refuses taphttp's own listeners, and is 403 when
/// started with `--api-no-send`.
async fn send(State(state): State<Arc<ApiState>>, Json(req): Json<SendRequest>) -> Response {
    if !state.send_enabled {
        return (
            StatusCode::FORBIDDEN,
            "POST /send is turned off (start --api-no-send)",
        )
            .into_response();
    }
    let body = match decode_body(req.body.as_deref(), req.body_encoding.unwrap_or_default()) {
        Ok(b) => b.unwrap_or_default(),
        Err(e) => return (StatusCode::BAD_REQUEST, format!("body: {e}")).into_response(),
    };
    let spec = SendSpec {
        method: req.method.unwrap_or_else(|| "GET".into()),
        url: req.url,
        req_headers: req.req_headers,
        body,
        meta: req.meta,
    };
    outcome(send_new(&state.store, &spec, &state.own).await)
}

#[derive(Debug, Deserialize)]
struct FeedParams {
    /// Resume: first send every entry recorded after this id, then go live.
    since: Option<String>,
}

/// Backlog page size when replaying `since` history onto the feed.
const FEED_BACKLOG_PAGE: usize = 500;

/// `GET /feed` — WebSocket of recorded entries.
///
/// Every text frame is JSON. A frame is either a [`TrafficEntry`] (the same
/// JSON as `/exchanges`; it has no `type` key) or a control frame, which
/// always has a `type`:
/// - `{"type":"reset","since":"<id>"}`: `since` names no exchange (e.g. the
///   database was reset). Nothing was replayed; the feed continues live.
///   Re-sync from `GET /exchanges`.
/// - `{"type":"lagged","skipped":N}`: this client fell behind and N live
///   entries were dropped. Reconnect with `?since=<last id received>`.
/// - `{"type":"message","message":{...}}`: a WebSocket message or SSE event
///   recorded on an exchange already sent. Live only: `since` replays
///   exchanges, not messages (`GET /exchanges/{id}/messages` has them).
///
/// With `?since=<id>`, entries recorded after `<id>` are sent first, oldest
/// first, then live entries, with no gap and no duplicates.
async fn feed(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<FeedParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // Subscribe before reading history: anything recorded from here on is
    // in the channel, and anything recorded earlier is already in sqlite
    // (record writes sqlite before broadcasting), so nothing falls between.
    let rx = state.store.subscribe();
    ws.on_upgrade(move |socket| pump_feed(socket, rx, state, params.since))
}

async fn send_json(socket: &mut WebSocket, value: &impl serde::Serialize) -> bool {
    let Ok(text) = serde_json::to_string(value) else {
        return true;
    };
    socket.send(Message::Text(text.into())).await.is_ok()
}

/// Send the `since` backlog, returning the ids sent (so the live phase can
/// skip entries that arrived in both), or `None` if the client went away.
async fn send_backlog(
    socket: &mut WebSocket,
    history: Option<&SqliteBackend>,
    since: &str,
) -> Option<HashSet<String>> {
    let mut sent = HashSet::new();
    let start = history.and_then(|h| h.rowid_of(since).ok().flatten());
    let (Some(history), Some(mut pos)) = (history, start) else {
        let reset = serde_json::json!({ "type": "reset", "since": since });
        return send_json(socket, &reset).await.then_some(sent);
    };
    loop {
        let page = match history.after(pos, FEED_BACKLOG_PAGE) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("feed backlog: {e}");
                return Some(sent);
            }
        };
        if page.is_empty() {
            return Some(sent);
        }
        for (rowid, entry) in page {
            pos = rowid;
            if !send_json(socket, &entry).await {
                return None;
            }
            sent.insert(entry.id);
        }
    }
}

async fn pump_feed(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<crate::storage::Live>,
    state: Arc<ApiState>,
    since: Option<String>,
) {
    let mut already_sent = match &since {
        Some(id) => match send_backlog(&mut socket, state.store.history(), id).await {
            Some(sent) => sent,
            None => return,
        },
        None => HashSet::new(),
    };
    loop {
        match rx.recv().await {
            Ok(crate::storage::Live::Entry(entry)) => {
                // Recorded after subscribing but already sent from history.
                if already_sent.remove(&entry.id) {
                    continue;
                }
                if !send_json(&mut socket, &entry).await {
                    break;
                }
            }
            Ok(crate::storage::Live::Message(message)) => {
                let frame = serde_json::json!({ "type": "message", "message": message });
                if !send_json(&mut socket, &frame).await {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                let lagged = serde_json::json!({ "type": "lagged", "skipped": skipped });
                if !send_json(&mut socket, &lagged).await {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures_util::StreamExt;
    use std::net::SocketAddr;
    use tempfile::TempDir;
    use tower::ServiceExt; // for `oneshot`

    const TEST_TOKEN: &str = "test-token-xyz";

    fn entry(id: &str, host: &str, method: &str, status: u16) -> TrafficEntry {
        TrafficEntry {
            id: id.to_string(),
            ts: taphttp_types::Timestamp::now(),
            host: host.to_string(),
            method: method.to_string(),
            url: format!("http://{host}/"),
            req_headers: Default::default(),
            req_body: None,
            req_body_encoding: Default::default(),
            status: Some(status),
            res_headers: Default::default(),
            res_body: None,
            res_body_encoding: Default::default(),
            duration_ms: Some(1),
            replay_of: None,
            source: None,
            meta: Default::default(),
            error: None,
            origin: crate::storage::Origin::Proxy,
            peer: None,
            refused: false,
        }
    }

    /// Writes straight into the API's sqlite history (no stdout/feed).
    struct Hist(Arc<Store>);
    impl Hist {
        fn append(&self, e: &TrafficEntry) -> Result<()> {
            self.0.history().unwrap().append(e)
        }
    }

    fn state_with_db(dir: &TempDir) -> (Arc<ApiState>, Hist) {
        let store = Store::new(None, Some(&dir.path().join("traffic.db"))).unwrap();
        let state = Arc::new(ApiState {
            store: store.clone(),
            token: TEST_TOKEN.to_string(),
            info: test_info(),
            ca_cert: test_ca_cert(),
            own: vec![],
            send_enabled: true,
            clients: Default::default(),
        });
        (state, Hist(store))
    }

    fn test_info() -> DeploymentInfo {
        let exposure = crate::deploy::Exposure {
            proxy: "127.0.0.1:8080".parse().ok(),
            api: "127.0.0.1:8081".parse().ok(),
            ..Default::default()
        };
        let banner = crate::deploy::BannerInfo {
            exposure,
            ..Default::default()
        };
        let ca = crate::ca::CaPublicInfo {
            subject: "CN=test".into(),
            sha256: "AB:CD".into(),
            not_before: "2024-01-01T00:00:00Z".parse().unwrap(),
            not_after: "2035-01-01T00:00:00Z".parse().unwrap(),
        };
        let history = crate::deploy::HistoryInfo {
            sqlite: true,
            log_file: false,
        };
        crate::deploy::deployment_info(&banner, ca, history, taphttp_types::Timestamp::now(), true)
            .unwrap()
    }

    #[tokio::test]
    async fn info_endpoint_returns_the_deployment_info() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let resp = router(state.clone())
            .oneshot(authed_get("/info"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await,
            serde_json::to_value(&state.info).unwrap()
        );
    }

    #[tokio::test]
    async fn info_endpoint_requires_token() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let resp = router(state)
            .oneshot(Request::get("/info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    fn test_ca_cert() -> crate::ca::CaCert {
        crate::ca::CaCert {
            pem: "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n".into(),
            der: vec![0, 1, 2, 0xff],
        }
    }

    async fn body_bytes(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn ca_endpoints_serve_the_public_cert_as_pem_and_der() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        for (path, ctype, file, body) in [
            (
                "/ca.pem",
                "application/x-pem-file",
                "taphttp-ca.pem",
                state.ca_cert.pem.as_bytes().to_vec(),
            ),
            (
                "/ca.der",
                "application/x-x509-ca-cert",
                "taphttp-ca.der",
                state.ca_cert.der.clone(),
            ),
        ] {
            let resp = router(state.clone())
                .oneshot(authed_get(path))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            let h = resp.headers();
            assert_eq!(h["content-type"], ctype, "{path}");
            assert_eq!(
                h["content-disposition"],
                format!("attachment; filename=\"{file}\"").as_str(),
                "{path}"
            );
            assert_eq!(body_bytes(resp).await, body, "{path}");
        }
    }

    #[tokio::test]
    async fn ca_endpoints_require_token() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        for path in ["/ca.pem", "/ca.der"] {
            let resp = router(state.clone())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    /// A GET request carrying the valid bearer token.
    fn authed_get(path: &str) -> Request<Body> {
        Request::get(path)
            .header(AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // --- auth ---

    #[tokio::test]
    async fn request_without_token_is_unauthorized() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let resp = router(state)
            .oneshot(Request::get("/schema").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_wrong_token_is_unauthorized() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let resp = router(state)
            .oneshot(
                Request::get("/schema")
                    .header(AUTHORIZATION, "Bearer not-the-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_via_query_param_is_accepted() {
        // The WebSocket-compatible path a browser SPA must use.
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let resp = router(state)
            .oneshot(
                Request::get(format!("/schema?token={TEST_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn constant_time_eq_matches_only_identical_strings() {
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "x"));
    }

    #[test]
    fn token_from_query_extracts_value() {
        assert_eq!(token_from_query("token=abc"), Some("abc"));
        assert_eq!(token_from_query("foo=1&token=abc&bar=2"), Some("abc"));
        assert_eq!(token_from_query("foo=1"), None);
    }

    #[test]
    fn generate_token_is_nonempty_and_unique() {
        let (a, b) = (generate_token(), generate_token());
        assert!(!a.is_empty());
        assert_ne!(a, b);
    }

    #[test]
    fn write_token_file_is_owner_only() {
        let dir = TempDir::new().unwrap();
        let path = write_token_file(dir.path(), "secret").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "token file must be owner-only");
        }
    }

    // --- endpoints (behind auth) ---

    #[tokio::test]
    async fn schema_endpoint_reports_version() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let resp = router(state).oneshot(authed_get("/schema")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn exchanges_returns_filtered_history() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        let backend = &log;
        backend
            .append(&entry("a", "api.example.com", "GET", 200))
            .unwrap();
        backend
            .append(&entry("b", "api.example.com", "POST", 201))
            .unwrap();
        backend.append(&entry("c", "other.io", "GET", 404)).unwrap();

        let resp = router(state)
            .oneshot(authed_get("/exchanges?method=GET"))
            .await
            .unwrap();
        let json = body_json(resp).await;
        let ids: Vec<&str> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["c", "a"], "newest first");
    }

    #[tokio::test]
    async fn exchange_by_id_returns_the_entry() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        let backend = &log;
        backend.append(&entry("a", "x.com", "GET", 200)).unwrap();
        backend.append(&entry("b", "y.com", "POST", 201)).unwrap();

        let resp = router(state)
            .oneshot(authed_get("/exchanges/b"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["id"], "b");
        assert_eq!(json["method"], "POST");
    }

    #[tokio::test]
    async fn exchange_by_id_unknown_is_not_found() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        log.append(&entry("a", "x.com", "GET", 200)).unwrap();

        let resp = router(state)
            .oneshot(authed_get("/exchanges/missing"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn history_endpoints_without_sqlite_are_unavailable() {
        let store = Store::new(None, None).unwrap();
        let state = Arc::new(ApiState {
            store,
            token: TEST_TOKEN.to_string(),
            info: test_info(),
            ca_cert: test_ca_cert(),
            own: vec![],
            send_enabled: true,
            clients: Default::default(),
        });
        for path in ["/exchanges", "/exchanges/x"] {
            let resp = router(state.clone())
                .oneshot(authed_get(path))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        }
    }

    // --- history paging / search ---

    #[tokio::test]
    async fn exchanges_pages_back_with_before_cursor() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        for i in 0..7 {
            log.append(&entry(&format!("e{i}"), "x.com", "GET", 200))
                .unwrap();
        }
        let page = |q: String| {
            let state = state.clone();
            async move {
                let json = body_json(router(state).oneshot(authed_get(&q)).await.unwrap()).await;
                json.as_array()
                    .unwrap()
                    .iter()
                    .map(|e| e["id"].as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(page("/exchanges?limit=3".into()).await, ["e6", "e5", "e4"]);
        assert_eq!(
            page("/exchanges?limit=3&before=e4".into()).await,
            ["e3", "e2", "e1"]
        );
        assert_eq!(page("/exchanges?limit=3&before=e1".into()).await, ["e0"]);
    }

    #[tokio::test]
    async fn exchanges_unknown_cursor_is_not_found() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let resp = router(state)
            .oneshot(authed_get("/exchanges?before=gone"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn exchanges_text_search_and_time_range() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        let mut a = entry("a", "api.example.com", "GET", 200);
        a.url = "https://api.example.com/login".into();
        a.ts = "2026-01-01T00:00:00Z".parse().unwrap();
        let mut b = entry("b", "api.example.com", "GET", 200);
        b.url = "https://api.example.com/login?next=1".into();
        b.ts = "2026-06-01T00:00:00Z".parse().unwrap();
        log.append(&a).unwrap();
        log.append(&b).unwrap();
        log.append(&entry("c", "other.io", "GET", 200)).unwrap();

        let json = body_json(
            router(state.clone())
                .oneshot(authed_get("/exchanges?q=login"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(json.as_array().unwrap().len(), 2);
        let json = body_json(
            router(state)
                .oneshot(authed_get("/exchanges?q=login&since=2026-03-01T00:00:00Z"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(json[0]["id"], "b");
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn exchanges_return_v3_entries() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        let mut e = entry("v3", "h", "GET", 200);
        e.res_headers.append("set-cookie", "a=1");
        e.res_headers.append("set-cookie", "b=2");
        log.append(&e).unwrap();
        let json = body_json(
            router(state)
                .oneshot(authed_get("/exchanges/v3"))
                .await
                .unwrap(),
        )
        .await;
        let back: TrafficEntry = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, e);
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
    }

    // --- token file ---

    #[test]
    fn token_file_is_created_owner_only_and_reused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("api-token");
        let first = load_or_create_token_file(&path).unwrap();
        assert!(!first.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A restart with the file kept gets the same token.
        assert_eq!(load_or_create_token_file(&path).unwrap(), first);
    }

    #[test]
    fn token_file_with_contents_is_used_trimmed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("api-token");
        std::fs::write(&path, "provisioned-token\n").unwrap();
        assert_eq!(
            load_or_create_token_file(&path).unwrap(),
            "provisioned-token"
        );
    }

    #[test]
    fn empty_token_file_is_an_error_that_says_what_to_do() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("api-token");
        std::fs::write(&path, "  \n").unwrap();
        let err = load_or_create_token_file(&path).unwrap_err().to_string();
        assert!(err.contains("empty") && err.contains("delete it"), "{err}");
    }

    #[test]
    fn token_file_in_missing_directory_errors() {
        let dir = TempDir::new().unwrap();
        assert!(load_or_create_token_file(&dir.path().join("no/such/dir/tok")).is_err());
    }

    #[tokio::test]
    async fn feed_streams_entries_recorded_after_connect() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let store = state.store.clone();

        // Real server on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });

        // Browsers can't set headers on a WS handshake, so authenticate via
        // the query param — the exact path the SPA's live feed will use.
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/feed?token={TEST_TOKEN}"))
                .await
                .unwrap();

        // Record after the socket is connected; the feed is live, not a replay.
        store.record(entry("live-42", "example.com", "GET", 200));

        let msg = ws.next().await.unwrap().unwrap();
        let json: serde_json::Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_eq!(json["id"], "live-42");

        ws.close(None).await.ok();
    }

    #[tokio::test]
    async fn replay_endpoint_records_and_returns_linked_entry() {
        // A throwaway upstream the replayed request will hit.
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uport = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = Router::new().route("/", get(|| async { "pong" }));
            axum::serve(upstream, app).await.unwrap();
        });

        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        let mut original = entry("orig-99", &format!("127.0.0.1:{uport}"), "GET", 200);
        original.url = format!("http://127.0.0.1:{uport}/");
        log.append(&original).unwrap();

        let req = Request::post("/replay")
            .header(AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id":"orig-99"}"#))
            .unwrap();
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        assert_eq!(json["replay_of"], "orig-99");
        assert_eq!(json["status"], 200);
        assert_eq!(json["res_body"], "pong");
        assert_ne!(json["id"], "orig-99", "replay gets its own id");
    }

    /// Upstream that answers with what it received: `{"headers": [[k, v]...],
    /// "body": [bytes...]}`.
    async fn start_echo_upstream() -> u16 {
        use axum::http::HeaderMap;
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/",
                post(|headers: HeaderMap, body: axum::body::Bytes| async move {
                    let pairs: Vec<(String, String)> = headers
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    Json(serde_json::json!({ "headers": pairs, "body": body.to_vec() }))
                }),
            );
            axum::serve(upstream, app).await.unwrap();
        });
        port
    }

    fn authed_post(path: &str, json: serde_json::Value) -> Request<Body> {
        Request::post(path)
            .header(AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap()
    }

    /// An original captured from `url`, recorded into the API's history.
    fn seed(log: &Hist, id: &str, url: String) {
        let mut original = entry(id, "127.0.0.1", "POST", 200);
        original.url = url;
        original.req_headers.append("x-captured", "yes");
        log.append(&original).unwrap();
    }

    #[tokio::test]
    async fn replay_endpoint_takes_req_headers_base64_body_and_meta() {
        let port = start_echo_upstream().await;
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        seed(&log, "orig-rh", format!("http://127.0.0.1:{port}/"));

        let resp = router(state.clone())
            .oneshot(authed_post(
                "/replay",
                serde_json::json!({
                    "id": "orig-rh",
                    "req_headers": [["cookie", "a=1"], ["cookie", "b=2"]],
                    "body": "AP8fiw==",
                    "body_encoding": "base64",
                    "meta": {"actor": "agent", "task_id": "T-3"},
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(
            json["meta"],
            serde_json::json!({"actor": "agent", "task_id": "T-3"})
        );
        assert_eq!(json["req_body"], "AP8fiw==");
        assert_eq!(json["req_body_encoding"], "base64");
        assert_eq!(json["peer"], format!("127.0.0.1:{port}"), "where it went");

        let echoed: serde_json::Value =
            serde_json::from_str(json["res_body"].as_str().unwrap()).unwrap();
        assert_eq!(echoed["body"], serde_json::json!([0, 255, 31, 139]));
        let sent: Vec<(String, String)> =
            serde_json::from_value(echoed["headers"].clone()).unwrap();
        let cookies: Vec<&str> = sent
            .iter()
            .filter(|(k, _)| k == "cookie")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(cookies, ["a=1", "b=2"]);
        assert!(!sent.iter().any(|(k, _)| k == "x-captured"), "replaced");
        assert!(
            !echoed.to_string().contains("T-3"),
            "meta never goes upstream: {echoed}"
        );

        // And it was recorded with its meta.
        let id = json["id"].as_str().unwrap();
        let stored = state.store.history().unwrap().get(id).unwrap().unwrap();
        assert_eq!(stored.meta.get("task_id").map(String::as_str), Some("T-3"));
    }

    #[tokio::test]
    async fn replay_endpoint_rejects_bad_input_with_400_and_records_nothing() {
        let port = start_echo_upstream().await;
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        seed(&log, "orig-bad", format!("http://127.0.0.1:{port}/"));

        for bad in [
            serde_json::json!({"id": "orig-bad", "body": "not base64!", "body_encoding": "base64"}),
            serde_json::json!({"id": "orig-bad", "req_headers": [["bad header", "v"]]}),
            serde_json::json!({"id": "orig-bad", "meta": {"": "v"}}),
        ] {
            let resp = router(state.clone())
                .oneshot(authed_post("/replay", bad.clone()))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
        }
        let all = state
            .store
            .history()
            .unwrap()
            .query(&HistoryQuery::default())
            .unwrap();
        assert_eq!(all.len(), 1, "only the original");
    }

    // --- POST /send ---

    fn state_with(dir: &TempDir, own: Vec<SocketAddr>, send_enabled: bool) -> Arc<ApiState> {
        let store = Store::new(None, Some(&dir.path().join("traffic.db"))).unwrap();
        Arc::new(ApiState {
            store,
            token: TEST_TOKEN.to_string(),
            info: test_info(),
            ca_cert: test_ca_cert(),
            own,
            send_enabled,
            clients: Default::default(),
        })
    }

    fn recorded(state: &ApiState) -> Vec<TrafficEntry> {
        state
            .store
            .history()
            .unwrap()
            .query(&HistoryQuery::default())
            .unwrap()
    }

    #[tokio::test]
    async fn send_endpoint_records_a_new_exchange_with_origin_send() {
        let port = start_echo_upstream().await;
        let dir = TempDir::new().unwrap();
        let state = state_with(&dir, vec![], true);
        state
            .store
            .history()
            .unwrap()
            .append(&entry("proxied", "h", "GET", 200))
            .unwrap();

        // The issue's shape, nulls included.
        let resp = router(state.clone())
            .oneshot(authed_post(
                "/send",
                serde_json::json!({
                    "method": "POST",
                    "url": format!("http://127.0.0.1:{port}/"),
                    "req_headers": [["accept", "*/*"]],
                    "body": "AP8=",
                    "body_encoding": "base64",
                    "meta": {"actor": "agent", "task": "T-3"},
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["origin"], "send");
        assert_eq!(json["replay_of"], serde_json::Value::Null);
        assert_eq!(json["meta"]["task"], "T-3");
        assert_eq!(json["status"], 200);
        let echoed: serde_json::Value =
            serde_json::from_str(json["res_body"].as_str().unwrap()).unwrap();
        assert_eq!(echoed["body"], serde_json::json!([0, 255]));
        let sent: Vec<(String, String)> =
            serde_json::from_value(echoed["headers"].clone()).unwrap();
        assert_eq!(sent[0], ("host".into(), format!("127.0.0.1:{port}")));
        assert_eq!(sent[1], ("accept".into(), "*/*".into()));

        let resp = router(state.clone())
            .oneshot(authed_get("/exchanges?origin=send"))
            .await
            .unwrap();
        let only: Vec<String> = body_json(resp)
            .await
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(only, [json["id"].as_str().unwrap()]);

        let resp = router(state.clone())
            .oneshot(authed_get("/exchanges?origin=carrier-pigeon"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn send_endpoint_accepts_null_body_and_encoding() {
        let port = start_echo_upstream().await;
        let dir = TempDir::new().unwrap();
        let state = state_with(&dir, vec![], true);
        let resp = router(state)
            .oneshot(authed_post(
                "/send",
                serde_json::json!({
                    "method": "POST",
                    "url": format!("http://127.0.0.1:{port}/"),
                    "body": null,
                    "body_encoding": null,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(
            json["req_headers"][1],
            serde_json::json!(["user-agent", crate::replay::USER_AGENT])
        );
    }

    #[tokio::test]
    async fn send_endpoint_400s_bad_input_and_records_nothing() {
        let port = start_echo_upstream().await;
        let dir = TempDir::new().unwrap();
        let state = state_with(&dir, vec![], true);
        let url = format!("http://127.0.0.1:{port}/");
        for bad in [
            serde_json::json!({"url": url, "body": "not base64!", "body_encoding": "base64"}),
            serde_json::json!({"url": "ftp://example.com/"}),
            serde_json::json!({"url": "/relative"}),
            serde_json::json!({"url": url, "method": "BAD METHOD"}),
            serde_json::json!({"url": url, "req_headers": [["bad header", "v"]]}),
            serde_json::json!({"url": url, "meta": {"": "v"}}),
        ] {
            let resp = router(state.clone())
                .oneshot(authed_post("/send", bad.clone()))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
        }
        assert!(recorded(&state).is_empty());
    }

    #[tokio::test]
    async fn failed_send_returns_502_with_the_recorded_entry() {
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);
        let dir = TempDir::new().unwrap();
        let state = state_with(&dir, vec![], true);
        let resp = router(state.clone())
            .oneshot(authed_post(
                "/send",
                serde_json::json!({"url": format!("http://127.0.0.1:{port}/"), "meta": {"actor": "human"}}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let json = body_json(resp).await;
        assert_eq!(json["origin"], "send");
        assert_eq!(json["method"], "GET", "the default method");
        assert!(json["error"].is_string());
        assert_eq!(json["meta"]["actor"], "human");
        let all = recorded(&state);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, json["id"].as_str().unwrap());
    }

    #[tokio::test]
    async fn send_and_replay_endpoints_refuse_taphttps_own_listeners() {
        let port = start_echo_upstream().await;
        let own: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let dir = TempDir::new().unwrap();
        let state = state_with(&dir, vec![own], true);
        let history = state.store.history().unwrap();
        let mut original = entry("to-self", "127.0.0.1", "POST", 200);
        original.url = format!("http://127.0.0.1:{port}/");
        history.append(&original).unwrap();

        let resp = router(state.clone())
            .oneshot(authed_post(
                "/send",
                serde_json::json!({"url": format!("http://localhost:{port}/")}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = router(state.clone())
            .oneshot(authed_post("/replay", serde_json::json!({"id": "to-self"})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(recorded(&state).len(), 1, "only the original");
    }

    #[tokio::test]
    async fn send_endpoint_can_be_turned_off() {
        let port = start_echo_upstream().await;
        let dir = TempDir::new().unwrap();
        let state = state_with(&dir, vec![], false);
        let resp = router(state.clone())
            .oneshot(authed_post(
                "/send",
                serde_json::json!({"url": format!("http://127.0.0.1:{port}/")}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(recorded(&state).is_empty());
    }

    #[tokio::test]
    async fn send_endpoint_requires_token() {
        let dir = TempDir::new().unwrap();
        let state = state_with(&dir, vec![], true);
        let req = Request::post("/send")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"url":"http://127.0.0.1:1/"}"#))
            .unwrap();
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn failed_replay_returns_502_with_the_one_recorded_entry() {
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        seed(&log, "orig-dead", format!("http://127.0.0.1:{port}/"));

        let resp = router(state.clone())
            .oneshot(authed_post(
                "/replay",
                serde_json::json!({"id": "orig-dead", "meta": {"actor": "human"}}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let json = body_json(resp).await;
        assert_eq!(json["replay_of"], "orig-dead");
        assert_eq!(json["status"], serde_json::Value::Null);
        assert!(
            json["error"].as_str().unwrap().contains("connect"),
            "{json}"
        );
        assert_eq!(json["meta"]["actor"], "human");

        let replays = state
            .store
            .history()
            .unwrap()
            .query(&HistoryQuery {
                replay_of: Some("orig-dead".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(replays.len(), 1, "exactly one recorded attempt");
        assert_eq!(replays[0].id, json["id"].as_str().unwrap());
    }

    fn authed(method: &str, path: &str, json: Option<serde_json::Value>) -> Request<Body> {
        let b = Request::builder()
            .method(method)
            .uri(path)
            .header(AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .header("content-type", "application/json");
        b.body(json.map_or_else(Body::empty, |j| Body::from(j.to_string())))
            .unwrap()
    }

    #[tokio::test]
    async fn clients_are_issued_listed_and_revoked() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let issue = |json| router(state.clone()).oneshot(authed("POST", "/clients", Some(json)));

        let resp = issue(serde_json::json!({
            "allow": ["example.com", "*.example.org", "10.0.0.0/8"],
            "rate": {"per_second": 5},
            "budget": 100,
            "meta": {"actor": "agent", "task": "T-7"},
        }))
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let issued = body_json(resp).await;
        let id = issued["id"].as_str().unwrap().to_string();
        assert_eq!(issued["username"], id.as_str());
        let password = issued["password"].as_str().unwrap().to_string();
        assert!(password.len() >= 32);
        assert_eq!(issued["remaining"], 100);
        assert_eq!(issued["meta"]["task"], "T-7");
        assert!(matches!(
            state.clients.authenticate(&id, &password),
            crate::clients::Lookup::Granted(_)
        ));

        let second = body_json(issue(serde_json::json!({"allow": ["*"]})).await.unwrap()).await;
        let second_id = second["id"].as_str().unwrap().to_string();

        for bad in [
            serde_json::json!({"allow": []}),
            serde_json::json!({"allow": ["not a host"]}),
            serde_json::json!({"allow": ["*"], "rate": {"per_second": -1}}),
            serde_json::json!({"allow": ["*"], "unknown": true}),
            serde_json::json!({}),
        ] {
            let resp = issue(bad.clone()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
        }

        let list = body_json(
            router(state.clone())
                .oneshot(authed("GET", "/clients", None))
                .await
                .unwrap(),
        )
        .await;
        let list = list.as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["id"], id.as_str());
        assert_eq!(list[0]["sent"], 0);
        assert_eq!(list[0]["refused"], 0);
        assert_eq!(list[0]["revoked"], false);
        assert!(!serde_json::to_string(list).unwrap().contains(&password));

        let del = |path: String| router(state.clone()).oneshot(authed("DELETE", &path, None));
        assert_eq!(
            del(format!("/clients/{id}")).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            del("/clients/c-nope".into()).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert!(matches!(
            state.clients.authenticate(&id, &password),
            crate::clients::Lookup::Denied
        ));

        // Revoke all: the e-stop.
        let resp = del("/clients".into()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await["revoked"],
            1,
            "only the second was live"
        );
        let views = state.clients.list();
        assert!(views.iter().all(|v| v.revoked), "{second_id}");

        let resp = router(state.clone())
            .oneshot(Request::get("/clients").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "same token as every route"
        );
    }

    #[tokio::test]
    async fn exchanges_filter_by_refused() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        log.append(&entry("ok", "h", "GET", 200)).unwrap();
        let mut no = entry("no", "h", "GET", 200);
        no.refused = true;
        log.append(&no).unwrap();
        for (q, want) in [("true", "no"), ("false", "ok")] {
            let resp = router(state.clone())
                .oneshot(authed_get(&format!("/exchanges?refused={q}")))
                .await
                .unwrap();
            let json = body_json(resp).await;
            let ids: Vec<&str> = json
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["id"].as_str().unwrap())
                .collect();
            assert_eq!(ids, [want], "refused={q}");
        }
        let resp = router(state)
            .oneshot(authed_get("/exchanges?refused=maybe"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn exchanges_filter_by_replay_of() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        log.append(&entry("orig", "h", "GET", 200)).unwrap();
        for (id, of) in [("r1", Some("orig")), ("x", None), ("r2", Some("orig"))] {
            let mut e = entry(id, "h", "GET", 200);
            e.replay_of = of.map(String::from);
            log.append(&e).unwrap();
        }
        let resp = router(state)
            .oneshot(authed_get("/exchanges?replay_of=orig"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let ids: Vec<&str> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["r2", "r1"]);
    }

    #[tokio::test]
    async fn replay_endpoint_unknown_id_is_not_found() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let req = Request::post("/replay")
            .header(AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id":"does-not-exist"}"#))
            .unwrap();
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn replay_endpoint_requires_token() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let req = Request::post("/replay")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id":"orig-99"}"#))
            .unwrap();
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Serve the router on an ephemeral port; returns its address.
    async fn serve_test(state: Arc<ApiState>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        addr
    }

    type Ws = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn next_json(ws: &mut Ws) -> serde_json::Value {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("feed frame within 5s")
            .unwrap()
            .unwrap();
        serde_json::from_str(msg.to_text().unwrap()).unwrap()
    }

    fn ws_message(exchange: &str, seq: u64, text: &str) -> taphttp_types::Message {
        let mut m = taphttp_types::Message {
            exchange_id: exchange.into(),
            seq,
            ts: taphttp_types::Timestamp::now(),
            kind: taphttp_types::MessageKind::Websocket,
            direction: taphttp_types::Direction::ClientToServer,
            opcode: Some(taphttp_types::Opcode::Text),
            event: None,
            event_id: None,
            size: 0,
            data: None,
            data_encoding: Default::default(),
            truncated: false,
        };
        m.set_data(text.as_bytes(), 1024);
        m
    }

    #[tokio::test]
    async fn feed_carries_messages_after_their_exchange() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let store = state.store.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/feed?token={TEST_TOKEN}"))
                .await
                .unwrap();
        store.record(entry("ws-9", "example.com", "GET", 101));
        store.record_message(ws_message("ws-9", 0, "hello"));
        assert_eq!(next_json(&mut ws).await["id"], "ws-9");
        let frame = next_json(&mut ws).await;
        assert_eq!(frame["type"], "message");
        assert_eq!(frame["message"]["exchange_id"], "ws-9");
        assert_eq!(frame["message"]["data"], "hello");
        assert_eq!(frame["message"]["schema_version"], SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn exchange_messages_are_paged_by_seq() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        log.append(&entry("ws-1", "h", "GET", 101)).unwrap();
        log.append(&entry("plain", "h", "GET", 200)).unwrap();
        for seq in 0..5 {
            state
                .store
                .record_message(ws_message("ws-1", seq, &format!("m{seq}")));
        }
        let page = |q: &str| {
            let state = state.clone();
            let q = q.to_string();
            async move {
                let resp = router(state).oneshot(authed_get(&q)).await.unwrap();
                let status = resp.status();
                let json = if status == StatusCode::OK {
                    body_json(resp).await
                } else {
                    serde_json::Value::Null
                };
                (status, json)
            }
        };
        let datas = |json: &serde_json::Value| -> Vec<String> {
            json.as_array()
                .unwrap()
                .iter()
                .map(|m| m["data"].as_str().unwrap().to_string())
                .collect()
        };
        let (status, json) = page("/exchanges/ws-1/messages").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(datas(&json), ["m0", "m1", "m2", "m3", "m4"]);
        let (_, json) = page("/exchanges/ws-1/messages?limit=2").await;
        assert_eq!(datas(&json), ["m0", "m1"]);
        let (_, json) = page("/exchanges/ws-1/messages?after=1&limit=2").await;
        assert_eq!(datas(&json), ["m2", "m3"]);
        let (status, json) = page("/exchanges/plain/messages").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json, serde_json::json!([]));
        let (status, _) = page("/exchanges/nope/messages").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = page("/exchanges/ws-1/messages?limit=0").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn feed_since_sends_backlog_then_live() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let store = state.store.clone();
        for i in 0..5 {
            store.record(entry(&format!("e{i}"), "h", "GET", 200));
        }
        let addr = serve_test(state).await;
        let (mut ws, _) = tokio_tungstenite::connect_async(format!(
            "ws://{addr}/feed?since=e1&token={TEST_TOKEN}"
        ))
        .await
        .unwrap();
        for want in ["e2", "e3", "e4"] {
            assert_eq!(next_json(&mut ws).await["id"], want);
        }
        store.record(entry("e5", "h", "GET", 200));
        assert_eq!(next_json(&mut ws).await["id"], "e5", "then live");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn feed_since_has_no_gap_and_no_duplicates_while_traffic_arrives() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let store = state.store.clone();
        for i in 0..1200 {
            store.record(entry(&format!("old{i}"), "h", "GET", 200));
        }
        let addr = serve_test(state).await;

        // Keep recording while the client connects and drains its backlog,
        // so entries land in both history and the live channel.
        let recorder = {
            let store = store.clone();
            tokio::spawn(async move {
                for i in 0..400 {
                    store.record(entry(&format!("new{i}"), "h", "GET", 200));
                    if i % 20 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            })
        };
        let (mut ws, _) = tokio_tungstenite::connect_async(format!(
            "ws://{addr}/feed?since=old99&token={TEST_TOKEN}"
        ))
        .await
        .unwrap();
        recorder.await.unwrap();
        store.record(entry("end", "h", "GET", 200));

        let mut got = Vec::new();
        loop {
            let frame = next_json(&mut ws).await;
            assert!(
                frame.get("type").is_none(),
                "unexpected control frame {frame}"
            );
            let id = frame["id"].as_str().unwrap().to_string();
            if id == "end" {
                break;
            }
            got.push(id);
        }
        let expected: Vec<String> = (100..1200)
            .map(|i| format!("old{i}"))
            .chain((0..400).map(|i| format!("new{i}")))
            .collect();
        assert_eq!(got.len(), expected.len(), "no gaps and no duplicates");
        assert_eq!(got, expected, "in record order");
    }

    #[tokio::test]
    async fn feed_since_unknown_id_sends_reset_then_live() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let store = state.store.clone();
        store.record(entry("e0", "h", "GET", 200));
        let addr = serve_test(state).await;
        let (mut ws, _) = tokio_tungstenite::connect_async(format!(
            "ws://{addr}/feed?since=wiped&token={TEST_TOKEN}"
        ))
        .await
        .unwrap();
        let reset = next_json(&mut ws).await;
        assert_eq!(reset["type"], "reset");
        assert_eq!(reset["since"], "wiped");
        store.record(entry("e1", "h", "GET", 200));
        assert_eq!(next_json(&mut ws).await["id"], "e1");
    }

    #[tokio::test]
    async fn exchanges_status_class_filter() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_db(&dir);
        for (id, code) in [("a", 200), ("b", 401), ("c", 403), ("d", 500)] {
            log.append(&entry(id, "h", "GET", code)).unwrap();
        }
        let ids = |json: serde_json::Value| {
            json.as_array()
                .unwrap()
                .iter()
                .map(|e| e["id"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        let json = body_json(
            router(state.clone())
                .oneshot(authed_get("/exchanges?status=4xx"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(ids(json), ["c", "b"]);
        let json = body_json(
            router(state.clone())
                .oneshot(authed_get("/exchanges?status=401,5xx"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(ids(json), ["d", "b"]);
        let resp = router(state)
            .oneshot(authed_get("/exchanges?status=9xx"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_over_tls_serves_clients_that_trust_the_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let ca = crate::ca::Ca::load_or_create(dir.path()).unwrap();
        let cfg = ca.listener_tls_config(&["127.0.0.1".into()]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tls(listener, router(state), cfg));

        let pem = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::get("/schema")
            .header("host", "127.0.0.1")
            .header(AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let res = sender.send_request(req).await.unwrap();
        assert_eq!(res.status(), 200);
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn feed_rejects_connection_without_token() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_db(&dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });

        let result = tokio_tungstenite::connect_async(format!("ws://{addr}/feed")).await;
        assert!(result.is_err(), "unauthenticated feed handshake must fail");
    }
}
