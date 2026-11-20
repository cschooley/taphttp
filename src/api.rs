//! The lever API: a small HTTP/WebSocket surface over the store that the
//! SPA and the MCP server both consume. It owns no logic of its own — every
//! endpoint delegates to the same store levers (`query_entries`, `subscribe`)
//! the CLI and the future in-process MCP handler use.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::storage::{
    load_entries, query_entries, Store, TrafficEntry, TrafficQuery, SCHEMA_VERSION,
};

/// Shared state for the lever API handlers.
pub struct ApiState {
    /// Live-feed source; also the process that owns the proxy's runtime state.
    pub store: Arc<Store>,
    /// JSON-lines history the proxy is writing to, if any. `GET /exchanges`
    /// reads from here; without it, history is empty (feed-only mode).
    pub log_path: Option<PathBuf>,
    /// Secret required on every request. The traffic this API exposes and
    /// (soon) replays includes captured credentials, so the surface is
    /// authenticated even on loopback.
    pub token: String,
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

/// Build the router. Kept separate from [`serve`] so tests can drive it
/// without binding a socket.
pub fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/schema", get(schema))
        .route("/exchanges", get(exchanges))
        .route("/feed", get(feed))
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
    query.split('&').find_map(|pair| pair.strip_prefix("token="))
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

/// Bind `addr` and serve the lever API until the process exits.
pub async fn serve(state: Arc<ApiState>, addr: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    tracing::info!("lever API listening on http://{bound}");
    eprintln!("lever API listening on http://{bound}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

/// `GET /schema` — the schema contract the SPA and MCP pin against.
async fn schema() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "schema_version": SCHEMA_VERSION }))
}

/// `GET /exchanges` — historical traffic, filtered by the query string
/// (`host`, `method`, `status`, `limit`) via the shared query core.
async fn exchanges(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<TrafficQuery>,
) -> Json<Vec<TrafficEntry>> {
    let entries = match &state.log_path {
        Some(path) => load_entries(path).unwrap_or_default(),
        None => Vec::new(),
    };
    Json(query_entries(entries, &query))
}

/// `GET /feed` — WebSocket of entries recorded after the client connects.
async fn feed(State(state): State<Arc<ApiState>>, ws: WebSocketUpgrade) -> Response {
    let rx = state.store.subscribe();
    ws.on_upgrade(move |socket| pump_feed(socket, rx))
}

/// Forward each recorded entry to the socket as a JSON text frame. A lagged
/// subscriber skips the gap rather than stalling the proxy; a closed channel
/// or a dropped client ends the stream.
async fn pump_feed(mut socket: WebSocket, mut rx: broadcast::Receiver<TrafficEntry>) {
    loop {
        match rx.recv().await {
            Ok(entry) => {
                let Ok(text) = serde_json::to_string(&entry) else {
                    continue;
                };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::JsonLinesBackend;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures_util::StreamExt;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use tower::ServiceExt; // for `oneshot`

    const TEST_TOKEN: &str = "test-token-xyz";

    fn entry(id: &str, host: &str, method: &str, status: u16) -> TrafficEntry {
        TrafficEntry {
            id: id.to_string(),
            ts: chrono::Utc::now(),
            host: host.to_string(),
            method: method.to_string(),
            url: format!("http://{host}/"),
            req_headers: HashMap::new(),
            req_body: None,
            status: Some(status),
            res_headers: HashMap::new(),
            res_body: None,
            duration_ms: Some(1),
            replay_of: None,
        }
    }

    fn state_with_log(dir: &TempDir) -> (Arc<ApiState>, PathBuf) {
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(dir.path(), Some(&log), false).unwrap();
        let state = Arc::new(ApiState {
            store,
            log_path: Some(log.clone()),
            token: TEST_TOKEN.to_string(),
        });
        (state, log)
    }

    /// A GET request carrying the valid bearer token.
    fn authed_get(path: &str) -> Request<Body> {
        Request::get(path)
            .header(AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // --- auth ---

    #[tokio::test]
    async fn request_without_token_is_unauthorized() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_log(&dir);
        let resp = router(state)
            .oneshot(Request::get("/schema").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_wrong_token_is_unauthorized() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_log(&dir);
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
        let (state, _) = state_with_log(&dir);
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
        let (state, _) = state_with_log(&dir);
        let resp = router(state).oneshot(authed_get("/schema")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn exchanges_returns_filtered_history() {
        let dir = TempDir::new().unwrap();
        let (state, log) = state_with_log(&dir);
        let backend = JsonLinesBackend::new(&log);
        backend.append(&entry("a", "api.example.com", "GET", 200)).unwrap();
        backend.append(&entry("b", "api.example.com", "POST", 201)).unwrap();
        backend.append(&entry("c", "other.io", "GET", 404)).unwrap();

        let resp = router(state)
            .oneshot(authed_get("/exchanges?method=GET"))
            .await
            .unwrap();
        let json = body_json(resp).await;
        let ids: Vec<&str> = json.as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["a", "c"]);
    }

    #[tokio::test]
    async fn exchanges_without_log_is_empty() {
        let dir = TempDir::new().unwrap();
        let store = Store::new(dir.path(), None, false).unwrap();
        let state = Arc::new(ApiState { store, log_path: None, token: TEST_TOKEN.to_string() });
        let resp = router(state).oneshot(authed_get("/exchanges")).await.unwrap();
        let json = body_json(resp).await;
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn feed_streams_entries_recorded_after_connect() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_log(&dir);
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
    async fn feed_rejects_connection_without_token() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_log(&dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });

        let result = tokio_tungstenite::connect_async(format!("ws://{addr}/feed")).await;
        assert!(result.is_err(), "unauthenticated feed handshake must fail");
    }
}
