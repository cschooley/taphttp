//! The lever API: a small HTTP/WebSocket surface over the store that the
//! SPA and the MCP server both consume. It owns no logic of its own — every
//! endpoint delegates to the same store levers (`query_entries`, `subscribe`)
//! the CLI and the future in-process MCP handler use.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::broadcast;

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
}

/// Build the router. Kept separate from [`serve`] so tests can drive it
/// without binding a socket.
pub fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/schema", get(schema))
        .route("/exchanges", get(exchanges))
        .route("/feed", get(feed))
        .with_state(state)
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
        }
    }

    fn state_with_log(dir: &TempDir) -> (Arc<ApiState>, PathBuf) {
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(dir.path(), Some(&log), false).unwrap();
        let state = Arc::new(ApiState { store, log_path: Some(log.clone()) });
        (state, log)
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn schema_endpoint_reports_version() {
        let dir = TempDir::new().unwrap();
        let (state, _) = state_with_log(&dir);
        let resp = router(state)
            .oneshot(Request::get("/schema").body(Body::empty()).unwrap())
            .await
            .unwrap();
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
            .oneshot(Request::get("/exchanges?method=GET").body(Body::empty()).unwrap())
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
        let state = Arc::new(ApiState { store, log_path: None });
        let resp = router(state)
            .oneshot(Request::get("/exchanges").body(Body::empty()).unwrap())
            .await
            .unwrap();
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

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/feed"))
            .await
            .unwrap();

        // Record after the socket is connected; the feed is live, not a replay.
        store.record(entry("live-42", "example.com", "GET", 200));

        let msg = ws.next().await.unwrap().unwrap();
        let json: serde_json::Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_eq!(json["id"], "live-42");

        ws.close(None).await.ok();
    }
}
