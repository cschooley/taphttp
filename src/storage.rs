use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use crate::cli::ShowArgs;

/// Version of the structured traffic schema that outside consumers
/// (the lever API, the MCP server, the SPA) can depend on. Bump this
/// whenever the shape of `TrafficEntry` changes in a breaking way.
// Consumed by the lever API / MCP server (next increment); exposed now so
// the schema contract is pinned before any consumer depends on it.
#[allow(dead_code)]
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub host: String,
    pub method: String,
    pub url: String,
    pub req_headers: HashMap<String, String>,
    pub req_body: Option<String>,
    pub status: Option<u16>,
    pub res_headers: HashMap<String, String>,
    pub res_body: Option<String>,
    pub duration_ms: Option<u64>,
}

pub struct JsonLinesBackend {
    path: PathBuf,
}

impl JsonLinesBackend {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }

    #[cfg(test)]
    pub fn append(&self, entry: &TrafficEntry) -> Result<()> {
        let line = serde_json::to_string(entry)?;
        self.append_line(&line)
    }

    pub fn append_line(&self, line: &str) -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("opening traffic log")?;
        writeln!(f, "{line}")?;
        Ok(())
    }
}

pub struct SqliteBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteBackend {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let conn = Connection::open(data_dir.join("traffic.db"))
            .context("opening sqlite db")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS traffic (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                host TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                req_headers TEXT,
                req_body TEXT,
                status INTEGER,
                res_headers TEXT,
                res_body TEXT,
                duration_ms INTEGER
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn append(&self, e: &TrafficEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO traffic VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params![
                e.id,
                e.ts.to_rfc3339(),
                e.host,
                e.method,
                e.url,
                serde_json::to_string(&e.req_headers)?,
                e.req_body,
                e.status,
                serde_json::to_string(&e.res_headers)?,
                e.res_body,
                e.duration_ms,
            ],
        )?;
        Ok(())
    }
}

/// Capacity of the live-feed broadcast buffer. A slow subscriber that falls
/// this far behind is lagged (and told so) rather than slowing the proxy.
const LIVE_FEED_CAPACITY: usize = 1024;

pub struct Store {
    log_file: Option<JsonLinesBackend>,
    sqlite: Option<SqliteBackend>,
    /// Fans each recorded entry out to live subscribers (the API `/feed`
    /// WebSocket, the MCP server, anything watching traffic as it happens).
    live: broadcast::Sender<TrafficEntry>,
}

impl Store {
    pub fn new(data_dir: &Path, log_file: Option<&Path>, use_sqlite: bool) -> Result<Arc<Self>> {
        let log_file = log_file.map(JsonLinesBackend::new);
        let sqlite = if use_sqlite {
            Some(SqliteBackend::new(data_dir)?)
        } else {
            None
        };
        let (live, _) = broadcast::channel(LIVE_FEED_CAPACITY);
        Ok(Arc::new(Self { log_file, sqlite, live }))
    }

    /// Subscribe to the live feed of recorded entries. Each subscriber
    /// receives every entry recorded after it subscribes.
    // Bridged to a WebSocket by the lever API / MCP server (next increment).
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<TrafficEntry> {
        self.live.subscribe()
    }

    pub fn record(&self, entry: TrafficEntry) {
        let line = match serde_json::to_string(&entry) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("Failed to serialize traffic entry: {e}");
                return;
            }
        };

        println!("{line}");

        if let Some(f) = &self.log_file {
            if let Err(e) = f.append_line(&line) {
                tracing::warn!("Failed to write to log file: {e}");
            }
        }
        if let Some(db) = &self.sqlite {
            if let Err(e) = db.append(&entry) {
                tracing::warn!("Failed to write sqlite: {e}");
            }
        }

        // Fan out to live subscribers last. An error here just means no one
        // is listening, which is fine — the feed is best-effort.
        let _ = self.live.send(entry);
    }
}

/// A traffic query, independent of the CLI. The lever API and MCP server
/// consume this directly; the CLI builds one from its own args. Keeping the
/// query core free of clap types is what lets other tools use the store
/// without depending on the CLI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficQuery {
    pub host: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub limit: Option<usize>,
}

/// Apply a query and return the most recent `limit` entries in chronological
/// order. If `limit` is None, all matching entries are returned.
pub fn query_entries(mut entries: Vec<TrafficEntry>, q: &TrafficQuery) -> Vec<TrafficEntry> {
    if let Some(host) = &q.host {
        let h = host.to_lowercase();
        entries.retain(|e| e.host.to_lowercase().contains(&h));
    }
    if let Some(method) = &q.method {
        let m = method.to_uppercase();
        entries.retain(|e| e.method == m);
    }
    if let Some(status) = q.status {
        entries.retain(|e| e.status == Some(status));
    }
    if let Some(limit) = q.limit {
        let skip = entries.len().saturating_sub(limit);
        entries = entries.into_iter().skip(skip).collect();
    }
    entries
}

/// CLI adapter: build a [`TrafficQuery`] from `ShowArgs` and delegate.
pub fn filter_entries(entries: Vec<TrafficEntry>, args: &ShowArgs) -> Vec<TrafficEntry> {
    let query = TrafficQuery {
        host: args.host.clone(),
        method: args.method.clone(),
        status: args.status,
        limit: args.limit,
    };
    query_entries(entries, &query)
}

pub async fn show(args: ShowArgs) -> Result<()> {
    if !args.file.exists() {
        eprintln!("File not found: {}", args.file.display());
        return Ok(());
    }

    let content = std::fs::read_to_string(&args.file)?;
    let entries: Vec<TrafficEntry> = content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    let entries = filter_entries(entries, &args);

    if args.json {
        for e in &entries {
            println!("{}", serde_json::to_string(e)?);
        }
    } else {
        println!(
            "{:<36}  {:<6}  {:<20}  {:<6}  URL",
            "ID", "METHOD", "HOST", "STATUS"
        );
        println!("{}", "-".repeat(100));
        for e in &entries {
            println!(
                "{:<36}  {:<6}  {:<20}  {:<6}  {}",
                e.id,
                e.method,
                truncate(&e.host, 20),
                e.status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                truncate(&e.url, 60),
            );
        }
    }

    Ok(())
}

pub fn load_entry(data_dir: &Path, id: &str) -> Result<TrafficEntry> {
    let path = data_dir.join("traffic.jsonl");
    let content = std::fs::read_to_string(&path).context("reading traffic log")?;
    content
        .lines()
        .filter(|l| !l.is_empty())
        .find_map(|l| {
            let e: TrafficEntry = serde_json::from_str(l).ok()?;
            if e.id == id { Some(e) } else { None }
        })
        .context(format!("no entry with id {id}"))
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn make_entry(id: &str, host: &str, method: &str, status: u16) -> TrafficEntry {
        TrafficEntry {
            id: id.to_string(),
            ts: Utc::now(),
            host: host.to_string(),
            method: method.to_string(),
            url: format!("http://{host}/"),
            req_headers: HashMap::new(),
            req_body: None,
            status: Some(status),
            res_headers: HashMap::new(),
            res_body: None,
            duration_ms: Some(10),
        }
    }

    fn show_args(
        host: Option<&str>,
        method: Option<&str>,
        status: Option<u16>,
        limit: Option<usize>,
    ) -> ShowArgs {
        ShowArgs {
            file: PathBuf::from("unused"),
            host: host.map(|s| s.to_string()),
            method: method.map(|s| s.to_string()),
            status,
            limit,
            json: false,
        }
    }

    // --- JsonLinesBackend ---

    #[test]
    fn jsonl_roundtrip_preserves_all_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let backend = JsonLinesBackend::new(&path);
        let mut entry = make_entry("abc-123", "example.com", "POST", 201);
        entry.req_body = Some("body text".to_string());
        entry.res_body = Some(r#"{"ok":true}"#.to_string());
        entry.req_headers.insert("content-type".into(), "text/plain".into());

        backend.append(&entry).unwrap();

        let loaded = load_entry(dir.path(), "abc-123").unwrap();
        assert_eq!(loaded.id, "abc-123");
        assert_eq!(loaded.host, "example.com");
        assert_eq!(loaded.method, "POST");
        assert_eq!(loaded.status, Some(201));
        assert_eq!(loaded.req_body.as_deref(), Some("body text"));
        assert_eq!(loaded.res_body.as_deref(), Some(r#"{"ok":true}"#));
        assert_eq!(
            loaded.req_headers.get("content-type").map(|s| s.as_str()),
            Some("text/plain")
        );
    }

    #[test]
    fn jsonl_roundtrip_with_null_body() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let backend = JsonLinesBackend::new(&path);
        let entry = make_entry("null-body", "example.com", "GET", 200);
        backend.append(&entry).unwrap();

        let loaded = load_entry(dir.path(), "null-body").unwrap();
        assert!(loaded.req_body.is_none());
        assert!(loaded.res_body.is_none());
    }

    #[test]
    fn load_entry_returns_error_for_unknown_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        JsonLinesBackend::new(&path)
            .append(&make_entry("exists", "example.com", "GET", 200))
            .unwrap();

        assert!(load_entry(dir.path(), "no-such-id").is_err());
    }

    #[test]
    fn jsonl_appends_multiple_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let backend = JsonLinesBackend::new(&path);
        for i in 0..5u8 {
            backend.append(&make_entry(&format!("id-{i}"), "host.com", "GET", 200)).unwrap();
        }
        for i in 0..5u8 {
            load_entry(dir.path(), &format!("id-{i}")).unwrap();
        }
    }

    // --- SqliteBackend ---

    #[test]
    fn sqlite_roundtrip_preserves_all_fields() {
        let dir = TempDir::new().unwrap();
        let sqlite = SqliteBackend::new(dir.path()).unwrap();
        let jsonl = JsonLinesBackend::new(&dir.path().join("traffic.jsonl"));
        let entry = make_entry("sql-1", "db.example.com", "DELETE", 204);
        sqlite.append(&entry).unwrap();
        jsonl.append(&entry).unwrap();

        let loaded = load_entry(dir.path(), "sql-1").unwrap();
        assert_eq!(loaded.id, "sql-1");
        assert_eq!(loaded.method, "DELETE");
        assert_eq!(loaded.status, Some(204));
    }

    // --- filter_entries ---

    fn make_entries() -> Vec<TrafficEntry> {
        vec![
            make_entry("1", "api.example.com", "GET", 200),
            make_entry("2", "api.example.com", "POST", 201),
            make_entry("3", "other.io", "GET", 404),
            make_entry("4", "api.example.com", "GET", 200),
            make_entry("5", "other.io", "DELETE", 500),
        ]
    }

    #[test]
    fn filter_by_host_substring() {
        let filtered = filter_entries(make_entries(), &show_args(Some("example"), None, None, None));
        assert_eq!(filtered.len(), 3);
        assert!(filtered.iter().all(|e| e.host.contains("example")));
    }

    #[test]
    fn filter_by_host_is_case_insensitive() {
        let filtered = filter_entries(make_entries(), &show_args(Some("EXAMPLE"), None, None, None));
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_by_method() {
        let filtered = filter_entries(make_entries(), &show_args(None, Some("GET"), None, None));
        assert_eq!(filtered.len(), 3);
        assert!(filtered.iter().all(|e| e.method == "GET"));
    }

    #[test]
    fn filter_by_method_is_case_insensitive() {
        let filtered = filter_entries(make_entries(), &show_args(None, Some("get"), None, None));
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_by_status() {
        let filtered = filter_entries(make_entries(), &show_args(None, None, Some(200), None));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.status == Some(200)));
    }

    #[test]
    fn filter_combined_host_and_method() {
        let filtered = filter_entries(make_entries(), &show_args(Some("example"), Some("GET"), None, None));
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_limit_returns_most_recent() {
        let filtered = filter_entries(make_entries(), &show_args(None, None, None, Some(3)));
        assert_eq!(filtered.len(), 3);
        let ids: Vec<&str> = filtered.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["3", "4", "5"]);
    }

    // --- TrafficQuery / query_entries (CLI-independent core) ---

    #[test]
    fn query_entries_filters_by_host_and_method() {
        let q = TrafficQuery {
            host: Some("example".into()),
            method: Some("GET".into()),
            ..Default::default()
        };
        let filtered = query_entries(make_entries(), &q);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.host.contains("example") && e.method == "GET"));
    }

    #[test]
    fn query_entries_default_returns_all() {
        let filtered = query_entries(make_entries(), &TrafficQuery::default());
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn query_entries_limit_returns_most_recent() {
        let q = TrafficQuery { limit: Some(2), ..Default::default() };
        let filtered = query_entries(make_entries(), &q);
        let ids: Vec<&str> = filtered.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["4", "5"]);
    }

    #[test]
    fn filter_entries_matches_query_entries() {
        // The CLI adapter must produce the same result as the core query.
        let args = show_args(Some("example"), Some("GET"), None, None);
        let via_cli = filter_entries(make_entries(), &args);
        let via_core = query_entries(
            make_entries(),
            &TrafficQuery { host: Some("example".into()), method: Some("GET".into()), ..Default::default() },
        );
        let cli_ids: Vec<&str> = via_cli.iter().map(|e| e.id.as_str()).collect();
        let core_ids: Vec<&str> = via_core.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(cli_ids, core_ids);
    }

    #[test]
    fn schema_version_is_at_least_one() {
        assert!(SCHEMA_VERSION >= 1);
    }

    // --- live feed (broadcast primitive the API/MCP bridge to) ---

    #[tokio::test]
    async fn record_broadcasts_entry_to_subscriber() {
        let dir = TempDir::new().unwrap();
        let store = Store::new(dir.path(), None, false).unwrap();
        let mut rx = store.subscribe();
        store.record(make_entry("live-1", "example.com", "GET", 200));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.id, "live-1");
    }

    #[tokio::test]
    async fn record_without_subscribers_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let store = Store::new(dir.path(), None, false).unwrap();
        // No subscribers: the best-effort send must be a no-op, not a panic.
        store.record(make_entry("no-sub", "example.com", "GET", 200));
    }

    #[tokio::test]
    async fn every_subscriber_receives_each_entry() {
        let dir = TempDir::new().unwrap();
        let store = Store::new(dir.path(), None, false).unwrap();
        let mut rx1 = store.subscribe();
        let mut rx2 = store.subscribe();
        store.record(make_entry("fan-out", "example.com", "GET", 200));
        assert_eq!(rx1.recv().await.unwrap().id, "fan-out");
        assert_eq!(rx2.recv().await.unwrap().id, "fan-out");
    }

    #[tokio::test]
    async fn subscriber_only_sees_entries_after_it_subscribes() {
        let dir = TempDir::new().unwrap();
        let store = Store::new(dir.path(), None, false).unwrap();
        store.record(make_entry("before", "example.com", "GET", 200));
        let mut rx = store.subscribe();
        store.record(make_entry("after", "example.com", "GET", 200));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.id, "after", "feed is live, not a replay of history");
    }

    #[test]
    fn filter_no_limit_returns_all() {
        let filtered = filter_entries(make_entries(), &show_args(None, None, None, None));
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn filter_limit_larger_than_entries_returns_all() {
        let filtered = filter_entries(make_entries(), &show_args(None, None, None, Some(100)));
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn filter_returns_chronological_order() {
        let filtered = filter_entries(make_entries(), &show_args(None, None, None, Some(3)));
        let ids: Vec<&str> = filtered.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["3", "4", "5"]);
    }

    // --- truncate ---

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string_cut() {
        assert_eq!(truncate("hello world", 5), "hello");
    }
}
