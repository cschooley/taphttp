use crate::cli::ShowArgs;
use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

// The traffic schema lives in the `taphttp-types` crate so consumers can
// depend on it without the proxy. Re-exported here so the rest of the crate
// keeps one import path.
pub use taphttp_types::{Headers, TrafficEntry, SCHEMA_VERSION};

pub struct JsonLinesBackend {
    path: PathBuf,
    /// Serializes writers. Every proxy connection task records through the
    /// same backend; unserialized, two lines can interleave (issue #6).
    write_lock: Mutex<()>,
}

impl JsonLinesBackend {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            write_lock: Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub fn append(&self, entry: &TrafficEntry) -> Result<()> {
        let line = serde_json::to_string(entry)?;
        self.append_line(&line)
    }

    /// Append `line` plus a newline as a single write, under the lock.
    ///
    /// `writeln!` on a `File` issues the line and the newline as separate
    /// syscalls; O_APPEND keeps each atomic but not the pair, so concurrent
    /// writers produced `{A}{B}\n\n`. One buffer means one O_APPEND write,
    /// which also keeps lines whole against another process appending
    /// (e.g. `taphttp replay` on the log a running proxy writes).
    ///
    /// The file is reopened per line rather than held open, so a log rotated
    /// by rename is followed by a fresh file instead of written to under its
    /// old name.
    pub fn append_line(&self, line: &str) -> Result<()> {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("opening traffic log")?;
        f.write_all(&buf).context("writing traffic log")?;
        Ok(())
    }
}

pub struct SqliteBackend {
    /// Shared with the history reader (`crate::history`).
    pub(crate) conn: Arc<Mutex<Connection>>,
}

/// Columns of the `traffic` table, in insert order. v1/v2 databases have
/// only the first eleven; [`SqliteBackend::new`] adds the rest.
const SQLITE_COLUMNS: [(&str, &str); 17] = [
    ("id", "TEXT PRIMARY KEY"),
    ("ts", "TEXT NOT NULL"),
    ("host", "TEXT NOT NULL"),
    ("method", "TEXT NOT NULL"),
    ("url", "TEXT NOT NULL"),
    ("req_headers", "TEXT"),
    ("req_body", "TEXT"),
    ("status", "INTEGER"),
    ("res_headers", "TEXT"),
    ("res_body", "TEXT"),
    ("duration_ms", "INTEGER"),
    // v3 additions (replay_of was v2 in the JSON schema but never reached sqlite).
    ("replay_of", "TEXT"),
    ("req_body_encoding", "TEXT"),
    ("res_body_encoding", "TEXT"),
    ("schema_version", "INTEGER"),
    // `ts` as microseconds since the epoch, for since/until filters. `ts` is
    // RFC 3339 text with variable fraction digits, which doesn't sort.
    ("ts_us", "INTEGER"),
    // v4: who sent the exchange (proxy-auth username).
    ("source", "TEXT"),
];

impl SqliteBackend {
    pub fn new(db_path: &Path) -> Result<Self> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("opening sqlite db {}", db_path.display()))?;
        // Every proxied exchange is an insert. With the default rollback
        // journal each one is an fsync'd transaction under the store lock,
        // which caps the proxy at ~100 req/s. WAL + NORMAL survives a crash
        // of taphttp; a power cut may lose the last few entries.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .context("configuring sqlite")?;
        let defs: Vec<String> = SQLITE_COLUMNS
            .iter()
            .map(|(n, t)| format!("{n} {t}"))
            .collect();
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS traffic ({});",
            defs.join(", ")
        ))?;
        // Migrate a database created by an older taphttp: add missing columns.
        // Old rows keep NULL there, which reads as utf8 / pre-v3.
        let existing: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('traffic')")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for (name, ty) in SQLITE_COLUMNS {
            if !existing.iter().any(|c| c == name) {
                conn.execute_batch(&format!("ALTER TABLE traffic ADD COLUMN {name} {ty};"))
                    .with_context(|| format!("migrating sqlite: adding column {name}"))?;
            }
        }
        conn.execute_batch("CREATE INDEX IF NOT EXISTS traffic_ts_us ON traffic (ts_us);")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn append(&self, e: &TrafficEntry) -> Result<()> {
        let names: Vec<&str> = SQLITE_COLUMNS.iter().map(|(n, _)| *n).collect();
        let slots: Vec<String> = (1..=names.len()).map(|i| format!("?{i}")).collect();
        let encoding = |enc| {
            serde_json::to_value(enc)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT OR REPLACE INTO traffic ({}) VALUES ({})",
                names.join(","),
                slots.join(",")
            ),
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
                e.replay_of,
                encoding(e.req_body_encoding),
                encoding(e.res_body_encoding),
                SCHEMA_VERSION,
                e.ts.timestamp_micros(),
                e.source,
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
    /// `db` is the sqlite database to also record into (and serve history
    /// from), if any.
    pub fn new(log_file: Option<&Path>, db: Option<&Path>) -> Result<Arc<Self>> {
        let log_file = log_file.map(JsonLinesBackend::new);
        let sqlite = db.map(SqliteBackend::new).transpose()?;
        let (live, _) = broadcast::channel(LIVE_FEED_CAPACITY);
        Ok(Arc::new(Self {
            log_file,
            sqlite,
            live,
        }))
    }

    /// Subscribe to the live feed of recorded entries. Each subscriber
    /// receives every entry recorded after it subscribes.
    pub fn subscribe(&self) -> broadcast::Receiver<TrafficEntry> {
        self.live.subscribe()
    }

    /// The sqlite history, when recording to sqlite.
    pub fn history(&self) -> Option<&SqliteBackend> {
        self.sqlite.as_ref()
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

/// Load all traffic entries from a JSON-lines log file, skipping blank and
/// unparseable lines. Shared by the `show` CLI command and the lever API.
pub fn load_entries(path: &Path) -> Result<Vec<TrafficEntry>> {
    let content = std::fs::read_to_string(path).context("reading traffic log")?;
    let (entries, skipped) = parse_log(&content);
    if skipped > 0 {
        // Corruption must be visible, not silently shrink the history.
        tracing::warn!(
            "{}: skipped {skipped} line(s) that are not valid traffic entries",
            path.display()
        );
    }
    Ok(entries)
}

/// Parse JSON-lines content into entries, returning how many non-blank lines
/// failed to parse.
fn parse_log(content: &str) -> (Vec<TrafficEntry>, usize) {
    let mut skipped = 0;
    let entries = content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let parsed = serde_json::from_str(l).ok();
            if parsed.is_none() {
                skipped += 1;
            }
            parsed
        })
        .collect();
    (entries, skipped)
}

pub async fn show(args: ShowArgs) -> Result<()> {
    if !args.file.exists() {
        eprintln!("File not found: {}", args.file.display());
        return Ok(());
    }

    let entries = load_entries(&args.file)?;
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

/// Find the entry with `id` in the JSON-lines log at `path`.
pub fn load_entry(path: &Path, id: &str) -> Result<TrafficEntry> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading traffic log {}", path.display()))?;
    content
        .lines()
        .filter(|l| !l.is_empty())
        .find_map(|l| {
            let e: TrafficEntry = serde_json::from_str(l).ok()?;
            if e.id == id {
                Some(e)
            } else {
                None
            }
        })
        .context(format!("no entry with id {id}"))
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
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
            req_headers: Headers::new(),
            req_body: None,
            req_body_encoding: Default::default(),
            status: Some(status),
            res_headers: Headers::new(),
            res_body: None,
            res_body_encoding: Default::default(),
            duration_ms: Some(10),
            replay_of: None,
            source: None,
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
        entry.req_headers.append("content-type", "text/plain");

        backend.append(&entry).unwrap();

        let loaded = load_entry(&dir.path().join("traffic.jsonl"), "abc-123").unwrap();
        assert_eq!(loaded.id, "abc-123");
        assert_eq!(loaded.host, "example.com");
        assert_eq!(loaded.method, "POST");
        assert_eq!(loaded.status, Some(201));
        assert_eq!(loaded.req_body.as_deref(), Some("body text"));
        assert_eq!(loaded.res_body.as_deref(), Some(r#"{"ok":true}"#));
        assert_eq!(loaded.req_headers.get("content-type"), Some("text/plain"));
    }

    #[test]
    fn jsonl_roundtrip_with_null_body() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let backend = JsonLinesBackend::new(&path);
        let entry = make_entry("null-body", "example.com", "GET", 200);
        backend.append(&entry).unwrap();

        let loaded = load_entry(&dir.path().join("traffic.jsonl"), "null-body").unwrap();
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

        assert!(load_entry(&dir.path().join("traffic.jsonl"), "no-such-id").is_err());
    }

    #[test]
    fn load_entries_reads_all_and_skips_blank_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let backend = JsonLinesBackend::new(&path);
        backend
            .append(&make_entry("a", "x.com", "GET", 200))
            .unwrap();
        backend
            .append(&make_entry("b", "y.com", "POST", 201))
            .unwrap();
        // A stray blank line and a garbage line must be tolerated.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .map(|mut f| writeln!(f, "\nnot json").unwrap())
            .unwrap();

        let entries = load_entries(&path).unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
    }

    /// Every line parses, and there is exactly one line per entry written.
    fn assert_log_intact(path: &Path, expected: usize) {
        let content = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = content.split_terminator('\n').collect();
        let blank = lines.iter().filter(|l| l.is_empty()).count();
        let bad = lines
            .iter()
            .filter(|l| !l.is_empty() && serde_json::from_str::<TrafficEntry>(l).is_err())
            .count();
        assert_eq!(
            (blank, bad),
            (0, 0),
            "{blank} blank and {bad} unparseable (fused) lines"
        );
        assert_eq!(lines.len(), expected, "one line per entry");
        assert!(content.ends_with('\n'));
    }

    fn entry_with_kb_body(id: String) -> TrafficEntry {
        let mut e = make_entry(&id, "example.com", "POST", 200);
        e.set_res_body("x".repeat(1024).as_bytes());
        e
    }

    #[test]
    fn concurrent_appends_never_fuse_lines() {
        // Issue #6: 32 writers x 200 ~1 KB entries on one backend.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let backend = Arc::new(JsonLinesBackend::new(&path));
        let threads: Vec<_> = (0..32)
            .map(|t| {
                let backend = backend.clone();
                std::thread::spawn(move || {
                    for i in 0..200 {
                        backend
                            .append(&entry_with_kb_body(format!("t{t}-{i}")))
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_log_intact(&path, 32 * 200);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_store_records_never_fuse_lines() {
        // The real path: every proxy connection task calls Store::record.
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(Some(&log), None).unwrap();
        let tasks: Vec<_> = (0..1000)
            .map(|i| {
                let store = store.clone();
                tokio::spawn(async move { store.record(entry_with_kb_body(format!("r{i}"))) })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        assert_log_intact(&log, 1000);
    }

    #[test]
    fn parse_log_counts_skipped_lines() {
        let good = serde_json::to_string(&make_entry("ok", "h", "GET", 200)).unwrap();
        let content = format!("{good}\n\n{good}{good}\nnot json\n{good}\n");
        let (entries, skipped) = parse_log(&content);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            skipped, 2,
            "the fused line and the garbage line; blank lines aren't counted"
        );
    }

    #[test]
    fn load_entries_errors_on_missing_file() {
        let dir = TempDir::new().unwrap();
        assert!(load_entries(&dir.path().join("nope.jsonl")).is_err());
    }

    #[test]
    fn jsonl_appends_multiple_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let backend = JsonLinesBackend::new(&path);
        for i in 0..5u8 {
            backend
                .append(&make_entry(&format!("id-{i}"), "host.com", "GET", 200))
                .unwrap();
        }
        for i in 0..5u8 {
            load_entry(&dir.path().join("traffic.jsonl"), &format!("id-{i}")).unwrap();
        }
    }

    // --- SqliteBackend ---

    #[test]
    fn sqlite_roundtrip_preserves_all_fields() {
        let dir = TempDir::new().unwrap();
        let sqlite = SqliteBackend::new(&dir.path().join("traffic.db")).unwrap();
        let jsonl = JsonLinesBackend::new(&dir.path().join("traffic.jsonl"));
        let entry = make_entry("sql-1", "db.example.com", "DELETE", 204);
        sqlite.append(&entry).unwrap();
        jsonl.append(&entry).unwrap();

        let loaded = load_entry(&dir.path().join("traffic.jsonl"), "sql-1").unwrap();
        assert_eq!(loaded.id, "sql-1");
        assert_eq!(loaded.method, "DELETE");
        assert_eq!(loaded.status, Some(204));
    }

    /// Read one row back the way a downstream sqlite reader would.
    fn sqlite_row(
        dir: &Path,
        id: &str,
    ) -> (
        Headers,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<u32>,
    ) {
        let conn = Connection::open(dir.join("traffic.db")).unwrap();
        conn.query_row(
            "SELECT res_headers, res_body, res_body_encoding, replay_of, schema_version FROM traffic WHERE id = ?1",
            [id],
            |r| {
                let h: String = r.get(0)?;
                Ok((serde_json::from_str(&h).unwrap(), r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            },
        )
        .unwrap()
    }

    #[test]
    fn sqlite_stores_repeated_headers_encoding_replay_of_and_version() {
        let dir = TempDir::new().unwrap();
        let sqlite = SqliteBackend::new(&dir.path().join("traffic.db")).unwrap();
        let mut e = make_entry("v3", "h", "GET", 200);
        e.res_headers.append("set-cookie", "a=1");
        e.res_headers.append("set-cookie", "b=2");
        e.set_res_body(&[0xff, 0x00]);
        e.replay_of = Some("orig".into());
        sqlite.append(&e).unwrap();

        let (h, body, enc, replay_of, version) = sqlite_row(dir.path(), "v3");
        assert_eq!(h.get_all("set-cookie").collect::<Vec<_>>(), ["a=1", "b=2"]);
        assert_eq!(body.as_deref(), Some("/wA="));
        assert_eq!(enc.as_deref(), Some("base64"));
        assert_eq!(replay_of.as_deref(), Some("orig"));
        assert_eq!(version, Some(SCHEMA_VERSION));
    }

    #[test]
    fn sqlite_uses_wal_with_normal_sync() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("traffic.db")).unwrap();
        let conn = db.conn.lock().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let sync: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!((mode.as_str(), sync), ("wal", 1), "wal + NORMAL(1)");
    }

    #[test]
    fn sqlite_migrates_a_v2_database_and_old_rows_still_read() {
        let dir = TempDir::new().unwrap();
        {
            // The exact table an older taphttp created, with one v2 row.
            let conn = Connection::open(dir.path().join("traffic.db")).unwrap();
            conn.execute_batch(
                "CREATE TABLE traffic (id TEXT PRIMARY KEY, ts TEXT NOT NULL, host TEXT NOT NULL,
                    method TEXT NOT NULL, url TEXT NOT NULL, req_headers TEXT, req_body TEXT,
                    status INTEGER, res_headers TEXT, res_body TEXT, duration_ms INTEGER);
                 INSERT INTO traffic VALUES ('old','2026-01-01T00:00:00+00:00','h','GET','http://h/',
                    '{}',NULL,200,'{\"set-cookie\":\"a=1\"}','ok',5);",
            )
            .unwrap();
        }

        let sqlite = SqliteBackend::new(&dir.path().join("traffic.db")).unwrap();
        sqlite.append(&make_entry("new", "h", "GET", 200)).unwrap();

        let (h, body, enc, _, version) = sqlite_row(dir.path(), "old");
        assert_eq!(
            h.get("set-cookie"),
            Some("a=1"),
            "v2 header map still reads"
        );
        assert_eq!(body.as_deref(), Some("ok"));
        assert_eq!(enc, None, "missing encoding means utf8");
        assert_eq!(version, None);
        assert_eq!(sqlite_row(dir.path(), "new").4, Some(SCHEMA_VERSION));
    }

    #[test]
    fn v2_jsonl_log_still_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("traffic.jsonl");
        std::fs::write(
            &path,
            concat!(
                r#"{"id":"v2","ts":"2026-01-01T00:00:00Z","host":"h","method":"GET","url":"http://h/","req_headers":{"accept":"*/*"},"req_body":null,"status":200,"res_headers":{"set-cookie":"a=1"},"res_body":"ok","duration_ms":1,"replay_of":null}"#,
                "\n"
            ),
        )
        .unwrap();
        let e = load_entry(&path, "v2").unwrap();
        assert_eq!(e.req_headers.get("accept"), Some("*/*"));
        assert_eq!(e.res_body_bytes().unwrap().as_deref(), Some(&b"ok"[..]));
        assert_eq!(load_entries(&path).unwrap().len(), 1);
    }

    #[test]
    fn record_writes_schema_version_on_every_line() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("traffic.jsonl");
        let store = Store::new(Some(&log), None).unwrap();
        store.record(make_entry("a", "h", "GET", 200));
        store.record(make_entry("b", "h", "GET", 200));
        let content = std::fs::read_to_string(&log).unwrap();
        for line in content.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["schema_version"], SCHEMA_VERSION, "{line}");
        }
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
        let filtered = filter_entries(
            make_entries(),
            &show_args(Some("example"), None, None, None),
        );
        assert_eq!(filtered.len(), 3);
        assert!(filtered.iter().all(|e| e.host.contains("example")));
    }

    #[test]
    fn filter_by_host_is_case_insensitive() {
        let filtered = filter_entries(
            make_entries(),
            &show_args(Some("EXAMPLE"), None, None, None),
        );
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
        let filtered = filter_entries(
            make_entries(),
            &show_args(Some("example"), Some("GET"), None, None),
        );
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
        assert!(filtered
            .iter()
            .all(|e| e.host.contains("example") && e.method == "GET"));
    }

    #[test]
    fn query_entries_default_returns_all() {
        let filtered = query_entries(make_entries(), &TrafficQuery::default());
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn query_entries_limit_returns_most_recent() {
        let q = TrafficQuery {
            limit: Some(2),
            ..Default::default()
        };
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
            &TrafficQuery {
                host: Some("example".into()),
                method: Some("GET".into()),
                ..Default::default()
            },
        );
        let cli_ids: Vec<&str> = via_cli.iter().map(|e| e.id.as_str()).collect();
        let core_ids: Vec<&str> = via_core.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(cli_ids, core_ids);
    }

    #[test]
    fn traffic_entry_without_replay_of_loads_as_none() {
        // A pre-v2 record on disk has no `replay_of` key; it must still parse.
        let json = r#"{"id":"old","ts":"2026-01-01T00:00:00Z","host":"h","method":"GET","url":"http://h/","req_headers":{},"req_body":null,"status":200,"res_headers":{},"res_body":null,"duration_ms":1}"#;
        let e: TrafficEntry = serde_json::from_str(json).unwrap();
        assert!(e.replay_of.is_none());
    }

    #[test]
    fn traffic_entry_roundtrips_replay_of() {
        let mut e = make_entry("r", "h", "GET", 200);
        e.replay_of = Some("orig".into());
        let back: TrafficEntry = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back.replay_of.as_deref(), Some("orig"));
    }

    // --- live feed (broadcast primitive the API/MCP bridge to) ---

    #[tokio::test]
    async fn record_broadcasts_entry_to_subscriber() {
        let store = Store::new(None, None).unwrap();
        let mut rx = store.subscribe();
        store.record(make_entry("live-1", "example.com", "GET", 200));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.id, "live-1");
    }

    #[tokio::test]
    async fn record_without_subscribers_does_not_panic() {
        let store = Store::new(None, None).unwrap();
        // No subscribers: the best-effort send must be a no-op, not a panic.
        store.record(make_entry("no-sub", "example.com", "GET", 200));
    }

    #[tokio::test]
    async fn every_subscriber_receives_each_entry() {
        let store = Store::new(None, None).unwrap();
        let mut rx1 = store.subscribe();
        let mut rx2 = store.subscribe();
        store.record(make_entry("fan-out", "example.com", "GET", 200));
        assert_eq!(rx1.recv().await.unwrap().id, "fan-out");
        assert_eq!(rx2.recv().await.unwrap().id, "fan-out");
    }

    #[tokio::test]
    async fn subscriber_only_sees_entries_after_it_subscribes() {
        let store = Store::new(None, None).unwrap();
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
